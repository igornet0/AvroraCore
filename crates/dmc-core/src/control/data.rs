use avrora_proto::{
    ControlMsg, DataRequest, DataResponse, WireAckBatch, WireConsumerLag, WireConsumerMetrics,
    WireDeliveredEvent, WireDelivery, WireDlqEntry, WirePending,
};

use crate::control::ControlState;
use crate::error::Error;
use crate::ids::{DlqEntryId, SessionId, StreamId, SubscriptionId};
use crate::runtime::{ConsumerLag, ConsumerMetrics, DbStatus, PutOptions};
use crate::subscription::{
    BatchLimits, ConsumerPolicy, DeliveredEvent, DeliveryId, RetryPolicy,
};
use crate::DlqEntry;

pub async fn handle_data(
    state: &ControlState,
    device_id: Option<&str>,
    session: &str,
    runtime_session: String,
    request: DataRequest,
) -> ControlMsg {
    if state.runtime.status().await != DbStatus::Unlocked {
        return data_err(&Error::Locked);
    }
    match dispatch(state, device_id, session, runtime_session, request).await {
        Ok(response) => ControlMsg::DataOk { response },
        Err(e) => data_err(&e),
    }
}

async fn dispatch(
    state: &ControlState,
    device_id: Option<&str>,
    _control_session: &str,
    runtime_session: String,
    request: DataRequest,
) -> Result<DataResponse, Error> {
    match request {
        DataRequest::OpenAdminSession => {
            let id = state.runtime.admin_session().await?;
            Ok(DataResponse::Session {
                runtime_session: id.to_string(),
            })
        }
        DataRequest::OpenUserSession { user_id, device_id: req_device } => {
            let device = req_device.as_deref().or(device_id);
            let id = state.runtime.open_user_session(&user_id, device).await?;
            Ok(DataResponse::Session {
                runtime_session: id.to_string(),
            })
        }
        other => {
            let session = SessionId::from(runtime_session.as_str());
            dispatch_authed(state, device_id, &session, other).await
        }
    }
}

async fn dispatch_authed(
    state: &ControlState,
    device_id: Option<&str>,
    session: &SessionId,
    request: DataRequest,
) -> Result<DataResponse, Error> {
    let rt = &state.runtime;
    match request {
        DataRequest::OpenAdminSession | DataRequest::OpenUserSession { .. } => {
            unreachable!("session open handled above")
        }
        DataRequest::PutPath {
            path,
            payload,
            producer_id,
            idempotency_key,
        } => {
            let options = idempotency_key.filter(|k| !k.is_empty()).map(|key| PutOptions {
                producer_id: producer_id
                    .filter(|s| !s.is_empty())
                    .or_else(|| device_id.map(str::to_string))
                    .unwrap_or_else(|| "local".into()),
                idempotency_key: key,
            });
            let put = rt.put_data_with(session, &path, &payload, options).await?;
            Ok(DataResponse::Put {
                event_id: put.event_id,
                sequence: put.sequence,
                replay: put.replay,
            })
        }
        DataRequest::DeletePath { path } => {
            rt.delete_data(session, &path).await?;
            Ok(DataResponse::Empty)
        }
        DataRequest::GetPath { path } => {
            let payload = rt.get_data(session, &path).await?;
            Ok(DataResponse::Bytes { payload })
        }
        DataRequest::ListPaths { prefix } => {
            let paths = rt.list_keys(session, &prefix).await?;
            Ok(DataResponse::Paths { paths })
        }
        DataRequest::CreateSubscription {
            stream_id,
            consumer_id,
        } => {
            let stream = StreamId::from(stream_id);
            let sub = rt
                .create_subscription(session, &stream, consumer_id.as_deref())
                .await?;
            Ok(DataResponse::Subscription {
                subscription_id: sub.id.to_string(),
            })
        }
        DataRequest::Consume { subscription_id } => {
            let sub = SubscriptionId::from(subscription_id);
            let events = rt.consume(&sub, 1).await?;
            Ok(DataResponse::Events {
                events: events.into_iter().map(wire_event).collect(),
            })
        }
        DataRequest::ConsumeBatch {
            subscription_id,
            max_events,
            max_bytes,
        } => {
            let sub = SubscriptionId::from(subscription_id);
            let events = rt
                .consume_batch(
                    &sub,
                    BatchLimits {
                        max_events: max_events as usize,
                        max_bytes,
                    },
                )
                .await?;
            Ok(DataResponse::Events {
                events: events.into_iter().map(wire_event).collect(),
            })
        }
        DataRequest::Ack {
            subscription_id,
            delivery_id,
        } => {
            let sub = SubscriptionId::from(subscription_id);
            rt.ack(session, &sub, &DeliveryId(delivery_id)).await?;
            let offset = rt
                .get_subscription(&sub)
                .await?
                .position
                .sequence;
            Ok(DataResponse::Ack { offset })
        }
        DataRequest::AckBatch {
            subscription_id,
            delivery_ids,
        } => {
            let sub = SubscriptionId::from(subscription_id);
            let ids: Vec<_> = delivery_ids.into_iter().map(DeliveryId).collect();
            let result = rt.ack_batch(session, &sub, &ids).await?;
            Ok(DataResponse::AckBatch {
                result: WireAckBatch {
                    offset: result.offset,
                    acked: result.acked,
                    stale: result.stale,
                    unknown: result.unknown,
                },
            })
        }
        DataRequest::Replay {
            subscription_id,
            from_sequence,
            limit,
        } => {
            let sub = SubscriptionId::from(subscription_id);
            let events = rt.replay(&sub, from_sequence, limit as usize).await?;
            Ok(DataResponse::Events {
                events: events.into_iter().map(wire_event).collect(),
            })
        }
        DataRequest::ListDlq { subscription_id } => {
            let sub = SubscriptionId::from(subscription_id);
            let entries = rt.list_dlq(session, &sub).await?;
            Ok(DataResponse::DlqList {
                entries: entries.into_iter().map(wire_dlq).collect(),
            })
        }
        DataRequest::ReadDlq { entry_id } => {
            let entry = rt.read_dlq_entry(session, &DlqEntryId::from(entry_id)).await?;
            Ok(DataResponse::DlqEntry {
                entry: wire_dlq(entry),
            })
        }
        DataRequest::RetryDlq { entry_id } => {
            let ev = rt.retry_dlq(session, &DlqEntryId::from(entry_id)).await?;
            Ok(DataResponse::Events {
                events: vec![wire_event(ev)],
            })
        }
        DataRequest::DeleteDlq { entry_id } => {
            rt.delete_dlq(session, &DlqEntryId::from(entry_id)).await?;
            Ok(DataResponse::Empty)
        }
        DataRequest::ConsumerLag { subscription_id } => {
            let sub = SubscriptionId::from(subscription_id);
            let lag = rt.consumer_lag(&sub).await?;
            Ok(DataResponse::Lag {
                lag: wire_lag(lag),
            })
        }
        DataRequest::ConsumerMetrics => {
            let metrics = rt.consumer_metrics().await?;
            Ok(DataResponse::Metrics {
                metrics: wire_metrics(metrics),
            })
        }
        DataRequest::SetRetryPolicy {
            subscription_id,
            max_attempts,
            initial_backoff_ms,
            max_backoff_ms,
            multiplier,
        } => {
            let sub = SubscriptionId::from(subscription_id);
            rt.set_retry_policy(
                session,
                &sub,
                RetryPolicy {
                    max_attempts,
                    initial_backoff_ms,
                    max_backoff_ms,
                    multiplier,
                },
            )
            .await?;
            Ok(DataResponse::Empty)
        }
        DataRequest::SetConsumerPolicy {
            subscription_id,
            max_in_flight,
            max_batch_events,
            max_batch_bytes,
        } => {
            let sub = SubscriptionId::from(subscription_id);
            rt.set_consumer_policy(
                session,
                &sub,
                ConsumerPolicy {
                    max_in_flight,
                    max_batch_events,
                    max_batch_bytes,
                },
            )
            .await?;
            Ok(DataResponse::Empty)
        }
    }
}

fn wire_event(ev: DeliveredEvent) -> WireDeliveredEvent {
    WireDeliveredEvent {
        sequence: ev.sequence,
        event_id: ev.event_id,
        path: ev.path,
        payload: ev.payload,
        operation: ev.operation,
        delivery: WireDelivery {
            delivery_id: ev.delivery.delivery_id.to_string(),
            subscription_id: ev.delivery.subscription_id.to_string(),
            event_id: ev.delivery.event_id,
            sequence: ev.delivery.sequence,
            attempt: ev.delivery.attempt,
        },
    }
}

fn wire_dlq(entry: DlqEntry) -> WireDlqEntry {
    WireDlqEntry {
        id: entry.id.to_string(),
        original_event_id: entry.original_event_id,
        original_sequence: entry.original_sequence,
        original_path: entry.original_path,
        subscription_id: entry.subscription_id.to_string(),
        attempts: entry.attempts,
        payload: entry.payload,
    }
}

fn wire_lag(lag: ConsumerLag) -> WireConsumerLag {
    WireConsumerLag {
        subscription_id: lag.subscription_id,
        journal_head: lag.journal_head,
        offset: lag.offset,
        lag_events: lag.lag_events,
        pending: lag.pending.map(|p| WirePending {
            sequence: p.sequence,
            attempt: p.attempt,
            event_id: p.event_id,
        }),
        dlq_count: lag.dlq_count,
        retry_backoff_until: lag.retry_backoff_until,
    }
}

fn wire_metrics(metrics: ConsumerMetrics) -> WireConsumerMetrics {
    WireConsumerMetrics {
        subscriptions: metrics.subscriptions.into_iter().map(wire_lag).collect(),
        journal_head: metrics.journal_head,
        total_dlq: metrics.total_dlq,
    }
}

fn data_err(err: &Error) -> ControlMsg {
    let (code, retry_at_ms, sequence) = match err {
        Error::AuthorizationDenied(_) => ("AUTHORIZATION_DENIED", None, None),
        Error::StaleDelivery(_) => ("STALE_DELIVERY", None, None),
        Error::RetryBackoff { retry_at_ms, .. } => ("RETRY_BACKOFF", Some(*retry_at_ms), None),
        Error::GroupRetryBackoff { retry_at_ms, .. } => ("GROUP_RETRY_BACKOFF", Some(*retry_at_ms), None),
        Error::GroupRetryExhausted { .. } => ("GROUP_RETRY_EXHAUSTED", None, None),
        Error::Backpressure { .. } => ("BACKPRESSURE", None, None),
        Error::UnknownDelivery(_) => ("UNKNOWN_DELIVERY", None, None),
        Error::UnknownSubscription(_) => ("UNKNOWN_SUBSCRIPTION", None, None),
        Error::UnknownDlq(_) => ("UNKNOWN_DLQ", None, None),
        Error::Locked => ("LOCKED", None, None),
        Error::HistoryUnavailable {
            oldest_available, ..
        } => ("HISTORY_UNAVAILABLE", None, Some(*oldest_available)),
        _ => ("INVALID", None, None),
    };
    ControlMsg::DataError {
        code: code.into(),
        message: err.to_string(),
        retry_at_ms,
        event_id: None,
        sequence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn history_unavailable_maps_to_wire_code() {
        let msg = data_err(&Error::HistoryUnavailable {
            requested_from: 100,
            oldest_available: 501,
        });
        match msg {
            ControlMsg::DataError {
                code,
                sequence,
                ..
            } => {
                assert_eq!(code, "HISTORY_UNAVAILABLE");
                assert_eq!(sequence, Some(501));
            }
            other => panic!("{other:?}"),
        }
    }
}

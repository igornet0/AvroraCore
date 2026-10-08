//! Trigger benchmark: write (`put_data`) → `OverlayApply` event → trigger
//! `ForwardToStream` → in-memory stream broadcast → receiver task.
//! Triggers run synchronously inside the write (under the runtime mutex).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dmc_core::channel::ChannelSpec;
use dmc_core::stream::{StreamDirection, StreamSpec};
use dmc_core::{EventKind, StreamId, TriggerAction, TriggerDef, TriggerId};
use dmc_vault::key::KeyPath;
use dmc_vault::{Permission, PermissionSet};
use serde_json::json;
use tokio::sync::broadcast::error::RecvError;

use crate::common::{make_payload, parse_header, round2, self_pid, Lat, ResMonitor, Sink, Timing};
use crate::driver::closed_loop;
use crate::storage::av_env;

pub async fn run(sink: &Sink, timing: Timing, size: usize) {
    for (triggers, writers) in [(0usize, 1usize), (1, 1), (5, 1), (0, 8), (1, 8), (5, 8)] {
        let env = av_env().await;
        let rt = env.rt.clone();
        let admin = env.admin.clone();
        rt.configure_channel(ChannelSpec::internal("bus")).await.unwrap();
        let base = Instant::now();
        let received = Arc::new(AtomicU64::new(0));
        let lagged = Arc::new(AtomicU64::new(0));
        let lat = Arc::new(Mutex::new(Lat::default()));
        let mut rx_tasks = Vec::new();
        for k in 0..triggers {
            let sid = StreamId::from(format!("trig-out-{k}").as_str());
            rt.create_stream(StreamSpec {
                id: sid.clone(),
                direction: StreamDirection::Outbound,
                channel_id: "bus".into(),
                path_scope: KeyPath::parse("trig").unwrap(),
                required_perms: PermissionSet::empty().with(Permission::Read),
            })
            .await
            .unwrap();
            rt.register_trigger(TriggerDef {
                id: TriggerId::from(format!("t{k}").as_str()),
                on: EventKind::OverlayApply,
                path_prefix: "trig".into(),
                action: TriggerAction::ForwardToStream { stream_id: sid.clone() },
            })
            .await
            .unwrap();
            let mut rx = rt.subscribe_stream(&sid).await.unwrap();
            let (received, lagged, lat) = (received.clone(), lagged.clone(), lat.clone());
            rx_tasks.push(tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(msg) => {
                            received.fetch_add(1, Ordering::Relaxed);
                            if let Some((_, _, _, t_ns)) = parse_header(&msg.payload) {
                                lat.lock().unwrap().record_ns((base.elapsed().as_nanos() as u64).saturating_sub(t_ns));
                            }
                        }
                        Err(RecvError::Lagged(n)) => {
                            lagged.fetch_add(n, Ordering::Relaxed);
                        }
                        Err(RecvError::Closed) => break,
                    }
                    if received.load(Ordering::Relaxed) == u64::MAX {
                        break;
                    }
                }
            }));
        }
        let written = Arc::new(AtomicU64::new(0));
        let mon = ResMonitor::start(vec![self_pid()]);
        let (rt2, ad2, w2) = (rt.clone(), admin.clone(), written.clone());
        let out = closed_loop(writers, timing, 0, move |w, i| {
            let (rt, admin, written) = (rt2.clone(), ad2.clone(), w2.clone());
            async move {
                let id = ((w as u64) << 40) | i;
                let p = make_payload(size, id, w as u32, i, base.elapsed().as_nanos() as u64);
                rt.put_data(&admin, &format!("trig/w{w}/k{i}"), &p).await.map_err(|e| e.to_string())?;
                written.fetch_add(1, Ordering::Relaxed);
                Ok((1, size as u64))
            }
        })
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let res = mon.finish();
        for t in rx_tasks {
            t.abort();
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let total_written = written.load(Ordering::Relaxed);
        let expected = total_written * triggers as u64;
        let got = received.load(Ordering::Relaxed);
        let mut rec = out.json();
        let o = rec.as_object_mut().unwrap();
        o.insert("suite".into(), json!("trigger"));
        o.insert("system".into(), json!("avrora_runtime_inproc"));
        o.insert("scenario".into(), json!(format!("{triggers}_triggers_{writers}_writers")));
        o.insert("params".into(), json!({"triggers": triggers, "writers": writers, "size": size, "timing": timing.json()}));
        o.insert("trigger_delivery_latency".into(), lat.lock().unwrap().stats());
        o.insert("trigger_correctness".into(), json!({
            "writes_total": total_written, "expected_trigger_deliveries": expected,
            "received": got, "lagged_dropped": lagged.load(Ordering::Relaxed),
            "lost": expected.saturating_sub(got),
        }));
        o.insert("trigger_deliveries_per_s".into(), json!(round2(got as f64 / (timing.warmup + timing.measure).as_secs_f64())));
        o.insert("resources".into(), res);
        sink.emit(rec);
    }
}

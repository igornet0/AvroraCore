//! Opaque UI Bearer sessions (in-memory, sliding TTL).

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use uuid::Uuid;

const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);

#[derive(Default)]
pub(crate) struct BearerStore {
    sessions: HashMap<String, Instant>,
}

impl BearerStore {
    pub fn issue(&mut self) -> String {
        self.prune();
        let token = format!(
            "avr_{}_{}",
            Uuid::new_v4().simple(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
        self.sessions
            .insert(token.clone(), Instant::now() + SESSION_TTL);
        token
    }

    pub fn validate(&mut self, token: &str) -> bool {
        self.prune();
        match self.sessions.get(token) {
            Some(exp) if *exp > Instant::now() => {
                self.sessions
                    .insert(token.to_string(), Instant::now() + SESSION_TTL);
                true
            }
            Some(_) => {
                self.sessions.remove(token);
                false
            }
            None => false,
        }
    }

    pub fn revoke(&mut self, token: &str) {
        self.sessions.remove(token);
    }

    fn prune(&mut self) {
        let now = Instant::now();
        self.sessions.retain(|_, exp| *exp > now);
    }
}

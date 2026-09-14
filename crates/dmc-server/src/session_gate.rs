use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct SessionGateStore {
    gates: HashMap<String, Arc<Mutex<()>>>,
}

impl SessionGateStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn gate_for(&mut self, session_id: &str) -> Arc<Mutex<()>> {
        self.gates
            .entry(session_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

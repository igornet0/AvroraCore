use axum::extract::FromRef;

use crate::control::sessions::ControlSessions;
use crate::runtime::Runtime;
use dmc_security::AuthManager;

#[derive(Clone)]
pub struct AppState {
    pub runtime: Runtime,
    pub auth: AuthManager,
    pub sessions: ControlSessions,
}

impl FromRef<AppState> for Runtime {
    fn from_ref(state: &AppState) -> Self {
        state.runtime.clone()
    }
}

impl FromRef<AppState> for AuthManager {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}

impl FromRef<AppState> for ControlSessions {
    fn from_ref(state: &AppState) -> Self {
        state.sessions.clone()
    }
}

use dmc_core::menu::daemon;

#[test]
fn pid_roundtrip_and_alive_self() {
    let dir = tempfile::tempdir().unwrap();
    let pid = std::process::id();
    daemon::write_pid(dir.path(), pid).unwrap();
    assert_eq!(daemon::read_pid(dir.path()), Some(pid));
    assert!(daemon::pid_alive(pid));
    // menu PID must not count as background serve
    assert!(!daemon::is_running(dir.path()));
    let st = daemon::status(dir.path()).unwrap();
    assert!(!st.running);
    assert!(st.pid.is_none());
}

#[test]
fn stale_pid_is_not_running() {
    let dir = tempfile::tempdir().unwrap();
    daemon::write_pid(dir.path(), 4_294_967_294).unwrap();
    assert!(!daemon::is_running(dir.path()));
    assert!(daemon::read_pid(dir.path()).is_none());
    let st = daemon::status(dir.path()).unwrap();
    assert!(!st.running);
    assert!(st.pid.is_none());
}

#[test]
fn own_pid_is_not_serve() {
    let pid = std::process::id();
    assert!(!daemon::is_serve_process(pid));
}

#[test]
fn menu_cmdline_is_not_serve() {
    assert!(!daemon::looks_like_avrora_serve(
        "/usr/local/bin/avrora menu"
    ));
    assert!(daemon::looks_like_avrora_serve(
        "/usr/local/bin/avrora serve"
    ));
}

#[test]
fn stale_self_pid_is_cleared() {
    let dir = tempfile::tempdir().unwrap();
    let pid = std::process::id();
    daemon::write_pid(dir.path(), pid).unwrap();
    assert!(!daemon::is_running(dir.path()));
    assert!(daemon::read_pid(dir.path()).is_none());
}

#[test]
fn stop_clears_missing_pid() {
    let dir = tempfile::tempdir().unwrap();
    daemon::stop(dir.path()).unwrap();
    assert!(daemon::read_pid(dir.path()).is_none());
}

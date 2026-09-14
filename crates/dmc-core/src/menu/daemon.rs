//! Background `avrora serve` process (pid + log under the control dir).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use crate::control::AvroraPaths;

pub const PID_FILE: &str = "avrora-serve.pid";
pub const LOG_FILE: &str = "avrora-serve.log";

#[derive(Clone, Debug)]
pub struct DaemonStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub log: PathBuf,
    pub pid_path: PathBuf,
}

pub fn pid_path(control_dir: &Path) -> PathBuf {
    control_dir.join(PID_FILE)
}

pub fn log_path(control_dir: &Path) -> PathBuf {
    control_dir.join(LOG_FILE)
}

pub fn read_pid(control_dir: &Path) -> Option<u32> {
    let raw = fs::read_to_string(pid_path(control_dir)).ok()?;
    raw.trim().parse().ok()
}

pub fn write_pid(control_dir: &Path, pid: u32) -> Result<(), String> {
    fs::create_dir_all(control_dir).map_err(|e| e.to_string())?;
    fs::write(pid_path(control_dir), format!("{pid}\n")).map_err(|e| e.to_string())
}

pub fn clear_pid(control_dir: &Path) {
    let _ = fs::remove_file(pid_path(control_dir));
}

/// True if `pid` is a live (non-zombie) process.
pub fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        if !probe_pid(pid) {
            return false;
        }
        !process_is_zombie(pid)
    }
    #[cfg(windows)]
    {
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
            .map(|o| {
                let out = String::from_utf8_lossy(&o.stdout);
                out.contains(&pid.to_string())
            })
            .unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

/// True if `pid` refers to a background `avrora serve`, not this menu/CLI process.
pub fn is_serve_process(pid: u32) -> bool {
    if pid == std::process::id() {
        return false;
    }
    process_cmdline(pid).is_some_and(|cmd| looks_like_avrora_serve(&cmd))
}

pub fn looks_like_avrora_serve(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    if lower.contains(" menu") {
        return false;
    }
    lower.contains("avrora") && lower.contains("serve")
}

#[cfg(unix)]
fn process_cmdline(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let cmd = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if cmd.is_empty() {
        None
    } else {
        Some(cmd)
    }
}

#[cfg(windows)]
fn process_cmdline(pid: u32) -> Option<String> {
    Command::new("wmic")
        .args([
            "process",
            "where",
            &format!("ProcessId={pid}"),
            "get",
            "CommandLine",
            "/value",
        ])
        .output()
        .ok()
        .and_then(|o| {
            let text = String::from_utf8_lossy(&o.stdout);
            text.lines()
                .find_map(|l| l.strip_prefix("CommandLine="))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
}

#[cfg(not(any(unix, windows)))]
fn process_cmdline(_pid: u32) -> Option<String> {
    None
}

#[cfg(unix)]
fn process_is_zombie(pid: u32) -> bool {
    Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "state="])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map(|o| {
            if !o.status.success() {
                return false;
            }
            String::from_utf8_lossy(&o.stdout).contains('Z')
        })
        .unwrap_or(false)
}

pub fn is_running(control_dir: &Path) -> bool {
    match read_pid(control_dir) {
        Some(pid) if pid_alive(pid) && is_serve_process(pid) => true,
        Some(_) => {
            clear_pid(control_dir);
            false
        }
        None => false,
    }
}

pub fn status(control_dir: &Path) -> Result<DaemonStatus, String> {
    let pid = read_pid(control_dir);
    let running = pid.is_some_and(|p| pid_alive(p) && is_serve_process(p));
    if pid.is_some() && !running {
        clear_pid(control_dir);
    }
    Ok(DaemonStatus {
        running,
        pid: pid.filter(|_| running),
        log: log_path(control_dir),
        pid_path: pid_path(control_dir),
    })
}

pub fn start(paths: &AvroraPaths) -> Result<u32, String> {
    if is_running(&paths.control_dir) {
        let pid = read_pid(&paths.control_dir).unwrap_or(0);
        return Err(format!("already running pid={pid}"));
    }
    if read_pid(&paths.control_dir).is_some() {
        clear_pid(&paths.control_dir);
    }
    fs::create_dir_all(&paths.control_dir).map_err(|e| e.to_string())?;
    let log = fs::File::create(log_path(&paths.control_dir)).map_err(|e| e.to_string())?;
    let err_log = log.try_clone().map_err(|e| e.to_string())?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut cmd = Command::new(exe);
    cmd.arg("serve")
        .env("AVRORA_DATA", &paths.db_path)
        .env("AVRORA_CONTROL_DIR", &paths.control_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(err_log));
    if let Some(home) = &paths.home {
        cmd.env("AVRORA_HOME", home);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let child = cmd.spawn().map_err(|e| format!("spawn serve: {e}"))?;
    let pid = child.id();
    write_pid(&paths.control_dir, pid)?;
    Ok(pid)
}

pub fn stop(control_dir: &Path) -> Result<(), String> {
    let Some(pid) = read_pid(control_dir) else {
        return Ok(());
    };
    if !pid_alive(pid) {
        clear_pid(control_dir);
        return Ok(());
    }
    if !is_serve_process(pid) {
        clear_pid(control_dir);
        return Ok(());
    }
    send_signal(pid, false)?;
    for _ in 0..50 {
        if !pid_alive(pid) {
            clear_pid(control_dir);
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    send_signal(pid, true)?;
    thread::sleep(Duration::from_millis(200));
    if pid_alive(pid) && is_serve_process(pid) {
        return Err(format!("process {pid} still running after SIGKILL"));
    }
    clear_pid(control_dir);
    Ok(())
}

#[cfg(unix)]
fn probe_pid(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(unix)]
fn signal_pid(pid: u32, kill: bool) -> bool {
    let sig = if kill { "-9" } else { "-TERM" };
    Command::new("kill")
        .args([sig, &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn send_signal(pid: u32, kill: bool) -> Result<(), String> {
    #[cfg(unix)]
    {
        if !signal_pid(pid, kill) && kill {
            return Err(format!("kill {pid} failed"));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let mut cmd = Command::new("taskkill");
        cmd.args(["/PID", &pid.to_string()]);
        if kill {
            cmd.arg("/F");
        }
        cmd.stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (pid, kill);
        Err("stop not supported on this platform".into())
    }
}

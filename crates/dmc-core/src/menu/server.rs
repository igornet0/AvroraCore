//! Server start/stop/status and UI URL.

use std::process::Command;

use crate::control::{format_status_for, format_ui_login_hint, AvroraPaths, ServerConfig};
use crate::menu::daemon;
use crate::menu::prompt;

pub async fn submenu(paths: &AvroraPaths) -> Result<(), String> {
    loop {
        let st = daemon::status(&paths.control_dir)?;
        let serve = if st.running {
            format!("UP pid={}", st.pid.unwrap_or(0))
        } else {
            "DOWN".into()
        };
        let items = [
            "Запустить в фоне",
            "Остановить",
            "Статус",
            "Открыть UI URL",
            "Подсказка: вход в UI",
            "Назад",
        ];
        match prompt::select(&format!("Сервер [{serve}]"), &items)? {
            0 => match daemon::start(paths) {
                Ok(pid) => prompt::show(&format!(
                    "serve started pid={pid}\nlog={}",
                    st.log.display()
                )),
                Err(e) => prompt::show_err(e),
            },
            1 => match daemon::stop(&paths.control_dir) {
                Ok(()) => prompt::show("serve stopped"),
                Err(e) => prompt::show_err(e),
            },
            2 => {
                let mut body = format_status_for(paths).await;
                body.push('\n');
                if st.running {
                    body.push_str(&format!(
                        "serve=UP pid={}\n",
                        st.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
                    ));
                } else {
                    body.push_str("serve=DOWN\n");
                }
                body.push_str(&format!("log={}\n", daemon::log_path(&paths.control_dir).display()));
                prompt::show(&body);
            }
            3 => open_ui(paths),
            4 => prompt::show(&format_ui_login_hint(&paths.db_path)),
            _ => return Ok(()),
        }
    }
}

fn open_ui(paths: &AvroraPaths) {
    let cfg = ServerConfig::resolve(&paths.control_dir);
    let url = cfg.display_http_url();
    println!("{url}");
    if !cfg.ui_enabled {
        println!("(UI выключен в server.json — открывается только API)");
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg(&url).status();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("xdg-open").arg(&url).status();
    }
    prompt::pause();
}

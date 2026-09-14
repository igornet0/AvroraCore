//! Browse vault keys / key-tree nodes.

use crate::control::AvroraPaths;
use crate::menu::prompt;
use crate::menu::vault;
use crate::runtime::Runtime;

const PAGE: usize = 50;

pub async fn submenu(paths: &AvroraPaths) -> Result<(), String> {
    let rt = Runtime::at_path(&paths.db_path);
    let session = match vault::ensure_admin(&rt).await {
        Ok(s) => s,
        Err(e) => {
            prompt::show_err(e);
            return Ok(());
        }
    };
    let prefix = prompt::input("Prefix (empty = all)", Some("company"))?;
    let prefix = prefix.trim();

    let mut body = String::new();
    match rt.list_nodes().await {
        Ok(nodes) => {
            let filtered: Vec<_> = nodes
                .into_iter()
                .filter(|n| prefix.is_empty() || n.path == "/" || n.path.starts_with(prefix))
                .collect();
            body.push_str(&format!("nodes ({})\n", filtered.len()));
            for n in filtered.iter().take(PAGE) {
                body.push_str(&format!("  {:<40} gen={} {:?}\n", n.path, n.generation, n.state));
            }
            if filtered.len() > PAGE {
                body.push_str(&format!("  … {} more\n", filtered.len() - PAGE));
            }
        }
        Err(e) => {
            prompt::show_err(e);
            return Ok(());
        }
    }
    body.push('\n');
    match rt.list_keys(&session, prefix).await {
        Ok(keys) => {
            body.push_str(&format!("keys ({})\n", keys.len()));
            for k in keys.iter().take(PAGE) {
                body.push_str(&format!("  {k}\n"));
            }
            if keys.len() > PAGE {
                body.push_str(&format!("  … {} more\n", keys.len() - PAGE));
            }
        }
        Err(e) => {
            prompt::show_err(e);
            return Ok(());
        }
    }
    prompt::show(&body);
    Ok(())
}

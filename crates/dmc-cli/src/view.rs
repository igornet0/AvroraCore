//! Verbose security / protocol trace for demos (`--view`).

use std::path::Path;

pub struct ViewLog {
    enabled: bool,
}

impl ViewLog {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn line(&self, category: &str, message: impl AsRef<str>) {
        if self.enabled {
            eprintln!("[view:{category}] {}", message.as_ref());
        }
    }

    pub fn protocol_send(&self, op: &str, detail: impl AsRef<str>) {
        self.line("protocol", format!("→ {op} {}", detail.as_ref()));
    }

    pub fn protocol_recv(&self, op: &str, detail: impl AsRef<str>) {
        self.line("protocol", format!("← {op} {}", detail.as_ref()));
    }

    pub fn crypto(&self, message: impl AsRef<str>) {
        self.line("crypto", message);
    }

    pub fn vault(&self, message: impl AsRef<str>) {
        self.line("vault", message);
    }

    pub fn sql(&self, message: impl AsRef<str>) {
        self.line("sql", message);
    }

    pub fn authz(&self, message: impl AsRef<str>) {
        self.line("authz", message);
    }

    pub fn disk(&self, message: impl AsRef<str>) {
        self.line("disk", message);
    }
}

/// Static key hierarchy for demos (no secret material). Always prints to stdout.
pub fn print_key_hierarchy_stdout() {
    println!("=== Иерархия ключей Avrora (dmc-vault) ===");
    println!("Master Key (32 B) — только в RAM после unlock; на диск не сохраняется");
    println!("  └─ HKDF(master, salt, \"root-kek\") → ROOT KEK");
    println!("       └─ unwrap → ROOT DEK → шифрование узлов key-tree");
    println!("Доменные KEK (HKDF от master + salt):");
    println!("  • journal  → \"{}\"", dmc_vault::JOURNAL_KEK_INFO);
    println!("  • audit    → \"{}\"", dmc_vault::AUDIT_KEK_INFO);
    println!("  • metadata → \"{}\"", dmc_vault::METADATA_KEK_INFO);
    println!("Путь строки: HKDF(parent KEK, path) → path DEK → AEAD(payload)");
    println!("UnlockBlob: AES-256-GCM(binding_key, AAD=session) — Master Key не в открытом виде на wire");
    println!("KeyPass (USB): Argon2id(Master Password) → wrap Master Key (клиент только)");
}

/// Same content routed through view log (stderr when `--view`).
pub fn print_key_hierarchy(view: &ViewLog) {
    view.line("keys", "=== Иерархия ключей Avrora (dmc-vault) ===");
    view.line(
        "keys",
        "Master Key (32 B) — только в RAM после unlock; на диск не сохраняется",
    );
    view.line(
        "keys",
        "  └─ HKDF(master, salt, \"root-kek\") → ROOT KEK",
    );
    view.line(
        "keys",
        "       └─ unwrap → ROOT DEK → шифрование узлов key-tree",
    );
    view.line(
        "keys",
        "Доменные KEK (HKDF от master + salt):",
    );
    view.line(
        "keys",
        format!("  • journal  → \"{}\"", dmc_vault::JOURNAL_KEK_INFO),
    );
    view.line(
        "keys",
        format!("  • audit    → \"{}\"", dmc_vault::AUDIT_KEK_INFO),
    );
    view.line(
        "keys",
        format!("  • metadata → \"{}\"", dmc_vault::METADATA_KEK_INFO),
    );
    view.line(
        "keys",
        "Путь строки: HKDF(parent KEK, path) → path DEK → AEAD(payload)",
    );
    view.line(
        "keys",
        "UnlockBlob: AES-256-GCM(binding_key, AAD=session) — Master Key не в открытом виде на wire",
    );
    view.line(
        "keys",
        "KeyPass (USB): Argon2id(Master Password) → wrap Master Key (клиент только)",
    );
}

/// Show hex preview of on-disk ciphertext (journal segment, storage row file, etc.).
pub fn inspect_encrypted_file(view: &ViewLog, label: &str, path: &Path, max_bytes: usize) {
    if !path.is_file() {
        view.disk(format!("{label}: файл не найден — {}", path.display()));
        return;
    }
    let data = std::fs::read(path).unwrap_or_default();
    let preview = data.len().min(max_bytes);
    let hex_preview = hex::encode(&data[..preview]);
    let truncated = if data.len() > preview {
        format!(" (+{} bytes)", data.len() - preview)
    } else {
        String::new()
    };
    view.disk(format!(
        "{label}: {} bytes, preview[{preview}]={hex_preview}{truncated}",
        data.len()
    ));
    if data.len() > 16 {
        view.crypto("Содержимое на диске — AEAD ciphertext / wrapped DEK, не plaintext");
    }
}

pub fn inspect_data_root(view: &ViewLog, data_root: &Path) {
    view.disk(format!("=== Снимок зашифрованных артефактов: {} ===", data_root.display()));
    let candidates = [
        ("journal/manifest.json", data_root.join("journal/manifest.json")),
        ("catalog/catalog.json", data_root.join("catalog/catalog.json")),
        ("recovery/state.json", data_root.join("recovery/state.json")),
    ];
    for (label, path) in candidates {
        inspect_encrypted_file(view, label, &path, 48);
    }
    let rows = data_root.join("storage/rows");
    if rows.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&rows) {
            let mut count = 0;
            for entry in entries.flatten() {
                if count >= 3 {
                    view.disk("storage/rows: … (другие файлы скрыты)");
                    break;
                }
                inspect_encrypted_file(view, "storage/rows", &entry.path(), 32);
                count += 1;
            }
        }
    }
}

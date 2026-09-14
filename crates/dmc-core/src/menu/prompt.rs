//! Shared prompts for `avrora menu`.

use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Select};

pub fn theme() -> ColorfulTheme {
    ColorfulTheme::default()
}

pub fn select(prompt: &str, items: &[&str]) -> Result<usize, String> {
    Select::with_theme(&theme())
        .with_prompt(prompt)
        .items(items)
        .default(0)
        .interact()
        .map_err(|e| e.to_string())
}

pub fn input(prompt: &str, default: Option<&str>) -> Result<String, String> {
    let theme = theme();
    let mut i = Input::<String>::with_theme(&theme).with_prompt(prompt);
    if let Some(d) = default {
        i = i.default(d.to_string());
    }
    i.allow_empty(true).interact_text().map_err(|e| e.to_string())
}

pub fn confirm(prompt: &str, default: bool) -> Result<bool, String> {
    Confirm::with_theme(&theme())
        .with_prompt(prompt)
        .default(default)
        .interact()
        .map_err(|e| e.to_string())
}

pub fn multi_select(prompt: &str, items: &[&str], defaults: &[bool]) -> Result<Vec<usize>, String> {
    MultiSelect::with_theme(&theme())
        .with_prompt(prompt)
        .items(items)
        .defaults(defaults)
        .interact()
        .map_err(|e| e.to_string())
}

pub fn pause() {
    let _ = Input::<String>::with_theme(&theme())
        .with_prompt("Enter to continue")
        .allow_empty(true)
        .interact_text();
}

pub fn show(text: &str) {
    println!();
    println!("{text}");
    println!();
    pause();
}

pub fn show_err(err: impl std::fmt::Display) {
    eprintln!("error: {err}");
    pause();
}

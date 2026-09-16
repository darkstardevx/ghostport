//! Small ANSI color helpers for plain `println!`/`eprintln!` output —
//! the CLI (`keygen`/`check`) and the daemon's own connection-lifecycle
//! logs. Distinct from `tui/ui.rs`'s `Theme`, which needs `ratatui::Color`
//! values, not ANSI escape strings; both read the same underlying
//! `cybercore` palette.

/// Wraps `s` in the palette's success color (acid green).
pub fn ok(s: &str) -> String {
    format!(
        "{}{s}{}",
        cybercore::palette::acid_green(),
        cybercore::palette::RESET
    )
}

/// Wraps `s` in the palette's warning color (orange).
pub fn warn(s: &str) -> String {
    format!(
        "{}{s}{}",
        cybercore::palette::orange(),
        cybercore::palette::RESET
    )
}

/// Wraps `s` in the palette's error color (red).
pub fn err(s: &str) -> String {
    format!(
        "{}{s}{}",
        cybercore::palette::red(),
        cybercore::palette::RESET
    )
}

/// Wraps `s` in the palette's accent color (cyan) — used for link IDs.
pub fn accent(s: &str) -> String {
    format!(
        "{}{s}{}",
        cybercore::palette::cyan(),
        cybercore::palette::RESET
    )
}

/// Wraps `s` in bold acid green, for text that needs to stand out more
/// than a plain [`ok`].
pub fn emphasis(s: &str) -> String {
    format!(
        "{}{}{s}{}",
        cybercore::palette::BOLD,
        cybercore::palette::acid_green(),
        cybercore::palette::RESET
    )
}

//! Small ANSI color helpers for plain `println!`/`eprintln!` output —
//! the CLI (`keygen`/`check`) and the daemon's own connection-lifecycle
//! logs. Distinct from `tui/ui.rs`'s `Theme`, which needs `ratatui::Color`
//! values, not ANSI escape strings; both read the same underlying
//! `cybercore` palette.

pub fn ok(s: &str) -> String {
    format!(
        "{}{s}{}",
        cybercore::palette::acid_green(),
        cybercore::palette::RESET
    )
}

pub fn warn(s: &str) -> String {
    format!(
        "{}{s}{}",
        cybercore::palette::orange(),
        cybercore::palette::RESET
    )
}

pub fn err(s: &str) -> String {
    format!(
        "{}{s}{}",
        cybercore::palette::red(),
        cybercore::palette::RESET
    )
}

pub fn accent(s: &str) -> String {
    format!(
        "{}{s}{}",
        cybercore::palette::cyan(),
        cybercore::palette::RESET
    )
}

pub fn emphasis(s: &str) -> String {
    format!(
        "{}{}{s}{}",
        cybercore::palette::BOLD,
        cybercore::palette::acid_green(),
        cybercore::palette::RESET
    )
}

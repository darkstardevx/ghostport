//! Human-readable formatting for the Status tab — raw seconds and raw
//! byte counts are correct but not pleasant to read at a glance.

pub fn duration(total_secs: u64) -> String {
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    if days > 0 {
        format!("{days}d {hours}h {mins}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m {secs}s")
    } else if mins > 0 {
        format!("{mins}m {secs}s")
    } else {
        format!("{secs}s")
    }
}

pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// A rate in bytes/sec, e.g. "1.2 KB/s".
pub fn rate(bytes_per_sec: f64) -> String {
    format!("{}/s", bytes(bytes_per_sec.round() as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_formats_each_scale() {
        assert_eq!(duration(0), "0s");
        assert_eq!(duration(45), "45s");
        assert_eq!(duration(65), "1m 5s");
        assert_eq!(duration(3665), "1h 1m 5s");
        assert_eq!(duration(90065), "1d 1h 1m");
    }

    #[test]
    fn bytes_formats_each_scale() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(2048), "2.0 KB");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn rate_appends_per_second() {
        assert_eq!(rate(2048.0), "2.0 KB/s");
    }
}

//! `StatusSnapshot` -> Prometheus text exposition format. Kept as a
//! pure function, deliberately separate from any socket/HTTP I/O, so
//! the actual rendering logic is directly unit-testable against
//! hand-built snapshots.

use ghostport_core::stats::StatusSnapshot;
use std::fmt::Write as _;

/// Renders `snapshot` (or, when the daemon wasn't reachable, `None`)
/// as a complete Prometheus text-exposition-format body. Always
/// includes `ghostport_up` first — the one metric that's meaningful
/// even when nothing else is; every other metric is only emitted when
/// `snapshot` is `Some`, since there's nothing real to report otherwise.
pub fn render(snapshot: Option<&StatusSnapshot>) -> String {
    let mut out = String::new();

    writeln!(
        out,
        "# HELP ghostport_up Whether the ghostport daemon's status socket answered this scrape."
    )
    .unwrap();
    writeln!(out, "# TYPE ghostport_up gauge").unwrap();
    writeln!(out, "ghostport_up {}", i32::from(snapshot.is_some())).unwrap();

    let Some(snapshot) = snapshot else {
        return out;
    };

    writeln!(
        out,
        "# HELP ghostport_uptime_seconds Seconds since the daemon started."
    )
    .unwrap();
    writeln!(out, "# TYPE ghostport_uptime_seconds gauge").unwrap();
    writeln!(out, "ghostport_uptime_seconds {}", snapshot.uptime_secs).unwrap();

    writeln!(
        out,
        "# HELP ghostport_control_connected Whether the control channel is currently connected."
    )
    .unwrap();
    writeln!(out, "# TYPE ghostport_control_connected gauge").unwrap();
    writeln!(
        out,
        "ghostport_control_connected {}",
        i32::from(snapshot.control_connected)
    )
    .unwrap();

    if let Some(secs) = snapshot.control_connected_since_secs_ago {
        writeln!(
            out,
            "# HELP ghostport_control_connected_seconds Seconds since the current control connection was established."
        )
        .unwrap();
        writeln!(out, "# TYPE ghostport_control_connected_seconds gauge").unwrap();
        writeln!(out, "ghostport_control_connected_seconds {secs}").unwrap();
    }

    if !snapshot.links.is_empty() {
        writeln!(
            out,
            "# HELP ghostport_link_active_streams Streams currently being relayed on this link."
        )
        .unwrap();
        writeln!(out, "# TYPE ghostport_link_active_streams gauge").unwrap();
        for link in &snapshot.links {
            writeln!(
                out,
                "ghostport_link_active_streams{{link_id=\"{}\",mode=\"{}\"}} {}",
                link.id, link.mode, link.active_streams
            )
            .unwrap();
        }

        writeln!(
            out,
            "# HELP ghostport_link_streams_total Total streams ever opened on this link."
        )
        .unwrap();
        writeln!(out, "# TYPE ghostport_link_streams_total counter").unwrap();
        for link in &snapshot.links {
            writeln!(
                out,
                "ghostport_link_streams_total{{link_id=\"{}\",mode=\"{}\"}} {}",
                link.id, link.mode, link.total_streams
            )
            .unwrap();
        }

        writeln!(
            out,
            "# HELP ghostport_link_bytes_forward_total Bytes relayed in the forward direction on this link."
        )
        .unwrap();
        writeln!(out, "# TYPE ghostport_link_bytes_forward_total counter").unwrap();
        for link in &snapshot.links {
            writeln!(
                out,
                "ghostport_link_bytes_forward_total{{link_id=\"{}\",mode=\"{}\"}} {}",
                link.id, link.mode, link.bytes_forward
            )
            .unwrap();
        }

        writeln!(
            out,
            "# HELP ghostport_link_bytes_back_total Bytes relayed in the opposite direction on this link."
        )
        .unwrap();
        writeln!(out, "# TYPE ghostport_link_bytes_back_total counter").unwrap();
        for link in &snapshot.links {
            writeln!(
                out,
                "ghostport_link_bytes_back_total{{link_id=\"{}\",mode=\"{}\"}} {}",
                link.id, link.mode, link.bytes_back
            )
            .unwrap();
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghostport_core::stats::LinkSnapshot;

    fn sample_snapshot() -> StatusSnapshot {
        StatusSnapshot {
            role: "server".to_string(),
            uptime_secs: 12345,
            control_connected: true,
            control_connected_since_secs_ago: Some(42),
            control_peer_addr: Some("1.2.3.4:5".to_string()),
            control_peer_name: Some("laptop".to_string()),
            links: vec![LinkSnapshot {
                id: "db".to_string(),
                mode: "forward".to_string(),
                active_streams: 1,
                total_streams: 57,
                bytes_forward: 123456,
                bytes_back: 654321,
            }],
        }
    }

    #[test]
    fn unreachable_daemon_reports_only_up_zero() {
        let text = render(None);
        assert!(text.contains("ghostport_up 0"));
        assert!(!text.contains("ghostport_uptime_seconds"));
        assert!(!text.contains("ghostport_link_"));
    }

    #[test]
    fn reachable_daemon_reports_up_one_and_real_fields() {
        let snapshot = sample_snapshot();
        let text = render(Some(&snapshot));
        assert!(text.contains("ghostport_up 1"));
        assert!(text.contains("ghostport_uptime_seconds 12345"));
        assert!(text.contains("ghostport_control_connected 1"));
        assert!(text.contains("ghostport_control_connected_seconds 42"));
        assert!(text.contains("ghostport_link_active_streams{link_id=\"db\",mode=\"forward\"} 1"));
        assert!(text.contains("ghostport_link_streams_total{link_id=\"db\",mode=\"forward\"} 57"));
        assert!(text.contains(
            "ghostport_link_bytes_forward_total{link_id=\"db\",mode=\"forward\"} 123456"
        ));
        assert!(text
            .contains("ghostport_link_bytes_back_total{link_id=\"db\",mode=\"forward\"} 654321"));
    }

    #[test]
    fn disconnected_control_omits_connected_since() {
        let mut snapshot = sample_snapshot();
        snapshot.control_connected = false;
        snapshot.control_connected_since_secs_ago = None;
        let text = render(Some(&snapshot));
        assert!(text.contains("ghostport_control_connected 0"));
        assert!(!text.contains("ghostport_control_connected_seconds"));
    }

    #[test]
    fn zero_links_omits_link_metrics_entirely() {
        let mut snapshot = sample_snapshot();
        snapshot.links.clear();
        let text = render(Some(&snapshot));
        assert!(!text.contains("ghostport_link_"));
    }

    #[test]
    fn every_help_line_has_a_matching_type_line() {
        let snapshot = sample_snapshot();
        let text = render(Some(&snapshot));
        for line in text.lines() {
            if let Some(metric) = line.strip_prefix("# HELP ") {
                let name = metric.split_whitespace().next().unwrap();
                assert!(
                    text.contains(&format!("# TYPE {name} ")),
                    "missing TYPE line for {name}"
                );
            }
        }
    }
}

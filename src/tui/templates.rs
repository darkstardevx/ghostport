//! Link templates for the add wizard's first step — common cases with
//! sensible defaults (id + port), so adding e.g. an SSH forward is
//! "pick SSH, accept the defaults, done" instead of typing everything
//! by hand every time. "Custom" (typing everything yourself) is always
//! available too — these are conveniences, not the only path.

use ghostport_core::config::LinkMode;

pub struct LinkTemplate {
    pub name: &'static str,
    pub mode: LinkMode,
    pub default_id: &'static str,
    pub default_port: u16,
}

pub const TEMPLATES: &[LinkTemplate] = &[
    LinkTemplate {
        name: "SSH",
        mode: LinkMode::Forward,
        default_id: "ssh",
        default_port: 22,
    },
    LinkTemplate {
        name: "HTTP",
        mode: LinkMode::Forward,
        default_id: "http",
        default_port: 80,
    },
    LinkTemplate {
        name: "HTTPS",
        mode: LinkMode::Forward,
        default_id: "https",
        default_port: 443,
    },
    LinkTemplate {
        name: "PostgreSQL",
        mode: LinkMode::Forward,
        default_id: "postgres",
        default_port: 5432,
    },
    LinkTemplate {
        name: "MySQL / MariaDB",
        mode: LinkMode::Forward,
        default_id: "mysql",
        default_port: 3306,
    },
    LinkTemplate {
        name: "Redis",
        mode: LinkMode::Forward,
        default_id: "redis",
        default_port: 6379,
    },
    LinkTemplate {
        name: "Expose local dev server",
        mode: LinkMode::Reverse,
        default_id: "dev",
        default_port: 3000,
    },
    LinkTemplate {
        name: "Expose local web server",
        mode: LinkMode::Reverse,
        default_id: "web",
        default_port: 8080,
    },
];

/// One past the last real template — selecting this index means
/// "custom", picked by index (not `Option`) so the dropdown list and
/// the selection cursor share one flat range with no special-casing in
/// the rendering/navigation code, only where the choice is acted on.
pub fn custom_index() -> usize {
    TEMPLATES.len()
}

pub fn menu_len() -> usize {
    TEMPLATES.len() + 1
}

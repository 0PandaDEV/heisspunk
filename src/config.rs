use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NetworkClass {
    A,

    B,

    #[default]
    C,
}

impl NetworkClass {
    pub fn defaults(&self) -> (&'static str, DhcpRange, &'static str) {
        match self {
            NetworkClass::A => (
                "10.0.0.1",
                DhcpRange {
                    start: "10.0.0.10".into(),
                    end: "10.0.0.250".into(),
                    netmask: "255.0.0.0".into(),
                },
                "10.0.0.0",
            ),
            NetworkClass::B => (
                "172.16.0.1",
                DhcpRange {
                    start: "172.16.0.10".into(),
                    end: "172.16.0.250".into(),
                    netmask: "255.240.0.0".into(),
                },
                "172.16.0.0",
            ),
            NetworkClass::C => (
                "192.168.100.1",
                DhcpRange {
                    start: "192.168.100.10".into(),
                    end: "192.168.100.250".into(),
                    netmask: "255.255.255.0".into(),
                },
                "192.168.100.0",
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub interface: String,
    pub ssid: String,
    pub passphrase: Option<String>,
    pub channel: u8,
    pub hw_mode: HwMode,

    pub network_class: NetworkClass,

    pub gateway: Option<String>,

    pub dhcp_range: Option<DhcpRange>,
    pub dhcp_lease: String,

    pub upstream: Option<String>,
    pub hidden: bool,
    pub ieee80211n: bool,
    pub ieee80211ac: bool,
    pub country_code: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: String::new(),
            ssid: String::new(),
            passphrase: None,
            channel: 6,
            hw_mode: HwMode::default(),
            network_class: NetworkClass::default(),
            gateway: None,
            dhcp_range: None,
            dhcp_lease: "12h".into(),
            upstream: None,
            hidden: false,
            ieee80211n: true,
            ieee80211ac: false,
            country_code: "CH".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HwMode {
    B,
    #[default]
    G,
    A,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpRange {
    pub start: String,
    pub end: String,
    pub netmask: String,
}

impl Config {
    pub fn load_xdg() -> Result<Option<Self>> {
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            if let Some(path) = sudo_user_config_path(&sudo_user) {
                if path.exists() {
                    return Self::load_file(&path).map(Some);
                }
            }
        }
        let xdg = xdg::BaseDirectories::with_prefix("heisspunk");
        let Some(path) = xdg.find_config_file("config.toml") else {
            return Ok(None);
        };
        Self::load_file(&path).map(Some)
    }

    pub fn load_file(path: &PathBuf) -> Result<Self> {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn config_path() -> Result<PathBuf> {
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            if let Some(path) = sudo_user_config_path(&sudo_user) {
                return Ok(path);
            }
        }
        let xdg = xdg::BaseDirectories::with_prefix("heisspunk");
        xdg.place_config_file("config.toml")
            .context("resolving XDG config path")
    }

    pub fn resolved_gateway(&self) -> String {
        self.gateway
            .clone()
            .unwrap_or_else(|| self.network_class.defaults().0.to_string())
    }

    pub fn resolved_dhcp_range(&self) -> DhcpRange {
        self.dhcp_range
            .clone()
            .unwrap_or_else(|| self.network_class.defaults().1)
    }

    pub fn validate(&self) -> Result<()> {
        if self.ssid.is_empty() || self.ssid.len() > 32 {
            bail!("ssid must be 1–32 characters");
        }
        if let Some(ref pw) = self.passphrase {
            if pw.len() < 8 || pw.len() > 63 {
                bail!("passphrase must be 8–63 characters (WPA2 PSK requirement)");
            }
        }
        Ok(())
    }
}

impl HwMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            HwMode::B => "b",
            HwMode::G => "g",
            HwMode::A => "a",
        }
    }
}

fn sudo_user_config_path(username: &str) -> Option<PathBuf> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    let home = passwd
        .lines()
        .find(|l| l.starts_with(&format!("{username}:")))?
        .split(':')
        .nth(5)?
        .to_owned();
    Some(PathBuf::from(home).join(".config/heisspunk/config.toml"))
}

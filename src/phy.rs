use anyhow::{Context, Result};
use std::process::Command;

#[derive(Debug, Default, Clone)]
pub struct PhyCaps {
    pub ht_caps: u16,
    pub vht_caps: u32,
    pub has_vht: bool,
    pub max_vht_width: VhtWidth,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VhtWidth {
    #[default]
    W80,
    W160,
    W80P80,
}

impl PhyCaps {
    pub fn query(iface: &str) -> Result<Self> {
        let phy = phy_name(iface)?;
        let out = Command::new("iw")
            .args(["phy", &phy, "info"])
            .output()
            .context("running iw phy info")?;
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(parse_iw_output(&text))
    }

    pub fn ht_capab_string(&self, channel: u8) -> String {
        let c = self.ht_caps;
        let mut s = String::new();

        if c & 0x0001 != 0 {
            s.push_str("[LDPC]");
        }

        if c & 0x0002 != 0 {
            s.push_str(ht_40mhz_flags(channel));
        }

        match (c >> 2) & 0x3 {
            0 => s.push_str("[SMPS-STATIC]"),
            1 => s.push_str("[SMPS-DYNAMIC]"),
            _ => {}
        }

        if c & 0x0010 != 0 {
            s.push_str("[GF]");
        }

        if c & 0x0020 != 0 {
            s.push_str("[SHORT-GI-20]");
        }

        if c & 0x0040 != 0 {
            s.push_str("[SHORT-GI-40]");
        }

        if c & 0x0080 != 0 {
            s.push_str("[TX-STBC]");
        }

        match (c >> 8) & 0x3 {
            1 => s.push_str("[RX-STBC1]"),
            2 => s.push_str("[RX-STBC12]"),
            3 => s.push_str("[RX-STBC123]"),
            _ => {}
        }

        if c & 0x0800 != 0 {
            s.push_str("[MAX-AMSDU-7935]");
        }

        if c & 0x1000 == 0 {
            s.push_str("[DSSS_CCK-40]");
        }

        s
    }

    pub fn vht_capab_string(&self) -> String {
        let c = self.vht_caps;
        let mut s = String::new();

        match c & 0x3 {
            1 => s.push_str("[MAX-MPDU-7991]"),
            2 => s.push_str("[MAX-MPDU-11454]"),
            _ => {}
        }

        if c & 0x0010 != 0 {
            s.push_str("[RXLDPC]");
        }

        if c & 0x0020 != 0 {
            s.push_str("[SHORT-GI-80]");
        }

        if c & 0x0040 != 0 {
            s.push_str("[SHORT-GI-160]");
        }

        if c & 0x0080 != 0 {
            s.push_str("[TX-STBC-2BY1]");
        }

        match (c >> 8) & 0x7 {
            1 => s.push_str("[RX-STBC-1]"),
            2 => s.push_str("[RX-STBC-12]"),
            3 => s.push_str("[RX-STBC-123]"),
            4 => s.push_str("[RX-STBC-1234]"),
            _ => {}
        }

        if c & 0x0800 != 0 {
            s.push_str("[SU-BEAMFORMER]");
        }

        if c & 0x1000 != 0 {
            s.push_str("[SU-BEAMFORMEE]");
        }

        let sts = (c >> 13) & 0x7;
        if sts > 0 {
            let val = sts + 1;
            if val <= 4 {
                s.push_str(&format!("[BF-ANTENNA-{val}]"));
            }
        }

        if c & 0x0008_0000 != 0 {
            s.push_str("[MU-BEAMFORMER]");
        }

        if c & 0x0010_0000 != 0 {
            s.push_str("[MU-BEAMFORMEE]");
        }

        if c & 0x0020_0000 != 0 {
            s.push_str("[VHT-TXOP-PS]");
        }

        if c & 0x0040_0000 != 0 {
            s.push_str("[HTC-VHT]");
        }

        if c & 0x1000_0000 != 0 {
            s.push_str("[RX-ANTENNA-PATTERN]");
        }

        if c & 0x2000_0000 != 0 {
            s.push_str("[TX-ANTENNA-PATTERN]");
        }

        s
    }

    pub fn vht_oper_chwidth(&self) -> u8 {
        match self.max_vht_width {
            VhtWidth::W80 => 1,
            VhtWidth::W160 => 2,
            VhtWidth::W80P80 => 3,
        }
    }
}

fn parse_iw_output(text: &str) -> PhyCaps {
    let mut caps = PhyCaps::default();
    let mut in_band2 = false;

    for line in text.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Band 1:") {
            in_band2 = false;
        }
        if trimmed.starts_with("Band 2:") {
            in_band2 = true;
        }
        if trimmed.starts_with("Band 3:") || trimmed.starts_with("Band 4:") {
            in_band2 = false;
        }

        if in_band2 {
            if let Some(rest) = trimmed.strip_prefix("Capabilities: 0x") {
                if let Ok(v) = u16::from_str_radix(rest.trim(), 16) {
                    caps.ht_caps = v;
                }
            }

            if let Some(rest) = trimmed.strip_prefix("VHT Capabilities (0x") {
                if let Some(hex) = rest.split(')').next() {
                    if let Ok(v) = u32::from_str_radix(hex.trim(), 16) {
                        caps.vht_caps = v;
                        caps.has_vht = true;

                        caps.max_vht_width = match (v >> 2) & 0x3 {
                            1 => VhtWidth::W160,
                            2 => VhtWidth::W80P80,
                            _ => VhtWidth::W80,
                        };
                    }
                }
            }
        }
    }

    caps
}

fn phy_name(iface: &str) -> Result<String> {
    let link = format!("/sys/class/net/{iface}/phy80211");
    let target =
        std::fs::read_link(&link).with_context(|| format!("reading phy symlink for {iface}"))?;
    target
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned)
        .context("invalid phy symlink target")
}

pub fn ht_40mhz_flags(channel: u8) -> &'static str {
    match channel {
        36 | 44 | 52 | 60 | 100 | 108 | 116 | 124 | 132 | 140 => "[HT40+]",
        40 | 48 | 56 | 64 | 104 | 112 | 120 | 128 | 136 | 144 => "[HT40-]",
        1..=7 => "[HT40+]",
        8..=13 => "[HT40-]",
        _ => "",
    }
}

pub fn vht_center_freq_idx(channel: u8, width: VhtWidth) -> u8 {
    match width {
        VhtWidth::W80 => match channel {
            36..=48 => 42,
            52..=64 => 58,
            100..=112 => 106,
            116..=128 => 122,
            132..=144 => 138,
            149..=161 => 155,
            _ => channel.saturating_add(6),
        },
        VhtWidth::W160 | VhtWidth::W80P80 => match channel {
            36..=64 => 50,
            100..=128 => 114,
            _ => channel.saturating_add(14),
        },
    }
}

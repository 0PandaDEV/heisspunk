use crate::config::Config;
use crate::phy::{self, PhyCaps, VhtWidth};
use anyhow::{Context, Result, bail};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

pub fn spawn_with_fallback(cfg: &Config, conf_path: &Path) -> Result<Child> {
    let caps = PhyCaps::query(&cfg.interface).unwrap_or_else(|e| {
        warn!(err = %e, "could not query phy caps, using empty defaults");
        PhyCaps::default()
    });

    info!(
        ht_caps  = format!("0x{:04x}", caps.ht_caps),
        vht_caps = format!("0x{:08x}", caps.vht_caps),
        has_vht  = caps.has_vht,
        vht_width = ?caps.max_vht_width,
        "detected phy capabilities"
    );

    let levels: &[&str] = &["full", "vht-minimal", "ht-only", "bare"];

    for &level in levels {
        let conf = generate(cfg, &caps, level);
        std::fs::write(conf_path, &conf)
            .with_context(|| format!("writing hostapd.conf (level={level})"))?;

        let mut child = Command::new("hostapd")
            .arg(conf_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawning hostapd")?;

        let stop_log = Arc::new(AtomicBool::new(false));
        if let Some(stdout) = child.stdout.take() {
            let stop = Arc::clone(&stop_log);
            std::thread::Builder::new()
                .name("hostapd-stdout".into())
                .spawn(move || pipe_to_tracing(stdout, "hostapd", stop))
                .ok();
        }
        if let Some(stderr) = child.stderr.take() {
            let stop = Arc::clone(&stop_log);
            std::thread::Builder::new()
                .name("hostapd-stderr".into())
                .spawn(move || pipe_to_tracing(stderr, "hostapd", stop))
                .ok();
        }

        match wait_or_alive(child, Duration::from_secs(2)) {
            Ok(running) => {
                if level != "full" {
                    warn!(level, "hostapd running with reduced capabilities");
                } else {
                    info!("hostapd running with full capabilities");
                }
                return Ok(running);
            }
            Err(status) => {
                stop_log.store(true, Ordering::Relaxed);
                warn!(
                    level,
                    ?status,
                    "hostapd exited immediately, trying next level"
                );
            }
        }
    }

    bail!("hostapd failed at all capability levels")
}

fn pipe_to_tracing<R: std::io::Read>(reader: R, source: &str, stop: Arc<AtomicBool>) {
    let buf = BufReader::new(reader);
    for line in buf.lines() {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match line {
            Ok(l) if !l.trim().is_empty() => classify_hostapd_line(&l, source),
            _ => break,
        }
    }
}

fn classify_hostapd_line(line: &str, _source: &str) {
    let lower = line.to_lowercase();
    if lower.contains("error")
        || lower.contains("failed")
        || lower.contains("could not")
        || lower.contains("unable")
    {
        warn!(target: "hostapd", "{line}");
    } else if lower.contains("warning") || lower.contains("beacon") {
        warn!(target: "hostapd", "{line}");
    } else if lower.contains("enabled")
        || lower.contains("connected")
        || lower.contains("disconnected")
        || lower.contains("authenticated")
        || lower.contains("associated")
        || lower.contains("handshake")
    {
        info!(target: "hostapd", "{line}");
    } else {
        debug!(target: "hostapd", "{line}");
    }
}

fn generate(cfg: &Config, caps: &PhyCaps, level: &str) -> String {
    let mut lines: Vec<String> = vec![
        format!("interface={}", cfg.interface),
        format!("ssid={}", cfg.ssid),
        format!("channel={}", cfg.channel),
        format!("hw_mode={}", cfg.hw_mode.as_str()),
        format!("country_code={}", cfg.country_code),
        format!("ignore_broadcast_ssid={}", u8::from(cfg.hidden)),
        "driver=nl80211".into(),
        "logger_syslog=-1".into(),
        "logger_syslog_level=3".into(),
        "logger_stdout=-1".into(),
        "logger_stdout_level=0".into(),
    ];

    match level {
        "full" => {
            if cfg.ieee80211n || cfg.ieee80211ac {
                lines.push("ieee80211n=1".into());
                lines.push("wmm_enabled=1".into());
                lines.push(format!("ht_capab={}", caps.ht_capab_string(cfg.channel)));
            }
            if cfg.ieee80211ac && caps.has_vht {
                lines.push("ieee80211ac=1".into());
                let vht_capab = caps.vht_capab_string();
                if !vht_capab.is_empty() {
                    lines.push(format!("vht_capab={vht_capab}"));
                }
                lines.push(format!("vht_oper_chwidth={}", caps.vht_oper_chwidth()));
                lines.push(format!(
                    "vht_oper_centr_freq_seg0_idx={}",
                    phy::vht_center_freq_idx(cfg.channel, caps.max_vht_width)
                ));
            }
        }
        "vht-minimal" => {
            if cfg.ieee80211n || cfg.ieee80211ac {
                lines.push("ieee80211n=1".into());
                lines.push("wmm_enabled=1".into());
                lines.push(format!(
                    "ht_capab={}[SHORT-GI-20][SHORT-GI-40]",
                    phy::ht_40mhz_flags(cfg.channel)
                ));
            }
            if cfg.ieee80211ac && caps.has_vht {
                lines.push("ieee80211ac=1".into());
                lines.push("vht_capab=[SHORT-GI-80]".into());
                lines.push("vht_oper_chwidth=1".into());
                lines.push(format!(
                    "vht_oper_centr_freq_seg0_idx={}",
                    phy::vht_center_freq_idx(cfg.channel, VhtWidth::W80)
                ));
            }
        }
        "ht-only" => {
            lines.push("ieee80211n=1".into());
            lines.push("wmm_enabled=1".into());
            lines.push(format!(
                "ht_capab={}[SHORT-GI-20]",
                phy::ht_40mhz_flags(cfg.channel)
            ));
        }
        _ /* "bare" */ => {
            lines.push("ieee80211n=1".into());
            lines.push("wmm_enabled=1".into());
        }
    }

    match &cfg.passphrase {
        Some(pw) => {
            lines.push("auth_algs=1".into());
            lines.push("wpa=2".into());
            lines.push("wpa_key_mgmt=WPA-PSK".into());
            lines.push("rsn_pairwise=CCMP".into());
            lines.push(format!("wpa_passphrase={pw}"));
        }
        None => {
            lines.push("auth_algs=1".into());
        }
    }

    lines.join("\n") + "\n"
}

fn wait_or_alive(
    mut child: Child,
    timeout: Duration,
) -> Result<Child, Option<std::process::ExitStatus>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(s)) => return Err(Some(s)),
            Ok(None) => {}
            Err(_) => return Err(None),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(child)
}

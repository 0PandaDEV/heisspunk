use anyhow::{Context, Result, bail};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

pub fn configure_interface(interface: &str, gateway: &str) -> Result<()> {
    which("ip")?;
    info!(interface, "flushing interface addresses");
    let status = Command::new("ip")
        .args(["addr", "flush", "dev", interface])
        .status()
        .context("flushing interface address")?;
    if !status.success() {
        bail!("ip addr flush failed");
    }

    let cidr = gateway_to_cidr(gateway)?;
    info!(interface, cidr, "assigning address");
    let status = Command::new("ip")
        .args(["addr", "add", &cidr, "dev", interface])
        .status()
        .context("assigning interface address")?;
    if !status.success() {
        bail!("ip addr add failed");
    }

    let status = Command::new("ip")
        .args(["link", "set", interface, "up"])
        .status()
        .context("bringing interface up")?;
    if !status.success() {
        bail!("ip link set up failed");
    }

    Ok(())
}

pub fn detect_upstream() -> Option<String> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);

    let mut iter = stdout.split_whitespace();
    while let Some(tok) = iter.next() {
        if tok == "dev" {
            return iter.next().map(str::to_owned);
        }
    }
    None
}

pub fn enable_nat(upstream: &str, ap_interface: &str, gateway: &str) -> Result<()> {
    which("iptables")?;
    info!(upstream, ap_interface, "enabling NAT / IP forwarding");

    fs::write("/proc/sys/net/ipv4/ip_forward", "1").context("enabling ip_forward")?;

    let subnet = gateway_to_subnet(gateway)?;

    ipt(&[
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-o",
        upstream,
        "-s",
        &subnet,
        "-j",
        "MASQUERADE",
    ])?;

    ipt(&[
        "-A",
        "FORWARD",
        "-i",
        ap_interface,
        "-o",
        upstream,
        "-s",
        &subnet,
        "-j",
        "ACCEPT",
    ])?;

    ipt(&[
        "-A",
        "FORWARD",
        "-i",
        upstream,
        "-o",
        ap_interface,
        "-d",
        &subnet,
        "-m",
        "state",
        "--state",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    ])?;

    info!(upstream, subnet, "NAT enabled");
    Ok(())
}

pub fn disable_nat(upstream: &str, ap_interface: &str, gateway: &str) -> Result<()> {
    info!(upstream, "removing NAT rules");

    let subnet = match gateway_to_subnet(gateway) {
        Ok(s) => s,
        Err(e) => {
            warn!(err = %e, "could not derive subnet, skipping NAT cleanup");
            return Ok(());
        }
    };

    let _ = ipt(&[
        "-t",
        "nat",
        "-D",
        "POSTROUTING",
        "-o",
        upstream,
        "-s",
        &subnet,
        "-j",
        "MASQUERADE",
    ]);
    let _ = ipt(&[
        "-D",
        "FORWARD",
        "-i",
        ap_interface,
        "-o",
        upstream,
        "-s",
        &subnet,
        "-j",
        "ACCEPT",
    ]);
    let _ = ipt(&[
        "-D",
        "FORWARD",
        "-i",
        upstream,
        "-o",
        ap_interface,
        "-d",
        &subnet,
        "-m",
        "state",
        "--state",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    ]);

    Ok(())
}

fn ipt(args: &[&str]) -> Result<()> {
    let status = Command::new("iptables")
        .args(args)
        .status()
        .with_context(|| format!("iptables {}", args.join(" ")))?;
    if !status.success() {
        bail!("iptables {} failed", args.join(" "));
    }
    Ok(())
}

pub fn write_pid_file(path: &Path, pid: u32) -> Result<()> {
    fs::create_dir_all(path.parent().unwrap_or(Path::new("/tmp")))
        .context("creating pid directory")?;
    fs::write(path, pid.to_string()).context("writing pid file")
}

pub fn kill_from_pid_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let raw = fs::read_to_string(path).context("reading pid file")?;
    let pid: i32 = raw.trim().parse().context("parsing pid")?;
    debug!(pid, path = %path.display(), "sending SIGTERM");
    let _ = signal::kill(Pid::from_raw(pid), Signal::SIGTERM);
    let _ = fs::remove_file(path);
    Ok(())
}

pub fn pid_is_running(pid_file: &Path) -> bool {
    let Ok(raw) = fs::read_to_string(pid_file) else {
        return false;
    };
    let Ok(pid) = raw.trim().parse::<i32>() else {
        return false;
    };
    signal::kill(Pid::from_raw(pid), None).is_ok()
}

pub fn teardown_hostapd(rt: &Path) {
    if let Err(e) = kill_from_pid_file(&rt.join("hostapd.pid")) {
        warn!(err = %e, "error stopping hostapd");
    }
}

pub fn runtime_dir() -> PathBuf {
    PathBuf::from("/tmp/heisspunk")
}

fn which(cmd: &str) -> Result<()> {
    let found = Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !found {
        bail!("{cmd} not found in PATH — please install it");
    }
    Ok(())
}

fn gateway_to_cidr(gateway: &str) -> Result<String> {
    let parts: Vec<&str> = gateway.split('.').collect();
    if parts.len() != 4 {
        bail!("invalid gateway IP: {gateway}");
    }
    let prefix = match parts[0] {
        "10" => 8,
        "172" => 12,
        _ => 24,
    };
    Ok(format!("{gateway}/{prefix}"))
}

fn gateway_to_subnet(gateway: &str) -> Result<String> {
    let parts: Vec<&str> = gateway.split('.').collect();
    if parts.len() != 4 {
        bail!("invalid gateway IP: {gateway}");
    }
    let prefix = match parts[0] {
        "10" => 8,
        "172" => 12,
        _ => 24,
    };
    Ok(format!("{}.{}.{}.0/{prefix}", parts[0], parts[1], parts[2]))
}

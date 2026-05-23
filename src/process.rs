use anyhow::{Context, Result, bail};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

pub fn configure_interface(interface: &str, gateway: &str) -> Result<()> {
    which("ip")?;
    let cidr = gateway_to_cidr(gateway)?;
    info!(interface, cidr, "configuring AP interface");

    run("ip", &["addr", "flush", "dev", interface]).context("ip addr flush")?;
    run("ip", &["addr", "add", &cidr, "dev", interface]).context("ip addr add")?;
    run("ip", &["link", "set", interface, "up"]).context("ip link set up")?;
    Ok(())
}

pub fn detect_upstream() -> Option<String> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .skip_while(|&t| t != "dev")
        .nth(1)
        .map(str::to_owned)
}

pub fn enable_nat(upstream: &str, ap_iface: &str, gateway: &str) -> Result<()> {
    which("iptables")?;
    let subnet = gateway_to_subnet(gateway)?;
    info!(upstream, ap_iface, subnet, "enabling NAT");

    fs::write("/proc/sys/net/ipv4/ip_forward", "1").context("enabling ip_forward")?;

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
        "-A", "FORWARD", "-i", ap_iface, "-o", upstream, "-s", &subnet, "-j", "ACCEPT",
    ])?;

    ipt(&[
        "-A",
        "FORWARD",
        "-i",
        upstream,
        "-o",
        ap_iface,
        "-d",
        &subnet,
        "-m",
        "state",
        "--state",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    ])?;
    Ok(())
}

pub fn disable_nat(upstream: &str, ap_iface: &str, gateway: &str) -> Result<()> {
    let subnet = match gateway_to_subnet(gateway) {
        Ok(s) => s,
        Err(e) => {
            warn!(err = %e, "could not derive subnet, skipping NAT cleanup");
            return Ok(());
        }
    };
    info!(upstream, "removing NAT rules");

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
        "-D", "FORWARD", "-i", ap_iface, "-o", upstream, "-s", &subnet, "-j", "ACCEPT",
    ]);
    let _ = ipt(&[
        "-D",
        "FORWARD",
        "-i",
        upstream,
        "-o",
        ap_iface,
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

pub fn write_pid_file(path: &Path, pid: u32) -> Result<()> {
    fs::create_dir_all(path.parent().unwrap_or(Path::new("/tmp"))).context("creating pid dir")?;
    fs::write(path, pid.to_string()).context("writing pid file")
}

pub fn kill_from_pid_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let pid: i32 = fs::read_to_string(path)
        .context("reading pid file")?
        .trim()
        .parse()
        .context("parsing pid")?;
    debug!(pid, "sending SIGTERM to hostapd");
    let _ = signal::kill(Pid::from_raw(pid), Signal::SIGTERM);
    let _ = fs::remove_file(path);
    Ok(())
}

pub fn pid_is_running(pid_file: &Path) -> bool {
    fs::read_to_string(pid_file)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .map(|pid| signal::kill(Pid::from_raw(pid), None).is_ok())
        .unwrap_or(false)
}

pub fn teardown_hostapd(rt: &Path) {
    if let Err(e) = kill_from_pid_file(&rt.join("hostapd.pid")) {
        warn!(err = %e, "error stopping hostapd");
    }
}

pub fn runtime_dir() -> PathBuf {
    PathBuf::from("/tmp/heisspunk")
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .with_context(|| format!("{cmd} {}", args.join(" ")))?;
    if !status.success() {
        bail!("{cmd} {} failed", args.join(" "));
    }
    Ok(())
}

fn ipt(args: &[&str]) -> Result<()> {
    run("iptables", args)
}

fn which(cmd: &str) -> Result<()> {
    if !Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        bail!("{cmd} not found in PATH");
    }
    Ok(())
}

fn gateway_to_cidr(gateway: &str) -> Result<String> {
    let p: Vec<&str> = gateway.split('.').collect();
    if p.len() != 4 {
        bail!("invalid gateway IP: {gateway}");
    }
    let prefix = match p[0] {
        "10" => 8,
        "172" => 12,
        _ => 24,
    };
    Ok(format!("{gateway}/{prefix}"))
}

fn gateway_to_subnet(gateway: &str) -> Result<String> {
    let p: Vec<&str> = gateway.split('.').collect();
    if p.len() != 4 {
        bail!("invalid gateway IP: {gateway}");
    }
    let prefix = match p[0] {
        "10" => 8,
        "172" => 12,
        _ => 24,
    };
    Ok(format!("{}.{}.{}.0/{prefix}", p[0], p[1], p[2]))
}

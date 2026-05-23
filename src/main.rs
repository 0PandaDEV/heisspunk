mod cli;
mod config;
mod dhcp;
mod dns;
mod hostapd;
mod phy;
mod process;

use anyhow::{Context, Result, bail};
use clap::Parser;
use cli::{Cli, Commands};
use config::{Config, HwMode, NetworkClass};
use dhcp::DhcpServer;
use dns::DnsForwarder;
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
use process::{detect_upstream, pid_is_running, runtime_dir, teardown_hostapd};
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{error, info, warn};

fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.command {
        Commands::Start(args) => cmd_start(args),
        Commands::Stop => cmd_stop(),
        Commands::Status => cmd_status(),
        Commands::Show { args } => cmd_show(args),
        Commands::ConfigPath => {
            println!("{}", Config::config_path()?.display());
            Ok(())
        }
        Commands::GenerateConfig { output } => cmd_generate_config(output),
    }
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_target(false)
        .init();
}

fn merge_args(base: Config, args: cli::StartArgs) -> Result<Config> {
    let mut cfg = base;
    if let Some(v) = args.interface {
        cfg.interface = v;
    }
    if let Some(v) = args.ssid {
        cfg.ssid = v;
    }
    if args.passphrase.is_some() {
        cfg.passphrase = args.passphrase;
    }
    if let Some(v) = args.channel {
        cfg.channel = v;
    }
    if let Some(v) = args.upstream {
        cfg.upstream = Some(v);
    }
    if let Some(v) = args.country_code {
        cfg.country_code = v;
    }
    if args.hidden {
        cfg.hidden = true;
    }
    if args.ieee80211ac {
        cfg.ieee80211ac = true;
    }

    if let Some(mode) = args.hw_mode {
        cfg.hw_mode = match mode.to_lowercase().as_str() {
            "b" => HwMode::B,
            "g" => HwMode::G,
            "a" => HwMode::A,
            other => bail!("unknown hw_mode '{other}', expected b/g/a"),
        };
    }
    if let Some(class) = args.network_class {
        cfg.network_class = match class.to_lowercase().as_str() {
            "a" => NetworkClass::A,
            "b" => NetworkClass::B,
            "c" => NetworkClass::C,
            other => bail!("unknown network_class '{other}', expected a/b/c"),
        };
    }
    Ok(cfg)
}

fn resolve_config(args: cli::StartArgs) -> Result<Config> {
    let base = Config::load_xdg()?.unwrap_or_default();
    let cfg = merge_args(base, args)?;
    cfg.validate()?;
    if cfg.interface.is_empty() {
        bail!(
            "interface is required — set it in ~/.config/heisspunk/config.toml \
             or pass --interface"
        );
    }
    if cfg.ssid.is_empty() {
        bail!(
            "ssid is required — set it in ~/.config/heisspunk/config.toml \
             or pass --ssid"
        );
    }
    Ok(cfg)
}

fn check_wireless_interface(iface: &str) -> Result<()> {
    let phy = format!("/sys/class/net/{iface}/phy80211");
    let wireless = format!("/sys/class/net/{iface}/wireless");
    if !std::path::Path::new(&phy).exists() && !std::path::Path::new(&wireless).exists() {
        bail!(
            "'{iface}' is not a wireless interface.\n\
             List wireless interfaces with: iw dev"
        );
    }
    Ok(())
}

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigterm(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}
extern "C" fn handle_sighup(_: libc::c_int) {
    RELOAD.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() -> Result<()> {
    let term = SigAction::new(
        SigHandler::Handler(handle_sigterm),
        SaFlags::SA_RESTART,
        SigSet::empty(),
    );
    let hup = SigAction::new(
        SigHandler::Handler(handle_sighup),
        SaFlags::SA_RESTART,
        SigSet::empty(),
    );
    unsafe {
        signal::sigaction(Signal::SIGTERM, &term).context("SIGTERM handler")?;
        signal::sigaction(Signal::SIGINT, &term).context("SIGINT handler")?;
        signal::sigaction(Signal::SIGHUP, &hup).context("SIGHUP handler")?;
    }
    Ok(())
}

fn cmd_start(args: cli::StartArgs) -> Result<()> {
    install_signal_handlers()?;
    let cfg = resolve_config(args.clone())?;
    check_wireless_interface(&cfg.interface)?;
    let rt = runtime_dir();
    fs::create_dir_all(&rt).context("creating runtime dir")?;
    run_hotspot_loop(&args, cfg, &rt)
}

fn run_hotspot_loop(args: &cli::StartArgs, initial_cfg: Config, rt: &PathBuf) -> Result<()> {
    let mut cfg = initial_cfg;
    let mut restart_delay = Duration::from_secs(1);
    const MAX_DELAY: Duration = Duration::from_secs(30);
    let mut svc_stop: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));

    loop {
        if SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }

        if RELOAD.swap(false, Ordering::SeqCst) {
            info!("SIGHUP — reloading config");
            match resolve_config(args.clone()) {
                Ok(new) => {
                    cfg = new;
                    info!("config reloaded");
                }
                Err(e) => warn!(err = %e, "config reload failed, keeping current config"),
            }
        }

        match start_session(&cfg, rt, Arc::clone(&svc_stop)) {
            Ok(mut hostapd) => {
                restart_delay = Duration::from_secs(1);
                log_running_summary(&cfg);

                loop {
                    if SHUTDOWN.load(Ordering::SeqCst) {
                        info!("shutdown signal received");
                        svc_stop.store(true, Ordering::SeqCst);
                        let _ = hostapd.kill();
                        let _ = hostapd.wait();
                        teardown_hostapd(rt);
                        cleanup_nat(&cfg);
                        return Ok(());
                    }

                    if RELOAD.swap(false, Ordering::SeqCst) {
                        info!("SIGHUP — restarting with new config");
                        svc_stop.store(true, Ordering::SeqCst);
                        let _ = hostapd.kill();
                        let _ = hostapd.wait();
                        teardown_hostapd(rt);
                        match resolve_config(args.clone()) {
                            Ok(new) => {
                                cfg = new;
                                info!("config reloaded");
                            }
                            Err(e) => warn!(err = %e, "config reload failed"),
                        }
                        svc_stop = Arc::new(AtomicBool::new(false));
                        break;
                    }

                    if hostapd.try_wait().map(|s| s.is_some()).unwrap_or(true) {
                        warn!("hostapd exited unexpectedly — will restart");
                        svc_stop.store(true, Ordering::SeqCst);
                        teardown_hostapd(rt);
                        svc_stop = Arc::new(AtomicBool::new(false));
                        break;
                    }

                    std::thread::sleep(Duration::from_millis(500));
                }
            }
            Err(e) => {
                error!(err = %e, "failed to start hotspot");
                svc_stop = Arc::new(AtomicBool::new(false));
            }
        }

        if SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }

        info!(secs = restart_delay.as_secs(), "waiting before restart");
        interruptible_sleep(restart_delay);
        restart_delay = (restart_delay * 2).min(MAX_DELAY);
    }

    info!("hotspot stopped");
    cleanup_nat(&cfg);
    Ok(())
}

fn start_session(cfg: &Config, rt: &PathBuf, stop: Arc<AtomicBool>) -> Result<std::process::Child> {
    let hostapd_conf = rt.join("hostapd.conf");

    process::configure_interface(&cfg.interface, &cfg.resolved_gateway())?;

    let upstream = cfg.upstream.clone().or_else(|| {
        let detected = detect_upstream();
        if let Some(ref u) = detected {
            if u != &cfg.interface {
                info!(upstream = %u, "auto-detected upstream interface");
                return detected;
            }
        }
        warn!("could not auto-detect upstream interface — NAT disabled");
        None
    });

    if let Some(ref up) = upstream {
        process::enable_nat(up, &cfg.interface, &cfg.resolved_gateway())?;
    }

    spawn_dhcp_thread(cfg, Arc::clone(&stop))?;
    spawn_dns_thread(cfg, Arc::clone(&stop));

    let hostapd = hostapd::spawn_with_fallback(cfg, &hostapd_conf)?;
    process::write_pid_file(&rt.join("hostapd.pid"), hostapd.id())?;

    Ok(hostapd)
}

fn spawn_dhcp_thread(cfg: &Config, stop: Arc<AtomicBool>) -> Result<()> {
    let gateway: Ipv4Addr = cfg.resolved_gateway().parse().context("parsing gateway")?;
    let range = cfg.resolved_dhcp_range();
    let start: Ipv4Addr = range.start.parse().context("parsing DHCP range start")?;
    let end: Ipv4Addr = range.end.parse().context("parsing DHCP range end")?;
    let mask: Ipv4Addr = range.netmask.parse().context("parsing subnet mask")?;
    let iface = cfg.interface.clone();

    let server = DhcpServer::new(gateway, start, end, mask, parse_lease_secs(&cfg.dhcp_lease));
    std::thread::Builder::new()
        .name("dhcp".into())
        .spawn(move || {
            if let Err(e) = server.run(&iface, stop) {
                error!(err = %e, "DHCP server error");
            }
        })
        .context("spawning DHCP thread")?;
    Ok(())
}

fn spawn_dns_thread(cfg: &Config, stop: Arc<AtomicBool>) {
    let Ok(gateway) = cfg.resolved_gateway().parse::<Ipv4Addr>() else {
        warn!("invalid gateway for DNS, skipping DNS forwarder");
        return;
    };
    let iface = cfg.interface.clone();
    let _ = std::thread::Builder::new()
        .name("dns".into())
        .spawn(move || {
            if let Err(e) = DnsForwarder::new(gateway).run(&iface, stop) {
                error!(err = %e, "DNS forwarder error");
            }
        });
}

fn parse_lease_secs(s: &str) -> u32 {
    if let Some(h) = s.strip_suffix('h') {
        return h.parse::<u32>().unwrap_or(12) * 3600;
    }
    if let Some(m) = s.strip_suffix('m') {
        return m.parse::<u32>().unwrap_or(30) * 60;
    }
    if let Some(s) = s.strip_suffix('s') {
        return s.parse::<u32>().unwrap_or(43200);
    }
    s.parse::<u32>().unwrap_or(43200)
}

fn log_running_summary(cfg: &Config) {
    let gateway = cfg.resolved_gateway();
    let range = cfg.resolved_dhcp_range();
    info!(
        ssid     = %cfg.ssid,
        iface    = %cfg.interface,
        security = if cfg.passphrase.is_some() { "WPA2" } else { "open" },
        gateway  = %gateway,
        dhcp     = %format!("{} – {}", range.start, range.end),
        "hotspot running"
    );
}

fn cleanup_nat(cfg: &Config) {
    let upstream = cfg
        .upstream
        .clone()
        .or_else(|| detect_upstream().filter(|u| u != &cfg.interface));
    if let Some(ref up) = upstream {
        let _ = process::disable_nat(up, &cfg.interface, &cfg.resolved_gateway());
    }
}

fn cmd_stop() -> Result<()> {
    let rt = runtime_dir();
    teardown_hostapd(&rt);
    if let Ok(Some(cfg)) = Config::load_xdg() {
        cleanup_nat(&cfg);
    }
    info!("hotspot stopped");
    Ok(())
}

fn cmd_status() -> Result<()> {
    let rt = runtime_dir();
    if pid_is_running(&rt.join("hostapd.pid")) {
        let pid = fs::read_to_string(rt.join("hostapd.pid")).unwrap_or_default();
        println!("running  hostapd={}", pid.trim());
    } else {
        println!("stopped");
    }
    Ok(())
}

fn cmd_show(args: cli::StartArgs) -> Result<()> {
    let cfg = resolve_config(args)?;
    let gateway = cfg.resolved_gateway();
    let range = cfg.resolved_dhcp_range();
    println!("interface    : {}", cfg.interface);
    println!("ssid         : {}", cfg.ssid);
    println!(
        "passphrase   : {}",
        cfg.passphrase.as_deref().unwrap_or("<none — open>")
    );
    println!("channel      : {}", cfg.channel);
    println!("hw_mode      : {}", cfg.hw_mode.as_str());
    println!("network_class: {:?}", cfg.network_class);
    println!("gateway      : {gateway}");
    println!(
        "dhcp_range   : {} – {} / {}",
        range.start, range.end, range.netmask
    );
    println!("dhcp_lease   : {}", cfg.dhcp_lease);
    println!(
        "upstream     : {}",
        cfg.upstream.as_deref().unwrap_or("<none>")
    );
    println!("hidden       : {}", cfg.hidden);
    println!("ieee80211n   : {}", cfg.ieee80211n);
    println!("ieee80211ac  : {}", cfg.ieee80211ac);
    println!("country_code : {}", cfg.country_code);
    Ok(())
}

fn cmd_generate_config(output: Option<PathBuf>) -> Result<()> {
    let content = default_config_toml();
    let path = match output {
        Some(p) => p,
        None => Config::config_path()?,
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(&path, &content).with_context(|| format!("writing {}", path.display()))?;
    println!("Config written to {}", path.display());
    Ok(())
}

fn default_config_toml() -> String {
    r#"# heisspunk configuration file
# All values shown are the built-in defaults.
# Lines starting with '#' are comments.

# Wireless interface to use as the access point (required).
# Find yours with: iw dev
interface = "wlan0"

# SSID to broadcast (required, 1–32 characters).
ssid = "MyHotspot"

# WPA2 passphrase (8–63 characters).
# Remove or comment out this line to create an open (unencrypted) network.
# passphrase = "secret123"

# WiFi channel number.
# 2.4 GHz: 1–13  |  5 GHz: 36, 40, 44, 48, 52, ...
channel = 6

# Hardware mode: "b", "g" (2.4 GHz), or "a" (5 GHz).
hw_mode = "g"

# RFC 1918 private network class used to derive the gateway and DHCP range.
# Overridden by explicit 'gateway' and 'dhcp_range' below.
#   "a" → 10.0.0.0/8      gateway 10.0.0.1
#   "b" → 172.16.0.0/12   gateway 172.16.0.1
#   "c" → 192.168.x.0/24  gateway 192.168.100.1  (default)
network_class = "c"

# Override the gateway IP derived from network_class.
# gateway = "192.168.100.1"

# Override the DHCP pool derived from network_class.
# [dhcp_range]
# start   = "192.168.100.10"
# end     = "192.168.100.250"
# netmask = "255.255.255.0"

# DHCP lease duration.  Suffixes: h (hours), m (minutes), s (seconds).
dhcp_lease = "12h"

# Upstream interface for NAT / internet sharing.
# Remove or comment out to disable NAT (isolated hotspot only).
# upstream = "eth0"

# Hide the SSID — clients must know it to connect.
hidden = false

# IEEE 802.11n (HT, up to 300 Mbps on 2.4/5 GHz).
ieee80211n = true

# IEEE 802.11ac (VHT, 5 GHz only).  Requires hw_mode = "a".
ieee80211ac = false

# ISO 3166-1 alpha-2 country code for regulatory domain.
# Controls which channels and power levels are legal to use.
country_code = "DE"
"#
    .to_string()
}

fn interruptible_sleep(duration: Duration) {
    let tick = Duration::from_millis(200);
    let mut remaining = duration;
    while remaining > Duration::ZERO && !SHUTDOWN.load(Ordering::SeqCst) {
        std::thread::sleep(tick.min(remaining));
        remaining = remaining.saturating_sub(tick);
    }
}

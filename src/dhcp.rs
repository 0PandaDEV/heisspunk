use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const SERVER_PORT: u16 = 67;
const CLIENT_PORT: u16 = 68;

const DHCPDISCOVER: u8 = 1;
const DHCPOFFER: u8 = 2;
const DHCPREQUEST: u8 = 3;
const DHCPACK: u8 = 5;
const DHCPNAK: u8 = 6;
const DHCPRELEASE: u8 = 7;

const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

#[derive(Clone)]
struct Lease {
    ip: Ipv4Addr,
    expires: Instant,
}

pub struct DhcpServer {
    gateway: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    pool: Vec<Ipv4Addr>,
    lease_duration: Duration,
    leases: Arc<Mutex<HashMap<[u8; 6], Lease>>>,
}

impl DhcpServer {
    pub fn new(
        gateway: Ipv4Addr,
        pool_start: Ipv4Addr,
        pool_end: Ipv4Addr,
        subnet_mask: Ipv4Addr,
        lease_secs: u32,
    ) -> Self {
        Self {
            gateway,
            subnet_mask,
            pool: ip_range(pool_start, pool_end),
            lease_duration: Duration::from_secs(lease_secs as u64),
            leases: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn run(&self, iface: &str, stop: Arc<AtomicBool>) -> Result<()> {
        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, SERVER_PORT);
        let sock = UdpSocket::bind(bind_addr)
            .with_context(|| format!("binding DHCP socket to {bind_addr}"))?;
        sock.set_broadcast(true).context("enabling SO_BROADCAST")?;
        sock.set_read_timeout(Some(Duration::from_millis(500)))
            .context("setting read timeout")?;
        bind_to_device(&sock, iface)?;

        info!(
            addr = %SocketAddrV4::new(self.gateway, SERVER_PORT),
            pool_start = %self.pool.first().map(|a| a.to_string()).unwrap_or_default(),
            pool_end   = %self.pool.last().map(|a| a.to_string()).unwrap_or_default(),
            lease_secs = self.lease_duration.as_secs(),
            "DHCP server listening"
        );

        let mut buf = [0u8; 1500];
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match sock.recv_from(&mut buf) {
                Ok((n, src)) => {
                    debug!(src = %src, bytes = n, "DHCP packet received");
                    if let Some(reply) = self.handle_packet(&buf[..n]) {
                        let dst = SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT);
                        match sock.send_to(&reply, dst) {
                            Ok(sent) => debug!(dst = %dst, bytes = sent, "DHCP reply sent"),
                            Err(e) => warn!(err = %e, "DHCP send failed"),
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => warn!(err = %e, "DHCP recv error"),
            }
        }

        info!("DHCP server stopped");
        Ok(())
    }

    fn handle_packet(&self, pkt: &[u8]) -> Option<Vec<u8>> {
        if pkt.len() < 240 {
            debug!(len = pkt.len(), "DHCP packet too short, ignoring");
            return None;
        }
        if pkt[0] != 1 {
            return None;
        }
        if pkt[236..240] != MAGIC_COOKIE {
            warn!("DHCP packet missing magic cookie, ignoring");
            return None;
        }

        let xid: [u8; 4] = pkt[4..8].try_into().ok()?;
        let mac: [u8; 6] = pkt[28..34].try_into().ok()?;
        let ciaddr = Ipv4Addr::from(<[u8; 4]>::try_from(&pkt[12..16]).ok()?);

        let options = parse_options(&pkt[240..]);
        let msg_type = options.get(&53).and_then(|v| v.first().copied())?;

        debug!(
            mac     = %fmt_mac(mac),
            msg     = msg_type_name(msg_type),
            ciaddr  = %ciaddr,
            "DHCP message"
        );

        match msg_type {
            DHCPDISCOVER => {
                let ip = self.assign_or_get(mac)?;
                info!(mac = %fmt_mac(mac), offer = %ip, "DHCPDISCOVER → DHCPOFFER");
                Some(self.build_reply(&xid, mac, ip, DHCPOFFER))
            }
            DHCPREQUEST => {
                let requested = options
                    .get(&50)
                    .and_then(|v| v.get(..4))
                    .and_then(|b| <[u8; 4]>::try_from(b).ok())
                    .map(Ipv4Addr::from)
                    .or_else(|| {
                        if ciaddr.is_unspecified() {
                            None
                        } else {
                            Some(ciaddr)
                        }
                    });

                debug!(mac = %fmt_mac(mac), requested = ?requested, "DHCPREQUEST");

                match self.validate_request(mac, requested) {
                    Some(ip) => {
                        info!(mac = %fmt_mac(mac), ip = %ip, "DHCPREQUEST → DHCPACK");
                        Some(self.build_reply(&xid, mac, ip, DHCPACK))
                    }
                    None => {
                        warn!(mac = %fmt_mac(mac), requested = ?requested, "DHCPREQUEST → DHCPNAK (invalid request)");
                        Some(self.build_nak(&xid, mac))
                    }
                }
            }
            DHCPRELEASE => {
                let mut leases = self.leases.lock().unwrap();
                if let Some(l) = leases.remove(&mac) {
                    info!(mac = %fmt_mac(mac), ip = %l.ip, "DHCPRELEASE — lease removed");
                }
                None
            }
            other => {
                debug!(mac = %fmt_mac(mac), msg_type = other, "unhandled DHCP message type");
                None
            }
        }
    }

    fn validate_request(&self, mac: [u8; 6], requested: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        let mut leases = self.leases.lock().unwrap();

        if let Some(lease) = leases.get_mut(&mac) {
            let ip = lease.ip;
            if let Some(req) = requested {
                if req != ip {
                    return None;
                }
            }
            lease.expires = Instant::now() + self.lease_duration;
            return Some(ip);
        }

        let now = Instant::now();
        let used: std::collections::HashSet<Ipv4Addr> = leases
            .values()
            .filter(|l| l.expires > now)
            .map(|l| l.ip)
            .collect();

        let ip = if let Some(req) = requested {
            if self.pool.contains(&req) && !used.contains(&req) {
                req
            } else {
                *self.pool.iter().find(|ip| !used.contains(ip))?
            }
        } else {
            *self.pool.iter().find(|ip| !used.contains(ip))?
        };

        leases.insert(
            mac,
            Lease {
                ip,
                expires: now + self.lease_duration,
            },
        );
        Some(ip)
    }

    fn assign_or_get(&self, mac: [u8; 6]) -> Option<Ipv4Addr> {
        let mut leases = self.leases.lock().unwrap();
        if let Some(l) = leases.get_mut(&mac) {
            l.expires = Instant::now() + self.lease_duration;
            return Some(l.ip);
        }
        let now = Instant::now();
        let used: std::collections::HashSet<Ipv4Addr> = leases
            .values()
            .filter(|l| l.expires > now)
            .map(|l| l.ip)
            .collect();
        let ip = *self.pool.iter().find(|ip| !used.contains(ip))?;
        leases.insert(
            mac,
            Lease {
                ip,
                expires: now + self.lease_duration,
            },
        );
        Some(ip)
    }

    fn build_reply(&self, xid: &[u8; 4], mac: [u8; 6], yiaddr: Ipv4Addr, msg_type: u8) -> Vec<u8> {
        let mut pkt = self.base_reply(xid, mac, yiaddr);
        let lease = (self.lease_duration.as_secs() as u32).to_be_bytes();
        let gw = self.gateway.octets();
        let mask = self.subnet_mask.octets();

        #[rustfmt::skip]
        pkt.extend_from_slice(&[
            53, 1, msg_type,
            54, 4, gw[0], gw[1], gw[2], gw[3],
            51, 4, lease[0], lease[1], lease[2], lease[3],
            58, 4, lease[0], lease[1], lease[2], lease[3],
            1,  4, mask[0], mask[1], mask[2], mask[3],
            3,  4, gw[0], gw[1], gw[2], gw[3],
            6,  4, gw[0], gw[1], gw[2], gw[3],
            255,
        ]);
        pkt
    }

    fn build_nak(&self, xid: &[u8; 4], mac: [u8; 6]) -> Vec<u8> {
        let mut pkt = self.base_reply(xid, mac, Ipv4Addr::UNSPECIFIED);
        let gw = self.gateway.octets();
        pkt.extend_from_slice(&[53, 1, DHCPNAK, 54, 4, gw[0], gw[1], gw[2], gw[3], 255]);
        pkt
    }

    fn base_reply(&self, xid: &[u8; 4], mac: [u8; 6], yiaddr: Ipv4Addr) -> Vec<u8> {
        let mut pkt = vec![0u8; 240];
        pkt[0] = 2;
        pkt[1] = 1;
        pkt[2] = 6;
        pkt[4..8].copy_from_slice(xid);
        pkt[16..20].copy_from_slice(&yiaddr.octets());
        pkt[20..24].copy_from_slice(&self.gateway.octets());
        pkt[28..34].copy_from_slice(&mac);
        pkt[236..240].copy_from_slice(&MAGIC_COOKIE);
        pkt
    }
}

fn parse_options(data: &[u8]) -> HashMap<u8, Vec<u8>> {
    let mut map = HashMap::new();
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            255 => break,
            0 => {
                i += 1;
                continue;
            }
            code => {
                if i + 1 >= data.len() {
                    break;
                }
                let len = data[i + 1] as usize;
                if i + 2 + len > data.len() {
                    break;
                }
                map.insert(code, data[i + 2..i + 2 + len].to_vec());
                i += 2 + len;
            }
        }
    }
    map
}

fn ip_range(start: Ipv4Addr, end: Ipv4Addr) -> Vec<Ipv4Addr> {
    let s = u32::from(start);
    let e = u32::from(end);
    (s..=e).map(Ipv4Addr::from).collect()
}

fn fmt_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn msg_type_name(t: u8) -> &'static str {
    match t {
        1 => "DISCOVER",
        2 => "OFFER",
        3 => "REQUEST",
        4 => "DECLINE",
        5 => "ACK",
        6 => "NAK",
        7 => "RELEASE",
        8 => "INFORM",
        _ => "UNKNOWN",
    }
}

fn bind_to_device(sock: &UdpSocket, iface: &str) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = sock.as_raw_fd();
    let name = std::ffi::CString::new(iface).context("interface name")?;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr() as *const libc::c_void,
            name.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).context("SO_BINDTODEVICE");
    }
    Ok(())
}

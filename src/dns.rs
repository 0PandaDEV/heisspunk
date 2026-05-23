use anyhow::{Context, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{debug, info, warn};

const DNS_PORT: u16 = 53;
const UPSTREAM: &str = "1.1.1.1:53";
const TIMEOUT: Duration = Duration::from_secs(3);

pub struct DnsForwarder {
    listen: SocketAddrV4,
}

impl DnsForwarder {
    pub fn new(gateway: Ipv4Addr) -> Self {
        Self {
            listen: SocketAddrV4::new(gateway, DNS_PORT),
        }
    }

    pub fn run(&self, iface: &str, stop: Arc<AtomicBool>) -> Result<()> {
        let sock = UdpSocket::bind(self.listen)
            .with_context(|| format!("binding DNS socket to {}", self.listen))?;
        sock.set_read_timeout(Some(Duration::from_millis(500)))
            .context("setting read timeout")?;
        bind_to_device(&sock, iface)?;

        info!(addr = %self.listen, upstream = UPSTREAM, "DNS forwarder listening");

        let mut buf = [0u8; 512];
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match sock.recv_from(&mut buf) {
                Ok((n, client)) => {
                    let query = buf[..n].to_vec();
                    let upstream: SocketAddr = UPSTREAM.parse().unwrap();
                    match forward_query(&query, upstream) {
                        Ok(resp) => {
                            if let Err(e) = sock.send_to(&resp, client) {
                                warn!(err = %e, "DNS send to client failed");
                            }
                            debug!(client = %client, "DNS query forwarded");
                        }
                        Err(e) => warn!(err = %e, "DNS forward failed"),
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => warn!(err = %e, "DNS recv error"),
            }
        }

        info!("DNS forwarder stopped");
        Ok(())
    }
}

fn forward_query(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").context("upstream DNS bind")?;
    sock.set_read_timeout(Some(TIMEOUT))
        .context("upstream read timeout")?;
    sock.connect(upstream).context("upstream DNS connect")?;
    sock.send(query).context("upstream DNS send")?;
    let mut resp = vec![0u8; 512];
    let n = sock.recv(&mut resp).context("upstream DNS recv")?;
    resp.truncate(n);
    Ok(resp)
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

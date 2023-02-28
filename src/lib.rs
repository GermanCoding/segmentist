use caps::{CapSet, Capability, CapsHashSet};
use hyper::Uri;
use nix::sys::utsname::uname;
use probes::packetsize_monitor::{ConnectionV4, ScanResult};
use redbpf::{Error, LruHashMap, Map};
use semver::Version;
use std::fmt::{Display, Formatter};
use std::net::{AddrParseError, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio_native_tls::native_tls;
use url::Url;

pub const OBSERVED_PACKET_SIZE_MAP_NAME: &str = "OBSERVED_PACKET_SIZE";
pub const XDP_PROGRAM_NAME: &str = "packetsize_monitor";
pub const PIN_OBSERVED_PACKET_SIZE: &str = "/sys/fs/bpf/observed_packet_size";
pub const PIN_XDP_PROGRAM: &str = "/sys/fs/bpf/packetsize_monitor";
pub const MIN_KERNEL_VERSION_CAP_BPF: &'static str = "5.8.0";
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const ADVERTISED_MSS: u32 = 1000;
// We don't actually advertise a MTU: Estimated based on 20 bytes IP header + 20 bytes TCP header
pub const ADVERTISED_MTU: u32 = ADVERTISED_MSS + 40;

pub const INFO: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    " +",
    env!("CARGO_PKG_REPOSITORY")
);

pub mod connection;
pub mod web;

#[derive(Debug)]
pub enum SegmentistError {
    UnsupportedScheme,
    MalformedURL,
    RedBPF(Error),
    Hyper(hyper::Error),
    HyperHttp(hyper::http::Error),
    LibraryError(url::ParseError),
    IOError(std::io::Error),
    TLSError(native_tls::Error),
    AddrParseError(AddrParseError),
    NoValidAddress,
    ConnectTimeout(SocketAddrV4),
    Semver(semver::Error),
    Other,
}

impl Display for SegmentistError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SegmentistError::UnsupportedScheme => {
                write!(f, "The requested URL scheme is not supported at this time. Only HTTP and HTTPS are supported.")
            }
            SegmentistError::MalformedURL => {
                write!(f, "The requested URL does not appear to be a valid URL, or contains forbidden parameters.")
            }
            SegmentistError::RedBPF(_) => {
                write!(f, "An internal error occurred.")
            }
            SegmentistError::Hyper(e) => {
                write!(
                    f,
                    "An error occurred while transmitting the HTTP request/response. {}",
                    e.to_string()
                )
            }
            SegmentistError::HyperHttp(e) => {
                write!(
                    f,
                    "An error occurred while transmitting the HTTP request/response. {}",
                    e.to_string()
                )
            }
            SegmentistError::LibraryError(_) => {
                write!(f, "The requested URL does not appear to be a valid URL, or contains forbidden parameters.")
            }
            SegmentistError::IOError(e) => {
                write!(
                    f,
                    "Unable to communicate due to an I/O error: {}",
                    e.to_string()
                )
            }
            SegmentistError::TLSError(e) => {
                write!(
                    f,
                    "TCP connection successful, but unable to negotiate TLS: {}",
                    e.to_string()
                )
            }
            SegmentistError::AddrParseError(e) => {
                write!(f, "Unable to parse IP address: {}", e.to_string())
            }
            SegmentistError::NoValidAddress => {
                write!(f, "The given URL does not resolve to any valid IPv4 address. IPv6 is not supported at this time.")
            }
            SegmentistError::ConnectTimeout(addr) => {
                write!(f, "Timeout while connecting to {}.", addr)
            }
            SegmentistError::Semver(_) => {
                write!(f, "An internal error occurred.")
            }
            SegmentistError::Other => {
                write!(f, "An internal error occurred.")
            }
        }
    }
}

impl From<Error> for SegmentistError {
    fn from(e: Error) -> SegmentistError {
        SegmentistError::RedBPF(e)
    }
}

impl From<std::io::Error> for SegmentistError {
    fn from(e: std::io::Error) -> SegmentistError {
        SegmentistError::IOError(e)
    }
}

impl From<AddrParseError> for SegmentistError {
    fn from(e: AddrParseError) -> SegmentistError {
        SegmentistError::AddrParseError(e)
    }
}

impl From<hyper::Error> for SegmentistError {
    fn from(e: hyper::Error) -> SegmentistError {
        SegmentistError::Hyper(e)
    }
}

impl From<hyper::http::Error> for SegmentistError {
    fn from(e: hyper::http::Error) -> SegmentistError {
        SegmentistError::HyperHttp(e)
    }
}

impl From<native_tls::Error> for SegmentistError {
    fn from(e: native_tls::Error) -> SegmentistError {
        SegmentistError::TLSError(e)
    }
}

pub struct ScanRequest<'a> {
    pub url: String,
    pub map: &'a Map,
    pub advertised_mss: usize,
    pub advertised_mtu: usize,
}

pub struct ConnectInfo {
    pub uri: Uri,
    pub address: SocketAddrV4,
}

pub fn check_url(url: &str) -> Result<ConnectInfo, SegmentistError> {
    match Url::parse(url) {
        Ok(url) => {
            if url.scheme() != "http" && url.scheme() != "https" {
                return Err(SegmentistError::UnsupportedScheme);
            }
            if url.password().is_some() {
                return Err(SegmentistError::MalformedURL);
            }
            if let None = url.port_or_known_default() {
                return Err(SegmentistError::MalformedURL);
            }
            if let None = url.host() {
                return Err(SegmentistError::MalformedURL);
            }
            let addresses = url.socket_addrs(|| None)?;
            let addr = addresses
                .into_iter()
                .filter(|address| match address {
                    SocketAddr::V4(v4) => v4_is_global(v4.ip()) && v4.port() != 0,
                    SocketAddr::V6(_) => false,
                })
                .next()
                .map(|addr| match addr {
                    SocketAddr::V4(v4) => v4,
                    SocketAddr::V6(_) => panic!("Filter did not remove IPv6 addresses"),
                })
                .ok_or(SegmentistError::NoValidAddress)?;
            let uri = url
                .as_str()
                .parse::<Uri>()
                .or_else(|_| Err(SegmentistError::MalformedURL))?;
            Ok(ConnectInfo { uri, address: addr })
        }
        Err(error) => Err(SegmentistError::LibraryError(error)),
    }
}

pub fn drop_root(user: &str) {
    let uid = users::get_user_by_name(user).expect("Failed to find given user");
    let gid = users::get_group_by_name(user).expect("Failed to find group of given user");
    caps::securebits::set_keepcaps(true)
        .expect("Unable to keep required capability on privilege drop");
    // Now drop all privileges (but keep capabilities - will drop them too in a second)
    if unsafe { libc::setresgid(gid.gid(), gid.gid(), gid.gid()) != 0 } {
        panic!("Failed to drop group privileges")
    }
    if unsafe { libc::setresuid(uid.uid(), uid.uid(), uid.uid()) != 0 } {
        panic!("Failed to drop user privileges")
    }
    let kernel_version = get_kernel_version().expect("Failed to determine kernel version!");
    let cap = if kernel_version >= semver::Version::parse(MIN_KERNEL_VERSION_CAP_BPF).unwrap() {
        // Loose all but CAP_BPF, because we loose map access otherwise (requires kernel 5.8+)
        Capability::CAP_BPF
    } else {
        // Loose all but fallback admin privileges
        eprintln!("Warning: Your kernel is too old to support strong privilege drop, retaining CAP_SYS_ADMIN");
        Capability::CAP_SYS_ADMIN
    };

    let mut caps = CapsHashSet::new();
    caps.insert(cap);
    caps::set(None, CapSet::Permitted, &caps)
        .expect(format!("Failed to set caps to {}", cap).as_str());
    // Re-add it to effective set (likely got cleared when dropping root)
    caps::set(None, CapSet::Effective, &caps)
        .expect(format!("Failed to reset effective to cap {}", cap).as_str());
    // One last safety check: We're definitely no longer root?
    no_longer_root();
}

fn no_longer_root() {
    if unsafe { libc::getuid() == 0 } {
        panic!("Still root after dropping privileges")
    }
}

pub fn get_kernel_version() -> Result<Version, SegmentistError> {
    let sysinfo = match uname() {
        Ok(sysinfo) => Ok(sysinfo),
        Err(_) => Err(SegmentistError::Other),
    }?;

    match Version::parse(sysinfo.release().to_str().ok_or(SegmentistError::Other)?) {
        Ok(ver) => Ok(ver),
        Err(err) => Err(SegmentistError::Semver(err)),
    }
}

pub fn load_map_from_pin() -> redbpf::Result<Map> {
    Map::from_pin_file(PIN_OBSERVED_PACKET_SIZE)
}

// Function to determine if IPv4 appears to be globally routable. Helper function because
// is_global() from the stdlib is not stable yet.
pub fn v4_is_global(v4: &Ipv4Addr) -> bool {
    !(v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_multicast()
        || v4.is_broadcast()
        || v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000 == 0b0100_0000) // RFC 6598
        || v4.is_documentation()
        || (v4.octets()[0] == 198 && (v4.octets()[1] & 0xfe) == 18)) // RFC 2544 errata
}

pub fn monitor_connection(monitor_map: &LruHashMap<ConnectionV4, ScanResult>, conn: ConnectionV4) {
    let result = ScanResult::default();
    monitor_map.set(conn, result);
}

pub fn get_monitor_result(
    monitor_map: &LruHashMap<ConnectionV4, ScanResult>,
    conn: ConnectionV4,
) -> Result<ScanResult, Error> {
    monitor_map.get(conn).ok_or(Error::Map)
}

pub fn clear_connection(monitor_map: &LruHashMap<ConnectionV4, ScanResult>, conn: ConnectionV4) {
    monitor_map.delete(conn);
}

use crate::{
    check_url, clear_connection, get_monitor_result, monitor_connection, SegmentistError,
    ADVERTISED_MSS, ADVERTISED_MTU, CONNECT_TIMEOUT,
};
use hyper::{Body, Request, StatusCode};
use nix::sys::time::{TimeVal, TimeValLike};
use probes::packetsize_monitor::{
    ConnectionV4, ScanResult, FLAG_FRAGMENTATION_DETECTED, FLAG_FRAGMENTATION_PROHIBITED,
};
use redbpf::{LruHashMap, Map};
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::str::FromStr;
use tokio::net::TcpSocket;

struct ConnGuard<'a> {
    conn: &'a ConnectionV4,
    map: &'a LruHashMap<'a, ConnectionV4, ScanResult>,
}

impl<'a> Drop for ConnGuard<'a> {
    fn drop(&mut self) {
        clear_connection(self.map, self.conn.clone());
    }
}

pub struct PrintableResult {
    pub warnings: Vec<String>,
    pub notices: Vec<String>,
    pub errors: Vec<String>,
}

pub struct InternalResult {
    addr: SocketAddrV4,
    result: ScanResult,
    response: StatusCode,
}

impl Display for PrintableResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for error in &self.errors {
            writeln!(f, "Error: {}", error)?;
        }
        for warning in &self.warnings {
            writeln!(f, "Warning: {}", warning)?;
        }
        for notice in &self.notices {
            writeln!(f, "{}", notice)?;
        }
        Ok(())
    }
}

impl InternalResult {
    pub fn to_printable(&self) -> PrintableResult {
        let mut warnings: Vec<String> = vec![];
        let mut notices: Vec<String> = vec![];
        let mut errors: Vec<String> = vec![];
        notices.push(format!("Successfully connected to target {}.", self.addr));
        notices.push(format!(
            "Received a {} response from target.",
            self.response
        ));
        if self.result.flags & FLAG_FRAGMENTATION_DETECTED != 0 {
            warnings.push(format!(
                "We received IP-fragmented packets from the target server. \
            While this is not generally an issue, our implementation currently has only limited \
            support for fragmented IP packets. There is a slight chance that the results shown \
            may be inaccurate."
            ));
        }
        if self.result.flags & FLAG_FRAGMENTATION_PROHIBITED != 0 {
            warnings.push(format!(
                "We received IP packets from the target server prohibiting fragmentation. \
            This prevents hops among the transit route from fragmenting packets, if \
            it is required. This message alone is not an error, but may be an issue \
            if packets exceed the Maximum Segment Size or Maximum Transmission Unit of a network."
            ));
        }
        if self.result.max_packet_size == 0 {
            // We got no data???
            errors.push(format!("An internal error occurred: No data received."));
        } else {
            if self.result.max_segment_size <= ADVERTISED_MSS {
                // MSS looks good, check if MTU matches too
                if self.result.max_packet_size <= ADVERTISED_MTU {
                    notices.push(format!("The target server appears to respect the Maximum Segment Size (MSS) advertised by us. \
                We requested a MSS of {} bytes and we received packets not exceeding {} bytes. \
                In addition, the packets send by the target never exceeded our (presumed) MTU of {} bytes. The largest packet in total, \
                including layer 3 headers, was {} bytes.", ADVERTISED_MSS, self.result.max_segment_size, ADVERTISED_MTU, self.result.max_packet_size));
                } else {
                    // MSS good, but MTU exceeded! Large headers?
                    warnings.push(format!("The target server appears to respect the Maximum Segment Size (MSS) advertised by us, \
                    but its IP or TCP headers were larger than expected. We received a maximum MSS of {} bytes (our maximum: {}), but \
                    the total packet size exceeded the maximum of {} bytes. The largest packet in total, including layer 3 headers, \
                    was {} bytes. This may cause connection issues.", self.result.max_segment_size,
                                          ADVERTISED_MSS, ADVERTISED_MTU, self.result.max_packet_size
                    ));
                }
            } else {
                // Nope, MSS disrespected.
                warnings.push(format!("The target server appears to NOT respect the Maximum Segment Size (MSS) advertised by us. \
                We requested a maximum of {} bytes, but received packets up to {} bytes. The total maximum packet size, including layer 3 headers, \
                was {} bytes (larger than {} bytes). This may cause connection issues.", ADVERTISED_MSS,
                                      self.result.max_segment_size, self.result.max_packet_size, ADVERTISED_MTU));
            }
        }
        PrintableResult {
            warnings,
            notices,
            errors,
        }
    }
}

pub async fn connect(url: &str, map: &Map) -> Result<InternalResult, SegmentistError> {
    let url = check_url(url)?;
    let address = url.address;
    let uri = url.uri;
    let map = LruHashMap::<ConnectionV4, ScanResult>::new(&map)?;
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::from_str("10.11.12.13")?, // TODO: Magic
        0,
    )))?;
    nix::sys::socket::setsockopt(
        socket.as_raw_fd(),
        nix::sys::socket::sockopt::ReceiveTimeout,
        &TimeVal::seconds(10), // TODO: Magic
    )
    .or_else(|_| Err(SegmentistError::Other))?;
    let conn = ConnectionV4::new(
        u32::from(address.ip().to_owned()).to_be(),
        address.port().to_be(),
    );
    // Guard will clean up the map on drop
    let conn_guard = ConnGuard {
        conn: &conn,
        map: &map,
    };
    monitor_connection(&map, conn.clone());

    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        socket.connect(SocketAddr::from(address.clone())),
    )
    .await
    .or_else(|_| Err(SegmentistError::ConnectTimeout(address.clone())))??;
    let scheme = uri.scheme().ok_or(SegmentistError::MalformedURL)?;
    let mut request_sender = match scheme.as_str().to_ascii_lowercase().as_str() {
        "http" => {
            let (sender, connection) = hyper::client::conn::handshake(stream).await?;

            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("Error in connection polling routine: {}", e);
                }
            });

            Ok(sender)
        }
        "https" => {
            // If https requested, negotiate TLS
            let connector = tokio_native_tls::TlsConnector::from(
                // Convert from tokio's TLS wrapper for async TCP streams to the native
                // connector, as the wrapper doesn't offer a builder
                tokio_native_tls::native_tls::TlsConnector::builder()
                    // We do not care about certificate errors. We do expect invalid certificates and we are not
                    // going to use the response in any way. We're also going to leave our TLS config
                    // at defaults, to ensure best compatibility.
                    .danger_accept_invalid_certs(true)
                    .build()?,
            );
            let tls = connector
                .connect(uri.host().ok_or(SegmentistError::MalformedURL)?, stream)
                .await?;
            let (sender, connection) = hyper::client::conn::handshake(tls).await?;

            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("Error in connection polling routine: {}", e);
                }
            });

            Ok(sender)
        }
        _ => Err(SegmentistError::MalformedURL),
    }?;

    let request = Request::builder()
        .uri(uri.clone())
        .header("Host", uri.host().unwrap().to_string())
        .header("User-Agent", crate::INFO)
        .method("GET")
        .body(Body::from(""))?;
    let response = request_sender.send_request(request).await?;
    let result = get_monitor_result(&map, conn.clone())?;
    // Explicitly drop here to prevent compiler optimizations from dropping early
    drop(conn_guard);
    Ok(InternalResult {
        addr: address,
        result,
        response: response.status(),
    })
}

/// At least one packet had the More Fragments (MF) bit set
pub const FLAG_FRAGMENTATION_DETECTED: u32 = 1;

/// At least one packet had the Don't Fragment (DF) bit set
pub const FLAG_FRAGMENTATION_PROHIBITED: u32 = 2;

pub const FLAG_STRANGE_OFFSET: u32 = 4;

// This is not an actual 4-tuple one would normally use to identify TCP connections.
// The problem is that we don't really know what *our* dst address/port is, as we're likely
// behind a PAT-NAT. Therefore we just use the src data as connection identifier, which isn't great,
// but for our purposes it shall suffice.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ConnectionV4 {
    pub src_address: u32,
    pub src_port: u16,
    pad: u16, // For padding reasons, so that verifier is happy
}

impl ConnectionV4 {
    pub fn new(src: u32, port: u16) -> Self {
        ConnectionV4 {
            src_address: src,
            src_port: port,
            pad: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub max_packet_size: u32,  // MTU used by peer
    pub max_segment_size: u32, // This is not the MSS, but the actual segment size used by the peer
    pub flags: u32, // u32 gives both headroom for new flags and also ensures alignment for eBPF
    // verifier validation
    pub byte_count: u32, // How many bytes have we seen?
}

impl Default for ScanResult {
    fn default() -> Self {
        ScanResult {
            max_packet_size: 0,
            max_segment_size: 0,
            flags: 0,
            byte_count: 0
        }
    }
}

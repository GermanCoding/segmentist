#![no_std]
#![no_main]

use probes::packetsize_monitor::{
    ConnectionV4, ScanResult, FLAG_FRAGMENTATION_DETECTED, FLAG_FRAGMENTATION_PROHIBITED,
    FLAG_NO_TSOPT, MAX_OPTIONS_SIZE,
};
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

/// This map is populated by userspace to indicate connections it would like to monitor
/// We check for packets matching this map and then insert the maximum observed packet size
/// (plus more useful metadata) received by this peer
#[map]
static mut OBSERVED_PACKET_SIZE: LruHashMap<ConnectionV4, ScanResult> =
    LruHashMap::with_max_entries(10240);

/// Scans the TCP header options, if any, and looks for the timestamp option (TS OPT)
#[inline(always)]
unsafe fn has_tcp_timestamp_option(tcphdr: *const tcphdr, ctx: &XdpContext) -> bool {
    // Offset is in 4-byte words
    let offset_count = (*tcphdr).doff() * 4;
    // TCP header has a minimum of 20 bytes, so anything greater
    // means we have options
    if offset_count > 20 && offset_count <= MAX_OPTIONS_SIZE as u16 {
        let option_bytes = (offset_count - 20) as u8;
        let base_address = (tcphdr as usize + 20) as *const u8;
        let mut offset: u8 = 0;
        let mut length_read = false;
        for _ in 0..(MAX_OPTIONS_SIZE - 20) {
            if offset > option_bytes {
                break;
            }
            let address = base_address as usize + offset as usize;
            if address < ctx.data_start() || address >= ctx.data_end() {
                break;
            }
            let byte = *(address as *const u8);
            offset += 1;

            if !length_read {
                if byte == 0x00 {
                    // End of header
                    break;
                }

                if byte == 0x01 {
                    // NOP, skip
                    continue;
                }

                if byte == 0x08 {
                    // TCP timestamp option
                    return true;
                }

                // Unknown option. Check length on next iteration
                length_read = true;
            } else {
                if length_read {
                    // Skip unknown option determined on previous iteration
                    length_read = false;
                    offset += byte - 1;
                }
            }
        }
    }
    false
}

#[xdp]
unsafe fn packetsize_monitor(ctx: XdpContext) -> XdpResult {
    // bpf_trace_printk(b"packetsize_monitor\0");
    // Performance is key here. This code will run for every single packet on the phys interface,
    // so filter as quickly as possible.
    let iphdr = ctx.ip()?; // RedBPF only supports IPv4 at this time.
    if let Transport::TCP(tcphdr) = ctx.transport()? {
        // Note that these values are in network byte order
        let conn = ConnectionV4::new((*iphdr).saddr, (*tcphdr).source);

        if let Some(scan_result) = OBSERVED_PACKET_SIZE.get_mut(&conn) {
            // Do not count link layer header, but do include the IP header and everything within
            // Note that we can't rely on IP header data, as the packet may be fragmented
            // This is essentially the layer 3 MTU
            let packet_size = ctx.len() - (iphdr as usize - ctx.data_start());
            // Our network interface won't handle packets larger than a few thousand bytes,
            // so cast *should* never be lossy
            scan_result.byte_count += packet_size as u32;
            if packet_size > scan_result.max_packet_size as usize {
                scan_result.max_packet_size = packet_size as u32;
            }
            // The MSS actually only counts the TCP payload (the segment), not TCP + IP header data
            // We still record the packet size (above) to have more data for debugging.
            let segment_size = (ctx.len() - (tcphdr as usize - ctx.data_start()))
                - ((*tcphdr).doff() * 4) as usize;
            if segment_size > scan_result.max_segment_size as usize {
                scan_result.max_segment_size = segment_size as u32;
                if !has_tcp_timestamp_option(tcphdr, &ctx) {
                    // Unusual trivia: No timestamp option, note this
                    scan_result.flags |= FLAG_NO_TSOPT;
                }
            }

            // frag_off stores the entire 16 bit (flags + offset),
            // the upper three bits are flags, we want the MF bit
            let fragmented = (*iphdr).frag_off & 0x2000;
            if fragmented != 0 {
                // Fragmentation *will* cause issues. We can't parse TCP headers on fragments, so
                // we will likely discard packets as unparseable. Fixing this would require us to
                // implement a fragmentation reassembly, which is horrible. If the other side is not
                // completely braindead we will still get good results, as no packet should be larger
                // than this one. Nevertheless, we might want to warn the user about this.
                scan_result.flags |= FLAG_FRAGMENTATION_DETECTED;
            }
            // Don't Fragment bit
            let df = (*iphdr).frag_off & 0x4000;
            if df != 0 {
                scan_result.flags |= FLAG_FRAGMENTATION_PROHIBITED;
            }
        }
    }
    Ok(XdpAction::Pass)
}

#![no_std]
#![no_main]
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

//#[xdp]
pub fn packet_inflator(_ctx: XdpContext) -> XdpResult {
    /*
    let eth = ctx.eth()?;
    let ip = ctx.ip()?;
    let transport = ctx.transport()?;
    if u16::from_be(transport.dest()) == TEST_PORT {
        // Inflate (if necessary) and retransmit the packet

        // Swap ethernet soure and dest
        let original_dest = eth.h_dest;
        eth.h_dest = eth.h_source;
        eth.h_source = original_dest;

        // Modify the IP header
    }
     */
    Ok(XdpAction::Pass)
}

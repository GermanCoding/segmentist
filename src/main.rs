use probes::packetsize_monitor::{ConnectionV4, ScanResult};
use redbpf::load::Loader;
use redbpf::{detach_xdp, if_nametoindex, pin_bpf_obj, unpin_bpf_obj, LruHashMap};
use segmentist::connection::connect;
use segmentist::web::web_main;
use segmentist::{
    drop_root, load_map_from_pin, PIN_OBSERVED_PACKET_SIZE, PIN_XDP_PROGRAM, XDP_PROGRAM_NAME,
};
use std::env;
use std::future::Future;
use std::process::exit;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/packetsize_monitor/packetsize_monitor.elf"
    ))
}

const HELP: &str = "\
Segmentist - Test whether TCP Maximum Segment Size (MSS) is honored
USAGE:
  segmentist TODO
ARGS:
  <TODO> - TODO.
";

const HELP_LOAD: &str = "\
USAGE:
  segmentist load <interface>
";

const HELP_UNLOAD: &str = "\
USAGE:
  segmentist unload <interface>
";

const HELP_TEST: &str = "\
USAGE:
  segmentist test <user> <url>
";

const HELP_WEB: &str = "\
USAGE:
  segmentist web <user> <bind ip> <bind port>
";

fn main() {
    // We want important messages from redBPF (libbpf loader errors, verifier rejections...)
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 1 {
        println!("{HELP}");
        exit(0);
    }

    match args[0].as_str() {
        "load" => {
            if args.len() < 2 {
                println!("{HELP_LOAD}");
                exit(0);
            }
            root_check();
            tokio_run(async move {
                load_xdp(args[1].as_str());
            });
        }
        "unload" => {
            if args.len() < 2 {
                println!("{HELP_UNLOAD}");
                exit(0);
            }
            root_check();
            tokio_run(async move {
                unload_xdp(args[1].as_str()).unwrap();
            });
        }
        "test" => {
            if args.len() < 3 {
                println!("{HELP_TEST}");
                exit(0);
            }
            root_check();
            // We need root to access the map
            let map = load_map_from_pin()
                .expect("Failed to load map from pin. Have you loaded the program?");
            // We no longer need root, drop everything but BPF rights
            drop_root(args[1].as_str());
            tokio_run(async move {
                // Just panic on any error, no reason to handle them gracefully
                println!(
                    "{}",
                    connect(args[2].as_str(), &map)
                        .await
                        .expect("")
                        .to_printable()
                );
            });
        }
        "web" => {
            if args.len() < 3 {
                println!("{HELP_WEB}");
                exit(0);
            }
            root_check();
            // We need root to access the map
            let map = load_map_from_pin()
                .expect("Failed to load map from pin. Have you loaded the program?");
            // We no longer need root, drop everything but BPF rights
            drop_root(args[1].as_str());
            tokio_run(async move {
                web_main(
                    args[2].as_str(),
                    args[3].parse::<u16>().expect("Failed to parse port"),
                    map,
                )
                .await;
            });
        }
        &_ => {
            println!("Unknown command {}", &args[0]);
        }
    };
}

fn tokio_run<F: Future>(future: F) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(future);
}

fn root_check() {
    if unsafe { libc::geteuid() != 0 } {
        eprintln!("Error: Not running as root.");
        exit(0);
    }
}

fn unload_xdp(interface: &str) -> redbpf::Result<()> {
    if let Ok(mut map) = load_map_from_pin() {
        map.unpin().expect("Failed to unpin map");
    }
    let index = if_nametoindex(interface)?;
    unsafe { detach_xdp(index)? };
    unpin_bpf_obj(PIN_XDP_PROGRAM)
}

fn load_xdp(interface: &str) {
    println!("Loading eBPF program");
    let mut loaded = Loader::load(probe_code()).expect("error loading eBPF XDP program");
    let map = loaded
        .map_mut("OBSERVED_PACKET_SIZE")
        .expect("Failed to get map");
    map.pin(PIN_OBSERVED_PACKET_SIZE)
        .expect("Failed to pin map");
    // Test whether the map appears valid for this definition. We want to catch potential problems early.
    let _ = LruHashMap::<ConnectionV4, ScanResult>::new(&map.clone())
        .expect("Cannot parse map as LruHashMap<ConnectionV4, ScanResult>");

    let xdp = loaded
        .xdp_mut(XDP_PROGRAM_NAME)
        .expect("Failed to find XDP program");
    xdp
        // Use XDP_SKB. SKB is the software-emulation mode where XDP does not run in driver context
        // (or on the real network card). Its slower, but also much more reliable and we don't have
        // to deal with hardware-weirdness. It also hopefully prevents drivers from switching to
        // promiscuous mode (we have no use for that, just slows the card down).
        .attach_xdp(interface, redbpf::xdp::Flags::SkbMode)
        .expect("Failed to attach XDP program");
    let program = loaded
        .program(XDP_PROGRAM_NAME)
        .expect("Failed to get raw XDP program");
    pin_bpf_obj(
        program
            .fd()
            .expect("Failed to get file descriptor for XDP program"),
        PIN_XDP_PROGRAM,
    )
    .expect("Failed to pin XDP program");
    // RedBPF automatically detaches the XDP interface once this struct is dropped
    // We don't want that, so we need to ensure that it is never dropped.
    // (This does create a memory leak, but we're going to terminate now anyway)
    Box::leak(Box::new(loaded));
}

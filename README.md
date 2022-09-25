# segmentist

Rust eBPF program to determine whether hosts respect MSS

### Live version

A deployed version of this project is here: https://segmentist.germancoding.com/

### What's MSS?

MSS is the maximum size a data packet can have in a TCP segment. A TCP segment is the payload contained within TCP, i.e.
the packet size without OSI layer 2/3/4 headers. MSS can be advertised by hosts during the TCP handshake and is often
1460 bytes, because the maximum size of an IP data-packet is often 1500 bytes, and the IPv4 and TCP headers are ~40
bytes long, though this can vary depending on options.

### About this tool

This tool (source on GitHub) allows you to test a certain server, identified by an URL, to check whether that host
appears to honor the MSS advertised by a system. To do this, this tool advertises a fake MSS of 1000 bytes, even though
the underlying network is capable of handling larger packets. We analyze raw network packets to check their sizes and
then infer whether a host appears to honor the 1000 byte limit. 1000 bytes is much lower than what a usual network can
handle, but it's also not unreasonably small.

### Building

Building this program requires:

- Linux x86-64 or aarch64
- Rust (v1.59 at this time, v1.6+ unsupported)
- RedBPF (https://github.com/foniod/redbpf)
    - In particular, you must install a recent version of cargo-bpf
- A recent Linux kernel version. eBPF is a relatively recent, fast moving
  technology within the Linux kernel. Many features are only available on
  recent (5.8+) kernels. I do not test on anything older than 5.10. You may be
  able to get this running on older kernels (technically 4.14+ should work), but I can't promise anything.
- Linux kernel with BTF support is highly recommended. Some BTF-enabled distribution
  versions: https://github.com/aquasecurity/tracee/discussions/713

#### Build instructions

At this time, RedBPF is not updated to support LLVM v14, but Rust 1.60+ uses LLVM v14.
Thus, make sure you install Rust 1.59.
If using rustup (https://rustup.rs):

```curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh```

Select "Customize installation".
Leave default host triple, but choose "1.59" when asked for "default toolchain". The other options are your preference,
but the defaults are easiest. Follow the on-screen instructions. You now have Rust!
Check that your Rust setup works and version is correct:

```rustc --version```

Should print: ```rustc 1.59.0 (9d1b2106e 2022-02-23)```

Now, let's install cargo-bpf (a module of RedBPF). This requires LLVM v13 suites.
See the README of RedBPF (https://github.com/foniod/redbpf) for details on various distros. We're assuming Ubuntu 20.04
here, but generally any recent Debian/Ubuntu should work.

This installs LLVM from the official upstream LLVM project (seems to work best) as well as some dependencies:

```
sudo su # Elevate to root
apt-get update \
&& apt-get -y install \
wget \
build-essential \
software-properties-common \
lsb-release \
libelf-dev \
linux-headers-generic \
pkg-config \
&& wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 13 && rm -f ./llvm.sh
exit # Drop root
```

Install cargo-bpf. We install from git instead of from crates.io (default), because the crates.io version is slightly
too old.

```cargo install cargo-bpf --git https://github.com/foniod/redbpf.git```

We now have all dependencies. Let's build our project:

```./build.sh```

This may take a while on first run, because cargo downloads and compiles many dependencies. It should complete without
errors. You now have the project build!

Binaries and other build artifacts can be found in ./target/

### Running the program

You can run segmentist's Rust component via

```sudo ./target/release/segmentist --help```

Note that currently all segmentist actions require root permissions.
This is due to eBPF restrictions: We need a number of capabilities,
which is easier to obtain by being root. We also need access to the debugfs,
which is (by default) only accessible for root.

Commands that do not require root for all actions will first perform
setup as root and then immediately drop their root privileges for security.

If you want to test MSS, you need an interface with a faked (clamped) MSS.
There is a script in this repository, ```./IPTABLES_CMDS.sh``` that
sets up an interface with clamped MSS. This interface is expected by
the Rust component.

Note that ```segmentist load/unload``` expects the real, physical, interface,
not the interface with faked MSS. This fake interface is only used to make
outbound connections with clamped MSS.

### Using the web component

The web directory hosts the website that can be used as an example frontend for this tool and is also what is running on
my hosted version of this tool.

Too bootstrap this, you need to fetch a few dependencies, which can be done automatically using the
```WEB_DEPENDENCY_DOWNLOAD.sh``` script (requires a POSIX-compatible shell and wget).

The web component sends HTTP(S) requests to ```backend/scanurl```, while
the Rust component reacts to requests for ```http://<bind-ip>:<bind-port>/scanurl```.

It is suggested to setup a reverse proxy that forwards the ```backend/scanurl``` HTTPS requests
to the Rust component (which only supports HTTP).

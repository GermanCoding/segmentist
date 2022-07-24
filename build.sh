#!/bin/bash
cd probes
cargo bpf build --target-dir=../target
cd ..
cargo build --release

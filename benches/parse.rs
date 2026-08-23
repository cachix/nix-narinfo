use std::hint::black_box;
use std::time::Instant;

use nix_derivation::StoreDir;
use nix_narinfo::NarInfo;

const FULL: &[u8] = include_bytes!("../tests/fixtures/nix-2.34-default-md.narinfo");
const MINIMAL: &[u8] = b"StorePath: /nix/store/00000000000000000000000000000000-example\n\
URL: nar/example.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 1\n";

fn measure<T>(name: &str, iterations: usize, mut operation: impl FnMut() -> T) {
    let started = Instant::now();
    for _ in 0..iterations {
        black_box(operation());
    }
    let elapsed = started.elapsed();
    println!(
        "{name:24} {iterations:>8} iterations in {elapsed:>10.3?} ({:>10.0}/s)",
        iterations as f64 / elapsed.as_secs_f64(),
    );
}

fn main() {
    let store_dir = StoreDir::default();
    let full = NarInfo::parse_in(&store_dir, FULL).unwrap();
    let parse_iterations = if cfg!(debug_assertions) {
        1_000
    } else {
        250_000
    };
    let operation_iterations = if cfg!(debug_assertions) {
        1_000
    } else {
        500_000
    };

    println!(
        "nix-narinfo microbenchmarks (minimal={} B, full={} B)",
        MINIMAL.len(),
        FULL.len()
    );
    measure("parse minimal", parse_iterations, || {
        NarInfo::parse_in(&store_dir, black_box(MINIMAL)).unwrap()
    });
    measure("parse full", parse_iterations, || {
        NarInfo::parse_in(&store_dir, black_box(FULL)).unwrap()
    });
    measure("canonical write", parse_iterations, || {
        full.to_canonical_bytes()
    });
    measure("parse + write", parse_iterations, || {
        NarInfo::parse_in(&store_dir, black_box(FULL))
            .unwrap()
            .to_canonical_bytes()
    });
    measure("fingerprint", operation_iterations, || {
        full.fingerprint(&store_dir)
    });
    measure("content-address check", operation_iterations, || {
        full.is_content_addressed(&store_dir)
    });
}

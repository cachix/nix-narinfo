#![no_main]

use libfuzzer_sys::fuzz_target;
use nix_derivation::StoreDir;
use nix_narinfo::NarInfo;

fuzz_target!(|data: &[u8]| {
    let _ = NarInfo::parse_in(&StoreDir::default(), data);
});

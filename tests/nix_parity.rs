//! Optional differential checks against `.narinfo` files emitted by Nix.
//!
//! Set `NIX_NARINFO_PARITY_DIR` to a `file://` binary-cache directory and run
//! this test normally. It skips cleanly when no external corpus is configured.

use std::path::Path;

use nix_derivation::StoreDir;
use nix_narinfo::NarInfo;

#[test]
fn configured_nix_cache_is_canonical_and_round_trippable() {
    let Ok(directory) = std::env::var("NIX_NARINFO_PARITY_DIR") else {
        eprintln!("skipping: NIX_NARINFO_PARITY_DIR is not set");
        return;
    };
    let mut checked = 0;
    for entry in std::fs::read_dir(Path::new(&directory)).expect("read configured Nix cache") {
        let path = entry.expect("read cache entry").path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("narinfo") {
            continue;
        }
        let bytes = std::fs::read(&path).expect("read narinfo fixture");
        let info = NarInfo::parse_in(&StoreDir::default(), &bytes)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert_eq!(
            info.to_canonical_bytes(),
            bytes,
            "{} differs from canonical writer",
            path.display()
        );
        assert_eq!(
            NarInfo::parse_in(&StoreDir::default(), &info.to_canonical_bytes()).unwrap(),
            info,
            "{} does not round trip",
            path.display()
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "configured directory contained no .narinfo files"
    );
}

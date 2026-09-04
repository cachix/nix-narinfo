use std::collections::BTreeSet;

use ed25519_dalek::{Signer as _, SigningKey};
use nix_derivation::{DrvOutput, StorePath};
use nix_narinfo::{
    realisation_cache_path, NixSignature, Realisation, RealisationParseError, SignatureError,
    TrustedPublicKey, UnkeyedRealisation, MAX_REALISATION_SIZE,
};

const DRV: &str = "00000000000000000000000000000000-producer.drv";
const OUT: &str = "11111111111111111111111111111111-produced";

fn path(basename: &str) -> StorePath {
    StorePath::from_basename(basename.as_bytes()).unwrap()
}

fn id() -> DrvOutput {
    DrvOutput::new(path(DRV), "out")
}

#[test]
fn realisation_cache_paths_follow_nix_layout() {
    assert_eq!(
        realisation_cache_path(&id()),
        format!("build-trace-v2/{DRV}/out.doi")
    );
}

#[test]
fn doi_parsing_and_writing_match_nix_json() {
    let input = format!(
        r#"{{"outPath":"{OUT}","signatures":["alpha:/w==",{{"keyName":"alpha","sig":"AA=="}},"alpha:AA=="],"dependentRealisations":{{"old":"field"}}}}"#
    );
    let value = UnkeyedRealisation::parse(input.as_bytes()).unwrap();

    assert_eq!(value.out_path(), &path(OUT));
    assert_eq!(value.signatures().len(), 2);
    assert_eq!(
        String::from_utf8(value.to_canonical_bytes()).unwrap(),
        format!(
            r#"{{"outPath":"{OUT}","signatures":[{{"keyName":"alpha","sig":"AA=="}},{{"keyName":"alpha","sig":"/w=="}}]}}"#
        )
    );

    let without_signatures =
        UnkeyedRealisation::parse(format!(r#"{{"outPath":"{OUT}"}}"#).as_bytes()).unwrap();
    assert!(without_signatures.signatures().is_empty());
    assert_eq!(
        String::from_utf8(without_signatures.to_canonical_bytes()).unwrap(),
        format!(r#"{{"outPath":"{OUT}","signatures":[]}}"#)
    );
}

#[test]
fn fingerprint_and_keyed_representation_have_nix_field_order() {
    let realisation = Realisation::new(id(), UnkeyedRealisation::new(path(OUT)));
    let expected_fingerprint = format!(
        r#"{{"key":{{"drvPath":"{DRV}","outputName":"out"}},"value":{{"outPath":"{OUT}"}}}}"#
    );
    let expected_json = format!(
        r#"{{"key":{{"drvPath":"{DRV}","outputName":"out"}},"value":{{"outPath":"{OUT}","signatures":[]}}}}"#
    );

    assert_eq!(realisation.fingerprint(), expected_fingerprint);
    assert_eq!(realisation.to_canonical_bytes(), expected_json.as_bytes());
    assert_eq!(
        Realisation::parse(expected_json.as_bytes()).unwrap(),
        realisation
    );
}

#[test]
fn realisation_signatures_verify_over_the_fingerprint() {
    let id = id();
    let mut value = UnkeyedRealisation::new(path(OUT));
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let signature = signing_key.sign(value.fingerprint(&id).as_bytes());
    value
        .insert_signature(NixSignature::from_bytes("cache.example", &signature.to_bytes()).unwrap())
        .unwrap();
    let trusted = TrustedPublicKey {
        name: "cache.example".to_owned(),
        key: signing_key.verifying_key(),
    };

    assert!(value.has_valid_signature(&id, std::slice::from_ref(&trusted)));
    assert_eq!(
        value.count_valid_signatures(&id, std::slice::from_ref(&trusted)),
        1
    );
    assert!(!value.has_valid_signature(&DrvOutput::new(path(DRV), "dev"), &[trusted]));
}

#[test]
fn signature_strings_use_the_shared_nix_type() {
    let parsed: NixSignature = "cache.example:AQID".parse().unwrap();
    assert_eq!(parsed.key_name, "cache.example");
    assert_eq!(parsed.encoded, "AQID");
    assert_eq!(parsed.to_string(), "cache.example:AQID");
    assert_eq!(
        NixSignature::parse("missing-separator").unwrap_err(),
        SignatureError::MissingSeparator
    );
    assert_eq!(
        NixSignature::parse(":AQID").unwrap_err(),
        SignatureError::EmptyKeyName
    );
    assert_eq!(
        NixSignature::parse("cache:").unwrap_err(),
        SignatureError::EmptySignature
    );

    let signatures = BTreeSet::from([
        NixSignature::parse("cache:/w==").unwrap(),
        NixSignature::parse("cache:AA==").unwrap(),
    ]);
    assert_eq!(
        signatures
            .iter()
            .map(NixSignature::to_nix_string)
            .collect::<Vec<_>>(),
        ["cache:AA==", "cache:/w=="]
    );
}

#[test]
fn malformed_and_oversized_realisations_are_rejected() {
    assert!(matches!(
        UnkeyedRealisation::parse(br#"{"outPath":"not-a-store-path"}"#),
        Err(RealisationParseError::InvalidStorePath {
            field: "outPath",
            ..
        })
    ));
    assert!(matches!(
        UnkeyedRealisation::parse(
            format!(r#"{{"outPath":"{OUT}","signatures":["broken"]}}"#).as_bytes()
        ),
        Err(RealisationParseError::InvalidSignature {
            index: 0,
            source: SignatureError::MissingSeparator
        })
    ));

    let oversized = vec![b' '; MAX_REALISATION_SIZE + 1];
    assert_eq!(
        UnkeyedRealisation::parse(&oversized).unwrap_err(),
        RealisationParseError::TooLarge {
            size: MAX_REALISATION_SIZE + 1,
            limit: MAX_REALISATION_SIZE,
        }
    );
}

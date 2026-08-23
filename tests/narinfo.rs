use std::collections::BTreeSet;

use ed25519_dalek::{Signer as _, SigningKey};
use nix_derivation::{CAHash, NixHash, StoreDir, StorePath};
use nix_narinfo::{
    BuildError, Compression, Field, KeyError, NarInfo, NarInfoSignature, ParseError,
    SignatureError, TrustedPublicKey, MAX_NARINFO_SIZE,
};

const PATH: &str = "/nix/store/00000000000000000000000000000000-fixture";
const REF_A: &str = "00000000000000000000000000000000-alpha";
const REF_B: &str = "00000000000000000000000000000001-beta";

fn hash(byte: u8) -> String {
    NixHash::Sha256([byte; 32]).to_nix_nixbase32_string()
}

fn minimal() -> String {
    format!(
        "StorePath: {PATH}\nURL: nar/fixture.nar\nNarHash: {}\nNarSize: 1\n",
        hash(1)
    )
}

fn parse(record: &str) -> NarInfo {
    NarInfo::parse_in(&StoreDir::default(), record.as_bytes()).unwrap()
}

#[test]
fn minimal_valid_narinfo_and_default_bzip2() {
    let info = parse(&minimal());
    assert_eq!(info.store_path().to_string(), PATH);
    assert_eq!(info.url(), "nar/fixture.nar");
    assert_eq!(info.compression(), &Compression::Bzip2);
    assert_eq!(info.nar_size(), 1);
    assert!(info.references().is_empty());
    assert_eq!(info.deriver(), None);
    assert!(info.signatures().is_empty());
    assert_eq!(info.content_address(), None);
    assert_eq!(info.file_hash(), None);
    assert_eq!(info.file_size(), None);
    assert!(info.extensions().is_empty());
}

#[test]
fn parses_every_compression_form() {
    let cases = [
        ("", Compression::None),
        ("none", Compression::None),
        ("bzip2", Compression::Bzip2),
        ("gzip", Compression::Gzip),
        ("xz", Compression::Xz),
        ("zstd", Compression::Zstd),
        ("brotli", Compression::Other("brotli".to_owned())),
    ];
    for (encoded, expected) in cases {
        let record = format!("{}Compression: {encoded}\n", minimal());
        assert_eq!(parse(&record).compression(), &expected, "{encoded:?}");
    }
}

#[test]
fn non_default_store_dir_controls_absolute_path_identity() {
    let store_dir = StoreDir::new("/gnu/store").unwrap();
    let record = minimal().replace("/nix/store", "/gnu/store");
    let info = NarInfo::parse_in(&store_dir, record.as_bytes()).unwrap();
    assert_eq!(
        store_dir.render_path(info.store_path()),
        record.lines().next().unwrap()[11..]
    );
    assert_eq!(info.store_dir(), &store_dir);
    let canonical = record.replace("NarHash:", "Compression: bzip2\nNarHash:") + "References: \n";
    assert_eq!(info.to_canonical_bytes(), canonical.as_bytes());
    assert_eq!(
        NarInfo::parse_in(&store_dir, &info.to_canonical_bytes()).unwrap(),
        info
    );
    assert!(info
        .fingerprint(&store_dir)
        .starts_with("1;/gnu/store/00000000000000000000000000000000-fixture;"));

    let error = NarInfo::parse_in(&store_dir, minimal().as_bytes()).unwrap_err();
    assert!(matches!(
        error,
        ParseError::InvalidField {
            field: "StorePath",
            ..
        }
    ));
}

#[test]
fn relative_and_absolute_references_are_sorted_and_deduplicated() {
    let record = format!(
        "{}References: {REF_B} /nix/store/{REF_A} {REF_B}\n",
        minimal()
    );
    let info = parse(&record);
    let basenames = info
        .references()
        .iter()
        .map(StorePath::to_basename)
        .collect::<Vec<_>>();
    assert_eq!(basenames, vec![REF_A, REF_B]);
    assert_eq!(info.references().len(), 2);
    assert!(info
        .fingerprint(&StoreDir::default())
        .ends_with(&format!("/nix/store/{REF_A},/nix/store/{REF_B}")));
}

#[test]
fn unknown_deriver_means_absent_and_paths_allow_basenames() {
    let unknown = parse(&format!("{}Deriver: unknown-deriver\n", minimal()));
    assert_eq!(unknown.deriver(), None);

    let known = parse(&format!("{}Deriver: {REF_A}\n", minimal()));
    assert_eq!(known.deriver().unwrap().to_basename(), REF_A);
}

#[test]
fn repeated_signatures_preserve_order_and_malformed_encoding_is_deferred() {
    let info = parse(&format!(
        "{}Sig: no-separator\nSig: first:not-base64\nSig: second:AAAA\n",
        minimal()
    ));
    assert_eq!(info.signatures().len(), 3);
    assert_eq!(info.signatures()[0].key_name, "no-separator");
    assert_eq!(info.signatures()[0].encoded, "");
    assert_eq!(info.signatures()[1].key_name, "first");
    assert_eq!(info.signatures()[2].encoded, "AAAA");
    assert_eq!(
        info.signatures()[1].verify(b"fingerprint", &[]),
        Err(SignatureError::InvalidBase64)
    );
}

#[test]
fn rejects_missing_and_duplicate_singletons() {
    for field in ["StorePath", "URL", "NarHash", "NarSize"] {
        let record = minimal()
            .lines()
            .filter(|line| !line.starts_with(&format!("{field}:")))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            NarInfo::parse_in(&StoreDir::default(), record.as_bytes()).unwrap_err(),
            ParseError::MissingField { field }
        );
    }

    for field in [
        "StorePath",
        "URL",
        "NarHash",
        "NarSize",
        "Compression",
        "References",
        "Deriver",
        "CA",
        "FileHash",
        "FileSize",
    ] {
        let value = match field {
            "StorePath" => PATH,
            "URL" => "other.nar",
            "NarHash" | "FileHash" => &hash(2),
            "NarSize" | "FileSize" => "2",
            "Compression" => "gzip",
            "References" => "",
            "Deriver" => "unknown-deriver",
            "CA" => "fixed:r:sha256:0000000000000000000000000000000000000000000000000000",
            _ => unreachable!(),
        };
        let once = if matches!(field, "StorePath" | "URL" | "NarHash" | "NarSize") {
            minimal()
        } else {
            format!("{}{field}: {value}\n", minimal())
        };
        let record = format!("{once}{field}: {value}\n");
        assert_eq!(
            NarInfo::parse_in(&StoreDir::default(), record.as_bytes()).unwrap_err(),
            ParseError::DuplicateField {
                field: field.to_owned()
            },
            "{field}"
        );
    }

    let invalid_hash_and_duplicate_compression =
        minimal().replace(&hash(1), "invalid") + "Compression: xz\nCompression: gzip\n";
    assert_eq!(
        NarInfo::parse_in(
            &StoreDir::default(),
            invalid_hash_and_duplicate_compression.as_bytes()
        )
        .unwrap_err(),
        ParseError::DuplicateField {
            field: "Compression".to_owned()
        }
    );
}

#[test]
fn rejects_invalid_utf8_malformed_lines_hashes_and_paths() {
    assert_eq!(
        NarInfo::parse_in(&StoreDir::default(), b"\xff").unwrap_err(),
        ParseError::InvalidUtf8
    );
    let malformed = format!("{}not a field\n", minimal());
    assert_eq!(
        NarInfo::parse_in(&StoreDir::default(), malformed.as_bytes()).unwrap_err(),
        ParseError::MalformedLine { line: 5 }
    );

    for (from, field) in [(PATH, "StorePath"), (&hash(1), "NarHash")] {
        let record = minimal().replace(from, "invalid");
        assert!(matches!(
            NarInfo::parse_in(&StoreDir::default(), record.as_bytes()),
            Err(ParseError::InvalidField { field: got, .. }) if got == field
        ));
    }

    let bad_reference = format!("{}References: /gnu/store/{REF_A}\n", minimal());
    assert!(matches!(
        NarInfo::parse_in(&StoreDir::default(), bad_reference.as_bytes()),
        Err(ParseError::InvalidField {
            field: "References",
            ..
        })
    ));

    for (field, value) in [("FileHash", "invalid"), ("CA", "invalid")] {
        let record = format!("{}{field}: {value}\n", minimal());
        assert!(matches!(
            NarInfo::parse_in(&StoreDir::default(), record.as_bytes()),
            Err(ParseError::InvalidField { field: got, .. }) if got == field
        ));
    }
}

#[test]
fn rejects_zero_and_overflowing_sizes() {
    for encoded in ["0", "18446744073709551616"] {
        let record = minimal().replace("NarSize: 1", &format!("NarSize: {encoded}"));
        assert!(matches!(
            NarInfo::parse_in(&StoreDir::default(), record.as_bytes()),
            Err(ParseError::InvalidField {
                field: "NarSize",
                ..
            })
        ));
    }
    let record = format!("{}FileSize: 18446744073709551616\n", minimal());
    assert!(matches!(
        NarInfo::parse_in(&StoreDir::default(), record.as_bytes()),
        Err(ParseError::InvalidField {
            field: "FileSize",
            ..
        })
    ));
}

#[test]
fn preserves_unknown_extensions_and_compression() {
    let record = format!(
        "{}X-Custom: first:value\nCompression: future-codec\nX-Custom: second\n",
        minimal()
    );
    let info = parse(&record);
    assert_eq!(
        info.compression(),
        &Compression::Other("future-codec".to_owned())
    );
    assert_eq!(
        info.extensions(),
        &[
            Field {
                name: "X-Custom".to_owned(),
                value: "first:value".to_owned()
            },
            Field {
                name: "X-Custom".to_owned(),
                value: "second".to_owned()
            }
        ]
    );
}

#[test]
fn verifies_known_nix_ed25519_signature_vector() {
    const PUBLIC_KEY: &str = "nix-narinfo-test-1:LdMfmDHlTSzpZMJIn8gLY2K2K2nk8h0IJAckIUKV66U=";
    const SIGNATURE: &str =
        "bMRDL2fSeGGLxKuaqquSYOcXo9xXagojZmbolAYvvv/+afPXI4QMypxNMzspnGN7P90ErTMqyhNbE2VOwZ6XDw==";
    let record = format!(
        "StorePath: /nix/store/ff43q3pvpl1sdyxj88dy8a0wzg47bih2-substituted-from-cache\n\
         URL: nar/example.nar\n\
         Compression: none\n\
         NarHash: sha256:1fm3wgw7wsx66fhyzi90l1avyn89qpa4fkz7064sb61j5xy8kx65\n\
         NarSize: 144\n\
         References: \n\
         Sig: malformed\n\
         Sig: broken:not-base64\n\
         Sig: nix-narinfo-test-1:{SIGNATURE}\n"
    );
    let info = parse(&record);
    let key = TrustedPublicKey::parse(PUBLIC_KEY).unwrap();
    assert_eq!(
        info.fingerprint(&StoreDir::default()),
        "1;/nix/store/ff43q3pvpl1sdyxj88dy8a0wzg47bih2-substituted-from-cache;sha256:1fm3wgw7wsx66fhyzi90l1avyn89qpa4fkz7064sb61j5xy8kx65;144;"
    );
    assert!(info.has_valid_signature(&StoreDir::default(), std::slice::from_ref(&key)));
    assert!(!info.has_valid_signature(&StoreDir::default(), &[]));

    let mut invalid = SIGNATURE.to_owned();
    invalid.replace_range(..1, "c");
    let invalid_record = record.replace(SIGNATURE, &invalid);
    assert!(!parse(&invalid_record).has_valid_signature(&StoreDir::default(), &[key]));
}

#[test]
fn tries_every_matching_key_name_and_accepts_a_later_valid_key() {
    let good_signing = SigningKey::from_bytes(&[7; 32]);
    let wrong_signing = SigningKey::from_bytes(&[8; 32]);
    let unsigned = parse(&minimal());
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        good_signing
            .sign(unsigned.fingerprint(unsigned.store_dir()).as_bytes())
            .to_bytes(),
    );
    let signed = parse(&format!("{}Sig: cache:{encoded}\n", minimal()));
    let keys = [
        TrustedPublicKey {
            name: "cache".to_owned(),
            key: wrong_signing.verifying_key(),
        },
        TrustedPublicKey {
            name: "cache".to_owned(),
            key: good_signing.verifying_key(),
        },
    ];
    assert!(signed.has_valid_signature(signed.store_dir(), &keys));
}

#[test]
fn public_key_parser_reports_structure_encoding_and_length_errors() {
    assert_eq!(
        TrustedPublicKey::parse("no-separator").unwrap_err(),
        KeyError::MissingName
    );
    assert_eq!(
        TrustedPublicKey::parse(":AAAA").unwrap_err(),
        KeyError::EmptyName
    );
    assert_eq!(
        TrustedPublicKey::parse("cache:not-base64").unwrap_err(),
        KeyError::InvalidBase64
    );
    assert_eq!(
        TrustedPublicKey::parse("cache:AAAA").unwrap_err(),
        KeyError::InvalidLength { got: 3 }
    );
}

#[test]
fn verifies_valid_and_invalid_content_addressed_paths() {
    let store_dir = StoreDir::default();
    let ca = CAHash::Nar(NixHash::Sha256([2; 32]));
    let expected = store_dir
        .build_ca_path("source", &ca, std::iter::empty(), false)
        .unwrap();
    let valid_record = format!(
        "StorePath: {}\nURL: nar/source.nar\nNarHash: {}\nNarSize: 1\nCA: {}\n",
        store_dir.render_path(&expected),
        hash(1),
        ca.to_nix_string()
    );
    assert!(parse(&valid_record).is_content_addressed(&store_dir));

    let invalid = valid_record.replace(
        &expected.to_basename(),
        &format!("{}-source", "0".repeat(32)),
    );
    assert!(!parse(&invalid).is_content_addressed(&store_dir));
    assert!(!parse(&minimal()).is_content_addressed(&store_dir));
}

#[test]
fn verifies_every_content_address_method_and_reference_shape() {
    let stores = [StoreDir::default(), StoreDir::new("/gnu/store").unwrap()];
    for store_dir in stores {
        let reference = store_dir
            .build_text_path("reference", b"reference", std::iter::empty())
            .unwrap();
        let cases = [
            (CAHash::Flat(NixHash::Sha256([1; 32])), false, false),
            (CAHash::Nar(NixHash::Sha256([2; 32])), true, true),
            (CAHash::Text([3; 32]), true, false),
            (CAHash::Git(NixHash::Sha1([4; 20])), false, false),
        ];
        for (ca, with_reference, self_reference) in cases {
            let other_references = with_reference.then_some(&reference).into_iter();
            let path = store_dir
                .build_ca_path("source", &ca, other_references, self_reference)
                .unwrap();
            let mut references = Vec::new();
            if with_reference {
                references.push(reference.to_basename());
            }
            if self_reference {
                references.push(path.to_basename());
            }
            references.sort();
            let record = format!(
                "StorePath: {}\nURL: nar/source.nar\nCompression: bzip2\nNarHash: {}\nNarSize: 1\nReferences: {}\nCA: {}\n",
                store_dir.render_path(&path),
                hash(9),
                references.join(" "),
                ca.to_nix_string(),
            );
            let info = NarInfo::parse_in(&store_dir, record.as_bytes()).unwrap();
            assert!(info.is_content_addressed(&store_dir), "{ca}");
            assert_eq!(info.to_canonical_bytes(), record.as_bytes(), "{ca}");
        }

        let ca = CAHash::Flat(NixHash::Sha256([5; 32]));
        let path = store_dir
            .build_ca_path("source", &ca, std::iter::empty(), false)
            .unwrap();
        let record = format!(
            "StorePath: {}\nURL: nar/source.nar\nNarHash: {}\nNarSize: 1\nReferences: {}\nCA: {}\n",
            store_dir.render_path(&path),
            hash(9),
            reference.to_basename(),
            ca.to_nix_string(),
        );
        let info = NarInfo::parse_in(&store_dir, record.as_bytes()).unwrap();
        assert!(!info.is_content_addressed(&store_dir));
    }
}

#[test]
fn builder_constructs_valid_round_trippable_records() {
    let store_dir = StoreDir::new("/gnu/store").unwrap();
    let store_path =
        StorePath::from_basename(b"00000000000000000000000000000000-constructed").unwrap();
    let reference = StorePath::from_basename(REF_A.as_bytes()).unwrap();
    let info = NarInfo::builder_in(
        store_dir.clone(),
        store_path,
        "nar/constructed.nar",
        NixHash::Sha256([6; 32]),
        42,
    )
    .compression(Compression::Other("future".to_owned()))
    .references([reference.clone(), reference])
    .deriver(Some(StorePath::from_basename(REF_B.as_bytes()).unwrap()))
    .signature(NarInfoSignature {
        key_name: "cache".to_owned(),
        encoded: "AAAA".to_owned(),
    })
    .file_hash(Some(NixHash::Sha256([7; 32])))
    .file_size(Some(21))
    .extension(Field {
        name: "X-Test".to_owned(),
        value: "yes".to_owned(),
    })
    .build()
    .unwrap();
    assert_eq!(info.store_dir(), &store_dir);
    assert_eq!(info.references().len(), 1);
    let reparsed = NarInfo::parse_in(&store_dir, &info.to_canonical_bytes()).unwrap();
    assert_eq!(reparsed, info);
}

#[test]
fn builder_rejects_noncanonical_values() {
    let path = StorePath::from_basename(b"00000000000000000000000000000000-built").unwrap();
    let base = || NarInfo::builder(path.clone(), "nar/file", NixHash::Sha256([1; 32]), 1);
    assert_eq!(
        NarInfo::builder(path.clone(), "nar/file", NixHash::Sha256([1; 32]), 0)
            .build()
            .unwrap_err(),
        BuildError::ZeroNarSize
    );
    assert!(matches!(
        base()
            .extension(Field {
                name: "NarSize".to_owned(),
                value: "2".to_owned(),
            })
            .build(),
        Err(BuildError::InvalidField { .. })
    ));
    assert!(matches!(
        base()
            .signature(NarInfoSignature {
                key_name: "bad:name".to_owned(),
                encoded: "AAAA".to_owned(),
            })
            .build(),
        Err(BuildError::InvalidField { .. })
    ));
    assert!(matches!(
        base()
            .compression(Compression::Other("gzip".to_owned()))
            .build(),
        Err(BuildError::InvalidField { .. })
    ));
    assert!(matches!(
        base()
            .extension(Field {
                name: "X-Test".to_owned(),
                value: "first\nsecond".to_owned(),
            })
            .build(),
        Err(BuildError::InvalidField { .. })
    ));
}

#[test]
fn nix_generated_narinfo_is_an_exact_offline_golden() {
    let input = include_bytes!("fixtures/nix-2.34-default-md.narinfo");
    let info = NarInfo::parse_in(&StoreDir::default(), input).unwrap();
    assert_eq!(info.to_canonical_bytes(), input);
    assert!(info.is_content_addressed(&StoreDir::default()));
    assert_eq!(info.nar_size(), 3096);
    assert_eq!(info.file_size(), Some(1384));
}

#[test]
fn canonical_write_is_golden_and_round_trips() {
    let record = format!(
        "X-One: yes\nReferences: {REF_B} {REF_A} {REF_A}\n\
         NarSize: 9\nURL: nar/example\nStorePath: {PATH}\n\
         FileSize: 7\nCompression: \nNarHash: {}\n\
         FileHash: {}\nDeriver: {REF_B}\n\
         Sig: cache:AAAA\nCA: fixed:r:{}\nX-Two: no\n",
        hash(3),
        hash(4),
        hash(5),
    );
    let info = parse(&record);
    let expected = format!(
        "StorePath: {PATH}\n\
         URL: nar/example\n\
         Compression: none\n\
         FileHash: {}\n\
         FileSize: 7\n\
         NarHash: {}\n\
         NarSize: 9\n\
         References: {REF_A} {REF_B}\n\
         Deriver: {REF_B}\n\
         Sig: cache:AAAA\n\
         CA: fixed:r:{}\n\
         X-One: yes\n\
         X-Two: no\n",
        hash(4),
        hash(3),
        hash(5),
    );
    assert_eq!(info.to_canonical_bytes(), expected.as_bytes());
    let reparsed = NarInfo::parse_in(&StoreDir::default(), &info.to_canonical_bytes()).unwrap();
    assert_eq!(reparsed, info);
}

#[test]
fn enforces_size_limit_before_other_validation() {
    let base = minimal();
    let overhead = "X: \n".len();
    let padding = "a".repeat(MAX_NARINFO_SIZE - base.len() - overhead);
    let at_limit = format!("{base}X: {padding}\n");
    assert_eq!(at_limit.len(), MAX_NARINFO_SIZE);
    assert!(NarInfo::parse_in(&StoreDir::default(), at_limit.as_bytes()).is_ok());

    let above = format!("{at_limit}x");
    assert_eq!(
        NarInfo::parse_in(&StoreDir::default(), above.as_bytes()).unwrap_err(),
        ParseError::TooLarge {
            size: MAX_NARINFO_SIZE + 1,
            limit: MAX_NARINFO_SIZE,
        }
    );
}

#[test]
fn reference_type_is_a_btree_set() {
    fn assert_type(_: &BTreeSet<StorePath>) {}
    assert_type(parse(&minimal()).references());
}

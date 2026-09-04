//! Nix derivation-output realisation (`.doi`) metadata.

use std::collections::BTreeSet;
use std::io;

use nix_derivation::{DrvOutput, StorePath};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{NixSignature, SignatureError, TrustedPublicKey};

/// Maximum accepted realisation JSON size: one mebibyte.
pub const MAX_REALISATION_SIZE: usize = 1024 * 1024;

/// Binary-cache directory containing derivation-output realisations.
pub const REALISATIONS_PREFIX: &str = "build-trace-v2";

/// Return the relative binary-cache key for a derivation output's `.doi` file.
#[must_use]
pub fn realisation_cache_path(id: &DrvOutput) -> String {
    format!(
        "{REALISATIONS_PREFIX}/{}/{}.doi",
        id.drv_path().to_basename(),
        id.output_name()
    )
}

/// The unkeyed value stored in a binary cache's `.doi` file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnkeyedRealisation {
    out_path: StorePath,
    signatures: BTreeSet<NixSignature>,
}

impl UnkeyedRealisation {
    /// Construct an unsigned realisation for an output store path.
    #[must_use]
    pub fn new(out_path: StorePath) -> Self {
        Self {
            out_path,
            signatures: BTreeSet::new(),
        }
    }

    /// Parse and validate an unkeyed `.doi` JSON document.
    pub fn parse(input: &[u8]) -> Result<Self, RealisationParseError> {
        check_size(input)?;
        let wire: WireUnkeyed = serde_json::from_slice(input)
            .map_err(|error| RealisationParseError::InvalidJson(error.to_string()))?;
        Self::from_wire(wire)
    }

    /// Replace the signature set after validating and canonicalizing each value.
    pub fn with_signatures(
        mut self,
        signatures: impl IntoIterator<Item = NixSignature>,
    ) -> Result<Self, SignatureError> {
        self.signatures.clear();
        for signature in signatures {
            self.insert_signature(signature)?;
        }
        Ok(self)
    }

    /// Insert a validated signature, returning whether it was newly added.
    pub fn insert_signature(&mut self, signature: NixSignature) -> Result<bool, SignatureError> {
        Ok(self.signatures.insert(signature.canonicalized()?))
    }

    /// Realised output store path.
    #[must_use]
    pub const fn out_path(&self) -> &StorePath {
        &self.out_path
    }

    /// Sorted and deduplicated signature set.
    #[must_use]
    pub const fn signatures(&self) -> &BTreeSet<NixSignature> {
        &self.signatures
    }

    /// Write deterministic compact JSON using Nix 2.36 signature objects.
    pub fn write_canonical(&self, writer: &mut impl io::Write) -> Result<(), io::Error> {
        writer.write_all(&self.to_canonical_bytes())
    }

    /// Return deterministic compact JSON using Nix 2.36 signature objects.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.to_wire()).expect("serializing strings cannot fail")
    }

    /// Construct the exact keyed JSON fingerprint signed by Nix.
    #[must_use]
    pub fn fingerprint(&self, id: &DrvOutput) -> String {
        let wire = WireFingerprint {
            key: WireDrvOutput::from(id),
            value: WireFingerprintValue {
                out_path: self.out_path.to_basename(),
            },
        };
        serde_json::to_string(&wire).expect("serializing strings cannot fail")
    }

    /// Return how many stored signatures verify with configured keys.
    #[must_use]
    pub fn count_valid_signatures(&self, id: &DrvOutput, keys: &[TrustedPublicKey]) -> usize {
        let fingerprint = self.fingerprint(id);
        self.signatures
            .iter()
            .filter(|signature| {
                signature
                    .verify(fingerprint.as_bytes(), keys)
                    .unwrap_or(false)
            })
            .count()
    }

    /// Return whether at least one stored signature verifies with a configured key.
    #[must_use]
    pub fn has_valid_signature(&self, id: &DrvOutput, keys: &[TrustedPublicKey]) -> bool {
        self.count_valid_signatures(id, keys) != 0
    }

    /// Return whether another value realises the same output store path.
    ///
    /// Nix deliberately ignores signatures for this compatibility check.
    #[must_use]
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.out_path == other.out_path
    }

    fn from_wire(wire: WireUnkeyed) -> Result<Self, RealisationParseError> {
        let out_path = parse_store_path("outPath", &wire.out_path)?;
        let mut signatures = BTreeSet::new();
        for (index, encoded) in wire.signatures.into_iter().enumerate() {
            let signature = match encoded {
                WireSignature::String(encoded) => NixSignature::parse(&encoded),
                WireSignature::Object(object) => NixSignature {
                    key_name: object.key_name,
                    encoded: object.sig,
                }
                .canonicalized(),
            }
            .map_err(|source| RealisationParseError::InvalidSignature { index, source })?;
            signatures.insert(signature);
        }
        Ok(Self {
            out_path,
            signatures,
        })
    }

    fn to_wire(&self) -> WireUnkeyed {
        WireUnkeyed {
            out_path: self.out_path.to_basename(),
            signatures: self
                .signatures
                .iter()
                .map(|signature| {
                    WireSignature::Object(WireSignatureObject {
                        key_name: signature.key_name.clone(),
                        sig: signature.encoded.clone(),
                    })
                })
                .collect(),
        }
    }
}

/// A derivation-output key paired with its realised value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Realisation {
    id: DrvOutput,
    value: UnkeyedRealisation,
}

impl Realisation {
    /// Pair a derivation-output identifier with its realised value.
    #[must_use]
    pub const fn new(id: DrvOutput, value: UnkeyedRealisation) -> Self {
        Self { id, value }
    }

    /// Parse Nix's full keyed realisation JSON representation.
    pub fn parse(input: &[u8]) -> Result<Self, RealisationParseError> {
        check_size(input)?;
        let wire: WireRealisation = serde_json::from_slice(input)
            .map_err(|error| RealisationParseError::InvalidJson(error.to_string()))?;
        let drv_path = parse_store_path("key.drvPath", &wire.key.drv_path)?;
        let id = DrvOutput::new(drv_path, wire.key.output_name);
        let value = UnkeyedRealisation::from_wire(wire.value)?;
        Ok(Self { id, value })
    }

    /// Derivation-output identifier serving as this realisation's key.
    #[must_use]
    pub const fn id(&self) -> &DrvOutput {
        &self.id
    }

    /// Unkeyed realisation value stored by binary caches.
    #[must_use]
    pub const fn value(&self) -> &UnkeyedRealisation {
        &self.value
    }

    /// Write the deterministic compact keyed JSON representation.
    ///
    /// Signatures use Nix 2.36's object representation.
    pub fn write_canonical(&self, writer: &mut impl io::Write) -> Result<(), io::Error> {
        writer.write_all(&self.to_canonical_bytes())
    }

    /// Return the deterministic compact keyed JSON representation.
    ///
    /// Signatures use Nix 2.36's object representation.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let wire = WireRealisation {
            key: WireDrvOutput::from(&self.id),
            value: self.value.to_wire(),
        };
        serde_json::to_vec(&wire).expect("serializing strings cannot fail")
    }

    /// Construct the exact fingerprint signed by Nix.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.value.fingerprint(&self.id)
    }

    /// Return how many stored signatures verify with configured keys.
    #[must_use]
    pub fn count_valid_signatures(&self, keys: &[TrustedPublicKey]) -> usize {
        self.value.count_valid_signatures(&self.id, keys)
    }

    /// Return whether at least one stored signature verifies with a configured key.
    #[must_use]
    pub fn has_valid_signature(&self, keys: &[TrustedPublicKey]) -> bool {
        self.value.has_valid_signature(&self.id, keys)
    }
}

fn check_size(input: &[u8]) -> Result<(), RealisationParseError> {
    if input.len() > MAX_REALISATION_SIZE {
        Err(RealisationParseError::TooLarge {
            size: input.len(),
            limit: MAX_REALISATION_SIZE,
        })
    } else {
        Ok(())
    }
}

fn parse_store_path(field: &'static str, value: &str) -> Result<StorePath, RealisationParseError> {
    StorePath::from_basename(value.as_bytes()).map_err(|error| {
        RealisationParseError::InvalidStorePath {
            field,
            message: error.to_string(),
        }
    })
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WireDrvOutput {
    drv_path: String,
    output_name: String,
}

impl From<&DrvOutput> for WireDrvOutput {
    fn from(id: &DrvOutput) -> Self {
        Self {
            drv_path: id.drv_path().to_basename(),
            output_name: id.output_name().to_owned(),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WireUnkeyed {
    out_path: String,
    #[serde(default)]
    signatures: Vec<WireSignature>,
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum WireSignature {
    String(String),
    Object(WireSignatureObject),
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WireSignatureObject {
    key_name: String,
    sig: String,
}

#[derive(Deserialize, Serialize)]
struct WireRealisation {
    key: WireDrvOutput,
    value: WireUnkeyed,
}

#[derive(Serialize)]
struct WireFingerprint {
    key: WireDrvOutput,
    value: WireFingerprintValue,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireFingerprintValue {
    out_path: String,
}

/// Failure to parse a derivation-output realisation.
#[derive(Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum RealisationParseError {
    /// The configured document-size limit was exceeded.
    #[error("realisation is {size} bytes, exceeding the {limit}-byte limit")]
    TooLarge {
        /// Actual input size.
        size: usize,
        /// Maximum accepted size.
        limit: usize,
    },
    /// The document was not valid realisation JSON.
    #[error("invalid realisation JSON: {0}")]
    InvalidJson(String),
    /// A store-path field was invalid.
    #[error("invalid {field}: {message}")]
    InvalidStorePath {
        /// JSON field containing the path.
        field: &'static str,
        /// Store-path parser detail.
        message: String,
    },
    /// An entry in the signatures array was malformed.
    #[error("invalid signature at index {index}: {source}")]
    InvalidSignature {
        /// Zero-based array index.
        index: usize,
        /// Signature parser detail.
        source: SignatureError,
    },
}

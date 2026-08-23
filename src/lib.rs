//! Pure Rust parsing, canonical writing, and validation for Nix `.narinfo` files.
//!
//! This crate deliberately contains no transport, decompression, store mutation,
//! or trust-policy code. Callers fetch the record, choose supported compression,
//! and decide whether a valid signature is required.
//!
//! # Example
//!
//! ```
//! use nix_derivation::StoreDir;
//! use nix_narinfo::{Compression, NarInfo};
//!
//! let record = b"StorePath: /nix/store/00000000000000000000000000000000-example\n\
//! URL: nar/example.nar\n\
//! NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
//! NarSize: 1\n";
//! let store_dir = StoreDir::default();
//! let info = NarInfo::parse_in(&store_dir, record)?;
//!
//! assert_eq!(info.compression(), &Compression::Bzip2);
//! assert!(info.fingerprint(&store_dir).starts_with("1;/nix/store/"));
//! # Ok::<(), nix_narinfo::ParseError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::str::FromStr;

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use nix_derivation::{CAHash, NixHash, StoreDir, StorePath};
use thiserror::Error;

/// Maximum accepted `.narinfo` record size: one mebibyte.
pub const MAX_NARINFO_SIZE: usize = 1024 * 1024;

/// A parsed Nix binary-cache metadata record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NarInfo {
    store_dir: StoreDir,
    store_path: StorePath,
    url: String,
    compression: Compression,
    nar_hash: NixHash,
    nar_size: u64,
    references: BTreeSet<StorePath>,
    deriver: Option<StorePath>,
    signatures: Vec<NarInfoSignature>,
    content_address: Option<CAHash>,
    file_hash: Option<NixHash>,
    file_size: Option<u64>,
    extensions: Vec<Field>,
}

/// The compression named by a `.narinfo` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Compression {
    /// An uncompressed NAR.
    None,
    /// Bzip2 compression.
    Bzip2,
    /// Gzip compression.
    Gzip,
    /// XZ compression.
    Xz,
    /// Zstandard compression.
    Zstd,
    /// A forward-compatible compression name unknown to this crate.
    Other(String),
}

impl Compression {
    /// Parse a `.narinfo` compression field.
    #[must_use]
    pub fn parse(input: &str) -> Self {
        match input {
            "" | "none" => Self::None,
            "bzip2" => Self::Bzip2,
            "gzip" => Self::Gzip,
            "xz" => Self::Xz,
            "zstd" => Self::Zstd,
            other => Self::Other(other.to_owned()),
        }
    }

    /// Return the canonical `.narinfo` spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Bzip2 => "bzip2",
            Self::Gzip => "gzip",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
            Self::Other(name) => name,
        }
    }
}

impl fmt::Display for Compression {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A named Ed25519 signature attached to a `.narinfo` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NarInfoSignature {
    /// Name used to select a configured public key.
    pub key_name: String,
    /// Base64-encoded Ed25519 signature bytes.
    pub encoded: String,
}

/// An unrecognized `.narinfo` field retained for forward compatibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Field {
    /// Field name before the first colon.
    pub name: String,
    /// Field value with separator whitespace removed.
    pub value: String,
}

/// A named trusted Ed25519 public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedPublicKey {
    /// Name matched against the name in a narinfo signature.
    pub name: String,
    /// Parsed Ed25519 verifying key.
    pub key: VerifyingKey,
}

/// Builder for a validated [`NarInfo`] value.
#[derive(Clone, Debug)]
pub struct NarInfoBuilder {
    store_dir: StoreDir,
    store_path: StorePath,
    url: String,
    compression: Compression,
    nar_hash: NixHash,
    nar_size: u64,
    references: BTreeSet<StorePath>,
    deriver: Option<StorePath>,
    signatures: Vec<NarInfoSignature>,
    content_address: Option<CAHash>,
    file_hash: Option<NixHash>,
    file_size: Option<u64>,
    extensions: Vec<Field>,
}

impl NarInfoBuilder {
    /// Start constructing a record in the conventional `/nix/store` store.
    #[must_use]
    pub fn new(
        store_path: StorePath,
        url: impl Into<String>,
        nar_hash: NixHash,
        nar_size: u64,
    ) -> Self {
        Self::new_in(StoreDir::default(), store_path, url, nar_hash, nar_size)
    }

    /// Start constructing a record in a configured logical store.
    #[must_use]
    pub fn new_in(
        store_dir: StoreDir,
        store_path: StorePath,
        url: impl Into<String>,
        nar_hash: NixHash,
        nar_size: u64,
    ) -> Self {
        Self {
            store_dir,
            store_path,
            url: url.into(),
            compression: Compression::Bzip2,
            nar_hash,
            nar_size,
            references: BTreeSet::new(),
            deriver: None,
            signatures: Vec::new(),
            content_address: None,
            file_hash: None,
            file_size: None,
            extensions: Vec::new(),
        }
    }

    /// Set the compression format.
    #[must_use]
    pub fn compression(mut self, compression: Compression) -> Self {
        self.compression = compression;
        self
    }

    /// Replace the reference set, sorting and deduplicating its paths.
    #[must_use]
    pub fn references(mut self, references: impl IntoIterator<Item = StorePath>) -> Self {
        self.references = references.into_iter().collect();
        self
    }

    /// Set or clear the producing derivation.
    #[must_use]
    pub fn deriver(mut self, deriver: Option<StorePath>) -> Self {
        self.deriver = deriver;
        self
    }

    /// Replace the ordered signature list.
    #[must_use]
    pub fn signatures(mut self, signatures: impl IntoIterator<Item = NarInfoSignature>) -> Self {
        self.signatures = signatures.into_iter().collect();
        self
    }

    /// Append one signature.
    #[must_use]
    pub fn signature(mut self, signature: NarInfoSignature) -> Self {
        self.signatures.push(signature);
        self
    }

    /// Set or clear the content address.
    #[must_use]
    pub fn content_address(mut self, content_address: Option<CAHash>) -> Self {
        self.content_address = content_address;
        self
    }

    /// Set or clear the downloaded-file hash.
    #[must_use]
    pub fn file_hash(mut self, file_hash: Option<NixHash>) -> Self {
        self.file_hash = file_hash;
        self
    }

    /// Set or clear the downloaded-file size.
    #[must_use]
    pub fn file_size(mut self, file_size: Option<u64>) -> Self {
        self.file_size = file_size;
        self
    }

    /// Replace the ordered extension-field list.
    #[must_use]
    pub fn extensions(mut self, extensions: impl IntoIterator<Item = Field>) -> Self {
        self.extensions = extensions.into_iter().collect();
        self
    }

    /// Append one extension field.
    #[must_use]
    pub fn extension(mut self, extension: Field) -> Self {
        self.extensions.push(extension);
        self
    }

    /// Validate all serialization invariants and finish the record.
    pub fn build(self) -> Result<NarInfo, BuildError> {
        if self.nar_size == 0 {
            return Err(BuildError::ZeroNarSize);
        }
        validate_line_value("StoreDir", self.store_dir.as_str())?;
        validate_line_value("URL", &self.url)?;
        if let Compression::Other(name) = &self.compression {
            validate_line_value("Compression", name)?;
            if matches!(
                name.as_str(),
                "" | "none" | "bzip2" | "gzip" | "xz" | "zstd"
            ) {
                return Err(BuildError::InvalidField {
                    field: "Compression".to_owned(),
                    message: "known names must use their typed compression variant".to_owned(),
                });
            }
        }
        for signature in &self.signatures {
            validate_line_value("Sig key name", &signature.key_name)?;
            validate_line_value("Sig encoding", &signature.encoded)?;
            if signature.key_name.contains(':') {
                return Err(BuildError::InvalidField {
                    field: "Sig key name".to_owned(),
                    message: "must not contain ':'".to_owned(),
                });
            }
        }
        for extension in &self.extensions {
            validate_line_value("extension name", &extension.name)?;
            validate_line_value("extension value", &extension.value)?;
            if extension.name.is_empty() || extension.name.contains(':') {
                return Err(BuildError::InvalidField {
                    field: "extension name".to_owned(),
                    message: "must be nonempty and must not contain ':'".to_owned(),
                });
            }
            if is_known_field(&extension.name) {
                return Err(BuildError::InvalidField {
                    field: extension.name.clone(),
                    message: "recognized fields must use their typed builder method".to_owned(),
                });
            }
        }

        Ok(NarInfo {
            store_dir: self.store_dir,
            store_path: self.store_path,
            url: self.url,
            compression: self.compression,
            nar_hash: self.nar_hash,
            nar_size: self.nar_size,
            references: self.references,
            deriver: self.deriver,
            signatures: self.signatures,
            content_address: self.content_address,
            file_hash: self.file_hash,
            file_size: self.file_size,
            extensions: self.extensions,
        })
    }
}

impl TrustedPublicKey {
    /// Parse `NAME:BASE64`, where the decoded public key is exactly 32 bytes.
    pub fn parse(input: &str) -> Result<Self, KeyError> {
        let (name, encoded) = input.split_once(':').ok_or(KeyError::MissingName)?;
        if name.is_empty() {
            return Err(KeyError::EmptyName);
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| KeyError::InvalidBase64)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| KeyError::InvalidLength { got: bytes.len() })?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| KeyError::InvalidKey)?;
        Ok(Self {
            name: name.to_owned(),
            key,
        })
    }
}

impl FromStr for TrustedPublicKey {
    type Err = KeyError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl NarInfoSignature {
    /// Verify this signature against the matching configured keys.
    ///
    /// `Ok(false)` means that no configured key has this signature's name, or
    /// that all matching keys rejected it. Encoding and length failures are
    /// reported as errors so callers can distinguish malformed signatures.
    pub fn verify(
        &self,
        fingerprint: &[u8],
        keys: &[TrustedPublicKey],
    ) -> Result<bool, SignatureError> {
        if self.key_name.is_empty() {
            return Err(SignatureError::EmptyKeyName);
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.encoded)
            .map_err(|_| SignatureError::InvalidBase64)?;
        let signature = Signature::from_slice(&bytes)
            .map_err(|_| SignatureError::InvalidLength { got: bytes.len() })?;

        Ok(keys
            .iter()
            .filter(|key| key.name == self.key_name)
            .any(|key| key.key.verify_strict(fingerprint, &signature).is_ok()))
    }
}

impl NarInfo {
    /// Start constructing a record in the conventional `/nix/store` store.
    #[must_use]
    pub fn builder(
        store_path: StorePath,
        url: impl Into<String>,
        nar_hash: NixHash,
        nar_size: u64,
    ) -> NarInfoBuilder {
        NarInfoBuilder::new(store_path, url, nar_hash, nar_size)
    }

    /// Start constructing a record in a configured logical store.
    #[must_use]
    pub fn builder_in(
        store_dir: StoreDir,
        store_path: StorePath,
        url: impl Into<String>,
        nar_hash: NixHash,
        nar_size: u64,
    ) -> NarInfoBuilder {
        NarInfoBuilder::new_in(store_dir, store_path, url, nar_hash, nar_size)
    }

    /// Parse and validate a `.narinfo` record for a logical Nix store directory.
    pub fn parse_in(store_dir: &StoreDir, input: &[u8]) -> Result<Self, ParseError> {
        if input.len() > MAX_NARINFO_SIZE {
            return Err(ParseError::TooLarge {
                size: input.len(),
                limit: MAX_NARINFO_SIZE,
            });
        }
        let text = std::str::from_utf8(input).map_err(|_| ParseError::InvalidUtf8)?;
        let mut fields = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            let (name, value) = line
                .split_once(':')
                .ok_or(ParseError::MalformedLine { line: index + 1 })?;
            fields.push(ParsedField {
                name,
                value: value.trim_start(),
                line: index + 1,
            });
        }

        let store_path_field = required(&fields, "StorePath")?;
        let url = required(&fields, "URL")?.value.to_owned();
        let nar_hash_field = required(&fields, "NarHash")?;
        let nar_size_field = required(&fields, "NarSize")?;
        let compression_field = optional(&fields, "Compression")?;
        let references_field = optional(&fields, "References")?;
        let deriver_field = optional(&fields, "Deriver")?;
        let content_address_field = optional(&fields, "CA")?;
        let file_hash_field = optional(&fields, "FileHash")?;
        let file_size_field = optional(&fields, "FileSize")?;

        let signatures = fields
            .iter()
            .filter(|field| field.name == "Sig")
            .map(|field| parse_signature(field))
            .collect();
        let extensions = fields
            .iter()
            .filter(|field| !is_known_field(field.name))
            .map(|field| Field {
                name: field.name.to_owned(),
                value: field.value.to_owned(),
            })
            .collect();

        let nar_size = parse_size(nar_size_field, "NarSize")?;
        if nar_size == 0 {
            return Err(ParseError::InvalidField {
                field: "NarSize",
                message: format!("at line {}: must be greater than zero", nar_size_field.line),
            });
        }

        let store_path = parse_absolute_path(store_dir, store_path_field, "StorePath")?;
        let nar_hash = NixHash::parse(nar_hash_field.value)
            .map_err(|error| invalid_field("NarHash", nar_hash_field.line, error))?;
        let compression =
            compression_field.map_or(Compression::Bzip2, |field| Compression::parse(field.value));

        let references = references_field
            .map(|field| {
                field
                    .value
                    .split_ascii_whitespace()
                    .map(|value| parse_path(store_dir, value, "References", field.line))
                    .collect()
            })
            .transpose()?
            .unwrap_or_default();

        let deriver = deriver_field
            .filter(|field| field.value != "unknown-deriver")
            .map(|field| parse_path(store_dir, field.value, "Deriver", field.line))
            .transpose()?;

        let content_address = content_address_field
            .map(|field| {
                CAHash::parse(field.value).map_err(|error| invalid_field("CA", field.line, error))
            })
            .transpose()?;
        let file_hash = file_hash_field
            .map(|field| {
                NixHash::parse(field.value)
                    .map_err(|error| invalid_field("FileHash", field.line, error))
            })
            .transpose()?;
        let file_size = file_size_field
            .map(|field| parse_size(field, "FileSize"))
            .transpose()?;

        Ok(Self {
            store_dir: store_dir.clone(),
            store_path,
            url,
            compression,
            nar_hash,
            nar_size,
            references,
            deriver,
            signatures,
            content_address,
            file_hash,
            file_size,
            extensions,
        })
    }

    /// Write this record in deterministic Nix field order.
    pub fn write_canonical(&self, writer: &mut impl io::Write) -> Result<(), io::Error> {
        writeln!(
            writer,
            "StorePath: {}",
            self.store_dir.render_path(&self.store_path)
        )?;
        writeln!(writer, "URL: {}", self.url)?;
        writeln!(writer, "Compression: {}", self.compression)?;
        if let Some(hash) = &self.file_hash {
            writeln!(writer, "FileHash: {}", hash.to_nix_nixbase32_string())?;
        }
        if let Some(size) = self.file_size {
            writeln!(writer, "FileSize: {size}")?;
        }
        writeln!(
            writer,
            "NarHash: {}",
            self.nar_hash.to_nix_nixbase32_string()
        )?;
        writeln!(writer, "NarSize: {}", self.nar_size)?;
        let references = self
            .references
            .iter()
            .map(StorePath::to_basename)
            .collect::<Vec<_>>()
            .join(" ");
        writeln!(writer, "References: {references}")?;
        if let Some(deriver) = &self.deriver {
            writeln!(writer, "Deriver: {}", deriver.to_basename())?;
        }
        for signature in &self.signatures {
            writeln!(writer, "Sig: {}:{}", signature.key_name, signature.encoded)?;
        }
        if let Some(content_address) = &self.content_address {
            writeln!(writer, "CA: {}", content_address.to_nix_string())?;
        }
        for field in &self.extensions {
            writeln!(writer, "{}: {}", field.name, field.value)?;
        }
        Ok(())
    }

    /// Return the deterministic canonical representation.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.write_canonical(&mut bytes)
            .expect("writing to a Vec cannot fail");
        bytes
    }

    /// Construct the exact byte-cache fingerprint signed by Nix cache keys.
    #[must_use]
    pub fn fingerprint(&self, store_dir: &StoreDir) -> String {
        let references = self
            .references
            .iter()
            .map(|path| store_dir.render_path(path))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "1;{};{};{};{}",
            store_dir.render_path(&self.store_path),
            self.nar_hash.to_nix_nixbase32_string(),
            self.nar_size,
            references,
        )
    }

    /// Return whether at least one signature verifies with a configured key.
    ///
    /// Malformed signatures are ignored independently and cannot mask a later
    /// valid signature.
    #[must_use]
    pub fn has_valid_signature(&self, store_dir: &StoreDir, keys: &[TrustedPublicKey]) -> bool {
        let fingerprint = self.fingerprint(store_dir);
        self.signatures.iter().any(|signature| {
            signature
                .verify(fingerprint.as_bytes(), keys)
                .unwrap_or(false)
        })
    }

    /// Verify that the content address, references, and name produce this path.
    #[must_use]
    pub fn is_content_addressed(&self, store_dir: &StoreDir) -> bool {
        let Some(content_address) = &self.content_address else {
            return false;
        };
        let self_reference = self.references.contains(&self.store_path);
        let other_references = self
            .references
            .iter()
            .filter(|path| *path != &self.store_path);
        store_dir
            .build_ca_path(
                self.store_path.name(),
                content_address,
                other_references,
                self_reference,
            )
            .is_ok_and(|expected| expected == self.store_path)
    }

    /// Store path described by this record.
    #[must_use]
    pub const fn store_path(&self) -> &StorePath {
        &self.store_path
    }

    /// Logical store directory used to parse or construct this record.
    #[must_use]
    pub const fn store_dir(&self) -> &StoreDir {
        &self.store_dir
    }

    /// Relative or absolute NAR location supplied by the cache.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Named compression format. Unknown values remain available to callers.
    #[must_use]
    pub const fn compression(&self) -> &Compression {
        &self.compression
    }

    /// Hash of the uncompressed NAR serialization.
    #[must_use]
    pub const fn nar_hash(&self) -> &NixHash {
        &self.nar_hash
    }

    /// Size of the uncompressed NAR serialization.
    #[must_use]
    pub const fn nar_size(&self) -> u64 {
        self.nar_size
    }

    /// Sorted, deduplicated store-path references.
    #[must_use]
    pub const fn references(&self) -> &BTreeSet<StorePath> {
        &self.references
    }

    /// Derivation that produced the path, if known.
    #[must_use]
    pub const fn deriver(&self) -> Option<&StorePath> {
        self.deriver.as_ref()
    }

    /// Signatures in their original record order.
    #[must_use]
    pub fn signatures(&self) -> &[NarInfoSignature] {
        &self.signatures
    }

    /// Declared Nix content address, if present.
    #[must_use]
    pub const fn content_address(&self) -> Option<&CAHash> {
        self.content_address.as_ref()
    }

    /// Hash of the downloaded, possibly compressed file, if present.
    #[must_use]
    pub const fn file_hash(&self) -> Option<&NixHash> {
        self.file_hash.as_ref()
    }

    /// Size of the downloaded, possibly compressed file, if present.
    #[must_use]
    pub const fn file_size(&self) -> Option<u64> {
        self.file_size
    }

    /// Unrecognized fields in their original record order.
    #[must_use]
    pub fn extensions(&self) -> &[Field] {
        &self.extensions
    }
}

impl FromStr for NarInfo {
    type Err = ParseError;

    /// Parse using the conventional `/nix/store` logical store directory.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse_in(&StoreDir::default(), input.as_bytes())
    }
}

#[derive(Clone, Copy)]
struct ParsedField<'a> {
    name: &'a str,
    value: &'a str,
    line: usize,
}

fn required<'a>(
    fields: &'a [ParsedField<'a>],
    name: &'static str,
) -> Result<ParsedField<'a>, ParseError> {
    optional(fields, name)?.ok_or(ParseError::MissingField { field: name })
}

fn optional<'a>(
    fields: &'a [ParsedField<'a>],
    name: &'static str,
) -> Result<Option<ParsedField<'a>>, ParseError> {
    let mut matching = fields.iter().copied().filter(|field| field.name == name);
    let first = matching.next();
    if matching.next().is_some() {
        return Err(ParseError::DuplicateField {
            field: name.to_owned(),
        });
    }
    Ok(first)
}

fn parse_absolute_path(
    store_dir: &StoreDir,
    field: ParsedField<'_>,
    name: &'static str,
) -> Result<StorePath, ParseError> {
    if !field.value.starts_with('/') {
        return Err(ParseError::InvalidField {
            field: name,
            message: format!("at line {}: expected an absolute store path", field.line),
        });
    }
    store_dir
        .parse_path(field.value.as_bytes())
        .map_err(|error| invalid_field(name, field.line, error))
}

fn parse_path(
    store_dir: &StoreDir,
    value: &str,
    field: &'static str,
    line: usize,
) -> Result<StorePath, ParseError> {
    let result = if value.starts_with('/') {
        store_dir.parse_path(value.as_bytes())
    } else {
        StorePath::from_basename(value.as_bytes())
    };
    result.map_err(|error| invalid_field(field, line, error))
}

fn parse_size(field: ParsedField<'_>, name: &'static str) -> Result<u64, ParseError> {
    field
        .value
        .parse()
        .map_err(|error| invalid_field(name, field.line, error))
}

fn parse_signature(field: &ParsedField<'_>) -> NarInfoSignature {
    let (key_name, encoded) = field.value.split_once(':').unwrap_or((field.value, ""));
    NarInfoSignature {
        key_name: key_name.to_owned(),
        encoded: encoded.to_owned(),
    }
}

fn invalid_field(field: &'static str, line: usize, error: impl fmt::Display) -> ParseError {
    ParseError::InvalidField {
        field,
        message: format!("at line {line}: {error}"),
    }
}

fn is_known_field(name: &str) -> bool {
    matches!(
        name,
        "StorePath"
            | "URL"
            | "Compression"
            | "NarHash"
            | "NarSize"
            | "References"
            | "Deriver"
            | "Sig"
            | "CA"
            | "FileHash"
            | "FileSize"
    )
}

fn validate_line_value(field: &str, value: &str) -> Result<(), BuildError> {
    if value.contains(['\r', '\n']) {
        Err(BuildError::InvalidField {
            field: field.to_owned(),
            message: "must not contain a line break".to_owned(),
        })
    } else {
        Ok(())
    }
}

/// Failure to construct a canonically serializable [`NarInfo`] value.
#[derive(Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    /// The uncompressed NAR size was zero.
    #[error("NarSize must be greater than zero")]
    ZeroNarSize,
    /// A field could not be represented without changing narinfo structure.
    #[error("invalid {field}: {message}")]
    InvalidField {
        /// Field or component name.
        field: String,
        /// Description of the violated construction invariant.
        message: String,
    },
}

/// Failure to parse or validate a `.narinfo` record.
#[derive(Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The configured record-size limit was exceeded.
    #[error("narinfo is {size} bytes, exceeding the {limit}-byte limit")]
    TooLarge {
        /// Actual input size.
        size: usize,
        /// Maximum accepted size.
        limit: usize,
    },
    /// The record was not UTF-8.
    #[error("narinfo is not UTF-8")]
    InvalidUtf8,
    /// A nonempty line did not contain a colon separator.
    #[error("invalid narinfo line {line}: expected NAME: VALUE")]
    MalformedLine {
        /// One-based source line number.
        line: usize,
    },
    /// A required field was absent.
    #[error("narinfo is missing {field}")]
    MissingField {
        /// Required field name.
        field: &'static str,
    },
    /// A singleton field occurred more than once.
    #[error("narinfo contains duplicate {field}")]
    DuplicateField {
        /// Duplicated field name.
        field: String,
    },
    /// A recognized field had an invalid value.
    #[error("invalid {field}: {message}")]
    InvalidField {
        /// Field name.
        field: &'static str,
        /// Field-specific detail, including its source line where applicable.
        message: String,
    },
}

/// Failure to parse a trusted public key.
#[derive(Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyError {
    /// The key did not have a `NAME:` prefix.
    #[error("public key has no name separator")]
    MissingName,
    /// The key name was empty.
    #[error("public key has an empty name")]
    EmptyName,
    /// The key material was not valid base64.
    #[error("public key is not valid base64")]
    InvalidBase64,
    /// The decoded key was not 32 bytes.
    #[error("public key is {got} bytes, expected 32")]
    InvalidLength {
        /// Decoded byte length.
        got: usize,
    },
    /// Ed25519 rejected the decoded public key.
    #[error("invalid Ed25519 public key")]
    InvalidKey,
}

/// Failure to decode a narinfo signature.
#[derive(Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum SignatureError {
    /// The signature did not name a key.
    #[error("signature has an empty key name")]
    EmptyKeyName,
    /// Signature bytes were not valid base64.
    #[error("signature is not valid base64")]
    InvalidBase64,
    /// The decoded signature was not 64 bytes.
    #[error("signature is {got} bytes, expected 64")]
    InvalidLength {
        /// Decoded byte length.
        got: usize,
    },
}

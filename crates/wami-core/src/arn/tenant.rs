//! A tenant's id as anatta-auth issues it, and the one ARN segment it maps to.
//!
//! Every service that receives a token reads the tenant claim with
//! [`TenantId::from_claim`] and builds its ARNs with [`TenantId::segment`]:
//! the segment IS the id, so the ARNs a service builds agree with the ones the
//! issuer builds. Nothing on a request path hashes a tenant's text: a claim
//! that is not the canonical decimal of a non-zero `u64` is refused.

use super::types::{TenantPath, WamiArn, ROOT_TENANT_ID};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::num::NonZeroU64;
use std::str::FromStr;

/// A tenant's id as anatta-auth issues it: never 0 (wami's root tenant, whose
/// context bypasses every authorisation check).
///
/// **One spelling**: on the wire, in a token and at rest the id is its
/// canonical decimal text (no sign, no leading zero, no space). A JSON number
/// would lose precision past 2^53 in a browser, and signed 64-bit stores cannot
/// hold an id above `i64::MAX`, so serde reads and writes the text, as
/// [`fmt::Display`] and [`FromStr`] do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantId(NonZeroU64);

/// Why a claim is not a tenant id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TenantIdError {
    /// The claim is empty.
    #[error("a tenant id is a canonical non-zero decimal: the claim is empty")]
    Empty,
    /// The claim holds something other than ASCII digits (a sign, a space, a
    /// letter, a non-ASCII digit…).
    #[error("a tenant id is a canonical non-zero decimal: the claim holds a non-digit")]
    NotDigits,
    /// The claim starts with `0` (`"0"` itself included): two texts would name
    /// one tenant.
    #[error("a tenant id is a canonical non-zero decimal: the claim has a leading zero")]
    LeadingZero,
    /// The claim is beyond `u64::MAX`.
    #[error("a tenant id is a canonical non-zero decimal: the claim overflows u64")]
    Overflow,
}

impl TenantId {
    /// The id `id` is, unless it is zero; usable in a constant.
    pub const fn from_const(id: u64) -> Option<TenantId> {
        match NonZeroU64::new(id) {
            Some(id) => Some(TenantId(id)),
            None => None,
        }
    }

    /// The canonical decimal a token carries: digits, non-zero, no leading zero,
    /// no sign, no space, fits u64. Everything else is refused, never hashed.
    ///
    /// # Errors
    ///
    /// [`TenantIdError`] names why the claim is not the canonical decimal of a
    /// non-zero `u64`.
    pub fn from_claim(text: &str) -> Result<TenantId, TenantIdError> {
        if text.is_empty() {
            return Err(TenantIdError::Empty);
        }
        if !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(TenantIdError::NotDigits);
        }
        if text.starts_with('0') {
            return Err(TenantIdError::LeadingZero);
        }
        let id = text.parse::<u64>().map_err(|_| TenantIdError::Overflow)?;
        // Digits with no leading zero are never 0: the fallback is unreachable
        // and kept only so that no path can yield the root tenant.
        Self::from_const(id).ok_or(TenantIdError::LeadingZero)
    }

    /// The number.
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// The ARN segment: the id itself. The one function every service calls.
    pub const fn segment(self) -> u64 {
        self.0.get()
    }

    /// The single-segment tenant path of this tenant.
    pub fn path(self) -> TenantPath {
        TenantPath::single(self.get())
    }

    /// The tenant an ARN names, when its tenant path is a single non-zero
    /// segment; `None` for the root tenant and for a nested path.
    pub fn of_arn(arn: &WamiArn) -> Option<TenantId> {
        match arn.tenant_path.segments.as_slice() {
            [segment] if *segment != ROOT_TENANT_ID => Self::from_const(*segment),
            _ => None,
        }
    }
}

impl FromStr for TenantId {
    type Err = TenantIdError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::from_claim(text)
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Serialize for TenantId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for TenantId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_claim(&text).map_err(serde::de::Error::custom)
    }
}

/// The unified graph's public space: one fixed id every service reads
/// (`legacy_id("public")`, the value anatta-auth pins).
pub const PUBLIC_TENANT_ID: TenantId = match TenantId::from_const(17_267_350_133_765_412_090) {
    Some(id) => id,
    None => panic!("the public id is not zero"),
};

/// anatta-auth's own tenant (the platform database; `legacy_id("anatta-auth")`).
pub const PLATFORM_TENANT_ID: TenantId = match TenantId::from_const(9_680_926_541_668_053_385) {
    Some(id) => id,
    None => panic!("the platform id is not zero"),
};

/// **One-shot only**: the id a tenant known by name before anatta-auth's task
/// 073 received — the first eight bytes, big-endian, of SHA-256 over the
/// trimmed, lowercased name, zero mapped to one.
///
/// For a migration tool, or a local configuration step that fixes a
/// deployment's tenant id once (`tenant_id = legacy_id(name)`); **never called
/// on a request path**. A token's tenant claim goes through
/// [`TenantId::from_claim`], which refuses a name rather than hashing it.
pub fn legacy_id(name: &str) -> TenantId {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(name.trim().to_lowercase().as_bytes());
    let mut head = [0_u8; 8];
    head.copy_from_slice(&digest[..8]);
    TenantId::from_const(u64::from_be_bytes(head)).unwrap_or(TenantId(NonZeroU64::MIN))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arn::{ArnBuilder, WamiArn};

    #[test]
    fn legacy_id_matches_the_vectors_auth_and_sippa_pin() {
        const ACME: u64 = 9_379_647_469_329_139_872;
        for (name, expected) in [
            // anatta-auth `tenant.rs`
            ("mermaid", 1_134_008_656_406_414_211_u64),
            ("gdd", 6_794_459_541_891_677_217),
            ("perso", 1_316_001_909_527_231_042),
            ("anatta", 15_442_934_347_416_025_529),
            ("", 16_406_829_232_824_261_652),
            ("public", 17_267_350_133_765_412_090),
            ("anatta-auth", 9_680_926_541_668_053_385),
            // Sippa `rights/src/seg.rs` (captured from anatta-auth)
            ("acme", ACME),
            ("Acme", ACME),
            ("  acme  ", ACME),
            ("lsh", 2_336_903_939_167_259_689),
            ("lsh/public/x", 16_839_067_350_420_195_545),
            ("ÉCOLE/été", 4_795_239_114_267_685_220),
            ("gleich-straße", 12_161_529_675_810_134_011),
        ] {
            assert_eq!(legacy_id(name).get(), expected, "{name:?}");
        }
        assert_eq!(legacy_id(" Mermaid "), legacy_id("mermaid"));
    }

    #[test]
    fn the_reserved_ids_are_the_legacy_ids_of_their_names() {
        assert_eq!(PUBLIC_TENANT_ID, legacy_id("public"));
        assert_eq!(PLATFORM_TENANT_ID, legacy_id("anatta-auth"));
        assert_ne!(PUBLIC_TENANT_ID, PLATFORM_TENANT_ID);
    }

    #[test]
    fn the_public_id_as_a_claim_is_the_public_tenant() {
        assert_eq!(
            TenantId::from_claim("17267350133765412090"),
            Ok(PUBLIC_TENANT_ID)
        );
        assert_eq!(
            TenantId::from_claim("9680926541668053385"),
            Ok(PLATFORM_TENANT_ID)
        );
    }

    #[test]
    fn from_claim_reads_the_canonical_decimal() {
        for n in [1, 2, 9, 10, 42, u64::from(u32::MAX), u64::MAX - 1, u64::MAX] {
            let id = TenantId::from_claim(&n.to_string()).unwrap();
            assert_eq!(id.get(), n);
            assert_eq!(id.segment(), n);
            assert_eq!(id.to_string(), n.to_string());
            assert_eq!(n.to_string().parse::<TenantId>(), Ok(id));
            assert_eq!(TenantId::from_const(n), Some(id));
        }
        assert_eq!(TenantId::from_const(0), None);
    }

    #[test]
    fn from_claim_refuses_every_other_text() {
        use TenantIdError::{Empty, LeadingZero, NotDigits, Overflow};
        for (claim, why) in [
            ("", Empty),
            ("0", LeadingZero),
            ("00", LeadingZero),
            ("007", LeadingZero),
            ("+7", NotDigits),
            ("-1", NotDigits),
            (" 42", NotDigits),
            ("42 ", NotDigits),
            ("4 2", NotDigits),
            ("\t42", NotDigits),
            ("42\n", NotDigits),
            ("0x2a", NotDigits),
            ("2a", NotDigits),
            ("7.0", NotDigits),
            ("1e3", NotDigits),
            ("public", NotDigits),
            ("acme", NotDigits),
            ("٣", NotDigits),
            ("４２", NotDigits),
            ("18446744073709551616", Overflow),
            ("99999999999999999999999", Overflow),
        ] {
            assert_eq!(TenantId::from_claim(claim), Err(why), "{claim:?}");
            assert!(claim.parse::<TenantId>().is_err(), "{claim:?}");
        }
    }

    #[test]
    fn serde_writes_and_reads_the_canonical_text() {
        let id = TenantId::from_claim("15442934347416025529").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"15442934347416025529\"");
        assert_eq!(serde_json::from_str::<TenantId>(&json).unwrap(), id);
        for refused in ["\"007\"", "\"0\"", "\"acme\"", "\"\"", "7", "null"] {
            assert!(
                serde_json::from_str::<TenantId>(refused).is_err(),
                "{refused}"
            );
        }
    }

    #[test]
    fn an_arn_built_with_the_segment_names_the_same_tenant() {
        for id in [PUBLIC_TENANT_ID, PLATFORM_TENANT_ID, legacy_id("anatta")]
            .into_iter()
            .chain([1, u64::MAX].into_iter().filter_map(TenantId::from_const))
        {
            let arn = ArnBuilder::new()
                .service_str("iam")
                .tenant(id.segment())
                .wami_instance("999888777")
                .resource("user", "77557755")
                .build()
                .unwrap();
            let parsed: WamiArn = arn.to_string().parse().unwrap();
            assert_eq!(TenantId::of_arn(&parsed), Some(id));
            assert_eq!(parsed.tenant_path, id.path());
        }
    }

    #[test]
    fn of_arn_refuses_the_root_and_nested_paths() {
        let arn = |segments: Vec<u64>| {
            ArnBuilder::new()
                .service_str("iam")
                .tenant_hierarchy(segments)
                .wami_instance("999888777")
                .resource("user", "77557755")
                .build()
                .unwrap()
        };
        assert_eq!(TenantId::of_arn(&arn(vec![ROOT_TENANT_ID])), None);
        assert_eq!(TenantId::of_arn(&arn(vec![7, 8])), None);
        assert_eq!(TenantId::of_arn(&arn(vec![7])), TenantId::from_const(7));
    }
}

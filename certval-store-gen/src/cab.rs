//! Reading a signed Microsoft cabinet.
//!
//! Two publishers this generator takes material from ship it inside a CAB: Microsoft's root
//! program (`authrootstl.cab`, carrying `authroot.stl`) and the TPM vendor roots
//! (`TrustedTpm.cab`). Both are Authenticode-signed, and for both the signature is the point
//! rather than packaging: nothing inside either cabinet is signed on its own, so what makes a
//! member trust material instead of bytes off an HTTP URL is that the cabinet around it verifies.
//! That check lives here rather than in each adapter so the two cannot come to differ about what
//! counts as verified.
//!
//! ## Two ways a cabinet's contents can be trusted, and the header says which
//!
//! ```text
//! TrustedTpm.cab     flags 0x0004 (cfhdrRESERVE_PRESENT)   signature in the reserved area
//! authrootstl.cab    flags 0x0000                          no reserved area, no signature
//! ```
//!
//! A CAB's Authenticode signature lives in the per-cabinet **reserved area**, which exists only
//! when `cfhdrRESERVE_PRESENT` is set. So a cabinet either vouches for its members or it is plain
//! packaging, and [`is_signed`] is how to tell before deciding which route to take:
//!
//! 1. **The cabinet vouches.** [`open_verified`] checks the Authenticode signature and hands back
//!    members that need no signature of their own. `TrustedTpm.cab` works this way: it carries
//!    thousands of bare `.crt` files, none of them signed.
//! 2. **A member vouches for itself.** [`members`] unpacks and verifies nothing, and the caller
//!    checks whatever the member carries. `authrootstl.cab` works this way: one member,
//!    `authroot.stl`, which is a CMS `SignedData` holding its own signature and chain.
//!
//! Taking route 1 on an unsigned cabinet is a refusal, not a pass -- [`verify`] says so rather than
//! finding no signature and shrugging -- and taking route 2 on a signed cabinet silently discards
//! the signature. Neither mistake is detectable from the members, which is why the flag is read
//! here and exposed rather than left implicit.
//!
//! This module decides nothing about the members. Which of them is trust material, how a name maps
//! to an environment, what to do with a certificate that builds no path — all of that is the
//! adapter's, because it differs per publisher. What comes back is names and bytes.
//!
//! Members are read whole into memory. A cabinet is compressed, so a modest file expands to
//! several times its size; both of the ones this generator reads are tens of megabytes at most,
//! and an adapter that walks hundreds of members wants them all anyway.
//!
//! Names come back exactly as the cabinet spells them, **with backslashes** —
//! `AMD\IntermediateCA\AMD-fTPM-ECC-RNFamily.crt`. They are paths in a Windows archive, not paths
//! on this host: do not hand one to `Path::new` and do not assume the separator. An adapter that
//! reads structure out of a name should split on `\\` itself, where the choice is visible.
//!
//! MSZIP's preset-dictionary trap — each block's deflate stream continues from the previous
//! block's output, so decompressing a block on its own fails with "invalid distance too far back"
//! — is the `cab` crate's problem here, and it handles it. It is worth knowing about because
//! anything that reaches into a cabinet by hand hits it immediately.
//!
//! ## Why this is behind a feature
//!
//! Verification is `tpm_cab_verify`, which brings the `authenticode` fork and its own certval
//! graph. A provider crate's build script that only refreshes a stream should not carry any of
//! that, so `cab` is off unless something asks for it — the same bargain `fetch` makes.

use std::io::{Cursor, Read};

use anyhow::{anyhow, bail, Context, Result};

use certval::{CertificationPathSettings, PkiEnvironment};
use tpm_cab_verify::CabVerifyParts;

/// One file inside a cabinet, named as the cabinet names it.
pub struct Member {
    /// The member's name, verbatim, backslashes and all.
    pub name: String,
    /// The member's contents, decompressed.
    pub bytes: Vec<u8>,
}

/// Whether a cabinet carries a per-cabinet reserved area, which is where an Authenticode
/// signature lives.
///
/// `false` does not mean "unsigned material": it means the *cabinet* is packaging, and whatever
/// authenticity its members have, they carry themselves. Read from `CFHEADER.flags`, the only
/// place that says so, rather than inferred from a verification failure.
pub fn is_signed(bytes: &[u8]) -> Result<bool> {
    // CFHEADER: signature[4] reserved1 cbCabinet reserved2 coffFiles reserved3 versionMinor
    // versionMajor cFolders cFiles flags, so `flags` sits at offset 30 as a little-endian u16.
    if bytes.len() < 32 {
        bail!("input is too short to be a cabinet");
    }
    if &bytes[..4] != b"MSCF" {
        bail!("input does not start with the MSCF cabinet signature");
    }
    const RESERVE_PRESENT: u16 = 0x0004;
    let flags = u16::from_le_bytes([bytes[30], bytes[31]]);
    Ok(flags & RESERVE_PRESENT != 0)
}

/// Verify the Authenticode signature over a cabinet.
///
/// The signer and the timestamp signer are checked against the Microsoft roots `tpm_cab_verify`
/// carries, and the signer's certificate is validated at the genTime of the verified RFC 3161
/// timestamp rather than at now — which is how Windows treats a timestamped Authenticode
/// signature, and the only way a cabinet published before its short-lived signing certificate
/// expired still verifies today. So this says "this cabinet was validly signed when it was
/// published", not "it is current". How old the material is, the caller answers separately, out of
/// what the cabinet itself states.
pub fn verify(bytes: &[u8]) -> Result<()> {
    // Said plainly, because the alternative is a parse error thirty frames down that reads like a
    // corrupt download. An unsigned cabinet is not a broken one; it is one whose members have to
    // vouch for themselves, and a caller that reached here has taken the wrong route.
    if !is_signed(bytes)? {
        bail!(
            "this cabinet has no reserved area, so it carries no Authenticode signature; its \
             members' authenticity, if any, is their own (see the module documentation)"
        );
    }

    let parts = CabVerifyParts::new(Cursor::new(bytes))
        .map_err(|e| anyhow!("{e:?}"))
        .context("the cabinet could not be read for signature verification")?;

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let cps = CertificationPathSettings::new();

    // Verification reaches a timestamp authority's revocation data, which is asynchronous, and the
    // callers here are a build script and a CLI. Same current-thread runtime as `verify.rs`, built
    // where it is used rather than held.
    runtime()?
        .block_on(parts.verify(&mut pe, &cps))
        .map_err(|e| anyhow!("{e:?}"))
        .context("the cabinet's Authenticode signature did not verify")
}

/// Every member of a cabinet, in the order the cabinet lists them.
///
/// Says nothing about the signature: call [`open_verified`] unless you have a reason to look
/// inside an unverified cabinet, such as reading the version it claims to be in order to decide
/// whether it is worth verifying at all.
pub fn members(bytes: &[u8]) -> Result<Vec<Member>> {
    let mut cabinet =
        ::cab::Cabinet::new(Cursor::new(bytes)).context("input is not a readable cabinet")?;

    // Names first, bodies second, because reading a member takes the cabinet mutably while
    // walking the directory borrows it.
    let names: Vec<String> = cabinet
        .folder_entries()
        .flat_map(|folder| folder.file_entries().map(|file| file.name().to_string()))
        .collect();

    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let mut bytes = vec![];
        cabinet
            .read_file(&name)
            .with_context(|| format!("{name} could not be read from the cabinet"))?
            .read_to_end(&mut bytes)
            .with_context(|| format!("{name} could not be decompressed"))?;
        out.push(Member { name, bytes });
    }
    Ok(out)
}

/// One named member, for a cabinet whose interesting content is a single file — `authroot.stl`
/// inside `authrootstl.cab`, or the `version.txt` beside the TPM certificates.
///
/// The name has to match exactly, including any backslashes. A miss is an error naming what the
/// cabinet does hold, since the usual cause is a publisher renaming something.
pub fn member(bytes: &[u8], name: &str) -> Result<Vec<u8>> {
    let members = members(bytes)?;
    members
        .into_iter()
        .find(|m| m.name == name)
        .map(|m| m.bytes)
        .ok_or_else(|| anyhow!("the cabinet holds no member named {name}"))
}

/// Verify a cabinet, then read every member out of it.
///
/// The entry point an adapter should use: taking the members is what the verification was for, and
/// two separate calls are two places for the second one to be forgotten.
pub fn open_verified(bytes: &[u8]) -> Result<Vec<Member>> {
    verify(bytes)?;
    members(bytes)
}

/// The runtime the timestamp check's revocation fetching is driven on. Current-thread, built where
/// it is needed, for the reason given on `verify::runtime`.
fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("a runtime for the cabinet's timestamp verification could not be started")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header flag is the discriminator between the two routes, so reading it wrongly sends a
    /// caller down the wrong one. Checked against the two cabinets this generator reads, by their
    /// measured flags: TrustedTpm.cab is 0x0004 and authrootstl.cab is 0x0000.
    #[test]
    fn the_reserved_area_flag_decides_which_route_applies() {
        let mut header = [0u8; 32];
        header[..4].copy_from_slice(b"MSCF");
        header[30..32].copy_from_slice(&0x0004u16.to_le_bytes());
        assert!(is_signed(&header).unwrap());
        header[30..32].copy_from_slice(&0x0000u16.to_le_bytes());
        assert!(!is_signed(&header).unwrap());
        // And an unsigned cabinet is refused by the verifying route rather than passing it.
        assert!(verify(&header).is_err());
    }

    /// Both readers have to refuse a file that is not a cabinet rather than reporting it empty --
    /// an empty member list is how a caller would otherwise see a truncated download.
    #[test]
    fn something_that_is_not_a_cabinet_is_refused() {
        let not_a_cab = b"MSCF is the signature this is missing";
        assert!(members(not_a_cab).is_err());
        assert!(verify(not_a_cab).is_err());
        assert!(member(not_a_cab, "authroot.stl").is_err());
    }

    /// An empty input is the shape a failed fetch leaves behind, and it must not read as a
    /// cabinet with nothing in it.
    #[test]
    fn an_empty_input_is_refused() {
        assert!(members(&[]).is_err());
        assert!(verify(&[]).is_err());
    }
}

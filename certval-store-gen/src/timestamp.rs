//! The RFC 3161 timestamp on an InstallRoot stream member, verified.
//!
//! A stream states no date of its own: DoD's `SignerInfo` carries `contentType` and
//! `messageDigest` and nothing else. What it does carry, in `[1] unsignedAttrs`, is an
//! `id-aa-timeStampToken` whose `TSTInfo.genTime` is a timestamp authority's statement that
//! the member's signature existed at that moment. That answers two questions at once: when
//! the stream was published, and what time to validate its signer at.
//!
//! Both answers depend on the token being verified, and this module is the reason it now is.
//! The token sits *outside* the member signature -- it is made after that signature exists,
//! so it cannot be inside it -- which means anyone handing over a stream can rewrite it.
//! Taking `genTime` on faith and validating the signer at it would be worse than not checking
//! validity at all: the holder of an expired or compromised DoD code-signing key could name
//! the time that makes their key valid again. Verified, the same value turns "we do not check
//! whether the signer had expired" into "the signer was valid when a third party attests the
//! signature existed".
//!
//! DISA does not run the timestamp authority. The tokens on all three committed streams chain
//! `Sectigo Public Time Stamping Signer R36` -> `... CA R36` -> `... Root R46`, so the DoD
//! roots in [`crate::verify`] reach none of it and a second anchor has to be pinned here.

use anyhow::{anyhow, Context, Result};

use cms::content_info::ContentInfo;
use cms::signed_data::SignerInfo;
use const_oid::db::rfc3161::ID_AA_TIME_STAMP_TOKEN;
use const_oid::db::rfc5280::ID_KP_TIME_STAMPING;
use const_oid::db::rfc5912::ID_SHA_256;
use der::asn1::{Any, GeneralizedTime, Int, ObjectIdentifier, OctetString};
use der::{Decode, Reader, SliceReader};
use sha2::{Digest, Sha256};

use certval::{PkiEnvironment, TimeOfInterest};
use rfc5934::signed::SignedData;

use crate::verify::{chain_to, verify_signed_data, ChainCheck, Revocation};

/// The anchor an InstallRoot timestamp is chained to.
///
/// One certificate, and a different one from `verify::INSTALLROOT_ANCHORS`: DISA signs
/// its streams with a DoD code-signing certificate and has them timestamped by a commercial
/// authority, so the two chains terminate in different places. Pinning the DoD roots for this
/// would fail every stream; pinning this for the stream signer would accept a timestamping
/// certificate as a publisher.
///
/// This is the **self-signed** Root R46 (`SHA256:4941B001...3AC046A5`, valid to 2046-03-21),
/// fetched from `http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.p7c` rather than taken
/// from a stream, for the same reason the DoD roots are not taken from a stream's `Root` message.
/// The streams themselves carry the USERTrust cross-signed variant instead, which shares this
/// key: a path terminates here by name and key regardless of which variant travelled with the
/// token.
static TIMESTAMP_ANCHORS: &[&[u8]] = &[include_bytes!(
    "../anchors/Sectigo_Public_Time_Stamping_Root_R46.der"
)];

/// Allowance for clock skew between the timestamp authority and the host running this, when
/// affirming that a token does not claim a time in the future.
const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// What a member's timestamp says, once it has been verified.
///
/// [`None`] where a member carries no `id-aa-timeStampToken` at all. Nothing in RFC 5934
/// requires one, so its absence is reported rather than refused -- but a token that is present
/// and does not verify fails the member, because a stream whose timestamp has been tampered
/// with is not a stream to generate a trust store from.
pub fn verified_gen_time(
    pe: &PkiEnvironment,
    si: &SignerInfo,
    revocation: Revocation,
) -> Result<Option<TimeOfInterest>> {
    let Some(value) = token_attribute(si) else {
        return Ok(None);
    };
    let token = token_signed_data(&value)
        .context("the timeStampToken attribute is neither a TimeStampToken nor a TimeStampResp")?;
    let tst = TstInfo::from_token(&token)?;

    // 1. The token is about *this* signature. Without this the token is a valid timestamp over
    //    something else entirely, and could be lifted from any other signed object.
    if tst.imprint_algorithm != ID_SHA_256 {
        return Err(anyhow!(
            "the timestamp's messageImprint uses {}; only SHA-256 is implemented",
            tst.imprint_algorithm
        ));
    }
    let signature_digest = Sha256::digest(si.signature.as_bytes());
    if tst.imprint.as_bytes() != signature_digest.as_slice() {
        return Err(anyhow!(
            "the timestamp's messageImprint is not the digest of this member's signature, so it \
             attests to some other signature"
        ));
    }

    // 2. A genuine timestamp is in the past. Rejecting a future one stops a forger post-dating a
    //    signature into a window where a compromised key was still valid. An unreadable clock
    //    fails closed: `now` of 0 makes every genTime a future one.
    let gen_time = TimeOfInterest(tst.gen_time.to_date_time());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if gen_time.as_unix_secs() > now + MAX_CLOCK_SKEW_SECS {
        return Err(anyhow!(
            "the timestamp claims {gen_time}, which is in the future; refusing to use it"
        ));
    }

    // 3. The token was signed by the authority it names, and 4. that authority is one to trust.
    //    Validated at genTime itself, like the stream signer it dates: timestamping certificates
    //    are short-lived by design, so validating at the current time would fail every stream
    //    older than a couple of years.
    let tsa = verify_signed_data(pe, &token, "the timestamp token")?;
    chain_to(
        &tsa,
        token.certificates.as_ref(),
        ChainCheck {
            anchors: TIMESTAMP_ANCHORS,
            eku: ID_KP_TIME_STAMPING,
            // The EKU is required across the whole path, not just on the signer: an intermediate
            // that omits timeStamping narrows what its subordinates may do, as RFC 5280 intends.
            eku_across_path: true,
            // The current time, and not `genTime` as the stream signer is validated at. The two
            // are asked different questions. `genTime` is what the token *asserts*, so validating
            // the authority as of its own assertion assumes what is to be shown; the reason to
            // believe a timestamp at all is that the authority vouching for it is one to trust
            // now. A Sectigo timestamping signer runs into the 2030s -- R35 to 2035-04-14, R36 to
            // 2036-03-21 -- so requiring it today costs nothing until then, and when it does
            // lapse the answer is a freshly fetched stream, which DISA timestamps again.
            toi: TimeOfInterest::now(),
            // Nothing travels with a token: the responses a stream staples are about the DoD
            // signing chain, which this is not part of. So this is the chain a responder has to be
            // asked about, and whether it may be asked is the caller's policy -- a consumer's build
            // is promised no fetching, and the gate that does ask runs in CI on the same bytes.
            stapled: &[],
            require_revocation: revocation.fetches(),
            fetch_missing: revocation.fetches(),
            what: "the timestamp authority",
        },
    )?;

    Ok(Some(gen_time))
}

/// The `id-aa-timeStampToken` attribute value, from whichever attribute set carries it.
///
/// The unsigned set is where RFC 3161 puts it and where DoD does, measured on all three
/// committed streams. The signed set is read too: a timestamp cannot cover the signature from
/// inside it, but a publisher could still file one there over the content, and reading both
/// costs nothing. What such a token attests to is checked either way -- the imprint has to be
/// the digest of this member's signature -- so a misfiled one fails on its own terms.
fn token_attribute(si: &SignerInfo) -> Option<Any> {
    si.unsigned_attrs
        .iter()
        .flat_map(|a| a.iter())
        .chain(si.signed_attrs.iter().flat_map(|a| a.iter()))
        .filter(|attr| attr.oid == ID_AA_TIME_STAMP_TOKEN)
        .find_map(|attr| attr.values.get(0).cloned())
}

/// The `SignedData` of a timestamp token, from either shape the attribute is found in.
///
/// RFC 3161 defines the attribute value as a `TimeStampToken`, i.e. a `ContentInfo` wrapping the
/// `SignedData`. DoD stores the whole **`TimeStampResp`** instead -- the `PKIStatusInfo` the
/// authority replied with, followed by that same token -- so a decoder that reads only the
/// defined shape finds nothing here. Both are accepted, the defined one first.
fn token_signed_data(value: &Any) -> Option<SignedData> {
    if let Ok(ci) = value.decode_as::<ContentInfo>() {
        if let Ok(sd) = ci.content.decode_as::<SignedData>() {
            return Some(sd);
        }
    }
    let mut reader = SliceReader::new(value.value()).ok()?;
    let _status: Any = reader.decode().ok()?;
    let ci: ContentInfo = reader.decode().ok()?;
    ci.content.decode_as::<SignedData>().ok()
}

/// The fields of a `TSTInfo` this needs: what the token covers, and when.
struct TstInfo {
    imprint_algorithm: ObjectIdentifier,
    imprint: OctetString,
    gen_time: GeneralizedTime,
}

impl TstInfo {
    /// Read a `TSTInfo` out of a timestamp token's encapsulated content.
    ///
    /// The fields are read positionally as far as `genTime` and the optional tail is left
    /// unread, which is why this uses a reader rather than a derived structure: everything
    /// after `genTime` is optional and unwanted, and a structure would have to model all of it
    /// to reach the fields before it.
    fn from_token(token: &SignedData) -> Result<TstInfo> {
        let econtent = token
            .encap_content_info
            .econtent
            .as_ref()
            .ok_or_else(|| anyhow!("the timestamp token carries no TSTInfo"))?;
        let tst_info = Any::from_der(econtent.value())
            .context("the timestamp token's content is not a TSTInfo SEQUENCE")?;

        let mut reader = SliceReader::new(tst_info.value())
            .context("the timestamp token's TSTInfo cannot be read")?;
        let _version: Int = reader
            .decode()
            .map_err(|e| anyhow!("the TSTInfo's version does not decode: {e}"))?;
        let _policy: ObjectIdentifier = reader
            .decode()
            .map_err(|e| anyhow!("the TSTInfo's policy does not decode: {e}"))?;
        let imprint: Any = reader
            .decode()
            .map_err(|e| anyhow!("the TSTInfo's messageImprint does not decode: {e}"))?;
        let _serial_number: Int = reader
            .decode()
            .map_err(|e| anyhow!("the TSTInfo's serialNumber does not decode: {e}"))?;
        // Strict: a genTime with fractional seconds is legal in RFC 3161 and would be refused
        // here. None of the committed streams carries one, and a stream that did would fail
        // loudly rather than quietly lose its date.
        let gen_time: GeneralizedTime = reader
            .decode()
            .map_err(|e| anyhow!("the TSTInfo's genTime does not decode: {e}"))?;

        let mut reader = SliceReader::new(imprint.value())
            .context("the TSTInfo's messageImprint cannot be read")?;
        let algorithm: Any = reader
            .decode()
            .map_err(|e| anyhow!("the messageImprint's hashAlgorithm does not decode: {e}"))?;
        let imprint: OctetString = reader
            .decode()
            .map_err(|e| anyhow!("the messageImprint's digest does not decode: {e}"))?;
        let mut reader = SliceReader::new(algorithm.value())
            .context("the messageImprint's hashAlgorithm cannot be read")?;
        let imprint_algorithm: ObjectIdentifier = reader
            .decode()
            .map_err(|e| anyhow!("the messageImprint's hashAlgorithm OID does not decode: {e}"))?;

        Ok(TstInfo {
            imprint_algorithm,
            imprint,
            gen_time,
        })
    }
}

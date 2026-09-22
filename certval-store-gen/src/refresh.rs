//! Refreshing a committed generator input from the stream it was collected from.
//!
//! A provider crate commits the stream it generates from, so that its build is reproducible
//! and an offline consumer still gets trust material. That makes the committed copy a cache
//! of something DISA republishes, and a cache with no refresh path goes stale quietly.
//!
//! This is the refresh, and it is deliberately narrow. It fetches, requires the bytes to
//! parse as a stream carrying the population asked for, and replaces the committed file only
//! when the publisher's own date is newer than the date already in hand. Everything that
//! decides *whether* to refresh lives in the caller: a build script gates this on being in a
//! source checkout, because a consumer building a published crate must never reach the
//! network. See `certval_stores_nipr`'s `build.rs`.
//!
//! **A network failure is not an error.** The committed stream is still good material, and a
//! build that failed because DISA was unreachable would be worse than one that builds last
//! week's anchors. Every unhappy path here ends in [`Outcome`] rather than `Err`, so a caller
//! cannot accidentally propagate one into a `panic!`.
//!
//! **A bad signature is a refusal, and lands here as [`Outcome::Kept`].** `adapters::tamp`
//! rejects a stream any of whose members fails verification, so a fetch that returns corrupted
//! or tampered bytes cannot replace the committed file -- the good material already in hand
//! stands and the build carries on. This is the case the whole gate exists for: a committed
//! stream a person put there needs the check least, and one pulled off the network needs it
//! most.

use std::path::Path;

use certval::PkiEnvironment;

use crate::adapters::tamp::{self, Population};
use crate::verify::Revocation;

/// Largest stream this will read. The four published `.ir4` files are 200-300 KB; this is two
/// orders of magnitude above that, which is enough headroom to be uninteresting and still a
/// bound, so a redirect to something enormous cannot be read into memory.
const MAX_STREAM_BYTES: u64 = 16 * 1024 * 1024;

/// What a refresh did, and why.
///
/// Every variant is a normal outcome. A caller logs these and carries on; none of them is a
/// reason to fail a build.
#[derive(Debug)]
pub enum Outcome {
    /// The committed file was replaced by a newer published stream.
    Replaced {
        /// The date the committed stream stated, where it stated one.
        was: Option<String>,
        /// The date the newly written stream states.
        now: String,
    },
    /// The fetched stream is the one already committed, by publication date.
    Current { published: Option<String> },
    /// The fetched stream is *older* than the committed one, so it was not written.
    ///
    /// Worth its own variant rather than folding into `Current`: a publisher serving
    /// something older than what is in hand is either a rollback or a mirror serving stale
    /// content, and both are worth a person seeing.
    Older {
        committed: Option<String>,
        offered: Option<String>,
    },
    /// Nothing was fetched, or what came back could not be used. The committed file stands.
    Kept { why: String },
}

/// Fetch `url` and replace `committed` if what comes back is a newer stream for `population`.
///
/// The comparison is on the date established for the stream (`TSTInfo.genTime` from the verified
/// timestamp on its members), never on file mtime or HTTP metadata: a republished but identical
/// stream must not churn the committed file, and a file copied between machines must not read
/// as new material.
pub fn stream(url: &str, committed: &Path, population: Population) -> Outcome {
    let fetched = match fetch(url) {
        Ok(bytes) => bytes,
        Err(e) => return Outcome::Kept { why: e.to_string() },
    };

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    // Parsing is the validation. A stream that does not yield the population asked for is not
    // material for this environment, whatever it is, and must not overwrite something that is.
    let offered = match tamp::build(&pe, &fetched, population, Revocation::StapledAndFetched) {
        Ok(inputs) => inputs.published,
        Err(e) => {
            return Outcome::Kept {
                why: format!("the stream fetched from {url} did not parse: {e}"),
            }
        }
    };

    let held = match std::fs::read(committed) {
        Ok(bytes) => match tamp::build(&pe, &bytes, population, Revocation::StapledAndFetched) {
            Ok(inputs) => Some(inputs.published),
            Err(e) => {
                // The committed file is unreadable as a stream, so there is nothing to compare
                // against and nothing worth keeping. Taking the fetched one is the repair.
                log::warn!(
                    "{} did not parse ({e}); replacing it with the stream fetched from {url}",
                    committed.display()
                );
                None
            }
        },
        Err(_) => None,
    };

    match (&held, &offered) {
        // Nothing in hand, or nothing comparable: write what was fetched.
        (None, _) => write(committed, &fetched, None, offered),
        // Neither side states a date. Without one there is no way to tell a refresh from a
        // churn, so the committed file stands rather than being rewritten on every build.
        (Some(None), None) => Outcome::Kept {
            why: format!(
                "neither {} nor the stream at {url} states a publication date",
                committed.display()
            ),
        },
        (Some(None), Some(_)) => write(committed, &fetched, None, offered),
        (Some(Some(_)), None) => Outcome::Kept {
            why: format!("the stream at {url} states no publication date"),
        },
        (Some(Some(have)), Some(get)) => match get.as_str().cmp(have.as_str()) {
            // ISO-8601 dates sort lexicographically, which is why the adapter writes them
            // that way.
            std::cmp::Ordering::Greater => write(committed, &fetched, Some(have.clone()), offered),
            std::cmp::Ordering::Equal => Outcome::Current {
                published: Some(have.clone()),
            },
            std::cmp::Ordering::Less => Outcome::Older {
                committed: Some(have.clone()),
                offered: Some(get.clone()),
            },
        },
    }
}

/// Write the fetched stream over the committed one.
fn write(path: &Path, bytes: &[u8], was: Option<String>, now: Option<String>) -> Outcome {
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return Outcome::Kept {
                why: format!("{} could not be created: {e}", parent.display()),
            };
        }
    }
    match std::fs::write(path, bytes) {
        Ok(()) => Outcome::Replaced {
            was,
            // A stream that parsed but states no date still replaced something; saying so
            // beats inventing a date for the report.
            now: now.unwrap_or_else(|| "an undated stream".to_string()),
        },
        Err(e) => Outcome::Kept {
            why: format!("{} could not be written: {e}", path.display()),
        },
    }
}

/// Why a fetch did not produce bytes.
///
/// The distinction is load-bearing for a mesh walk and irrelevant for a single stream, which is
/// why it lives here rather than being flattened into a message. A publisher answering "there is
/// nothing at this URI" has told you something true about its own repository; a connection that
/// never completed has told you nothing, and a walk that treats the two alike either refuses to
/// ever refresh or silently ships a subset.
pub(crate) enum FetchError {
    /// The server answered, with a status saying there is nothing to have.
    Absent(String),
    /// No usable answer: DNS, connection, timeout, a 5xx, or a body that would not read.
    Unreachable(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Absent(m) | FetchError::Unreachable(m) => f.write_str(m),
        }
    }
}

/// The body of a conditional GET and the validator to store for next time, or `None` when the
/// server said nothing has changed.
///
/// Behind `authroot` rather than `fetch`, because that is where the only caller is: an InstallRoot
/// stream is compared by the publication date inside it, so nothing else here asks a server
/// whether it has anything new. A second caller arriving under `fetch` alone will fail to compile
/// and can move this gate then, which is better than an `allow(dead_code)` that hides the day it
/// stops being true.
#[cfg(feature = "authroot")]
pub(crate) type Conditional = Option<(Vec<u8>, Option<String>)>;

/// GET `url` unless the server says it has not changed since `since`.
///
/// `Ok(None)` is a 304: the copy in hand is current, and the point of asking. A publisher that
/// changes its material monthly answers this way on all but one request, which is what makes a
/// refresh cheap enough to run on every build in a working tree.
///
/// `Ok(Some((bytes, last_modified)))` carries the validator to store for next time, where the
/// server offers one. A server that offers none is not an error -- the caller then falls back to
/// whatever the material states about itself, which is the stronger check anyway.
#[cfg(feature = "authroot")]
pub(crate) fn fetch_if_modified(url: &str, since: Option<&str>) -> Result<Conditional, FetchError> {
    let mut request = ureq::get(url);
    if let Some(since) = since {
        request = request.header("If-Modified-Since", since);
    }

    let mut response = match request.call() {
        // Not modified reaches here two ways depending on how the client is configured: as a
        // status error below, and -- measured against this CDN -- as a perfectly ordinary response
        // with status 304 and no body. Reading only the first leaves a caller holding zero bytes
        // and calling them content, which is how a no-op refresh turns into "what the server sent
        // is not a cabinet".
        Ok(response) if response.status() == 304 => return Ok(None),
        Ok(response) => response,
        // Not modified is an answer, not a failure, and it arrives here as a status error because
        // ureq treats every non-2xx that way. Checked before the 4xx/5xx split below, which would
        // otherwise file it as unreachable.
        Err(ureq::Error::StatusCode(304)) => return Ok(None),
        Err(e) => {
            let message = format!("{url} could not be fetched: {e}");
            return Err(match &e {
                ureq::Error::StatusCode(code) => match (400..500).contains(code) {
                    true => FetchError::Absent(message),
                    false => FetchError::Unreachable(message),
                },
                _ => FetchError::Unreachable(message),
            });
        }
    };

    let last_modified = response
        .headers()
        .get("last-modified")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_STREAM_BYTES)
        .read_to_vec()
        .map_err(|e| FetchError::Unreachable(format!("{url} could not be read: {e}")))?;

    Ok(Some((bytes, last_modified)))
}

/// GET `url` into memory, bounded by [`MAX_STREAM_BYTES`].
pub(crate) fn fetch(url: &str) -> Result<Vec<u8>, FetchError> {
    let mut response = ureq::get(url).call().map_err(|e| {
        let message = format!("{url} could not be fetched: {e}");
        // 4xx is the server's own answer about its own repository. Everything else -- 5xx
        // included, since a server erroring is not a server saying "nothing here" -- leaves the
        // question open.
        match &e {
            ureq::Error::StatusCode(code) => match (400..500).contains(code) {
                true => FetchError::Absent(message),
                false => FetchError::Unreachable(message),
            },
            _ => FetchError::Unreachable(message),
        }
    })?;

    response
        .body_mut()
        .with_config()
        .limit(MAX_STREAM_BYTES)
        .read_to_vec()
        .map_err(|e| FetchError::Unreachable(format!("{url} could not be read: {e}")))
}

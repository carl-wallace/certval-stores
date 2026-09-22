//! Checks this crate's committed material on every build.
//!
//! Every file in `roots/` must hash to its own name. That is the same comparison that admitted the
//! certificate in the first place: Microsoft's trust list is signed and the certificates it names
//! are not, so what binds them is the SHA-1 the list gave for each. A few hundred digests over
//! half a megabyte, and `sha1` is the only build dependency this crate has.
//!
//! **Refreshing is not here.** It is `certval-store-gen authroot --crate certval_stores_msft`,
//! run by a maintainer or by the scheduled job that opens a pull request. It needs
//! `tpm_cab_verify`, the `authenticode` fork and a pre-release ASN.1 stack, whose patch-table
//! entries do not travel with a git dependency -- so a build script that could refresh would make
//! every consumer resolve them to embed a store it never refreshes.

use std::path::Path;

use sha1::{Digest, Sha1};

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=roots");

    if let Err(e) = check_committed() {
        panic!("this crate's committed material does not check out: {e}");
    }
}

/// Every file in `roots/` hashes to its own name.
fn check_committed() -> Result<(), String> {
    let dir = Path::new("roots");
    let entries = std::fs::read_dir(dir).map_err(|e| format!("roots/ could not be read: {e}"))?;
    let mut checked = 0;
    for entry in entries {
        let path = entry
            .map_err(|e| format!("roots/ holds an unreadable entry: {e}"))?
            .path();
        if path.extension().and_then(|e| e.to_str()) != Some("der") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_ascii_uppercase();
        let bytes =
            std::fs::read(&path).map_err(|e| format!("{} is unreadable: {e}", path.display()))?;
        let digest: String = Sha1::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        if digest != name {
            return Err(format!(
                "{} does not hash to its own name ({digest}); it is not the certificate the \
                 trust list named",
                path.display()
            ));
        }
        checked += 1;
    }
    match checked {
        0 => Err("roots/ holds no certificates".to_string()),
        _ => Ok(()),
    }
}

# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.
See the README's "Versioning" section for what each level means for the trust material.

## [1.0.0-rc.2] - 2026-11-06

### Changed
- The stores follow Microsoft's root program list published 2026-10-23, from 2026-08-25. Their trust
  anchors change:
  - Removed from every store, the program no longer listing them: emSign Root CS CA - G3, emSign ECC
    Root CA - G3, emSign Root TLS CA - G3, emSign Root Client Auth CA - G3, emSign Root TSA CA - G3,
    emSign Root SMIME CA - G3 and Sectigo (AAA).
  - ANCERT Certificados CGN V2 and Saudi National Root CA are no longer trusted for server
    authentication, so `msft_tls` leaves them out; the other stores keep them.
  - Roots per store: `msft_all` 350 (from 357), `msft_tls` 229 (234), `msft_client_auth` 264 (267),
    `msft_email` 212 (215), `msft_code_signing` 140 (143), `msft_timestamping` 159 (162).
- The minimum supported Rust version is 1.89.

## [1.0.0-rc.1] - 2026-10-29

Initial release, with a store behind each of the `msft_all`, `msft_tls`, `msft_client_auth`, `msft_email`, `msft_code_signing` and `msft_timestamping` features.

# Provenance

This implementation is original work under the MIT License.

The public `bitshiftza/fnb-api` project and the `yashiels/fnb-api` fork establish only that prior tooling and relevant Online Banking UI areas have existed. Their GPL-3.0 source code is not read or used as an implementation reference for M1 or later milestones.

Implementation inputs are limited to:

- the approved design in `docs/plan.md`;
- `docs/pages.md` produced from the owner's own M0 capture work;
- synthetic fixtures generated from the owner's captures and accepted after secret and personal-data scanning;
- public Go and operating-system API documentation;
- the read-only `yashiels/investec` repository for house CLI layout and build conventions.

Raw HAR files, real credentials, real cookies, the fixture generator and its private denylist remain outside this repository. Synthetic fixtures preserve only the minimum structure needed to test parsers and request routing.

No FNB mobile application API is reverse engineered. No FNB source code or proprietary client implementation is copied into this repository.

# Upstream submission inventory

**Source of truth:** the reviewed specifications on `opldotdev/BRCs` `master`. This inventory covers 14 individual submissions: 13 new proposals (178–189 and 191), plus an editorial amendment to the already-published BRC-190.

**Fork integration:** PRs [#6–#19](https://github.com/opldotdev/BRCs/pulls?q=is%3Apr+is%3Amerged) have been merged. BRC-178 is included. The two BRC-190 editorial corrections are submitted upstream in [PR #241](https://github.com/bsv-blockchain/BRCs/pull/241). The 13 new proposals have not been submitted upstream.

## Individual submission branches

Each `brc/<number>-<topic>` branch contains one proposal extracted from the integrated fork `master`, based directly on upstream `master`. This keeps each upstream diff focused. Opening several PRs from the same fork `master` head would include the same complete corpus, so `master` is the content source, not the submission head for every PR.

**Content check:** all 14 submission branches were compared with fork `master`. Every specification and example file is byte-for-byte identical, and every index entry is present. No proposal content is missing from fork `master`.

A comparison whose base repository is `bsv-blockchain/BRCs` shows what is missing from **upstream**, not from the OPL fork. The separate submission commits have different history from the original fork merges; that does not mean their content is unmerged.

Each branch contains only its specification, its index entries, and any static examples. This inventory is fork workflow documentation and is excluded from the individual upstream branches.

| BRC | Original draft | Specification | Merged fork PR | Individual upstream comparison | Earlier corpus references |
|---|---|---|---|---|---|
| 178 | 178 (unchanged) | [Collaborative Atomic Exchange for BRC-100 Wallets](./tokens/0178.md) | [#6](https://github.com/opldotdev/BRCs/pull/6) | [`brc/178-collaborative-exchange`](https://github.com/bsv-blockchain/BRCs/compare/master...opldotdev:BRCs:brc/178-collaborative-exchange?expand=1) | — |
| 179 | 500 | [Bitcom — Universal Bitcoin Computer: Decentralized Protocol Registry and Composition](./scripts/0179.md) | [#7](https://github.com/opldotdev/BRCs/pull/7) | [`brc/179-bitcom`](https://github.com/bsv-blockchain/BRCs/compare/master...opldotdev:BRCs:brc/179-bitcom?expand=1) | — |
| 180 | 501 | [B — Bitcoin Data Protocol](./scripts/0180.md) | [#8](https://github.com/opldotdev/BRCs/pull/8) | [`brc/180-b-protocol`](https://github.com/bsv-blockchain/BRCs/compare/master...opldotdev:BRCs:brc/180-b-protocol?expand=1) | 179 |
| 181 | 502 | [AIP — Author Identity Protocol](./scripts/0181.md) | [#9](https://github.com/opldotdev/BRCs/pull/9) | [`brc/181-aip`](https://github.com/bsv-blockchain/BRCs/compare/master...opldotdev:BRCs:brc/181-aip?expand=1) | 179, 180 |
| 182 | 503 | [MAP — Magic Attribute Protocol](./scripts/0182.md) | [#10](https://github.com/opldotdev/BRCs/pull/10) | [`brc/182-map`](https://github.com/bsv-blockchain/BRCs/compare/master...opldotdev:BRCs:brc/182-map?expand=1) | 179, 180, 181 |
| 183 | 504 | [Sigma — Transaction-Bound Script Signatures](./scripts/0183.md) | [#11](https://github.com/opldotdev/BRCs/pull/11) | [`brc/183-sigma`](https://github.com/bsv-blockchain/BRCs/compare/master...opldotdev:BRCs:brc/183-sigma?expand=1) | 179, 181, 182 |
| 184 | 505 | [Outpoint Content Addressing](./outpoints/0184.md) | [#12](https://github.com/opldotdev/BRCs/pull/12) | [`brc/184-content-addressing`](https://github.com/bsv-blockchain/BRCs/compare/master...opldotdev:BRCs:brc/184-content-addressing?expand=1) | 180 |
| 185 | 508 | [1Sat Ordinal Collections](./tokens/0185.md) | [#13](https://github.com/opldotdev/BRCs/pull/13) | [`brc/185-collections`](https://github.com/bsv-blockchain/BRCs/compare/master...opldotdev:BRCs:brc/185-collections?expand=1) | 183, 184 |
| 186 | 511 | [BAP — Bitcoin Attestation Protocol](./peer-to-peer/0186.md) | [#14](https://github.com/opldotdev/BRCs/pull/14) | [`brc/186-bap`](https://github.com/bsv-blockchain/BRCs/compare/master...opldotdev:BRCs:brc/186-bap?expand=1) | 179, 181 |
| 187 | 512 | [Bitcoin Schema — Social Data Types](./apps/0187.md) | [#15](https://github.com/opldotdev/BRCs/pull/15) | [`brc/187-social-schema`](https://github.com/bsv-blockchain/BRCs/compare/master...opldotdev:BRCs:brc/187-social-schema?expand=1) | 179, 180, 181, 182, 186 |
| 188 | 513 | [Encrypted Group Messaging over BRC-78](./peer-to-peer/0188.md) | [#16](https://github.com/opldotdev/BRCs/pull/16) | [`brc/188-group-messaging`](https://github.com/bsv-blockchain/BRCs/compare/master...opldotdev:BRCs:brc/188-group-messaging?expand=1) | 186 |
| 189 | 514 | [MAP State Resolution over a 1Sat Chain](./scripts/0189.md) | [#17](https://github.com/opldotdev/BRCs/pull/17) | [`brc/189-map-state`](https://github.com/bsv-blockchain/BRCs/compare/master...opldotdev:BRCs:brc/189-map-state?expand=1) | 179, 181, 182, 183 |
| 190 | published 190 | [Correct manifest integrity and room-ban references](./apps/0190.md) | [#19](https://github.com/opldotdev/BRCs/pull/19) | [`brc/190-editorial-repairs`](https://github.com/bsv-blockchain/BRCs/compare/master...opldotdev:BRCs:brc/190-editorial-repairs?expand=1) | — |
| 191 | 515 | [MAP Location Keys (`quadkey`, `world`, `coordinates.*`)](./apps/0191.md) | [#18](https://github.com/opldotdev/BRCs/pull/18) | [`brc/191-location`](https://github.com/bsv-blockchain/BRCs/compare/master...opldotdev:BRCs:brc/191-location?expand=1) | 181, 182, 183, 189 |

The reference column includes background references as well as prerequisites. It is deliberately conservative; a citation is not automatically a normative dependency.

## Numbering and dependency order

Checked 2026-09-05T01:12:30+00:00 against upstream commit `39a643ff148a8dcd23ec08986a8ddeb7d5713743` and all currently open upstream PRs and issues. No matching new-number assignment or pending number claim was found for 178–189 or 191. Number availability is not a formal reservation; upstream maintainers may request a different allocation.

- Upstream PR #240 adds BRC-230; PR #237 adds BRC-175; PR #224 adds BRC-300. Actual changed filenames were inspected, not just branch names.
- The eight open non-PR issues contain no claim to these proposed numbers.
- BRC-190 already exists upstream. Its submission changes that document; it does not claim a new number.
- Required dependencies of the new proposals have earlier numbers. BRC-178 depends on existing standards, with no dependency on 179–191.
- BRC-188 references published BRC-190 only as informative room-policy context, explicitly outside its cryptographic authorization rules. That is not a later prerequisite.
- Published BRC-190 already references published BRC-218. The editorial amendment preserves that existing relationship; neither published standard is renumbered.
- BRC-191 follows BRC-189, whose state-resolution rules it consumes.

## Reference audit

Checked all 14 proposal documents: **318 BRC mentions and 129 numbered links**. The audit covers prose, link labels, target paths, examples and accompanying JSON metadata.

- No surviving references to the old 500-series draft aliases were found.
- Every referenced BRC exists, and numbered link labels match their target document numbers.
- Published BRC-147/150/159–163/165/176 references were checked as published standards, not treated as old draft aliases.
- File links and section anchors were checked during corpus integration; substantive reference/dependency review was independently performed.
- Companion-proposal links use integrated fork `master`, so they resolve during separate upstream review. Replace them with upstream canonical references when the companion proposals land.

## Branch lifecycle

The `brc/...` branches above are the only active submission queue. Their specification and example bytes match integrated fork `master`. Each contains only its focused proposal changes over the checked upstream base.

The old `codex/upstream-brc-*` names were preparation aliases, not additional proposals. They are retired after exact-commit preservation under the names above. Merged `codex/brc-*` review branches are retired only after verifying that their commits are ancestors of fork `master`. Local historical review worktrees may retain their internal branch names; they are not another submission queue.

Submit these individually in numeric order, treating 190 as an amendment. Do not open one corpus-wide upstream PR. Software implementation projects remain in their respective repositories.

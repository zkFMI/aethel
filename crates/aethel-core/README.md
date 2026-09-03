# aethel-core

Aethel's protocol state above DeFMI and zkPI: signed stream state, receivable
series, provider capabilities, credit decisions, guarantees, funding quotes,
issuance, default, and claim semantics. Asset title and money stay in DeFMI;
identity stays in DeKYX; guarantee capacity stays in DeCCP.

## DeKYX cutover (2026-09-02)

The KYB / anonymous-subject logic that used to live here and in
`qomm-zkpi::confidential_subject` is DeKYX's. The `qomm-zkpi` module is
deleted; nothing implements a credential outside `dekyx-core`. What remains in
Aethel is the thin adapter in `src/subject.rs`:

| Concern | Before | Now |
|---|---|---|
| Issuer trust and key epochs | Aethel provider registry + DeFMI participant quote-key epoch | `dekyx_core::IssuerDirectory` stored in `AethelBook::credential_issuers`; a `CredentialIssuer` provider vouches for a DeKYX issuer key with `RegisterCredentialIssuer` (first epoch) and rotates it with a later registration that bounds the earlier epochs |
| Credential and proof verification | `qomm_zkpi::confidential_subject` verified in the Avalanche VM | `dekyx_core::AnonymousPresentation` verified by `dekyx_aethel::AethelDeKyxAdapter` inside `AethelBook::record_confidential_{credit_decision,guarantee}` |
| What the proof is bound to | issuer, scope, policy, expiry | plus audience (`aethel_domain_id`), action (credit decision vs guarantee), the unsigned artifact statement, and the artifact nonce (`ConfidentialArtifact::presentation_context`) |
| Revocation | none | issuer-signed `RevocationStatusList` published with `PublishCredentialStatus`; an epoch without a list fails closed |
| Key rotation | none | `RegisterCredentialIssuer { previous_epochs_valid_until: Some(t) }`; `t` before the old epoch's `valid_from` retires it immediately |
| Line identity | issuer, epoch, commitment, scope, policy, nullifier, expiry all equal | `subject_line_id = H(issuer, scope, policy, nullifier)`; a re-issued credential after rotation continues the line |
| Replay | operation id, provider nonce, subject nullifier per line | plus DeKYX `PresentationLedger` over (nullifier, context) in `AethelBook::consumed_presentations` |
| Stored record | Aethel-owned `ConfidentialSubjectBinding` built by the VM | `dekyx_aethel::AethelSubjectBinding` (re-exported under the old name) built only by DeKYX verification |
| Series policy | `requires_confidential_subject` | plus `subject_kind` (default legal entity), `required_qualifications`, `accepted_issuer_namespace_digest`; all default so existing series digests are unchanged |

`ProviderCapability::CredentialIssuer` is kept: it is Aethel governance saying
which provider may vouch for a DeKYX issuer key, not a credential format.

## Credential and provider key policy

Two kinds of key rotate independently, and both leave what they signed in
place.

- **DeKYX issuer keys.** A rotation is a second `RegisterCredentialIssuer`
  by the same provider at a higher epoch with `previous_epochs_valid_until`.
  Credentials under an earlier epoch verify until that instant (the grace
  window); an instant before the epoch's `valid_from` retires it at once,
  which is the key-compromise path. A credential re-issued under the new key
  with the same subject secret continues the same line. Revocation is the
  issuer-signed status list: a newer list naming the credential stops new
  artifacts on that line, an older list cannot lift it, and a line's already
  recorded decision and guarantee stay in the book.
- **Aethel provider keys.** `RotateProviderKey` installs the next artifact
  key; the request is signed by the next key as proof of possession, and the
  authority to rotate is the application's (in the VM, quorum approval plus
  equality with the DeFMI participant's admin-rotated quote key). The retired
  key is kept in `ProviderDefinition::retired_keys`: artifacts it signed while
  live remain valid under `AethelBook::validate`, and it signs nothing new. A
  key that was ever the provider's cannot return. `SetProviderStatus`
  suspends, reinstates, or revokes; revocation is terminal and blocks further
  rotation. Nothing recorded is removed by either.

## Guarantees and DeCCP

Aethel records what a guarantee means; DeCCP owns the capacity it draws on. A
`GuaranteeCommitment` names the DeFMI facility and hold; the Avalanche VM
reserves the same hold in its DeCCP `ClearingBook` through
`deccp_aethel::AethelDeCcpAdapter` in the same transaction, binds it at
issuance, consumes it at claim, and releases it through the new
`GuaranteeRelease` (`AethelBook::release_guarantee`, only for an unbound
guarantee). DeCCP never sees a plaintext amount: it holds the coverage
commitment and a hash chain of DeFMI-attested transitions.

## Avalanche VM surface

Eighteen consensus methods: the original ten Aethel methods,
`issueAethelCredentialIssuer` and `issueAethelCredentialStatus` for DeKYX,
`issueAethelGuaranteeRelease`, `issueAethelProviderKeyRotation`,
`issueAethelProviderStatus`, and the DeCCP methods `issueDeccpClearingBook`,
`issueDeccpMember` (DeKYX presentation for the clearing-membership scope; DeCCP
stores a subject line, never a legal entity), and
`issueDeccpGuaranteeFacility`. `issueAethelCreditDecision` and
`issueAethelGuarantee` still take an optional `subjectProof`, a DeKYX
`AnonymousPresentation`. Note that the VM's hex normalisation converts every
64-character string field into bytes, so a DeKYX qualification namespace must
not be exactly 64 characters long.

## Build and test

Inside the research tree, `aethel-core` depends on the sibling workspace
`mvp/dekyx` by relative path (`../../../dekyx/crates/…`), and the Avalanche VM
depends on `mvp/deccp` the same way; the QOMM `Makefile` remote-test target
rsyncs both and mounts them at `/dekyx` and `/deccp` in the test container.
The publication exporter rewrites those paths to the public `dekyx` and
`deccp` repositories and publishes this crate as the `aethel` repository.
Tests run only on OmenX or SoftBank:

```sh
# from mvp/qomm
make remote-test REMOTE_TEST_COMMAND='cargo test -p aethel-core -p qomm-avalanche-vm'
```

## Touch points outside this crate

- `mvp/qomm/rust/Cargo.lock`: `dekyx-core`, `dekyx-aethel`, `deccp-core`,
  `deccp-aethel`; `ed25519-dalek` is no longer a `qomm-zkpi` dependency.
- `mvp/qomm/Makefile` `remote-test`: rsync and bind mount for `mvp/dekyx` and
  `mvp/deccp`.
- `mvp/qomm/rust/qomm-avalanche-vm`: `execution/deccp.rs` (DeCCP methods,
  the VM `DeFmiPort`, the DeKYX `EligibilityPort`), `execution/aethel.rs`
  (adapter calls, release, provider control), `state.rs` (`State::deccp`),
  `transaction.rs`, and the tests.
- `rust/qomm-harness/src/bin/export_repos.rs`: `dekyx`, `deccp`, and
  `aethel` are published repositories; `defmi` takes `aethel-core`,
  `deccp-core`, and `deccp-aethel` as Git dependencies.

## Remaining work

- Cross-issuer anti-Sybil (shared registry or VOPRF) when a series accepts
  more than one issuer namespace.
- Issuer-unlinkable credentials (BBS+/CL) if issuance-record correlation must
  be prevented.
- Partial claims and partial releases; the VM still accepts full-cover
  claims only.

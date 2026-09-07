# Provider authentication

Provider artifacts require **Ed25519 AND ML-DSA-65**, using the existing
`zkfmi-crypto::hybrid::signature::{HybridSigner, HybridVerifier}` backend.
There is no classical-only verification branch. Aethel imports the foundation;
the foundation never imports Aethel. No cryptographic core is implemented here.

The mandatory `artifact_key: KeyRecord` carries the closed `Ed25519MlDsa65 / V1`
suite and `Attestation` purpose, binding the participant, key ID, key generation,
public components and validity interval. The provider ID stays stable across
rotation. The retained `public_key` field is the classical participant/guarantor
binding; it is not a complete artifact verification key. The VM additionally
checks the participant quote key's PQ component against the provider's PQ key.

`sign_artifact(artifact, signer, key_record)` signs the validated artifact digest
under `AETHEL:PROVIDER-HYBRID-ARTIFACT:v2`, with the provider ID and enrolled key
metadata. Existing artifact-specific digest domains remain intact. Both primitive
signatures bind the hybrid suite and the `Attestation` purpose. The wire signature
is exactly 64 + 3309 bytes; missing components and trailing bytes are rejected.
Every capability, including payment observations in the servicing consumer, uses
this mandatory verification path.

Registration remains an application/governance-authorized trust-anchor operation.
The host validates the initial key at its authoritative time.
`RotateProviderKey::sign_possession` proves possession of the next hybrid key under
`KeyRotation`, binding the exact transition and expected sequence. Rotation requires
the next generation, the same participant and fresh key ID, classical component
and PQ component. The complete successor is validated before changing the provider
book. Status changes increment the control sequence but not the key generation.

New-message verification accepts only the current key while the provider is active
and the key is valid and unrevoked at the host clock. The separately named
`verify_recorded_signature` only verifies integrity of already accepted state:
it accepts retained historical keys without granting them new authorization.
Revocation is excluded from the signed key identity so it does not invalidate
archived artifacts. Provider rotation history governs the lifecycle; generic
`KeyRecord.rotation_proof` payloads are rejected on provider keys.

The optional `test-support` feature contains publicly known deterministic keys for
repository tests only. Production callers provision independent hybrid secret
handles using `HybridSigner::generate` or authenticated key custody; they must
never derive a PQ secret from a public classical key or enroll these fixtures.

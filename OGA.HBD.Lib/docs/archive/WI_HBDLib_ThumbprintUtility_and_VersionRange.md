# Work Instruction — OGA.HBD.Lib: Public Thumbprint Utility + Version-Range Gate

**For:** the OGA.HBD.Lib (HBD library) design + implementation effort
**From:** the GCS Zero-Trust Host Provisioning & Attestation Protocol effort (S1)
**Status:** Ready for handoff
**Created:** 2026-06-04
**Affects:** OGA.HBD.Lib spec and code. Neither change alters the HBD wire format; no HBD version bump is required for either change.

---

## Context

The HBD library is consumed by the GCS zero-trust protocol. The GCS is the central **issuer** of HBDs and the sole **remote verifier** of host identity. To verify a host's proof-of-possession, the GCS issues a fresh challenge, the host signs it with its Host Binding Key (HBK), and the GCS must confirm that the signing key is the one bound in the HBD's `cnf.pkthumb`. Doing that requires the GCS to compute `base64url(SHA-256(SPKI_DER))` of a public key it receives over the wire and compare it to the HBD's `cnf.pkthumb`.

Two small, pre-live library changes make this correct and future-proof. Both are requirements with rationale and acceptance criteria — the exact API shape and spec wording remain the HBD-library effort's to decide, consistent with that library's own methodology.

---

## Change 1 — Expose the binding-thumbprint formula as a public, platform-neutral utility

**Current state.** The binding-thumbprint formula `base64url(SHA-256(SPKI_DER))` exists only *inside* `SpkiFileThumbprintProvider.GetLocalPkthumb()`, which is file/PEM-specific (reads a PEM path, extracts the SPKI, hashes, base64url-encodes). There is no public way to compute the same value from key material already held in memory.

**Requested change.** Add a public, stateless, platform-neutral utility that computes the canonical binding thumbprint from SPKI material, and refactor `SpkiFileThumbprintProvider` to call it, so there is exactly one implementation of the formula. Suggested (non-binding) shape:

- `string ComputePkthumbFromSpki(ReadOnlySpan<byte> spkiDer)` returning `base64url(SHA-256(spkiDer))`; and/or
- a convenience overload accepting a PEM string or a public-key object that extracts the SPKI internally.
- Keep it free of any platform-specific dependency (e.g., no Windows Certificate Store) — it should operate purely on SPKI bytes / public-key material, consistent with the library's cross-platform posture.

**Rationale.** The GCS computes this same thumbprint from a remotely-presented key during proof-of-possession verification. Sharing one library utility makes the binding formula a single source of truth and removes the risk that a GCS-side reimplementation drifts from the library (e.g., a DER-encoding or base64url-padding difference), which would silently break binding verification.

**Acceptance criteria.**
- A public method computes `base64url(SHA-256(SPKI_DER))` from SPKI bytes (and/or a public key), producing output identical to the existing `SpkiFileThumbprintProvider` for the same key.
- `SpkiFileThumbprintProvider.GetLocalPkthumb()` is refactored to call the new utility (the formula is not duplicated).
- No new platform-specific dependency is introduced.
- The spec documents this utility as the canonical binding-thumbprint computation (in the HBK / thumbprint section).

---

## Change 2 — Widen the HBD version gate from equality to a supported-version range

**Current state.** `HBD_ContextVerifier.HBDVersion_IsValid(int ver)` accepts only `ver == 1` (returns false for `< 1` and `> 1`).

**Requested change.** Replace the hard equality with a **supported-version range** check (`MinSupportedVersion <= ver <= MaxSupportedVersion`), expressed via named constants (or configuration). Today `Min = Max = 1` (no v2 exists), so effective behavior is unchanged now. This is a structural change so that a future version can be introduced by bumping the max and adding that version's handling, without reworking the gate or performing a flag-day cutover.

**Keep the strict posture.** Continue to **reject** any version outside the supported range, and continue to reject documents/claims the verifier does not fully understand. Do **not** add silent unknown-claim tolerance, version negotiation, or an extensibility framework. For a security document, refusing to process a version you don't fully understand is the correct posture; and because the GCS is the sole issuer and the sole verifier and hosts auto-update and renew, any future version bump is a fully coordinated rollout — teach the verifier to accept `v1 + vN`, deploy verifiers first, then begin minting `vN`, and hosts renew into it. The range gate is the only machinery that rollout needs.

**Rationale.** Cheap, pre-live future-proofing of the version-rollout path, matched to the actual (centralized issuer + verifier) topology rather than building distribution machinery the topology does not require.

**Acceptance criteria.**
- The version gate accepts a configured/declared range and rejects out-of-range versions; current effective behavior (only v1 accepted) is preserved.
- No silent unknown-claim tolerance is introduced; the reject-unknown posture is retained.
- The spec documents the supported-version-range policy and the coordinated-rollout expectation (in the versioning section), noting that the consuming protocol handles version evolution via the same coordinated approach.

---

## Notes for the HBD-library effort

- These are requirements with rationale and acceptance criteria, not a prescriptive patch — the library effort owns the exact API shape and spec wording.
- Neither change alters the HBD wire format or requires an HBD version bump.
- Downstream dependency: the GCS protocol side will consume the public thumbprint utility for proof-of-possession verification, and assumes the range gate for its protocol-versioning posture.

# OGA.HBD: Implementation Directive — Spec Alignment Pass 2

> **Status:** Archived. The work described in this directive landed in `[commit: 4a6d2b6]` on 2026-05-11. Congruency checks OI-18/19/20 closed in the SPEC.md revision dated 2026-05-11T06:15:07Z. Subsequent passes are described in their own directives.

**Target Spec:** `SPEC.md`, revision `2026-05-11T05:55:38Z`
**Repository:** `https://github.com/ogauto/OGA.HBD.Lib`
**Predecessor:** `IMPLEMENTATION_DIRECTIVE_2026-05-11.md` (already landed; will be archived as part of this pass)
**Purpose:** Implement the OI-15 async migration, the OI-16 encoder standardization, and the OI-17 result-code documentation. Update tests and README to match. Move the predecessor directive to archive.

---

## Reading this document

This directive is the second implementation pass on OGA.HBD.Lib. The first pass closed OI-01, OI-07, OI-08, OI-10 by implementing the cnf evaluation logic, renaming `cnf.jkt` to `cnf.pkthumb`, adding signer validation, and rewriting doc comments. That pass landed cleanly; this pass addresses three additional items the implementer surfaced in their post-implementation feedback.

The spec (`SPEC.md`, revision `2026-05-11T05:55:38Z`) is authoritative. This directive is the worklist derived from the spec for this pass. As before:

- The **what** describes the code change to make.
- The **why** points to the spec item(s) that motivate the change.
- The **acceptance criteria** describes what "done" looks like, including tests.

All work items SHOULD land in a single coordinated commit. Three of the items (1, 2, 3) are real code changes; two (4, 5) are documentation and housekeeping. The README updates that would otherwise be part of this pass are being handled separately by the project owner.

When this work is complete, the implementer SHOULD:
1. Make a single commit containing all code, test, and (non-README) documentation changes.
2. Note the commit hash.
3. Make a small follow-up edit to `docs/SPEC.md` replacing every `[commit: TBD]` placeholder with the actual commit hash. This is item 4 below.
4. Update the spec to close OI-18, OI-19, OI-20 (the congruency checks for this pass) with the same commit hash, in either the same follow-up edit or a separate commit. (The implementer's choice; either is fine.)

---

## Work Item 1: Migrate verifier to async

### What

In `OGA.HBD.Lib_SP/Service/HBD_ContextVerifier.cs`:

1. **Rename `Verify` to `VerifyAsync`** and change its return type from `BootstrapDocResult` to `Task<BootstrapDocResult>`. Add the `async` keyword to the method.

2. **Change the call at the former line 249** from `handler.ValidateToken(trimmed, tvp)` to `await handler.ValidateTokenAsync(trimmed, tvp)`.

3. **Remove the sync `Verify` method entirely.** Do not preserve it as a wrapper. Do not introduce a sync-over-async shim like `.GetAwaiter().GetResult()` or `.Result`. The migration is in-place, not add-alongside.

4. **The internal helper methods stay synchronous.** `CanUse_Algo`, `BasicPayloadChecks`, `TryReadCnfJkt`, the cnf evaluation logic, `Fail()`, `StringEquals`, `TimingSafeEquals` — none of these need to become async. Only the one `await` at the `ValidateTokenAsync` call matters.

5. **The `BootstrapDocResult` returns from inside the async method** are direct returns of `BootstrapDocResult` instances (not `Task.FromResult(...)`); the `async` keyword wraps them appropriately.

### Why

- Spec OI-15 — full text describing the migration and the in-place-over-add-alongside decision.
- Spec FR-04 — describes the verification function as asynchronous.
- Spec §9.2 — describes the verification flow as an awaited call.
- Spec §10 — references `VerifyAsync` as the public API.
- Microsoft.IdentityModel.JsonWebTokens v8.x has marked `ValidateToken` deprecated with a `[System.Obsolete]` attribute. The compile-time CS0618 warning goes away when this migration lands.

### Acceptance criteria

- Build clean on all targets (NET 5, 6, 7), with **no `CS0618` warnings** related to `ValidateToken`. (Other CS0618 warnings unrelated to `ValidateToken` are out of scope.)
- `HBD_ContextVerifier.VerifyAsync` exists; `HBD_ContextVerifier.Verify` does not exist.
- Tests are updated to `await` the new method. Tests that were previously `public async Task Test_X()` retain the `async Task` signature (it was already there); only the call to the verifier changes.
- A new test, `Test_VerifyAsync_ReturnsTask`, confirms the method signature is `Task<BootstrapDocResult>`. (Either inspecting `typeof` or simply that the test's `await` resolves to `BootstrapDocResult`.)
- All existing tests, after their `Verify` → `VerifyAsync` updates, continue to pass.

---

## Work Item 2: Standardize on a single base64url encoder

### What

In `OGA.HBD.Lib_SP/Service/HBD_Signer.cs`, in `ComputePkthumbFromSpkiPem`:

1. **Change the base64url encoder** from `Jose.Base64Url.Encode` to `Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode`.

2. **Verify that no other place in the library uses `Jose.Base64Url`** for thumbprint computation. Search the codebase. If found, update those too.

3. **Retain the `jose-jwt` dependency** — it is still used for `JWT.Encode` in the signer. Do not remove the NuGet reference. The role of `jose-jwt` narrows to JWS encoding only; thumbprint computation goes through Microsoft.IdentityModel.

### Why

- Spec OI-16 — full text describing the rationale.
- The signer and verifier compute the same `pkthumb` value. Today they happen to agree because both libraries implement base64url the same way; if either library changes its behavior, the agreement breaks invisibly. Standardizing eliminates that coupling risk.

### Acceptance criteria

- Build clean.
- `HBD_Signer.ComputePkthumbFromSpkiPem` uses `Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode`.
- No call to `Jose.Base64Url.Encode` remains anywhere in the library for thumbprint operations.
- The jose-jwt NuGet reference is retained.
- All existing tests pass.
- **A new test, `Test_SignerAndVerifier_AgreeOnPkthumb`**, generates a P-256 keypair, computes its SPKI thumbprint via both the signer's `ComputePkthumbFromSpkiPem` and the verifier's `SpkiFileThumbprintProvider.GetLocalPkthumb`, and confirms they match byte-for-byte. This is the regression test for OI-16.

---

## Work Item 3: Document signer result codes

### What

In `OGA.HBD.Lib_SP/Service/HBD_Signer.cs`, on `CreateBootstrapJws`, expand the XML doc comment to enumerate each return code value and its meaning.

The recommended shape (use whichever XML doc syntax reads best to you):

```csharp
/// <summary>
/// Sign the given HBD payload with the given issuer key, producing a JWS compact serialization.
/// </summary>
/// <param name="payload">The HBD to sign. iat and exp must be populated; see KD-03.</param>
/// <param name="issuerKey">The issuer's ECDsa private key.</param>
/// <param name="kid">The kid to embed in the JWS header.</param>
/// <returns>
/// A tuple of (res, val) where val is the JWS compact serialization when successful.
/// Result codes:
///   1  — success; val contains the signed JWS.
///  -1  — null or blank required argument.
///  -2  — caught exception during signing; val is empty.
///  -3  — invalid iat or exp (zero, negative, or exp not strictly greater than iat).
/// </returns>
```

If other signer-side methods (or related helpers in `OGA.HBD.Helpers.ES256_Issuer`, etc.) use the same multi-return-code convention, audit them and apply the same treatment. The audit is part of this work item.

### Why

- Spec OI-17 — full text describing the rationale.
- The `-3` code added by the prior implementation pass made the existing magic-number convention more painful; this work item closes that gap with the lightweight (no API change) approach.

### Acceptance criteria

- `HBD_Signer.CreateBootstrapJws` has XML doc comments enumerating each return code value and its meaning.
- Any other methods identified by the audit are similarly documented.
- IntelliSense in Visual Studio (verified by hovering over the method in a test file) shows the return-code documentation.
- No code behavior changes; the API surface is unchanged.

---

## Work Item 4: Fill in commit hashes in the spec

### What

After the commit containing Work Items 1, 2, 3 (plus 5, 6) lands:

1. **Note the commit hash** of that commit.
2. **Edit `docs/SPEC.md`** to replace every occurrence of `[commit: TBD]` with the actual commit hash (e.g., `[commit: abc1234]`).
3. **Update OI-18, OI-19, OI-20** from `[planted, awaiting implementation]` to `[resolved]` with the same commit hash. The commit hash references both the prior implementation pass (for OI-12/13/14) and the current one (for OI-18/19/20). Use whatever commit hashes are accurate; you may also need to consult the implementer-of-the-previous-pass commit hash for OI-12/13/14 if it differs from the current pass.

Wait — important clarification on the previous-pass hashes:

OI-12, OI-13, and OI-14 are congruency-check OIs for the *first* implementation pass (the one that landed before this directive was written). The `[commit: TBD]` placeholders in those OIs should reference that first pass's commit hash, not this current pass's hash. The implementer should determine the correct hash to use. If `git log` shows the first implementation pass as a distinct commit, use that hash; if the first pass is multiple commits, use the most relevant one or a range, at the implementer's discretion.

OI-18, OI-19, OI-20 are congruency checks for *this* pass; they reference this pass's commit hash.

4. **Commit the spec edits** as a small follow-up commit. Title suggestion: `docs: fill in commit hashes for resolved OIs`.

### Why

- Spec methodology requires audit-traceable references between OIs and the commits that resolved them. The placeholders are temporary; replacing them is part of completing this revision.

### Acceptance criteria

- No `[commit: TBD]` strings remain in `docs/SPEC.md`.
- OI-12, OI-13, OI-14 carry the commit hash of the prior implementation pass.
- OI-18, OI-19, OI-20 are marked `[resolved]` with the commit hash of this pass.

---

## Work Item 5: Archive the previous implementation directive

### What

1. **Create the directory** `docs/archive/` if it does not exist.

2. **Move** `docs/IMPLEMENTATION_DIRECTIVE_2026-05-11.md` to `docs/archive/IMPLEMENTATION_DIRECTIVE_2026-05-11.md`.

3. **Add a brief note at the top of the archived directive** indicating it has been retired:

   ```markdown
   > **Status:** Archived. The work described in this directive landed in the first implementation pass on 2026-05-11. Subsequent passes are described in their own directives.
   ```

4. **This document itself**, `IMPLEMENTATION_DIRECTIVE_2026-05-11-r2.md`, **also gets archived** to `docs/archive/` after this pass lands and OI-18/19/20 close in the spec. The implementer SHOULD perform this archival as part of the follow-up commit in Work Item 4, with the same banner note added at the top of this document.

### Why

- The previous directive has served its purpose; the work it described has landed. Keeping it in the active `docs/` directory is misleading.
- Same shape applies to this directive after this pass lands.

### Acceptance criteria

- `docs/archive/IMPLEMENTATION_DIRECTIVE_2026-05-11.md` exists.
- `docs/archive/IMPLEMENTATION_DIRECTIVE_2026-05-11-r2.md` exists.
- Neither directive remains in `docs/` (active).
- Both archived directives carry the "Status: Archived" banner note at the top.

---

## Note on README updates

The README has been updated by the project owner in a separate commit that lands alongside the spec revision. This includes:

- Removal of the "Current implementation status" section (now obsolete).
- Update of the verification quick-start example to use `await HBD_ContextVerifier.VerifyAsync(...)`.

The implementer does not need to make README changes as part of this pass. If, during implementation, the implementer notices README content that has become stale or incorrect because of code changes, they MAY flag it for the project owner in their post-implementation report, but SHOULD NOT modify the README directly.

---

## Out of scope for this pass

- **The key-retrieval callback (`dKeyRetrievalCallback`) remains synchronous.** The OI-15 async migration only forces the verifier method to be async. The callback signature is unchanged in this pass; making it async (so callbacks can do I/O cleanly) is a separate decision left for a future spec revision if/when the need arises.
- **The `ILocalKeyThumbprintProvider` interface remains synchronous.** Same logic — the verifier awaits the JWS validation but calls `GetLocalPkthumb` synchronously. A future TPM-backed provider might want async, but that's not forced by this pass.
- **The structural improvement to signer return codes (introducing an enum).** OI-17's resolution is the lightweight XML-doc fix. The structural improvement is deferred.
- **Any further refactoring** beyond what is specified above.

---

## Spec revision after this work lands

After this implementation pass is complete:

- OI-12, OI-13, OI-14 have their commit hashes filled in (Work Item 4).
- OI-18, OI-19, OI-20 close with this pass's commit hash (Work Item 4).
- Both implementation directives (the previous and this one) are archived (Work Item 6).
- A small revision-log entry in `docs/SPEC.md` notes that the implementation pass landed and the relevant OIs closed. The implementer may write this entry or leave it for the project owner. Either is acceptable; if leaving for the project owner, mention this in the commit message of Work Item 4.

After Work Item 4 commits, the OGA.HBD.Lib spec and code are in their first fully-converged state: SPEC.md describes the library, the code implements the spec, and the README is consistent with both.

---

*End of directive.*

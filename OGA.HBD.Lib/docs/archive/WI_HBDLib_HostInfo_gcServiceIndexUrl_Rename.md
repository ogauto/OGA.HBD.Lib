# Work Instruction — OGA.HBD.Lib: Rename HostInfo field `gcBaseUrl` → `gcServiceIndexUrl`

**For:** the OGA.HBD.Lib (HBD library) design + implementation effort
**From:** the GCS Zero-Trust Host Provisioning & Attestation Protocol effort (S1)
**Status:** Ready for handoff
**Created:** 2026-06-04
**Affects:** OGA.HBD.Lib spec and code (HBD HostInfo schema, HostInfo construction/serialization, any reader of the field, sample generation, tests).

---

## Context

The GCS protocol has adopted a **service-index discovery model** (NuGet service-index style): a host is pointed at a single discovery-document URL and reads all GCS endpoint URLs, supported protocol versions, and JWKS URI(s) out of that document. The HBD HostInfo field that tells a host where to reach the GCS therefore now holds **the URL of the discovery document itself**, not a base URL the host appends paths to.

The current field name `gcBaseUrl` is misleading under this model (it is no longer a "base"). Rename it for honesty.

## The change

Rename the HBD HostInfo field **`gcBaseUrl` → `gcServiceIndexUrl`** throughout the library: the HBD/HostInfo schema, wherever HostInfo is constructed/serialized at mint, any helper or reader that accesses the field by name, the spec's HostInfo documentation, and sample-generation/tests.

**Semantics to document:** `gcServiceIndexUrl` is the absolute URL of the GCS **service-index discovery document**, which the host fetches to resolve endpoints, supported versions, and JWKS URI(s).

## Versioning

This is a HostInfo **schema** change, but the project is **pre-live** — no HBDs have been minted in production, so there is no v1 corpus to break. Make it an **in-place change to HBD v1**; **no version bump** is required. (If the HBD effort prefers to treat it as a v2 field-set instead, that is its call, but in-place v1 is the simpler path given pre-live status.)

## Acceptance criteria

- The field is renamed to `gcServiceIndexUrl` everywhere it appears (schema/DTO, HostInfo construction at mint, any by-name reader, sample generators, tests).
- No `gcBaseUrl` references remain.
- The spec's HostInfo documentation reflects the new name **and** the new meaning (URL of the service-index discovery document).
- No HBD version bump; effective version handling unchanged.
- Build and tests green.

## Notes for the HBD-library effort

- This is a requirement with rationale and acceptance criteria, not a prescriptive patch — the library effort owns the exact code touchpoints (it knows where HostInfo is built and read).
- No wire-format change beyond the field name; the value is still a URL string.
- Downstream: the GCS protocol (S1) reads `gcServiceIndexUrl` as the discovery-document anchor (S1 FR-28 / §9.1.8 / §10.4).
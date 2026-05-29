# Microsoft Cloud Collector Overview

The Microsoft Cloud collector gathers Microsoft Entra ID and Azure security posture metrics for evidence packs. It is designed for continuous monitoring and posture drift detection across a Microsoft tenant and a configured set of Azure subscriptions.

The collector emits aggregate evidence only. It does not emit usernames, email addresses, raw sign-in rows, resource names, raw tags, policy bodies, tokens, secrets, or credential values.

## Artifacts

Every successful run emits the detailed Entra artifact:

- `artifacts/microsoft-cloud.entra.json`

When normalized identity posture fields are available, the collector also emits:

- `artifacts/microsoft-cloud.idp-posture.json`
- Schema: `evidencepack/idp-posture@v1`

When `subscription_ids` are configured and at least one Azure subscription can be read, the collector also emits:

- `artifacts/microsoft-cloud.azure.json`
- `artifacts/microsoft-cloud.cloud-posture.json`
- Normalized cloud schema: `evidencepack/cloud-posture@v1`

The detailed schema files live in:

- `docs/schema/microsoft-cloud.entra.v1.0.0.json`
- `docs/schema/microsoft-cloud.azure.v1.0.0.json`

## Collection Levels

The optional `level` config controls collection depth. Levels are cumulative.

| Level | Adds | Does not emit |
|-------|------|---------------|
| `trust` | Tenant identity, MFA registration coverage, Conditional Access posture, security defaults, privileged role counts, app credential hygiene, identity secure score, Azure RBAC, Defender, Policy, storage, key vault, SQL, compute, backup, network, and logging posture. | Usernames, emails, app names, resource names, sign-in rows, raw policy bodies. |
| `audit` | Trust plus Azure resource inventory aggregates and ownership tag coverage. | Raw resource names, raw tag values, resource IDs. |
| `internal` | Audit plus aggregate Entra directory activity and sign-in monitoring counts for the last 7 days. | Raw audit events, raw sign-in rows, usernames, emails, IP addresses, device details. |

If `level` is omitted, the collector runs at `trust`.

## Microsoft APIs

The collector uses Microsoft Graph v1.0 only. Beta endpoints are not allowed in v1. The route contract is documented in `docs/graph-endpoints.md`.

Azure posture is collected through Azure Resource Manager management-plane APIs. The collector does not call Azure data-plane APIs and does not read customer content.

## Licensing and Partial Data

Some Microsoft surfaces require Entra ID P1, P2, or Entra ID Governance licensing. If a licensed surface is unavailable, the collector does not fail the whole run. It emits `null` for affected metrics where appropriate and records the unavailable capability in `diagnostics.license.capabilities_unavailable`.

Common examples:

- MFA registration report unavailable without the right Entra licensing.
- `signInActivity` unavailable without the right Entra licensing.
- PIM eligibility schedules unavailable without Entra ID P2 or Entra ID Governance.

## Privacy Boundary

The collector is built around aggregate posture evidence. It intentionally avoids:

- Usernames and email addresses.
- Per-user sign-in event rows.
- IP addresses and device identifiers.
- Application display names.
- Azure resource names and raw tags.
- Policy bodies and customer-authored policy text.
- Tokens, secrets, private keys, password hashes, and credential values.

Subscription IDs and tenant IDs are emitted because they identify the scoped Microsoft environment for the evidence pack.

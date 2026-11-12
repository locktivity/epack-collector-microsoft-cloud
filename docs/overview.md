# Microsoft Cloud Collector Overview

The Microsoft Cloud collector gathers Microsoft Entra ID and Azure security posture metrics for evidence packs. It is designed for continuous monitoring and posture drift detection across a Microsoft tenant and a configured set of Azure subscriptions.

The collector emits aggregate evidence only. It does not emit usernames, email addresses, raw sign-in rows, resource names, raw tags, policy bodies, tokens, secrets, or credential values.

## Artifacts

Every successful run emits the detailed Entra artifact:

- `artifacts/microsoft-cloud.entra.json`
- Schema: `microsoft-cloud/entra@v1`

When normalized identity posture fields are available, the collector also emits:

- `artifacts/microsoft-cloud.idp-posture.json`
- Schema: `evidencepack/idp-posture@v1`

Every run also emits the Azure artifacts, with one entry in `accounts` for each subscription in `subscription_ids`, in the configured order. A subscription the collector cannot read keeps its entry with only `account_id`, which is written from the `audit` level, so at `trust` the entry is empty.

- `artifacts/microsoft-cloud.azure.json`
- Schema: `microsoft-cloud/azure@v1`
- `artifacts/microsoft-cloud.cloud-posture.json`
- Normalized cloud schema: `evidencepack/cloud-posture@v1`
- `artifacts/microsoft-cloud.access-posture.json`
- Normalized access schema: `evidencepack/access-posture@v1`

When the collector is configured under another name in `epack.yaml`, such as `microsoft-cloud-prod`, its files take that name, such as `artifacts/microsoft-cloud-prod.entra.json`.

Every run also emits a collector result, which lists each value the collector could not read and why, the API calls it made, and the identity it signed in as:

- `artifacts/microsoft-cloud.collector-result.json`
- Schema: `evidencepack/collector-result@v1`

The detailed schema files live in:

- `docs/schema/microsoft-cloud.entra.v1.0.0.json`
- `docs/schema/microsoft-cloud.azure.v1.0.0.json`

Each field in the detailed schemas has a label and a summary for readers of the pack. Each value a trust run writes also has an `x-epack-method` sentence on how the collector measures it. The methods for the normalized artifacts are in `docs/schema/methods.json`.

When the collector emits, it checks the detailed artifacts against these schemas and the normalized artifacts against epack's schemas for their types. Anything that does not hold, such as a percentage over a population of zero, is listed in the collector result under `checks`. A check finding never fails the run.

## Collection Levels

The optional `level` config controls collection depth. Levels are cumulative.

| Level | Adds | Does not emit |
|-------|------|---------------|
| `trust` | Tenant domain, MFA registration coverage, Conditional Access posture, security defaults, privileged role counts, app credential hygiene, identity secure score, Azure RBAC, Defender, Policy, storage, key vault, SQL, compute, backup, network, and logging posture. | Tenant and subscription IDs, usernames, emails, app names, resource names, sign-in rows, raw policy bodies. |
| `audit` | Trust plus the tenant and subscription IDs, Azure resource inventory aggregates, and ownership tag coverage. | Raw resource names, raw tag values, resource IDs. |
| `internal` | Audit plus aggregate Entra directory activity and sign-in monitoring counts for the last 7 days. | Raw audit events, raw sign-in rows, usernames, emails, IP addresses, device details. |

If `level` is omitted, the collector runs at `trust`.

The detailed artifacts write `tenant_id` and each subscription's `account_id` from the `audit` level. At `trust`, `subscription_errors` and the warnings name a subscription by its place in `subscription_ids`, such as `subscription 2`. A subscription error then gives only the HTTP status and Azure's error code, and none of Azure's message, which can name the subscription, the tenant, the app, and resource groups.

The normalized artifacts write the counts behind their percentages, the privileged and Global Administrator counts, each subscription's `account_id`, and the access posture's `scopes` from the `audit` level. At `trust`, flags such as `users_present` and `privileged_users_present` say whether each population has any members. A percentage over an empty population is `null`.

## Choosing What to Collect

The optional `collect` config key lists the kinds of evidence to collect. The kinds are `idp-posture`, `cloud-posture`, `access-posture`, `entra` and `azure`:

```yaml
config:
  collect: [cloud-posture, access-posture, idp-posture, azure, entra]
```

Without the key, the collector collects every kind. A kind left out of the list is not written, and it gets a `not_shared` gap in the collector result.

## Access Posture

The access posture counts the people and service principals with an Azure role assignment on each configured subscription. The counts cover assignments on the subscription and on the management groups above it. Assignments on resource groups and resources are not read.

People sign in to Azure through Microsoft Entra ID, so `sign_in.sso_configured` and `sso_required` are true in every subscription. No one can sign in to Azure without Entra ID, so the members' and admins' local values are false, 0, or null. MFA for Entra ID sign-ins is in `idp-posture`.

Members are the enabled users in the tenant's user list who hold a role anywhere in the subscription, including on one resource group or resource. A disabled user is not a member, and neither is a user deleted after the role was assigned. Guests count as external members. A member is inactive when their last successful sign-in was more than 90 days before the run. Admins are the members with the Owner, Contributor, User Access Administrator or Role Based Access Control Administrator role over the whole subscription, held on it or above it. These roles can change who has access, or change or delete any resource.

Credentials are the service principals that hold a role anywhere in the subscription, including on one resource group or resource. One counts as never expiring when an active client secret or certificate has no end date or ends more than 50 years after the run. Secrets created with the Azure portal's former Never option end in 2299. One is overdue for rotation when an active client secret or certificate became valid more than 90 days before the run. A client secret becomes valid when it is added, unless whoever adds it picks another start date. A certificate becomes valid on its own start date. The credentials checked are the service principal's own and those of the application with its appId, so a managed identity never counts. When the service principal or application list cannot be read, the never-expiring and rotation values are left out with that read's gap.

A service principal with any role other than Reader, Security Reader, Monitoring Reader, Billing Reader, Cost Management Reader, or Log Analytics Reader counts as having write access. When no service principal holds such a role, the unrestricted values are 0, since read-only roles are narrower than full access. Otherwise they are left out with a `not_read` gap. Custom role definitions and the location conditions of Conditional Access policies for service principals are not read. The unused values are left out with a `not_read` gap too, since Microsoft Graph reports service principal sign-ins only in its beta API. Each gap's detail says why.

When a role is assigned to a group, the counts and percentages over everyone with a role are left out with a `not_read` gap, since group members are not read. The admin values are left out too when the group holds one of those four roles over the whole subscription.

Azure has no built-in root account, so `root_accounts_present` and `root_access_keys_present` are false and `root_mfa_coverage_pct` is null. From the `audit` level the root counts are 0. `connected_apps` is left out with a `not_read` gap. Microsoft Graph lists the apps with delegated access to Azure Resource Manager in its delegated permission grants, which are not read.

The sections hold totals across the configured subscriptions, and a principal with roles in several subscriptions counts once. From the `audit` level, `scopes` lists each subscription with its own sections.

## Not Collected

Microsoft offers the following through its APIs, and the collector does not read them.

- **Devices.** Intune managed devices and their compliance state, and Defender for Endpoint machines with their sensor and antivirus health. The Intune API requires an Intune license. The collector writes no `endpoint-posture` file.
- **Vulnerability findings.** Open vulnerabilities and their severity from Defender Vulnerability Management and Defender for Cloud. The collector writes no `vuln-scanning` file. The Azure artifact's `defender.unpatched_pct` comes from the healthy or unhealthy status of Defender for Cloud's update and vulnerability assessments.
- **Access reviews.** Microsoft Entra ID Governance access reviews and their decisions.
- **Defender plans.** Which Defender for Cloud plans, such as Defender for Servers, are on for each subscription. The `cloud-posture` file has no `threat_detection` value.
- **Other databases.** Azure Database for PostgreSQL, Azure Database for MySQL and Azure Cosmos DB. The collector reads Azure SQL only.

## Microsoft APIs

The collector uses Microsoft Graph v1.0 only. Beta endpoints are not allowed in v1. The route contract is documented in `docs/graph-endpoints.md`.

Azure posture is collected through Azure Resource Manager management-plane APIs. The collector does not call Azure data-plane APIs and does not read customer content.

## Licensing and Partial Data

Some Microsoft surfaces require Entra ID P1, P2, or Entra ID Governance licensing. If a licensed surface is unavailable, the collector does not fail the whole run. It emits `null` for affected metrics where appropriate and records the unavailable capability in `diagnostics.license.capabilities_unavailable`.

Common examples:

- MFA registration report unavailable without the right Entra licensing.
- `signInActivity` unavailable without the right Entra licensing.
- PIM eligibility schedules unavailable without Entra ID P2 or Entra ID Governance.
- Sign-in risk levels unavailable without Entra ID P2.

The same holds for any value the collector cannot read, such as one behind a missing permission or an API that keeps failing. The value is `null` or absent, and the collector result records it with a code such as `not_licensed`, `permission_denied`, or `vendor_error`. A percentage over items the collector read only in part is left out the same way. Only invalid configuration or a failed sign-in fails the run.

The MFA registration percentages come from Microsoft's registration report, which Microsoft refreshes on its own schedule rather than live. They cover the enabled member users the report lists, and `posture.denominator_enabled_member_users` counts those users. A member created since the report's last refresh is not counted until the report lists them, so this count can be lower than `users.enabled_member_users_count`. When the report cannot be read, the count is `null` along with the percentages. When it lists none of the enabled members yet, as for a new tenant, they are `null` with a `vendor_error` gap.

The normalized artifacts count the tenant's enabled member users in `user_count`, guests left out, and `inactive_pct` is taken over them. When none of them are in the report yet, their MFA percentages are left out with a `vendor_error` gap, since their registration is unknown. Microsoft does not report locked-out users or password strength, so those `idp-posture` values are left out with an `unsupported` gap.

A domain the tenant federates with another identity provider, such as AD FS or Okta, sends its users' sign-ins to that provider, which decides whether they use MFA. The organization's verified domains give each domain's type, and each user's user principal name gives their domain. When an enabled member's domain is federated, `idp-posture`'s `user_security` MFA values and `policy.mfa_required`, `mfa_required_user_count` and `mfa_required_coverage_pct` are left out with an `unsupported` gap that names the domain. When a privileged user's domain is federated, the `privileged_access` MFA values are left out the same way. `entra`'s `posture` and `policy` values still report what Entra ID registers and requires.

Microsoft Graph gives some users no user type, as it can for older accounts. When an enabled user has none, the collector can't tell whether they are a member or a guest. The values that count members or guests, and the shares taken over them, are then left out with a `not_read` gap. `users_present` is still true when another user is a member.

Privileged users hold a directory role Microsoft classifies as privileged, or Global Administrator, apart from roles whose every directory action only reads, such as Global Reader. Microsoft Graph v1.0 returns the classification as null but filters on it, so the collector reads the role definitions once filtered on `isPrivileged eq true` and once on `isPrivileged eq false`. Custom roles are classified the same way, and a user who holds only a role Microsoft hasn't classified leaves the privileged values out with a gap. A disabled account is not counted as a privileged user or a Global Administrator. When the registration report doesn't list every privileged user yet, the privileged MFA values are left out with a `vendor_error` gap. Its role assignment still counts toward `pim_eligible_pct` and `standing_assignment_count`. When the report doesn't list every Global Administrator, `cloud-posture`'s deprecated `iam.root_mfa_enabled` and `root_access_protected` are left out with the same gap.

Group members are not read. When a privileged role is assigned to a group, the counts and percentages over privileged users are left out with a `not_read` gap. `privileged_users_present` is still true when another user holds a privileged role directly. MFA policy coverage is left out the same way when a policy includes or excludes a group or a role and its members could change the coverage.

Conditional Access policies combine. `mfa_required` is true when the enabled policies that include all users, between them, require MFA for or block every sign-in to every app, whatever its client, device platform, location, risk and authentication flow. An MFA policy for browsers and mobile and desktop apps beside one that blocks legacy authentication is enough, and so are two policies for trusted and untrusted locations. A list of every known platform leaves out devices on a platform Microsoft doesn't recognize, which only all covers. A device filter, an app filter, a named location whose trust can't be read, or a condition, value or grant control the collector doesn't recognize leaves the value out with a `not_read` gap that names it, unless the answer is the same either way. With security defaults on, MFA policy coverage counts the users with an admin role security defaults name, since they require MFA of other users only when Microsoft judges a sign-in risky, and `legacy_auth_blocked` is true.

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

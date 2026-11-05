# Microsoft Cloud Collector Configuration

This guide walks through the Microsoft-side setup and the `epack.yaml` configuration for the Microsoft Cloud collector.

## 1. Create an App Registration

In the Azure portal:

1. Open [App registrations](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps).
2. Select **New registration**.
3. Name it `epack-collector-microsoft-cloud`.
4. Use **Accounts in this organizational directory only**.
5. Leave the redirect URI empty.
6. Select **Register**.

Record these values:

- **Directory (tenant) ID**: used as `tenant_id`.
- **Application (client) ID**: used as `client_id`.

## 2. Choose an Auth Mode

The collector supports two auth modes, `client_secret` and `oidc`. OIDC takes its token from GitHub Actions in a workflow, or from a file elsewhere.

### Client Secret

Use this mode for local testing or environments where OIDC is not available.

In the app registration:

1. Open **Certificates & secrets**.
2. Select **New client secret**.
3. Choose an expiration.
4. Copy the secret value immediately.

Pass the secret as `AZURE_CLIENT_SECRET`.

### GitHub Actions OIDC

Use this mode for GitHub Actions so the workflow does not store a long-lived Azure secret.

In the app registration:

1. Open **Certificates & secrets**.
2. Select **Federated credentials**.
3. Select **Add credential**.
4. Choose the GitHub Actions scenario.
5. Enter the repository owner and repository name.
6. Choose the exact branch, tag, pull request, or environment subject that will run the collector.

For this mode, set `auth_mode: oidc`.

Common OIDC setup failure: the federated credential subject is too narrow. For example, a credential for the `main` branch will not work on pull request workflows unless a matching pull request or environment subject is also configured.

#### Subject format during GitHub's immutable-subject rollout

The credential matches the subject claim of the token GitHub sends, and GitHub is moving that claim to a format with immutable IDs:

- Name-based: `repo:<owner>/<repo>:ref:refs/heads/<branch>`
- Immutable: `repo:<owner>@<owner_id>/<repo>@<repo_id>:ref:refs/heads/<branch>`

Repositories created, renamed, or transferred after July 15, 2026 send the immutable format. Older repositories keep the name-based format until they opt in. The Entra portal form builds the immutable format, so a credential created through the form cannot match an older repository's token. When the formats disagree, the run fails at the token exchange and the error prints the token's exact subject.

To match an older repository, select **Edit (optional)** on the **Subject identifier** field and paste the name-based subject, for example `repo:my-org/my-repo:ref:refs/heads/main`.

To move to the immutable format instead, follow Microsoft's zero-downtime recipe: read the owner and repository IDs from the GitHub API, create a second federated credential with the immutable subject, opt the repository in under its OIDC settings, confirm the run succeeds, then delete the name-based credential.

### OIDC with a Token from a File

Outside GitHub Actions, OIDC mode reads the token from the file named by `AZURE_FEDERATED_TOKEN_FILE`. Use this for any issuer Entra can trust, such as a GitLab job's ID token or Azure workload identity on Kubernetes.

In the app registration:

1. Open **Certificates & secrets**.
2. Select **Federated credentials**.
3. Select **Add credential**.
4. Choose the **Other issuer** scenario.
5. Enter the token's issuer URL and its exact subject claim.
6. Set the audience to `api://AzureADTokenExchange`.

Set `auth_mode: oidc` and list `AZURE_FEDERATED_TOKEN_FILE` under `secrets`.

#### Example: GitLab CI

The federated credential's issuer is `https://gitlab.com`, or your self-managed host, and its subject is `project_path:your-group/your-project:ref_type:branch:ref:main`. The job requests an ID token with the audience above and writes it to the file:

```yaml
  id_tokens:
    AZURE_ID_TOKEN:
      aud: api://AzureADTokenExchange
  script:
    - umask 077
    - printf '%s' "$AZURE_ID_TOKEN" > "$CI_PROJECT_DIR/.azure-federated-token"
    - export AZURE_FEDERATED_TOKEN_FILE="$CI_PROJECT_DIR/.azure-federated-token"
```

## 3. Grant Microsoft Graph Application Permissions

In the app registration:

1. Open **API permissions**.
2. Select **Add a permission**.
3. Choose **Microsoft Graph**.
4. Choose **Application permissions**.
5. Add the permissions below.
6. Select **Grant admin consent**.

Required Microsoft Graph application permissions:

| Permission | Used for |
|------------|----------|
| `Organization.Read.All` | Tenant identity and verified domains. |
| `User.Read.All` | User counts and account status, including for the users who hold Azure roles. |
| `AuditLog.Read.All` | MFA registration report, sign-in activity, sign-in monitoring, and directory activity. |
| `Policy.Read.All` | Conditional Access policies and security defaults. |
| `RoleManagement.Read.Directory` | Directory role assignments. |
| `RoleEligibilitySchedule.Read.Directory` | PIM eligibility schedules. |
| `Application.Read.All` | Enterprise app and app credential hygiene posture, and the credentials of the service principals that hold Azure roles. |
| `SecurityEvents.Read.All` | Identity secure score. |

If a permission or license is missing for a non-blocking surface, the collector records a warning and continues. For a missing permission, the collector result names it on each value left out.

## 4. Assign Azure Reader on Each Subscription

Azure collection requires the service principal to have Azure Reader on every subscription listed in `subscription_ids`.

In the Azure portal:

1. Open [Subscriptions](https://portal.azure.com/#view/Microsoft_Azure_Billing/SubscriptionsBlade).
2. Select the subscription.
3. Open **Access control (IAM)**.
4. Select **Add > Add role assignment**.
5. Choose **Reader**.
6. Under **Assign access to**, choose **User, group, or service principal**.
7. Search for the app registration by its display name, not the client ID, if the client ID search returns no results.
8. Select the service principal.
9. Select **Review + assign**.

Repeat this for each subscription in `subscription_ids`.

Reader also includes permission to list the subscription's role assignments, which the access posture counts. Without it, the access posture's role holders are left out with a `permission_denied` gap that names Reader.

## 5. Configure epack.yaml

Client secret mode:

```yaml
collectors:
  microsoft-cloud:
    source: locktivity/epack-collector-microsoft-cloud@^0.1.0
    config:
      tenant_id: 00000000-0000-0000-0000-000000000000
      client_id: 11111111-1111-1111-1111-111111111111
      auth_mode: client_secret
      subscription_ids:
        - 22222222-2222-2222-2222-222222222222
      level: trust
    secrets:
      AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
```

GitHub Actions OIDC mode:

```yaml
collectors:
  microsoft-cloud:
    source: locktivity/epack-collector-microsoft-cloud@^0.1.0
    config:
      tenant_id: 00000000-0000-0000-0000-000000000000
      client_id: 11111111-1111-1111-1111-111111111111
      auth_mode: oidc
      subscription_ids:
        - 22222222-2222-2222-2222-222222222222
      level: audit
```

## Config Reference

| Key | Required | Description |
|-----|----------|-------------|
| `tenant_id` | Yes | Concrete Microsoft Entra tenant GUID. Do not use `common` or `organizations`. |
| `client_id` | Yes | Application client ID for the app registration. |
| `auth_mode` | Yes | `oidc` or `client_secret`. |
| `subscription_ids` | Yes | Azure subscription GUIDs to collect. |
| `level` | No | `trust`, `audit`, or `internal`. Defaults to `trust`. |
| `collect` | No | The kinds of evidence to collect, from `idp-posture`, `cloud-posture`, `access-posture`, `entra` and `azure`. Defaults to all of them. |
| `azure_environment` | No | Reserved for future sovereign cloud support. |

## Local Test

For local testing with a client secret:

```bash
export AZURE_CLIENT_SECRET="..."
cat > /tmp/microsoft-cloud-config.json <<'JSON'
{
  "tenant_id": "00000000-0000-0000-0000-000000000000",
  "client_id": "11111111-1111-1111-1111-111111111111",
  "auth_mode": "client_secret",
  "subscription_ids": ["22222222-2222-2222-2222-222222222222"],
  "level": "trust"
}
JSON

EPACK_COLLECTOR_CONFIG=/tmp/microsoft-cloud-config.json ./epack-collector-microsoft-cloud
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `Authorization_RequestDenied` from Graph | Missing application permission or admin consent. | Re-check API permissions and grant admin consent. |
| Azure artifact missing, with subscription errors | Service principal lacks Reader on the subscription. | Assign Azure Reader to the app service principal at the subscription scope. |
| PIM metrics are `null` | Missing Entra ID P2 or Entra ID Governance license. | Accept the diagnostic or enable the required license. |
| MFA registration metrics are `null` | MFA registration report is unavailable for the tenant or app. | Confirm `AuditLog.Read.All`, admin consent, and licensing. |
| OIDC works on `main` but fails on PRs | Federated credential subject only matches `main`. | Add a federated credential for the pull request or environment subject. |
| `AADSTS70021`, no matching federated identity record | The credential subject does not match the token. Common for repositories created before July 15, 2026, because the portal form builds the immutable subject format and older repositories send the name-based format. | The error prints the token's subject. Paste that exact value into the credential's Subject identifier, using the Edit (optional) override on the form. |

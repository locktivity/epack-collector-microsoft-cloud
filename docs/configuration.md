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

The collector supports two auth modes.

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
| `User.Read.All` | User posture denominator and account status. |
| `AuditLog.Read.All` | MFA registration report, sign-in activity, sign-in monitoring, and directory activity. |
| `Policy.Read.All` | Conditional Access policies and security defaults. |
| `RoleManagement.Read.Directory` | Directory role assignments. |
| `RoleEligibilitySchedule.Read.Directory` | PIM eligibility schedules. |
| `Application.Read.All` | Enterprise app and app credential hygiene posture. |
| `SecurityEvents.Read.All` | Identity secure score. |

If a permission or license is missing for a non-blocking surface, the collector records a warning and continues.

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
| `auth_mode` | Yes | `client_secret` or `oidc`. |
| `subscription_ids` | Yes | Azure subscription GUIDs to collect. |
| `level` | No | `trust`, `audit`, or `internal`. Defaults to `trust`. |
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

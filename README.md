# epack-collector-microsoft-cloud

Microsoft Entra ID and Azure posture collector for [epack](https://github.com/locktivity/epack).

This collector gathers Microsoft Entra ID and Azure security posture metrics for continuous monitoring and posture drift detection. It emits vendor-detail artifacts plus normalized artifacts for downstream evidence profiles:

- `artifacts/microsoft-cloud.entra.json`
- `artifacts/microsoft-cloud.idp-posture.json`
- `artifacts/microsoft-cloud.azure.json`, when `subscription_ids` are configured
- `artifacts/microsoft-cloud.cloud-posture.json`, when Azure posture is collected

The collector uses Microsoft Graph v1.0 only. See `docs/graph-endpoints.md` for the endpoint contract.

Structured registry docs live in:

- [Overview](docs/overview.md)
- [Configuration](docs/configuration.md)
- [Examples](docs/examples.md)

## Collection Levels

Set the optional `level` config key to control evidence depth:

- `trust` (default): aggregate tenant, identity, app, policy, and Azure posture.
- `audit`: trust plus aggregate Azure inventory and ownership tag posture.
- `internal`: audit plus aggregate Entra directory and sign-in monitoring activity.

Higher levels are cumulative. The collector never emits usernames, email addresses, raw resource names, raw tags, sign-in rows, or policy bodies.

## epack.yaml

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
      level: trust
```

`subscription_ids` is required for Azure collection. Each listed subscription needs at least the Azure Reader role assigned to the application service principal.

## Required Microsoft Permissions

Grant admin consent for the Microsoft Graph application permissions needed by your chosen level:

- Trust: `Organization.Read.All`, `User.Read.All`, `AuditLog.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory`, `RoleEligibilitySchedule.Read.Directory`, `Application.Read.All`, `SecurityEvents.Read.All`
- Audit: the trust permission set
- Internal: the audit permission set

Azure collection also requires the Azure Reader role on each listed subscription. Some Entra features require Microsoft Entra ID P1 or P2 licensing. When a licensed surface is unavailable, the collector emits `null` for the affected metrics and records the missing capability in diagnostics.

## Build

```bash
make build
```

## Test

```bash
make test lint
```

End-to-end tests are opt-in and run against a real Microsoft tenant and Azure subscription:

```bash
MICROSOFT_CLOUD_E2E_RUN=true \
MICROSOFT_CLOUD_E2E_TENANT_ID=00000000-0000-0000-0000-000000000000 \
MICROSOFT_CLOUD_E2E_CLIENT_ID=11111111-1111-1111-1111-111111111111 \
MICROSOFT_CLOUD_E2E_AUTH_MODE=client_secret \
MICROSOFT_CLOUD_E2E_CLIENT_SECRET="$AZURE_CLIENT_SECRET" \
MICROSOFT_CLOUD_E2E_SUBSCRIPTION_IDS=22222222-2222-2222-2222-222222222222 \
MICROSOFT_CLOUD_E2E_LEVEL=trust \
make test-e2e
```

Set `MICROSOFT_CLOUD_E2E_AUTH_MODE=oidc` in GitHub Actions to exercise federated credentials. OIDC mode uses `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` from the runner environment.

## Release

Push a version tag to build signed release assets with SLSA provenance:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow publishes Linux and macOS binaries for amd64 and arm64, matching `.sigstore.json` bundles, and `checksums.txt`.

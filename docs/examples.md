# Microsoft Cloud Collector Examples

These examples show common configurations and abbreviated output shapes.

## Trust-Level Client Secret Run

Use `trust` for aggregate evidence suitable for routine third-party assurance.

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

Abbreviated artifacts:

```json
[
  {
    "path": "artifacts/microsoft-cloud.entra.json"
  },
  {
    "path": "artifacts/microsoft-cloud.idp-posture.json",
    "schema": "evidencepack/idp-posture@v1"
  },
  {
    "path": "artifacts/microsoft-cloud.azure.json"
  },
  {
    "path": "artifacts/microsoft-cloud.cloud-posture.json",
    "schema": "evidencepack/cloud-posture@v1"
  }
]
```

## Audit-Level Azure Inventory

Use `audit` when you need ownership-tag and resource-inventory aggregates for Azure posture drift detection.

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
      level: audit
    secrets:
      AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
```

Abbreviated Azure inventory output:

```json
{
  "accounts": [
    {
      "account_id": "22222222-2222-2222-2222-222222222222",
      "inventory": {
        "resources_count": 128,
        "resource_groups_count": 12,
        "regions_count": 3,
        "owner_tag_coverage_pct": 86,
        "environment_tag_coverage_pct": 91,
        "production_resources_pct": 42,
        "top_resource_types": [
          {
            "type": "Microsoft.Compute/virtualMachines",
            "count": 18
          }
        ]
      }
    }
  ]
}
```

The inventory output contains resource types and counts only. It does not emit resource names, resource IDs, or raw tags.

## Internal-Level Monitoring

Use `internal` for deeper aggregate monitoring of Entra directory activity and sign-in posture.

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
      level: internal
```

Abbreviated sign-in monitoring output:

```json
{
  "sign_in_monitoring": {
    "lookback_hours": 168,
    "sign_ins_count": 2400,
    "failure_count": 75,
    "unique_users_count": 420,
    "unique_apps_count": 38,
    "legacy_client_sign_ins_count": 0,
    "risky_sign_ins_count": 3,
    "conditional_access_success_count": 2100,
    "conditional_access_failure_count": 22,
    "conditional_access_not_applied_count": 278,
    "applied_policies_count": 9,
    "applied_policy_evaluations_count": 6100,
    "applied_policy_success_count": 5800,
    "applied_policy_failure_count": 22,
    "applied_policy_not_applied_count": 278,
    "applied_policy_report_only_fail_count": 5,
    "top_failure_codes": [
      {
        "code": 50126,
        "count": 21
      }
    ]
  }
}
```

This output is aggregate only. It does not emit individual sign-ins, users, IP addresses, devices, or application display names.

## License-Limited Tenant

If a tenant lacks a required Entra license, the collector still emits the available posture and records the unavailable capability.

```json
{
  "posture": {
    "mfa_coverage": null,
    "denominator_enabled_member_users": 2
  },
  "diagnostics": {
    "warnings": [
      "Entra ID P1/P2 not licensed, mfa registration report reported as not_collected"
    ],
    "license": {
      "entra_tier": "unknown",
      "capabilities_unavailable": [
        "mfa_registration_report"
      ]
    }
  }
}
```

## Subscription Reader Missing

If the app registration can read Graph but lacks Azure Reader on a listed subscription, the collector emits Entra artifacts and records a subscription error. Assign Reader to the app service principal at the subscription scope and rerun.

```json
{
  "diagnostics": {
    "subscription_errors": [
      "22222222-2222-2222-2222-222222222222: arm request /subscriptions/[subscription_id] failed: status=403 code=AuthorizationFailed message=denied"
    ]
  }
}
```

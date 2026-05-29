# Microsoft Graph v1.0 Endpoint Contract

The collector uses Microsoft Graph v1.0 only. `beta` endpoints are not allowed
in v1.

| Surface | v1.0 endpoint | Application permission | Slice |
|---------|---------------|------------------------|-------|
| Tenant identity and verified domain | `/organization` | `Organization.Read.All` or `Directory.Read.All` | A |
| User base inventory | `/users` with `$select=id,accountEnabled,userType` | `User.Read.All` | A |
| Authentication method registration report | `/reports/authenticationMethods/userRegistrationDetails` | `AuditLog.Read.All` | A |
| User `signInActivity` | `/users` with `$select=signInActivity` | `User.Read.All` plus `AuditLog.Read.All` | B2 |
| Conditional Access policies | `/identity/conditionalAccess/policies` | `Policy.Read.All` | B1 |
| Security defaults | `/policies/identitySecurityDefaultsEnforcementPolicy` | `Policy.Read.All` | B1 |
| Directory role assignments and definitions | `/roleManagement/directory/roleAssignments`, `/roleManagement/directory/roleDefinitions` | `RoleManagement.Read.Directory` | B2 |
| PIM role eligibility schedules | `/roleManagement/directory/roleEligibilitySchedules` | `RoleEligibilitySchedule.Read.Directory` | B2 |
| Enterprise apps | `/servicePrincipals` | `Application.Read.All` | B2 |
| App and service-principal credentials | `/applications`, `/servicePrincipals` | `Application.Read.All` | B2 |
| Sign-in logs and applied CA policies | `/auditLogs/signIns` | `AuditLog.Read.All`, plus `Policy.Read.All` for applied CA detail | I |
| Directory audit logs | `/auditLogs/directoryAudits` | `AuditLog.Read.All` or `Directory.Read.All` | G |
| Identity secure score | `/security/secureScores` | `SecurityEvents.Read.All` | B2 |

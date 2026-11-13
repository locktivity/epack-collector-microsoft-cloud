package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

var kitOperations = []string{
	"github.id_token.get",
	"login.token.create",
	"graph.organization.get",
	"graph.users.list",
	"graph.user_registration_details.list",
	"graph.users.sign_in_activity.list",
	"graph.conditional_access.policies.list",
	"graph.security_defaults.get",
	"graph.role_assignments.list",
	"graph.role_definitions.list",
	"graph.role_eligibility_schedules.list",
	"graph.service_principals.list",
	"graph.applications.list",
	"graph.secure_scores.list",
	"graph.directory_audits.list",
	"graph.sign_ins.list",
	"arm.subscriptions.get",
	"arm.defender.secure_score.get",
	"arm.defender.assessments.list",
	"arm.role_assignments.list",
	"arm.policy.assignments.list",
	"arm.policy.states.summarize",
	"arm.storage.accounts.list",
	"arm.keyvault.vaults.list",
	"arm.sql.servers.list",
	"arm.sql.databases.list",
	"arm.sql.transparent_data_encryption.get",
	"arm.compute.virtual_machines.list",
	"arm.network.public_ip_addresses.list",
	"arm.network.security_groups.list",
	"arm.backup.vaults.list",
	"arm.backup.vaults.get",
	"arm.backup.protected_items.list",
	"arm.backup.policies.list",
	"arm.backup.jobs.list",
	"arm.monitor.subscription_diagnostic_settings.list",
	"arm.monitor.diagnostic_settings.list",
	"arm.resources.list",
}

// kitPopulations are the lists in Microsoft's answers where an empty list
// means there are none.
var kitPopulations = []collectortest.Population{
	{Operation: "arm.backup.vaults.list", List: "/value", Reason: "A subscription with no Recovery Services vault lists none, and nothing in it is backed up with Azure Backup."},
	{Operation: "arm.backup.protected_items.list", List: "/value", Reason: "A vault that protects nothing lists no items; the sandbox recording lists none."},
	{Operation: "arm.backup.jobs.list", List: "/value", Reason: "A vault that has run no backup lists no jobs; the sandbox recording lists none."},
	{Operation: "arm.compute.virtual_machines.list", List: "/value", Reason: "A subscription with no virtual machines lists none; the sandbox recording lists none."},
	{Operation: "arm.defender.assessments.list", List: "/value", Reason: "Defender for Cloud lists the assessments of the subscription's resources, and none when it has assessed none."},
	{Operation: "arm.keyvault.vaults.list", List: "/value", Reason: "A subscription with no key vaults lists none."},
	{Operation: "arm.monitor.diagnostic_settings.list", List: "/value", Reason: "A resource with no diagnostic setting lists none; the sandbox recording lists none for most of its resources."},
	{Operation: "arm.monitor.diagnostic_settings.list", List: "/value/*/properties/logs", Reason: "A setting can send metrics alone, and a storage account's own setting has no logs to send: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/logs-index"},
	{Operation: "arm.monitor.subscription_diagnostic_settings.list", List: "/value", Reason: "A subscription that exports no activity log has no diagnostic setting, and lists none."},
	{Operation: "arm.monitor.subscription_diagnostic_settings.list", List: "/value/*/properties/logs", Reason: "A setting's logs are the activity log categories it exports, so a setting that lists none exports none."},
	{Operation: "arm.network.public_ip_addresses.list", List: "/value", Reason: "A subscription with no public IP addresses lists none; the sandbox recording lists none."},
	{Operation: "arm.network.security_groups.list", List: "/value", Reason: "A subscription with no network security groups lists none."},
	{Operation: "arm.network.security_groups.list", List: "/value/*/properties/securityRules", Reason: "A group with only Azure's default rules lists no securityRules, since those are in defaultSecurityRules: https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview#default-security-rules"},
	{Operation: "arm.policy.assignments.list", List: "/value", Reason: "A subscription with no policy assigned to it, or above it, lists none."},
	{Operation: "arm.resources.list", List: "/value", Reason: "A subscription with no resources lists none."},
	{Operation: "arm.sql.servers.list", List: "/value", Reason: "A subscription with no SQL servers lists none."},
	{Operation: "arm.storage.accounts.list", List: "/value", Reason: "A subscription with no storage accounts lists none."},
	{Operation: "graph.users.list", List: "/value", Reason: "A tenant with no users lists none. Graph refuses an app without User.Read.All with a 403, rather than listing none."},
	{Operation: "graph.users.sign_in_activity.list", List: "/value", Reason: "A tenant with no users lists none. Graph refuses an app without AuditLog.Read.All with a 403, rather than listing none."},
	{Operation: "graph.user_registration_details.list", List: "/value/*/methodsRegistered", Reason: "A user who has registered no authentication method lists none: https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails"},
	{Operation: "graph.conditional_access.policies.list", List: "/value", Reason: "A tenant with no Conditional Access policy lists none."},
	{Operation: "graph.conditional_access.policies.list", List: "/value/*/conditions/applications/includeApplications", Reason: "A policy for a user action or an authentication context includes no applications: https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications"},
	{Operation: "graph.conditional_access.policies.list", List: "/value/*/conditions/users/includeUsers", Reason: "A policy that includes only groups, roles or guests lists no users; the sandbox recording holds three such policies."},
	{Operation: "graph.conditional_access.policies.list", List: "/value/*/grantControls/builtInControls", Reason: "A policy that grants with an authentication strength, terms of use or a custom control alone lists no built-in control: https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols"},
	{Operation: "graph.role_assignments.list", List: "/value", Reason: "roleAssignments lists active assignments only, so a tenant whose directory roles are all held through PIM eligibility lists none."},
	{Operation: "graph.role_eligibility_schedules.list", List: "/value", Reason: "A tenant that has made no one eligible for a directory role lists no schedules."},
	{Operation: "graph.service_principals.list", List: "/value/*/passwordCredentials", Reason: "A service principal with no client secret of its own lists none; every one in the sandbox recording does."},
	{Operation: "graph.service_principals.list", List: "/value/*/keyCredentials", Reason: "A service principal with no certificate of its own lists none; every one in the sandbox recording does."},
	{Operation: "graph.applications.list", List: "/value", Reason: "Graph lists the apps registered in the tenant, and a tenant can have none, as when the collector's own app is registered in another tenant."},
	{Operation: "graph.applications.list", List: "/value/*/passwordCredentials", Reason: "An app with no client secret lists none; the sandbox recording lists three."},
	{Operation: "graph.applications.list", List: "/value/*/keyCredentials", Reason: "An app with no certificate lists none; the sandbox recording lists three."},
	{Operation: "graph.directory_audits.list", List: "/value", Reason: "A tenant with no directory change in the lookback lists no audit events."},
	{Operation: "graph.sign_ins.list", List: "/value", Reason: "A tenant with no user sign-in in the lookback lists none."},
	{Operation: "graph.sign_ins.list", List: "/value/*/appliedConditionalAccessPolicies", Reason: "A sign-in no Conditional Access policy applied to lists none. Graph leaves the list out, rather than empty, for an app that can't read Conditional Access."},
}

// kitDestinationUnused says why a diagnostic setting with no workspaceId
// sends nothing to a workspace.
const kitDestinationUnused = "A setting can send to a storage account, an event hub or a partner instead, and Azure Monitor sends null for each destination a setting doesn't use; the sandbox recording shows a null storageAccountId and eventHubAuthorizationRuleId."

// kitSecretEnd says why a client secret with no endDateTime doesn't expire.
const kitSecretEnd = "\"Optional\": a client secret's endDateTime, and a secret with none doesn't expire. passwordCredential in https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential"

// kitOmissions are the fields Microsoft leaves out, or sends as null, to
// mean a value.
var kitOmissions = []collectortest.Omission{
	{Operation: "arm.backup.vaults.get", Field: "/properties/securitySettings/immutabilitySettings/state", Reason: "A vault whose immutability was never set has none, which is Disabled. The azurerm provider reads it so, as Azure returns the setting only once it is set."},
	{Operation: "arm.keyvault.vaults.list", Field: "/value/*/properties/enablePurgeProtection", Reason: "\"the property does not accept false as its value\", so a vault without purge protection leaves it out, as one in the sandbox recording does: VaultProperties in https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/vaults/list-by-subscription"},
	{Operation: "arm.keyvault.vaults.list", Field: "/value/*/properties/enableRbacAuthorization", Reason: "\"If null or not specified, the vault is created with the default value of false\": VaultProperties in https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/vaults/list-by-subscription"},
	{Operation: "arm.monitor.diagnostic_settings.list", Field: "/value/*/properties/workspaceId", Reason: kitDestinationUnused},
	{Operation: "arm.monitor.subscription_diagnostic_settings.list", Field: "/value/*/properties/workspaceId", Reason: kitDestinationUnused},
	{Operation: "arm.network.public_ip_addresses.list", Field: "/value/*/properties/ipConfiguration", Reason: "ipConfiguration is the configuration an address is attached to, so an address attached to nothing has none: https://learn.microsoft.com/en-us/rest/api/virtualnetwork/public-ip-addresses/list-all"},
	{Operation: "arm.resources.list", Field: "/value/*/tags", Reason: "A resource with no tags has no tags field; the sandbox recording lists three."},
	{Operation: "arm.resources.list", Field: "/value/*/tags/*", Reason: "A resource's tags hold only the tags set on it."},
	{Operation: "arm.sql.servers.list", Field: "/value/*/properties/minimalTlsVersion", Reason: "A server with no minimal TLS version set accepts any version, and the Servers - List sample answer lists such servers: https://learn.microsoft.com/en-us/rest/api/sql/servers/list"},
	{Operation: "arm.storage.accounts.list", Field: "/value/*/properties/allowBlobPublicAccess", Reason: "Microsoft's remediation script and audit policy count an account whose allowBlobPublicAccess is null as allowing anonymous access: https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent"},
	{Operation: "arm.storage.accounts.list", Field: "/value/*/properties/minimumTlsVersion", Reason: "\"The default interpretation is TLS 1.0 for this property\": StorageAccountProperties in https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list"},
	{Operation: "arm.storage.accounts.list", Field: "/value/*/properties/publicNetworkAccess", Reason: "An account without the setting accepts traffic from any network its firewall allows, and the Storage Accounts - List sample answer lists such accounts: https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list"},
	{Operation: "arm.storage.accounts.list", Field: "/value/*/properties/encryption/keySource", Reason: "keySource defaults to Microsoft.Storage, Azure's own key: Encryption in https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list"},
	{Operation: "arm.storage.accounts.list", Field: "/value/*/properties/encryption/requireInfrastructureEncryption", Reason: "An account created without infrastructure encryption leaves the field out; the sandbox recording lists two."},
	{Operation: "graph.service_principals.list", Field: "/value/*/preferredSingleSignOnMode", Reason: "Graph sends null for a service principal with no single sign-on mode set; the sandbox recording lists 182."},
	{Operation: "graph.service_principals.list", Field: "/value/*/passwordCredentials/*/endDateTime", Reason: kitSecretEnd},
	{Operation: "graph.applications.list", Field: "/value/*/passwordCredentials/*/endDateTime", Reason: kitSecretEnd},
	{Operation: "graph.users.sign_in_activity.list", Field: "/value/*/signInActivity/lastSuccessfulSignInDateTime", Reason: "\"The data isn't backfilled for this property\", so a user with no successful sign-in since December 1, 2023 has none: https://learn.microsoft.com/en-us/graph/api/resources/signinactivity"},
}

// kitResultPath is where the kit's runs write their collector result.
var kitResultPath = componentsdk.ArtifactPath(collectorName, "evidencepack/collector-result@v1")

var kitAssessmentsURL = kitARMBase + "/subscriptions/" + kitSubscriptionID + "/providers/Microsoft.Security/assessments?api-version=2020-01-01"

func kitConfig() map[string]any {
	return map[string]any{
		"tenant_id":        kitTenantID,
		"client_id":        kitClientID,
		"auth_mode":        "oidc",
		"subscription_ids": []any{kitSubscriptionID},
		"level":            "internal",
	}
}

func kitSecrets() map[string]string {
	return map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_URL":   kitGitHubTokenURL,
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "kit-github-request-token-0123456789",
	}
}

func defenderAssessmentsFailResponses() []collectortest.Response {
	return replaceResponse(kitResponses(), collectortest.Response{
		URL:    kitAssessmentsURL,
		Status: http.StatusInternalServerError,
		Body:   `{"error":{"code":"InternalServerError","message":"Encountered internal server error."}}`,
	})
}

func TestCollectorKit(t *testing.T) {
	collectortest.Run(t, collectortest.Suite{
		Spec:        Spec("test", "collectortest"),
		Run:         Run,
		Config:      kitConfig(),
		Secrets:     kitSecrets(),
		Clock:       goldenTime,
		FieldFaults: true,
		Populations: kitPopulations,
		Omissions:   kitOmissions,
		Scenarios: []collectortest.Scenario{
			{
				Name:      "clean",
				Responses: kitResponses(),
				Expect: map[string]map[string]any{accessPosturePath: {
					"/credentials/rotation_overdue_credential_count": 2,
					"/credentials/rotation_overdue_pct":              100,
					"/credentials/unused_pct":                        collectortest.Absent,
					"/credentials/unrestricted_pct":                  collectortest.Absent,
					"/sign_in/sso_required":                          true,
					"/scopes/0/sign_in/sso_required":                 true,
					"/root/root_accounts_present":                    false,
					"/root/root_account_count":                       0,
					"/root/root_mfa_coverage_pct":                    nil,
					"/scopes/0/root/root_accounts_present":           false,
				}},
			},
			{Name: "defender assessments fail", Responses: defenderAssessmentsFailResponses()},
			{Name: "empty tenant", Responses: emptyTenantResponses()},
			{
				Name:      "registration report behind the user list",
				Responses: registrationReportBehindResponses(),
				Expect: map[string]map[string]any{
					entraPath: {
						"/users/enabled_member_users_count":         2,
						"/posture/denominator_enabled_member_users": nil,
						"/posture/mfa_coverage":                     nil,
					},
					cloudPosturePath: {
						"/accounts/0/iam/root_mfa_enabled":      collectortest.Absent,
						"/accounts/0/iam/root_access_protected": collectortest.Absent,
					},
				},
			},
			{
				Name:      "registration report empty",
				Responses: emptyRegistrationReportResponses(),
				Expect: map[string]map[string]any{
					entraPath: {
						"/posture/denominator_enabled_member_users": nil,
						"/posture/mfa_coverage":                     nil,
					},
					idpPosturePath: {
						"/user_security/user_count":       2,
						"/user_security/mfa_coverage_pct": collectortest.Absent,
					},
					cloudPosturePath: {
						"/accounts/0/iam/mfa_coverage_pct":      collectortest.Absent,
						"/accounts/0/iam/root_mfa_enabled":      collectortest.Absent,
						"/accounts/0/iam/root_access_protected": collectortest.Absent,
					},
					kitResultPath: {"/outcome/status": "partial"},
				},
			},
			{
				Name:      "user with no user type",
				Responses: untypedUserResponses(),
				Expect: map[string]map[string]any{
					entraPath: {
						"/users/total_count":                        4,
						"/users/enabled_member_users_count":         nil,
						"/users/guest_pct":                          nil,
						"/posture/denominator_enabled_member_users": nil,
						"/posture/mfa_coverage":                     nil,
						"/policy/mfa_required_coverage_pct":         nil,
						"/privileged_access/privileged_users_count": 3,
						"/privileged_access/privileged_guest_count": nil,
					},
					idpPosturePath: {
						"/user_security/users_present":      true,
						"/user_security/user_count":         collectortest.Absent,
						"/user_security/mfa_coverage_pct":   collectortest.Absent,
						"/user_security/inactive_pct":       collectortest.Absent,
						"/policy/mfa_required_coverage_pct": collectortest.Absent,
					},
					accessPosturePath: {
						"/members/member_count":             3,
						"/members/external_members_present": true,
						"/members/external_member_count":    collectortest.Absent,
					},
				},
			},
			{
				Name:      "sign-in activity user with no user type",
				Responses: untypedSignInUserResponses(),
				Expect: map[string]map[string]any{entraPath: {
					"/users/inactive_pct":       67,
					"/users/inactive_guest_pct": nil,
				}},
			},
			{
				Name:      "Entra ID Free tenant",
				Responses: freeTenantResponses(),
				Expect: map[string]map[string]any{
					entraPath: {
						"/posture/mfa_coverage":                     nil,
						"/users/inactive_pct":                       nil,
						"/policy/mfa_required":                      nil,
						"/policy/mfa_required_coverage_pct":         0,
						"/privileged_access/pim_eligible_pct":       nil,
						"/privileged_access/privileged_users_count": 3,
					},
					idpPosturePath: {
						"/user_security/mfa_coverage_pct":   collectortest.Absent,
						"/user_security/users_present":      true,
						"/policy/mfa_required_coverage_pct": 0,
					},
					accessPosturePath: {
						"/members/members_present": true,
						"/members/member_count":    3,
						"/members/inactive_pct":    collectortest.Absent,
					},
					kitResultPath: {"/outcome/status": "partial"},
				},
			},
			{
				Name:      "audit log permission missing",
				Responses: auditLogDeniedResponses(),
				Expect: map[string]map[string]any{
					entraPath: {
						"/posture/mfa_coverage": nil,
						"/users/inactive_pct":   nil,
					},
					idpPosturePath: {
						"/user_security/mfa_coverage_pct": collectortest.Absent,
						"/user_security/inactive_pct":     collectortest.Absent,
					},
					accessPosturePath: {
						"/members/inactive_member_count": collectortest.Absent,
						"/members/inactive_pct":          collectortest.Absent,
						"/admins/admin_share_pct":        67,
					},
				},
			},
			{
				Name:      "role held through a group",
				Responses: groupRoleResponses(),
				Expect: map[string]map[string]any{
					accessPosturePath: {
						"/members/members_present":         true,
						"/members/member_count":            collectortest.Absent,
						"/members/inactive_pct":            collectortest.Absent,
						"/admins/admins_present":           true,
						"/admins/admin_count":              collectortest.Absent,
						"/credentials/credentials_present": true,
						"/credentials/write_access_pct":    collectortest.Absent,
						"/sign_in/sso_required":            true,
					},
					azurePath: {"/accounts/0/rbac/owner_count": 3},
				},
			},
			{
				Name:      "secret set to never expire",
				Responses: neverSecretResponses(),
				Expect: map[string]map[string]any{accessPosturePath: {
					"/credentials/never_expiring_credential_count": 1,
					"/credentials/never_expiring_pct":              50,
				}},
			},
			{
				Name:      "credential with no end date",
				Responses: noEndDateResponses(),
				Expect: map[string]map[string]any{accessPosturePath: {
					"/credentials/never_expiring_credential_count": 1,
					"/credentials/never_expiring_pct":              50,
				}},
			},
			{
				Name:      "managed identity with a role",
				Responses: managedIdentityResponses(),
				Expect: map[string]map[string]any{accessPosturePath: {
					"/credentials/credential_count":                  3,
					"/credentials/never_expiring_credential_count":   0,
					"/credentials/never_expiring_pct":                0,
					"/credentials/write_access_pct":                  67,
					"/credentials/rotation_overdue_credential_count": 2,
					"/credentials/rotation_overdue_pct":              67,
				}},
			},
			{
				Name:      "service principals with read-only roles",
				Responses: readOnlyServicePrincipalsResponses(),
				Expect: map[string]map[string]any{accessPosturePath: {
					"/credentials/write_access_pct":              0,
					"/credentials/unrestricted_credential_count": 0,
					"/credentials/unrestricted_pct":              0,
					"/credentials/unused_pct":                    collectortest.Absent,
				}},
			},
			{
				Name:      "credentials rotated last month",
				Responses: rotatedCredentialsResponses(),
				Expect: map[string]map[string]any{accessPosturePath: {
					"/credentials/rotation_overdue_credential_count": 0,
					"/credentials/rotation_overdue_pct":              0,
					"/credentials/unrestricted_pct":                  collectortest.Absent,
				}},
			},
			{
				Name:      "application read denied",
				Responses: applicationsDeniedResponses(),
				Expect: map[string]map[string]any{
					accessPosturePath: {
						"/credentials/credentials_present":             true,
						"/credentials/never_expiring_credential_count": collectortest.Absent,
						"/credentials/never_expiring_pct":              collectortest.Absent,
						"/credentials/rotation_overdue_pct":            collectortest.Absent,
						"/credentials/write_access_pct":                50,
					},
					kitResultPath: {"/outcome/status": "partial"},
				},
			},
			{
				Name:      "role assignments denied",
				Responses: roleAssignmentsDeniedResponses(),
				Expect: map[string]map[string]any{
					accessPosturePath: {
						"/members/members_present":         collectortest.Absent,
						"/admins/admins_present":           collectortest.Absent,
						"/credentials/credentials_present": collectortest.Absent,
						"/members/local_members_present":   false,
						"/sign_in/sso_required":            true,
					},
					kitResultPath: {"/outcome/status": "partial"},
				},
			},
			{
				Name:          "token rejected",
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses: append(kitSignInResponses()[:1], collectortest.Response{
					Method: http.MethodPost,
					URL:    kitTokenURL,
					Status: http.StatusBadRequest,
					Body:   `{"error":"invalid_request","error_description":"AADSTS700213: No matching federated identity record found for presented assertion subject.","error_codes":[700213]}`,
				}),
			},
		},
		Required: []string{"github.id_token.get", "login.token.create", "graph.organization.get"},
		Semantics: []collectortest.Semantic{
			{
				Operation: "arm.subscriptions.get",
				Fault:     "404",
				Meaning:   "the subscription does not exist or the app cannot see it",
				Expect: map[string]map[string]any{azurePath: {
					"/accounts/0/account_id":                     kitSubscriptionID,
					"/accounts/0/storage/storage_accounts_count": nil,
				}},
			},
			{
				Operation: "arm.defender.secure_score.get",
				Fault:     "404",
				Meaning:   "Defender for Cloud has no secure score for the subscription",
				Expect:    map[string]map[string]any{azurePath: {"/accounts/0/defender/secure_score_pct": nil}},
			},
			{
				Operation: "graph.secure_scores.list",
				Fault:     "404",
				Meaning:   "the tenant has no identity secure score",
				Expect:    map[string]map[string]any{entraPath: {"/secure_score/identity_pct": nil}},
			},
		},
		Ignore: map[string][]string{
			entraPath: {"/diagnostics"},
			azurePath: {"/diagnostics"},
		},
		Operations:  kitOperations,
		Insensitive: []string{"login.token.create"},
	})
}

func TestDefenderAssessmentsFailureLeavesAVendorErrorGap(t *testing.T) {
	res := runInProcess(t, kitConfig(), kitSecrets(), defenderAssessmentsFailResponses())
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	want := componentsdk.Gap{
		Location: componentsdk.Location{Path: azurePath, Pointer: "/accounts/0/defender/unpatched_pct"},
		Status:   componentsdk.GapNotCollected,
		Code:     componentsdk.CodeVendorError,
	}
	found := false
	for _, gap := range res.Result.Gaps {
		if gap.Path == want.Path && gap.Pointer == want.Pointer {
			found = gap.Status == want.Status && gap.Code == want.Code && gap.VendorCode == "InternalServerError"
		}
	}
	if !found {
		t.Fatalf("no vendor_error gap at %s; gaps: %#v", want.Pointer, res.Result.Gaps)
	}
	if res.Result.Outcome.Status != componentsdk.OutcomePartial {
		t.Fatalf("outcome = %#v, want partial", res.Result.Outcome)
	}
	for _, op := range res.Result.Calls.Operations {
		if op.Name == "arm.defender.assessments.list" && op.Attempts != 5 {
			t.Fatalf("assessments attempts = %d, want the SDK's 5", op.Attempts)
		}
	}
}

func TestRegistrationReportBehindTheUserListLeavesTheMFAValuesOut(t *testing.T) {
	res := runInProcess(t, kitConfig(), kitSecrets(), registrationReportBehindResponses())
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	var entra EntraArtifact
	for _, artifact := range res.Artifacts {
		if artifact.Path == entraPath {
			if err := json.Unmarshal(artifact.Data, &entra); err != nil {
				t.Fatal(err)
			}
		}
	}
	assertPtrInt(t, "users.enabled_member_users_count", entra.Users.EnabledMemberUsersCount, 2)
	if entra.Posture.DenominatorEnabledMemberUsers != nil || entra.Posture.MFACoverage != nil || entra.Posture.SSPRRegistered != nil {
		t.Fatalf("denominator = %v, MFA coverage = %v, SSPR = %v; want each left out while the report lists no member",
			entra.Posture.DenominatorEnabledMemberUsers, entra.Posture.MFACoverage, entra.Posture.SSPRRegistered)
	}
	if len(res.Result.Checks) != 0 {
		t.Fatalf("output checks found %+v", res.Result.Checks)
	}
}

// TestMissingGraphFieldsLeaveValuesOutWithAGap checks that a null or missing
// Graph field leaves the values it feeds out with a gap.
func TestMissingGraphFieldsLeaveValuesOutWithAGap(t *testing.T) {
	type want struct {
		path, pointer string
		code          componentsdk.Code
	}
	cases := []struct {
		name      string
		responses []collectortest.Response
		gaps      []want
	}{
		{
			name:      "registration report empty",
			responses: emptyRegistrationReportResponses(),
			gaps: []want{
				{entraPath, "/posture/denominator_enabled_member_users", componentsdk.CodeVendorError},
				{entraPath, "/posture/mfa_coverage", componentsdk.CodeVendorError},
				{idpPosturePath, "/user_security/mfa_coverage_pct", componentsdk.CodeVendorError},
				{idpPosturePath, "/user_security/mfa_user_count", componentsdk.CodeVendorError},
				{cloudPosturePath, "/accounts/0/iam/mfa_coverage_pct", componentsdk.CodeVendorError},
				{cloudPosturePath, "/accounts/0/iam/root_mfa_enabled", componentsdk.CodeVendorError},
				{cloudPosturePath, "/accounts/0/iam/root_access_protected", componentsdk.CodeVendorError},
			},
		},
		{
			name:      "registration report behind the user list",
			responses: registrationReportBehindResponses(),
			gaps: []want{
				{entraPath, "/posture/mfa_coverage", componentsdk.CodeVendorError},
				{cloudPosturePath, "/accounts/0/iam/root_mfa_enabled", componentsdk.CodeVendorError},
			},
		},
		{
			name:      "user with no user type",
			responses: untypedUserResponses(),
			gaps: []want{
				{entraPath, "/users/enabled_member_users_count", componentsdk.CodeNotRead},
				{entraPath, "/users/guest_pct", componentsdk.CodeNotRead},
				{entraPath, "/posture/mfa_coverage", componentsdk.CodeNotRead},
				{entraPath, "/policy/mfa_required_coverage_pct", componentsdk.CodeNotRead},
				{entraPath, "/privileged_access/privileged_guest_count", componentsdk.CodeNotRead},
				{idpPosturePath, "/user_security/user_count", componentsdk.CodeNotRead},
				{idpPosturePath, "/user_security/inactive_pct", componentsdk.CodeNotRead},
				{accessPosturePath, "/members/external_member_count", componentsdk.CodeNotRead},
			},
		},
		{
			name:      "sign-in activity user with no user type",
			responses: untypedSignInUserResponses(),
			gaps: []want{
				{entraPath, "/users/inactive_guest_pct", componentsdk.CodeNotRead},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runInProcess(t, kitConfig(), kitSecrets(), tc.responses)
			if res.ExitCode != 0 || res.Result == nil {
				t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
			}
			for _, w := range tc.gaps {
				var got *componentsdk.Gap
				for i, gap := range res.Result.Gaps {
					if gap.Path == w.path && gap.Pointer == w.pointer {
						got = &res.Result.Gaps[i]
					}
				}
				switch {
				case got == nil:
					t.Errorf("%s %s: no gap", w.path, w.pointer)
				case got.Code != w.code:
					t.Errorf("%s %s: gap code %s, want %s (%s)", w.path, w.pointer, got.Code, w.code, got.Detail)
				}
			}
		})
	}
}

func TestRunRecordsTheSignedInPrincipal(t *testing.T) {
	res := runInProcess(t, kitConfig(), kitSecrets(), kitResponses())
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, gap := range res.Result.Gaps {
		if gap.Code != componentsdk.CodeUnsupported && gap.Code != componentsdk.CodeNotRead {
			t.Fatalf("expected a clean run, got gap %#v", gap)
		}
	}
	want := &componentsdk.Principal{
		Provider: "microsoft-entra",
		Kind:     "service_principal",
		TenantID: kitTenantID,
		Scopes:   append([]string(nil), kitAppRoles...),
		ID:       kitClientID,
	}
	sort.Strings(want.Scopes)
	if !reflect.DeepEqual(res.Result.SignedInAs, want) {
		t.Fatalf("signed_in_as = %#v, want %#v", res.Result.SignedInAs, want)
	}
}

func TestRunWithClientSecret(t *testing.T) {
	config := kitConfig()
	config["auth_mode"] = "client_secret"
	responses := kitResponses()[1:]
	res := runInProcess(t, config, map[string]string{"AZURE_CLIENT_SECRET": "kit-client-secret-0123456789"}, responses)
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, op := range res.Result.Calls.Operations {
		if op.Name == "github.id_token.get" {
			t.Fatal("client_secret mode should not ask GitHub for an identity token")
		}
	}
}

func TestCredentialHosts(t *testing.T) {
	cfg := testConfig()
	cfg.AuthMode = "oidc"
	cfg.OIDCRequestURL = kitGitHubTokenURL
	want := []string{"login.microsoftonline.com", "graph.microsoft.com", "management.azure.com", "pipelines.actions.githubusercontent.test"}
	if got := cfg.CredentialHosts(); !reflect.DeepEqual(got, want) {
		t.Fatalf("CredentialHosts() = %v, want %v", got, want)
	}
	cfg.AuthMode = "client_secret"
	if got := cfg.CredentialHosts(); !reflect.DeepEqual(got, want[:3]) {
		t.Fatalf("CredentialHosts() = %v, want %v", got, want[:3])
	}
}

func runInProcess(t *testing.T, config map[string]any, secrets map[string]string, responses []collectortest.Response) componentsdk.InProcessResult {
	t.Helper()
	replay, err := collectortest.NewReplay(collectortest.Scenario{Responses: responses})
	if err != nil {
		t.Fatal(err)
	}
	res := componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
		Config:    config,
		Secrets:   secrets,
		Transport: replay,
		Seed:      1,
		Sleep:     func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
		Clock:     func() time.Time { return goldenTime },
	})
	if unmatched := replay.Unmatched(); len(unmatched) > 0 {
		t.Fatalf("no canned response for %s", strings.Join(unmatched, ", "))
	}
	return res
}

func TestRunOverHTTPMatchesGoldens(t *testing.T) {
	cases := []struct {
		level   string
		goldens map[string]string
	}{
		{"internal", map[string]string{entraPath: "../../testdata/golden/slice_i/entra.json"}},
		{"audit", map[string]string{azurePath: "../../testdata/golden/slice_h/azure.json"}},
		{"trust", map[string]string{
			idpPosturePath:   "../../testdata/golden/slice_b2/idp-posture.json",
			cloudPosturePath: "../../testdata/golden/slice_f/cloud-posture.json",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.level, func(t *testing.T) {
			config := kitConfig()
			config["level"] = tc.level
			res := runInProcess(t, config, kitSecrets(), kitResponses())
			if res.ExitCode != 0 {
				t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
			}
			emitted := map[string]json.RawMessage{}
			for _, artifact := range res.Artifacts {
				emitted[artifact.Path] = artifact.Data
			}
			for path, golden := range tc.goldens {
				want, err := os.ReadFile(golden)
				if err != nil {
					t.Fatal(err)
				}
				assertSameJSON(t, path, emitted[path], want)
			}
		})
	}
}

func assertSameJSON(t *testing.T, label string, got, want []byte) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("%s differs from its golden\ngot:  %s\nwant: %s", label, got, want)
	}
}

func TestRequestRowsCarryNoResourceNames(t *testing.T) {
	config := kitConfig()
	config["level"] = "audit"
	res := runInProcess(t, config, kitSecrets(), kitResponses())
	if res.ExitCode != 0 || res.Result == nil || len(res.Result.Calls.Requests) == 0 {
		t.Fatalf("run failed with exit %d or recorded no requests: %s", res.ExitCode, res.Stderr)
	}
	names := map[string]bool{}
	for _, name := range []string{"data", "security", "compute", "network", "backup", "monitor", "storagea", "storageb", "kv-a", "kv-b", "sql-a", "appdb", "logdb", "vm-a", "vm-b", "vault-a", "vault-b", kitSubscriptionID, kitTenantID} {
		names[strings.ToLower(name)] = true
	}
	for _, row := range res.Result.Calls.Requests {
		if row.Host != "management.azure.com" {
			continue
		}
		for _, segment := range strings.Split(row.Route, "/") {
			if names[strings.ToLower(segment)] {
				t.Errorf("%s route %s names %q", row.Operation, row.Route, segment)
			}
		}
	}
}

func TestCollectLeavesOutTheDetailedFiles(t *testing.T) {
	config := kitConfig()
	config["collect"] = []any{"cloud-posture", "idp-posture"}
	res := runInProcess(t, config, kitSecrets(), kitResponses())
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	written := map[string]bool{}
	for _, artifact := range res.Artifacts {
		written[artifact.Path] = true
	}
	for _, path := range []string{entraPath, azurePath} {
		if written[path] {
			t.Errorf("%s was written although collect leaves it out", path)
		}
	}
	for _, path := range []string{idpPosturePath, cloudPosturePath} {
		if !written[path] {
			t.Errorf("%s was not written", path)
		}
	}
	// A gap on a whole file with a schema ID names the file by its schema.
	notShared := map[string]bool{}
	for _, gap := range res.Result.Gaps {
		if gap.Code == componentsdk.CodeNotShared {
			notShared[gap.Schema] = true
		}
	}
	if !notShared[entraSchema] || !notShared[azureSchema] {
		t.Fatalf("not_shared gaps = %v, want one for each detailed file", notShared)
	}
}

// The deprecated iam block in each subscription moved to access-posture, so
// a collect list that leaves out access-posture leaves it out, with a
// not_shared gap.
func TestCollectLeavesOutTheDeprecatedIAMWithAccessPosture(t *testing.T) {
	accounts := func(collect []any) ([]map[string]any, componentsdk.InProcessResult) {
		config := kitConfig()
		if collect != nil {
			config["collect"] = collect
		}
		res := runInProcess(t, config, kitSecrets(), kitResponses())
		if res.ExitCode != 0 || res.Result == nil {
			t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
		}
		for _, artifact := range res.Artifacts {
			if artifact.Path != cloudPosturePath {
				continue
			}
			var posture struct {
				Accounts []map[string]any `json:"accounts"`
			}
			if err := json.Unmarshal(artifact.Data, &posture); err != nil {
				t.Fatal(err)
			}
			return posture.Accounts, res
		}
		t.Fatalf("no %s", cloudPosturePath)
		return nil, res
	}

	full, _ := accounts(nil)
	if len(full) == 0 || full[0]["iam"] == nil {
		t.Fatalf("accounts = %v, want iam with every kind collected", full)
	}
	left, res := accounts([]any{"cloud-posture", "idp-posture"})
	for i, account := range left {
		if account["iam"] != nil {
			t.Errorf("subscription %d has iam = %v, which moved to access-posture", i, account["iam"])
		}
		pointer := accountPointer(i, "iam")
		found := false
		for _, gap := range res.Result.Gaps {
			if gap.Path == cloudPosturePath && strings.HasPrefix(gap.Pointer, pointer+"/") {
				t.Errorf("gap %+v is inside a block the pack does not hold", gap)
			}
			found = found || (gap.Path == cloudPosturePath && gap.Pointer == pointer && gap.Code == componentsdk.CodeNotShared)
		}
		if !found {
			t.Errorf("no not_shared gap at %s", pointer)
		}
	}
}

// kitRefusedSubscriptionID is a second configured subscription that ARM
// refuses to show the app.
const kitRefusedSubscriptionID = "bbbbbbbb-1111-2222-3333-cccccccccccc"

// accountIDResponses answer a run over kitSubscriptionID, whose Defender has
// no secure score, and kitRefusedSubscriptionID, which ARM refuses.
func accountIDResponses() []collectortest.Response {
	responses := replaceResponse(kitResponses(), collectortest.Response{
		URL:    kitARMBase + "/subscriptions/" + kitSubscriptionID + "/providers/Microsoft.Security/secureScores/ascScore?api-version=2020-01-01",
		Status: http.StatusNotFound,
		Body:   `{"error":{"code":"NotFound","message":"Not found."}}`,
	})
	return append(responses, refusedSubscriptionResponse())
}

// refusedSubscriptionResponse is ARM refusing to show the app
// kitRefusedSubscriptionID, with an error that names the app, the tenant,
// and the subscription.
func refusedSubscriptionResponse() collectortest.Response {
	return collectortest.Response{
		URL:    kitARMBase + "/subscriptions/" + kitRefusedSubscriptionID + "?api-version=2020-01-01",
		Status: http.StatusForbidden,
		Body: kitJSON(map[string]any{"error": map[string]any{
			"code":    "AuthorizationFailed",
			"message": "The client '" + kitClientID + "' in tenant '" + strings.ToUpper(kitTenantID) + "' does not have authorization to perform action 'Microsoft.Resources/subscriptions/read' over scope '/subscriptions/" + kitRefusedSubscriptionID + "' or the scope is invalid.",
		}}),
	}
}

// A trust run writes no tenant, subscription, or app ID: not in the data
// artifacts, their diagnostics, or the collector result. Its diagnostics name
// a subscription by its place in subscription_ids. An audit run writes the
// tenant and subscription IDs as before.
func TestTrustRunWritesNoAccountIDs(t *testing.T) {
	run := func(level string) (componentsdk.InProcessResult, EntraArtifact, map[string]any) {
		t.Helper()
		config := kitConfig()
		config["level"] = level
		config["subscription_ids"] = []any{kitSubscriptionID, kitRefusedSubscriptionID}
		res := runInProcess(t, config, kitSecrets(), accountIDResponses())
		if res.ExitCode != 0 || res.Result == nil {
			t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
		}
		var entra EntraArtifact
		var azure map[string]any
		for _, artifact := range res.Artifacts {
			switch artifact.Path {
			case entraPath:
				if err := json.Unmarshal(artifact.Data, &entra); err != nil {
					t.Fatal(err)
				}
			case azurePath:
				if err := json.Unmarshal(artifact.Data, &azure); err != nil {
					t.Fatal(err)
				}
			}
		}
		return res, entra, azure
	}

	trust, entra, azure := run("trust")
	for _, artifact := range trust.Artifacts {
		data := strings.ToLower(string(artifact.Data))
		for _, id := range []string{kitTenantID, kitClientID, kitSubscriptionID, kitRefusedSubscriptionID} {
			if strings.Contains(data, id) {
				t.Errorf("%s names %s at trust: %s", artifact.Path, id, artifact.Data)
			}
		}
	}
	if accounts := azure["accounts"].([]any); len(accounts) != 2 || len(accounts[1].(map[string]any)) != 0 {
		t.Errorf("accounts = %v, want two with the refused one empty", accounts)
	}
	wantError := "subscription 2: status=403 code=AuthorizationFailed"
	if got := entra.Diagnostics.SubscriptionErrors; len(got) != 1 || got[0] != wantError {
		t.Errorf("subscription_errors = %q, want %q", got, wantError)
	}
	if !containsString(entra.Diagnostics.Warnings, "Defender secure score unavailable for subscription 1") {
		t.Errorf("warnings = %q, want the first subscription named by its place", entra.Diagnostics.Warnings)
	}
	for _, check := range trust.Result.Checks {
		t.Errorf("trust run has check finding %+v", check)
	}

	_, entra, azure = run("audit")
	if entra.TenantID != kitTenantID {
		t.Errorf("tenant_id = %q at audit, want %s", entra.TenantID, kitTenantID)
	}
	accounts := azure["accounts"].([]any)
	for i, id := range []string{kitSubscriptionID, kitRefusedSubscriptionID} {
		if got := accounts[i].(map[string]any)["account_id"]; got != id {
			t.Errorf("accounts[%d].account_id = %v at audit, want %s", i, got, id)
		}
	}
	if got := entra.Diagnostics.SubscriptionErrors; len(got) != 1 || !strings.HasPrefix(got[0], kitRefusedSubscriptionID+": arm request") || !strings.Contains(got[0], kitClientID) {
		t.Errorf("subscription_errors = %q at audit, want the ID and Azure's text as before", got)
	}
	if !containsString(entra.Diagnostics.Warnings, "Defender secure score unavailable for subscription "+kitSubscriptionID) {
		t.Errorf("warnings = %q at audit, want the first subscription named by its ID", entra.Diagnostics.Warnings)
	}
}

// A permission_denied gap names the Graph permission or Azure role its call
// needs, at every level.
func TestDeniedReadsNameWhatToGrant(t *testing.T) {
	cases := []struct {
		name       string
		responses  []collectortest.Response
		pointer    string
		permission string
	}{
		{"role assignments", roleAssignmentsDeniedResponses(), "/members/members_present", "Reader"},
		{"applications", applicationsDeniedResponses(), "/credentials/never_expiring_pct", "Application.Read.All"},
		{"sign-in activity", auditLogDeniedResponses(), "/members/inactive_pct", "AuditLog.Read.All"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := kitConfig()
			config["level"] = "trust"
			res := runInProcess(t, config, kitSecrets(), tc.responses)
			if res.ExitCode != 0 || res.Result == nil {
				t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
			}
			for _, gap := range res.Result.Gaps {
				if gap.Path != accessPosturePath || gap.Pointer != tc.pointer {
					continue
				}
				if gap.Code != componentsdk.CodePermissionDenied || gap.MissingPermission != tc.permission {
					t.Fatalf("gap = %s missing %q, want permission_denied missing %q", gap.Code, gap.MissingPermission, tc.permission)
				}
				return
			}
			t.Fatalf("no gap at %s; gaps: %#v", tc.pointer, res.Result.Gaps)
		})
	}
}

// An empty role assignment list leaves the role holders out with a
// permission_denied gap that names the call, since the identity can't see
// even the role it reads the subscription with.
func TestHiddenRoleAssignmentsLeaveRoleHoldersOut(t *testing.T) {
	res := runInProcess(t, kitConfig(), kitSecrets(), roleAssignmentsHiddenResponses())
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, gap := range res.Result.Gaps {
		if gap.Path != accessPosturePath || gap.Pointer != "/members/members_present" {
			continue
		}
		if gap.Code != componentsdk.CodePermissionDenied || gap.Operation != "arm.role_assignments.list" || !strings.Contains(gap.Detail, "Azure Lighthouse") {
			t.Fatalf("gap = %s from %q (%s), want permission_denied from arm.role_assignments.list", gap.Code, gap.Operation, gap.Detail)
		}
		return
	}
	t.Fatalf("no gap at /members/members_present; gaps: %#v", res.Result.Gaps)
}

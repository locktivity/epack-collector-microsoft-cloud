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
	"arm.backup.protected_items.list",
	"arm.backup.policies.list",
	"arm.backup.jobs.list",
	"arm.monitor.subscription_diagnostic_settings.list",
	"arm.monitor.diagnostic_settings.list",
	"arm.resources.list",
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
		Spec:    Spec("test", "collectortest"),
		Run:     Run,
		Config:  kitConfig(),
		Secrets: kitSecrets(),
		Clock:   goldenTime,
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
				}},
			},
			{Name: "defender assessments fail", Responses: defenderAssessmentsFailResponses()},
			{Name: "empty tenant", Responses: emptyTenantResponses()},
			{Name: "registration report behind the user list", Responses: registrationReportBehindResponses()},
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
						"/admins/admin_share_pct":        34,
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

func TestRegistrationReportBehindTheUserListLeavesMFACoverageOverNoOne(t *testing.T) {
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
	assertPtrInt(t, "posture.denominator_enabled_member_users", entra.Posture.DenominatorEnabledMemberUsers, 0)
	if entra.Posture.MFACoverage != nil || entra.Posture.SSPRRegistered != nil {
		t.Fatalf("MFA coverage = %v, SSPR = %v; want null over members the report does not list", entra.Posture.MFACoverage, entra.Posture.SSPRRegistered)
	}
	if len(res.Result.Checks) != 0 {
		t.Fatalf("output checks found %+v", res.Result.Checks)
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

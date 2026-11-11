package collector

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

const (
	kitTenantID       = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	kitClientID       = "11111111-2222-3333-4444-555555555555"
	kitSubscriptionID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	kitGitHubTokenURL = "https://pipelines.actions.githubusercontent.test/kit/idtoken?api-version=2.0"

	kitGraphBase  = "https://graph.microsoft.com/v1.0"
	kitARMBase    = "https://management.azure.com"
	kitTokenURL   = "https://login.microsoftonline.com/" + kitTenantID + "/oauth2/v2.0/token"
	kitGitHubWith = kitGitHubTokenURL + "&audience=api%3A%2F%2FAzureADTokenExchange"
)

var kitAppRoles = []string{
	"Application.Read.All",
	"AuditLog.Read.All",
	"Organization.Read.All",
	"Policy.Read.All",
	"RoleEligibilitySchedule.Read.Directory",
	"RoleManagement.Read.Directory",
	"SecurityEvents.Read.All",
	"User.Read.All",
}

// kitSignInResponses answer the sign-in: GitHub's identity token and the
// Entra token exchange, which both scopes share.
func kitSignInResponses() []collectortest.Response {
	assertion := kitJWT(map[string]any{"sub": "repo:northwind/compliance:ref:refs/heads/main", "aud": "api://AzureADTokenExchange"})
	accessToken := kitJWT(map[string]any{"tid": kitTenantID, "appid": kitClientID, "roles": kitAppRoles})
	return []collectortest.Response{
		{URL: kitGitHubWith, Body: kitJSON(map[string]any{"value": assertion})},
		{Method: http.MethodPost, URL: kitTokenURL, Body: kitJSON(map[string]any{"token_type": "Bearer", "access_token": accessToken, "expires_in": 3600})},
	}
}

// kitResponses answer every call a clean internal-level run makes, with the
// data the unit tests' fakes hold. URLs are built the way the clients build
// them.
func kitResponses() []collectortest.Response {
	return kitResponsesFor(fakeGraphClient(), fakeARMClient())
}

func kitResponsesFor(graph *fakeGraph, arm *fakeARM) []collectortest.Response {
	responses := kitSignInResponses()
	responses = append(responses, kitGraphResponses(graph)...)
	return append(responses, kitARMResponses(arm)...)
}

// emptyTenantResponses answer a tenant with no users, apps, roles, or
// policies, and a subscription with no resources.
func emptyTenantResponses() []collectortest.Response {
	graph := &fakeGraph{
		org:              fakeGraphClient().org,
		securityDefaults: &microsoft.IdentitySecurityDefaultsEnforcementPolicy{IsEnabled: true},
	}
	arm := &fakeARM{
		subscriptions: map[string]*microsoft.Subscription{kitSubscriptionID: {SubscriptionID: kitSubscriptionID, State: "Enabled"}},
		secureScores:  map[string]*microsoft.ARMSecureScore{kitSubscriptionID: {Name: "ascScore"}},
	}
	return kitResponsesFor(graph, arm)
}

// registrationReportBehindResponses answer a tenant whose MFA registration
// report predates both enabled members: it lists the guest, the disabled
// member, and a member deleted since, while the live user list has u1 and u2.
func registrationReportBehindResponses() []collectortest.Response {
	graph := fakeGraphClient()
	graph.registrations = []microsoft.UserRegistrationDetail{
		{ID: "u3", IsMFARegistered: true, MethodsRegistered: []string{"mobilePhone"}},
		{ID: "u4", IsMFARegistered: true, IsSSPRRegistered: true, MethodsRegistered: []string{"fido2SecurityKey"}},
		{ID: "u9", IsMFARegistered: true, IsSSPRRegistered: true, MethodsRegistered: []string{"fido2SecurityKey"}},
	}
	return kitResponsesFor(graph, fakeARMClient())
}

// groupRoleResponses answer a subscription where a group holds the Owner
// role besides the clean scenario's direct assignments.
func groupRoleResponses() []collectortest.Response {
	arm := fakeARMClient()
	arm.roleAssignments[kitSubscriptionID] = append(arm.roleAssignments[kitSubscriptionID],
		fakeRoleAssignment("owner-group", kitSubscriptionID, azureOwnerRoleDefinitionID, "Group", "g1"))
	return kitResponsesFor(fakeGraphClient(), arm)
}

// neverSecretResponses answer a tenant where app1, which sp1 belongs to, has
// a client secret created with the Azure portal's former Never option.
func neverSecretResponses() []collectortest.Response {
	graph := fakeGraphClient()
	graph.applications[0].PasswordCredentials = append(graph.applications[0].PasswordCredentials,
		microsoft.PasswordCredential{KeyID: "app-p-never", StartDateTime: "2020-01-01T00:00:00Z", EndDateTime: "2299-12-31T00:00:00Z"})
	return kitResponsesFor(graph, fakeARMClient())
}

// noEndDateResponses answer a tenant where sp2 has a client secret of its own
// with no end date.
func noEndDateResponses() []collectortest.Response {
	graph := fakeGraphClient()
	graph.servicePrincipals[1].PasswordCredentials = append(graph.servicePrincipals[1].PasswordCredentials,
		microsoft.PasswordCredential{KeyID: "sp-p-open", StartDateTime: "2025-01-01T00:00:00Z"})
	return kitResponsesFor(graph, fakeARMClient())
}

// managedIdentityResponses answer a subscription where a managed identity,
// which the Application service principal list does not hold, is a
// Contributor.
func managedIdentityResponses() []collectortest.Response {
	arm := fakeARMClient()
	arm.roleAssignments[kitSubscriptionID] = append(arm.roleAssignments[kitSubscriptionID],
		fakeRoleAssignment("contributor-identity", kitSubscriptionID, azureContributorRoleDefinitionID, "ServicePrincipal", "mi1"))
	return kitResponsesFor(fakeGraphClient(), arm)
}

// readOnlyServicePrincipalsResponses answer a subscription where sp1 is a
// Reader like sp2, so no service principal holds a role that writes.
func readOnlyServicePrincipalsResponses() []collectortest.Response {
	arm := fakeARMClient()
	for i, assignment := range arm.roleAssignments[kitSubscriptionID] {
		if assignment.Properties.PrincipalID == "sp1" {
			arm.roleAssignments[kitSubscriptionID][i] = fakeRoleAssignment("reader-sp1", kitSubscriptionID, azureReaderRoleDefinitionID, "ServicePrincipal", "sp1")
		}
	}
	return kitResponsesFor(fakeGraphClient(), arm)
}

// rotatedCredentialsResponses answer a tenant where every client secret and
// certificate of sp1, sp2, and their applications was added a month before
// the run.
func rotatedCredentialsResponses() []collectortest.Response {
	graph := fakeGraphClient()
	const added = "2026-04-26T00:00:00Z"
	for i := range graph.servicePrincipals {
		for j := range graph.servicePrincipals[i].PasswordCredentials {
			graph.servicePrincipals[i].PasswordCredentials[j].StartDateTime = added
		}
		for j := range graph.servicePrincipals[i].KeyCredentials {
			graph.servicePrincipals[i].KeyCredentials[j].StartDateTime = added
		}
	}
	for i := range graph.applications {
		for j := range graph.applications[i].PasswordCredentials {
			graph.applications[i].PasswordCredentials[j].StartDateTime = added
		}
		for j := range graph.applications[i].KeyCredentials {
			graph.applications[i].KeyCredentials[j].StartDateTime = added
		}
	}
	return kitResponsesFor(graph, fakeARMClient())
}

// applicationsDeniedResponses answer an app without permission to read the
// tenant's applications.
func applicationsDeniedResponses() []collectortest.Response {
	return replaceResponse(kitResponses(), graphError(kitApplicationsURL, http.StatusForbidden, kitRequestDeniedCode, kitRequestDeniedText))
}

// kitRoleAssignmentsURL is the subscription's role assignment list.
const kitRoleAssignmentsURL = kitARMBase + "/subscriptions/" + kitSubscriptionID + "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"

// roleAssignmentsDeniedResponses answer an app without permission to read
// the subscription's role assignments.
func roleAssignmentsDeniedResponses() []collectortest.Response {
	return replaceResponse(kitResponses(), collectortest.Response{
		URL:    kitRoleAssignmentsURL,
		Status: http.StatusForbidden,
		Body:   kitJSON(map[string]any{"error": map[string]any{"code": "AuthorizationFailed", "message": "The client does not have authorization to perform action 'Microsoft.Authorization/roleAssignments/read'."}}),
	})
}

// graphError is a Microsoft Graph error answer with status, code and message.
func graphError(url string, status int, code, message string) collectortest.Response {
	return collectortest.Response{
		URL:    url,
		Status: status,
		Body:   kitJSON(map[string]any{"error": map[string]any{"code": code, "message": message}}),
	}
}

const (
	kitServicePrincipalsURL = kitGraphBase + "/servicePrincipals?$filter=servicePrincipalType%20eq%20'Application'&$select=id,appId,accountEnabled,appRoleAssignmentRequired,preferredSingleSignOnMode,servicePrincipalType,passwordCredentials,keyCredentials&$top=999"
	kitApplicationsURL      = kitGraphBase + "/applications?$select=id,appId,passwordCredentials,keyCredentials&$top=999"
	kitRegistrationsURL     = kitGraphBase + "/reports/authenticationMethods/userRegistrationDetails"
	kitSignInActivityURL    = kitGraphBase + "/users?$select=id,accountEnabled,userType,signInActivity&$top=999"
	kitConditionalURL       = kitGraphBase + "/identity/conditionalAccess/policies"
	kitEligibilityURL       = kitGraphBase + "/roleManagement/directory/roleEligibilitySchedules?$expand=roleDefinition&$top=999"
	kitNonPremiumCode       = "Authentication_RequestFromNonPremiumTenantOrB2CTenant"
	kitNonPremiumMessage    = "Neither tenant is B2C or tenant doesn't have premium license"
	kitRequestDeniedCode    = "Authorization_RequestDenied"
	kitRequestDeniedText    = "Insufficient privileges to complete the operation."
	kitP2RequiredMessage    = "The tenant needs an AAD Premium 2 license."
	kitP2RequiredCode       = "AadPremiumLicenseRequired"
	kitConditionalMessage   = "Tenant does not have a premium license."
)

// freeTenantResponses answer a tenant on Entra ID Free, which has no MFA
// registration report, sign-in activity, Conditional Access or PIM.
func freeTenantResponses() []collectortest.Response {
	responses := kitResponses()
	for _, r := range []collectortest.Response{
		graphError(kitRegistrationsURL, http.StatusForbidden, kitNonPremiumCode, kitNonPremiumMessage),
		graphError(kitSignInActivityURL, http.StatusForbidden, kitNonPremiumCode, kitNonPremiumMessage),
		graphError(kitConditionalURL, http.StatusForbidden, kitP2RequiredCode, kitConditionalMessage),
		graphError(kitEligibilityURL, http.StatusBadRequest, kitP2RequiredCode, kitP2RequiredMessage),
	} {
		responses = replaceResponse(responses, r)
	}
	return responses
}

// auditLogDeniedResponses answer an app that lacks AuditLog.Read.All, so the
// MFA registration report and sign-in activity are refused.
func auditLogDeniedResponses() []collectortest.Response {
	responses := kitResponses()
	for _, url := range []string{kitRegistrationsURL, kitSignInActivityURL} {
		responses = replaceResponse(responses, graphError(url, http.StatusForbidden, kitRequestDeniedCode, kitRequestDeniedText))
	}
	return responses
}

func kitGraphResponses(graph *fakeGraph) []collectortest.Response {
	since := goldenTime.Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)

	signIns := url.Values{}
	signIns.Set("$filter", "createdDateTime ge "+since)
	signIns.Set("$orderby", "createdDateTime desc")
	signIns.Set("$select", "id,createdDateTime,userId,appId,status,conditionalAccessStatus,appliedConditionalAccessPolicies,clientAppUsed,riskLevelAggregated,riskLevelDuringSignIn")
	signIns.Set("$top", "999")

	audits := url.Values{}
	audits.Set("$filter", "activityDateTime ge "+since)
	audits.Set("$orderby", "activityDateTime desc")
	audits.Set("$select", "id,activityDateTime,activityDisplayName,category,loggedByService,operationType,result,targetResources")
	audits.Set("$top", "999")

	usersPage1 := kitGraphBase + "/users?$select=id,accountEnabled,userType&$top=999"
	usersPage2 := usersPage1 + "&$skiptoken=page-2"

	responses := []collectortest.Response{
		{URL: kitGraphBase + "/organization?$select=id,verifiedDomains", Body: graphPage([]any{graph.org}, "")},
	}
	responses = append(responses, twoPages(usersPage1, usersPage2, graph.users, graphPage[microsoft.User])...)
	return append(responses, []collectortest.Response{
		{URL: kitGraphBase + "/reports/authenticationMethods/userRegistrationDetails", Body: graphPage(graph.registrations, "")},
		{URL: kitGraphBase + "/users?$select=id,accountEnabled,userType,signInActivity&$top=999", Body: graphPage(graph.signInUsers, "")},
		{URL: kitGraphBase + "/identity/conditionalAccess/policies", Body: graphPage(graph.policies, "")},
		{URL: kitGraphBase + "/policies/identitySecurityDefaultsEnforcementPolicy", Body: kitJSON(graph.securityDefaults)},
		{URL: kitGraphBase + "/roleManagement/directory/roleAssignments?$expand=principal&$top=999", Body: graphPage(graph.roleAssignments, "")},
		{URL: kitRoleDefinitionsURL(true), Body: graphPage(roleDefinitionsClassed(graph.roleDefinitions, true), "")},
		{URL: kitRoleDefinitionsURL(false), Body: graphPage(roleDefinitionsClassed(graph.roleDefinitions, false), "")},
		{URL: kitGraphBase + "/identity/conditionalAccess/namedLocations", Body: graphPage(graph.namedLocations, "")},
		{URL: kitGraphBase + "/roleManagement/directory/roleEligibilitySchedules?$expand=roleDefinition&$top=999", Body: graphPage(graph.roleSchedules, "")},
		{URL: kitServicePrincipalsURL, Body: graphPage(graph.servicePrincipals, "")},
		{URL: kitApplicationsURL, Body: graphPage(graph.applications, "")},
		{URL: kitGraphBase + "/security/secureScores?$top=1", Body: graphPage(graph.secureScores, "")},
		{URL: kitGraphBase + "/auditLogs/directoryAudits?" + audits.Encode(), Body: graphPage(graph.directoryAudits, "")},
		{URL: kitGraphBase + "/auditLogs/signIns?" + signIns.Encode(), Body: graphPage(graph.signIns, "")},
	}...)
}

func kitARMResponses(arm *fakeARM) []collectortest.Response {
	subscription := "/subscriptions/" + kitSubscriptionID
	provider := func(path, apiVersion string) string {
		return kitARMBase + subscription + "/providers/" + path + "?api-version=" + apiVersion
	}
	assessmentsPage1 := provider("Microsoft.Security/assessments", "2020-01-01")
	assessmentsPage2 := assessmentsPage1 + "&$skipToken=page-2"

	responses := []collectortest.Response{
		{URL: kitARMBase + subscription + "?api-version=2020-01-01", Body: kitJSON(arm.subscriptions[kitSubscriptionID])},
		{URL: provider("Microsoft.Security/secureScores/ascScore", "2020-01-01"), Body: kitJSON(arm.secureScores[kitSubscriptionID])},
	}
	responses = append(responses, twoPages(assessmentsPage1, assessmentsPage2, arm.defenderAssessments[kitSubscriptionID], armPage[microsoft.SecurityAssessment])...)
	responses = append(responses, []collectortest.Response{
		{URL: kitRoleAssignmentsURL, Body: armPage(arm.roleAssignments[kitSubscriptionID], "")},
		{URL: provider("Microsoft.Authorization/policyAssignments", "2023-04-01") + "&$filter=atScope%28%29", Body: armPage(arm.policyAssignments[kitSubscriptionID], "")},
		{Method: http.MethodPost, URL: provider("Microsoft.PolicyInsights/policyStates/latest/summarize", "2019-10-01"), Body: kitJSON(arm.policyStateSummaries[kitSubscriptionID])},
		{URL: provider("Microsoft.Storage/storageAccounts", "2024-01-01"), Body: armPage(arm.storageAccounts[kitSubscriptionID], "")},
		{URL: provider("Microsoft.KeyVault/vaults", "2024-11-01"), Body: armPage(arm.keyVaults[kitSubscriptionID], "")},
		{URL: provider("Microsoft.Sql/servers", "2023-08-01"), Body: armPage(arm.sqlServers[kitSubscriptionID], "")},
		{URL: provider("Microsoft.Compute/virtualMachines", "2024-07-01"), Body: armPage(arm.virtualMachines[kitSubscriptionID], "")},
		{URL: provider("Microsoft.Network/publicIPAddresses", "2023-11-01"), Body: armPage(arm.publicIPs[kitSubscriptionID], "")},
		{URL: provider("Microsoft.Network/networkSecurityGroups", "2023-11-01"), Body: armPage(arm.networkSecurityGroups[kitSubscriptionID], "")},
		{URL: provider("Microsoft.RecoveryServices/vaults", "2026-01-01"), Body: armPage(listedVaults(arm.recoveryVaults[kitSubscriptionID]), "")},
		{URL: provider("Microsoft.Insights/diagnosticSettings", "2021-05-01-preview"), Body: armPage(arm.diagnosticSettings[subscription], "")},
		{URL: kitARMBase + subscription + "/resources?api-version=2021-04-01", Body: armPage(arm.resources[kitSubscriptionID], "")},
	}...)

	for _, server := range arm.sqlServers[kitSubscriptionID] {
		databases := arm.sqlDatabases[server.ID]
		responses = append(responses, collectortest.Response{URL: kitARMBase + server.ID + "/databases?api-version=2023-08-01", Body: armPage(databases, "")})
		for _, database := range databases {
			if tde, ok := arm.sqlTDE[database.ID]; ok {
				responses = append(responses, collectortest.Response{URL: kitARMBase + database.ID + "/transparentDataEncryption/current?api-version=2023-08-01", Body: kitJSON(tde)})
			}
		}
	}

	jobsQuery := url.Values{"api-version": []string{"2026-01-01"}, "$filter": []string{"operation eq 'Backup'"}}
	for _, vault := range arm.recoveryVaults[kitSubscriptionID] {
		responses = append(responses,
			collectortest.Response{URL: kitARMBase + vault.ID + "?api-version=2026-01-01", Body: kitJSON(vault)},
			collectortest.Response{URL: kitARMBase + vault.ID + "/backupProtectedItems?api-version=2026-01-01", Body: armPage(arm.backupProtectedItems[vault.ID], "")},
			collectortest.Response{URL: kitARMBase + vault.ID + "/backupPolicies?api-version=2026-01-01", Body: armPage(arm.backupPolicies[vault.ID], "")},
			collectortest.Response{URL: kitARMBase + vault.ID + "/backupJobs?" + jobsQuery.Encode(), Body: armPage(arm.backupJobs[vault.ID], "")},
		)
	}

	for _, resourceID := range kitMonitoredResourceIDs(arm) {
		responses = append(responses, collectortest.Response{
			URL:  kitARMBase + resourceID + "/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview",
			Body: armPage(arm.diagnosticSettings[resourceID], ""),
		})
	}
	return responses
}

// kitMonitoredResourceIDs lists every resource whose diagnostic settings a
// run can read. Those are each storage account and its services, each key
// vault, each SQL database including master, and each virtual machine.
func kitMonitoredResourceIDs(arm *fakeARM) []string {
	var ids []string
	for _, account := range arm.storageAccounts[kitSubscriptionID] {
		ids = append(ids, account.ID)
		for _, service := range storageServices {
			ids = append(ids, account.ID+"/"+service+"/default")
		}
	}
	for _, vault := range arm.keyVaults[kitSubscriptionID] {
		ids = append(ids, vault.ID)
	}
	for _, server := range arm.sqlServers[kitSubscriptionID] {
		for _, database := range arm.sqlDatabases[server.ID] {
			ids = append(ids, database.ID)
		}
	}
	for _, vm := range arm.virtualMachines[kitSubscriptionID] {
		ids = append(ids, vm.ID)
	}
	return ids
}

// replaceResponse swaps the response for one URL, such as a failing call in
// an otherwise clean scenario.
func replaceResponse(responses []collectortest.Response, replacement collectortest.Response) []collectortest.Response {
	out := make([]collectortest.Response, 0, len(responses))
	for _, response := range responses {
		if response.URL == replacement.URL && response.Method == replacement.Method {
			out = append(out, replacement)
			continue
		}
		out = append(out, response)
	}
	return out
}

// twoPages serves items the way the clients page through them: past two
// items, the rest come from the next link.
func twoPages[T any](first, second string, items []T, page func([]T, string) string) []collectortest.Response {
	if len(items) <= 2 {
		return []collectortest.Response{{URL: first, Body: page(items, "")}}
	}
	return []collectortest.Response{
		{URL: first, Body: page(items[:2], second)},
		{URL: second, Body: page(items[2:], "")},
	}
}

func graphPage[T any](items []T, next string) string {
	if items == nil {
		items = []T{}
	}
	page := map[string]any{"value": items}
	if next != "" {
		page["@odata.nextLink"] = next
	}
	return kitJSON(page)
}

// kitRoleDefinitionsURL is the role definitions read filtered on
// isPrivileged, the only way Graph v1.0 gives the classification.
func kitRoleDefinitionsURL(privileged bool) string {
	return kitGraphBase + "/roleManagement/directory/roleDefinitions?$filter=isPrivileged%20eq%20" + strconv.FormatBool(privileged) + "&$select=id,templateId,isPrivileged,rolePermissions"
}

// roleDefinitionsClassed is what that read returns: the roles Microsoft
// classifies that way, each with isPrivileged null, as Graph v1.0 leaves it.
func roleDefinitionsClassed(definitions []microsoft.UnifiedRoleDefinition, privileged bool) []microsoft.UnifiedRoleDefinition {
	var out []microsoft.UnifiedRoleDefinition
	for _, definition := range definitions {
		if definition.IsPrivileged != nil && *definition.IsPrivileged == privileged {
			definition.IsPrivileged = nil
			out = append(out, definition)
		}
	}
	return out
}

func armPage[T any](items []T, next string) string {
	if items == nil {
		items = []T{}
	}
	page := map[string]any{"value": items}
	if next != "" {
		page["nextLink"] = next
	}
	return kitJSON(page)
}

func kitJSON(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func kitJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(kitJSON(claims)))
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString([]byte("collectortest-signature"))
}

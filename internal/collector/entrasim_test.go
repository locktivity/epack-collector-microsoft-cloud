package collector

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
)

// entraSim answers the calls the collector makes for a tenant a roster
// describes, as Microsoft Graph answers them: Graph's response shapes, its
// page sizes and @odata.nextLink paging, and its error bodies for a missing
// license or permission. Which calls need which license and permission comes
// from each API's Microsoft Learn page, not from the collector. The Azure
// side is in azuresim_test.go.
//
// The roster's vendor extras give the tenant's license (tenant.license, one
// of AAD_PREMIUM_P2, AAD_PREMIUM, or empty for Entra ID Free), whether
// security defaults are on (tenant.security_defaults, or a sign-in policy
// marked security_defaults), each directory role's
// template ID (directory_role_ids), Microsoft's labels for roles the terms
// don't settle (directory_role_labels), and the Graph permissions of the app
// the collector signs in as (apps.collector.graph_permissions). An account with
// in_registration_report false is missing from the registration report.
type entraSim struct {
	r           *roster.Roster
	now         time.Time
	license     string
	defaults    bool
	permissions []string
	domain      string
	roleIDs     map[string]string
	// pageSize, when set, replaces Graph's page sizes, as a server may.
	pageSize int
}

// Graph's page sizes. The signInActivity size is the cap the users API puts
// on a $top above it. The registration report's size is not documented.
const (
	simUsersPage        = 999
	simSignInPage       = 500
	simRegistrationPage = 999
)

func newEntraSim(r *roster.Roster, now time.Time) (*entraSim, error) {
	var tenant struct {
		InitialDomain    string `json:"initial_domain"`
		License          string `json:"license"`
		SecurityDefaults bool   `json:"security_defaults"`
	}
	if _, err := r.Extra.Get("tenant", &tenant); err != nil {
		return nil, err
	}
	s := &entraSim{r: r, now: now, license: tenant.License, defaults: tenant.SecurityDefaults, domain: tenant.InitialDomain}
	for _, p := range r.Policies {
		s.defaults = s.defaults || securityDefaultsPolicy(p)
	}
	if _, err := r.Extra.Get("directory_role_ids", &s.roleIDs); err != nil {
		return nil, err
	}
	i := slices.IndexFunc(r.Apps, func(a roster.App) bool { return a.Key == "collector" })
	if i < 0 {
		return nil, fmt.Errorf("the roster has no collector app")
	}
	if _, err := r.Apps[i].Extra.Get("graph_permissions", &s.permissions); err != nil {
		return nil, err
	}
	roles := map[string]bool{}
	for _, a := range r.Accounts {
		for _, role := range append(slices.Clone(a.Roles), a.EligibleRoles...) {
			roles[role] = true
		}
	}
	for _, g := range r.Groups {
		for _, role := range g.Roles {
			roles[role] = true
		}
	}
	for _, p := range r.Policies {
		for _, role := range append(slices.Clone(p.Include.Roles), p.Exclude.Roles...) {
			roles[role] = true
		}
	}
	for role := range roles {
		if s.roleIDs[role] == "" {
			return nil, fmt.Errorf("directory_role_ids has no template ID for %s", role)
		}
	}
	return s, nil
}

func (s *entraSim) p1() bool { return s.license == "AAD_PREMIUM" || s.license == "AAD_PREMIUM_P2" }
func (s *entraSim) p2() bool { return s.license == "AAD_PREMIUM_P2" }

// responses answers every call of a run at any level.
func (s *entraSim) responses() []collectortest.Response {
	out := s.signIn()
	out = append(out, s.organization()...)
	out = append(out, s.users()...)
	out = append(out, s.usersWithSignInActivity()...)
	out = append(out, s.registrationDetails()...)
	out = append(out, s.conditionalAccess()...)
	out = append(out, s.securityDefaults()...)
	out = append(out, s.roleAssignments()...)
	out = append(out, s.roleDefinitions()...)
	out = append(out, s.eligibilitySchedules()...)
	out = append(out, s.servicePrincipals()...)
	out = append(out, s.applications()...)
	out = append(out, s.logs()...)
	return append(out, s.azure()...)
}

func (s *entraSim) signIn() []collectortest.Response {
	assertion := kitJWT(map[string]any{"sub": "repo:northwind/compliance:environment:sandbox-microsoft-cloud", "aud": "api://AzureADTokenExchange"})
	accessToken := kitJWT(map[string]any{"tid": kitTenantID, "appid": kitClientID, "roles": s.permissions})
	return []collectortest.Response{
		{URL: kitGitHubWith, Body: kitJSON(map[string]any{"value": assertion})},
		{Method: http.MethodPost, URL: kitTokenURL, Body: kitJSON(map[string]any{"token_type": "Bearer", "access_token": accessToken, "expires_in": 3599, "ext_expires_in": 3599})},
	}
}

// simAccess is what a Graph call needs: a license, and for each group of
// permissions one of them.
type simAccess struct {
	p1, p2 bool
	// licenseStatus, licenseCode and licenseMessage are Graph's answer
	// without the license.
	licenseStatus                int
	licenseCode, licenseMessage  string
	permissions                  [][]string
	deniedCode, deniedMessage    string
	deniedStatus                 int
	deniedMessageNamesPermission bool
}

var (
	simNonPremium = simAccess{p1: true, licenseStatus: http.StatusForbidden,
		licenseCode: "Authentication_RequestFromNonPremiumTenantOrB2CTenant", licenseMessage: "Neither tenant is B2C or tenant doesn't have premium license"}
	simDirectoryDenied = simAccess{deniedStatus: http.StatusForbidden,
		deniedCode: "Authorization_RequestDenied", deniedMessage: "Insufficient privileges to complete the operation."}
	simReportDenied = simAccess{deniedStatus: http.StatusForbidden,
		deniedCode: "Authentication_MSGraphPermissionMissing", deniedMessage: "Calling principal does not have required MSGraph permissions %s", deniedMessageNamesPermission: true}
	simPolicyDenied = simAccess{deniedStatus: http.StatusForbidden,
		deniedCode: "AccessDenied", deniedMessage: "You cannot perform the requested operation, required scopes are missing in the token."}
)

func access(base simAccess, license *simAccess, permissions ...[]string) simAccess {
	if license != nil {
		base.p1, base.p2 = license.p1, license.p2
		base.licenseStatus, base.licenseCode, base.licenseMessage = license.licenseStatus, license.licenseCode, license.licenseMessage
	}
	base.permissions = permissions
	return base
}

// refusal is Graph's error answer when the tenant lacks the call's license
// or the app lacks its permission, or nil when the call goes through.
func (s *entraSim) refusal(a simAccess) *collectortest.Response {
	for _, anyOf := range a.permissions {
		if slices.ContainsFunc(anyOf, func(p string) bool { return slices.Contains(s.permissions, p) }) {
			continue
		}
		message := a.deniedMessage
		if a.deniedMessageNamesPermission {
			message = fmt.Sprintf(message, anyOf[0])
		}
		return &collectortest.Response{Status: a.deniedStatus, Body: simError(a.deniedCode, message, s.now)}
	}
	if (a.p1 && !s.p1()) || (a.p2 && !s.p2()) {
		return &collectortest.Response{Status: a.licenseStatus, Body: simError(a.licenseCode, a.licenseMessage, s.now)}
	}
	return nil
}

func simError(code, message string, now time.Time) string {
	return kitJSON(map[string]any{"error": map[string]any{
		"code":    code,
		"message": message,
		"innerError": map[string]any{
			"date":              now.UTC().Format("2006-01-02T15:04:05"),
			"request-id":        "8a8d1a9e-4a43-4e4f-9b1e-5a3b5a0a2b1c",
			"client-request-id": "8a8d1a9e-4a43-4e4f-9b1e-5a3b5a0a2b1c",
		},
	}})
}

// list answers a Graph list at first, in pages of size with an opaque
// $skiptoken in each next link, or with Graph's refusal.
func (s *entraSim) list(first, context string, a simAccess, items []any, size int) []collectortest.Response {
	if refused := s.refusal(a); refused != nil {
		refused.URL = first
		return []collectortest.Response{*refused}
	}
	if items == nil {
		items = []any{}
	}
	if s.pageSize > 0 {
		size = s.pageSize
	}
	sep := "&"
	if !strings.Contains(first, "?") {
		sep = "?"
	}
	var out []collectortest.Response
	// A URL with no query matches any query unless it ends in ?, and the
	// next pages add one.
	at := first
	if sep == "?" {
		at += "?"
	}
	for start := 0; ; start += size {
		end := min(start+size, len(items))
		page := map[string]any{"@odata.context": kitGraphBase + "/$metadata#" + context, "value": items[start:end]}
		next := ""
		if end < len(items) {
			token := base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, "RFNwdAIAAQAAA%s:%d", context, end))
			next = first + sep + "$skiptoken=" + token
			page["@odata.nextLink"] = next
		}
		out = append(out, collectortest.Response{URL: at, Body: kitJSON(page)})
		if next == "" {
			return out
		}
		at = next
	}
}

func (s *entraSim) organization() []collectortest.Response {
	org := map[string]any{"id": kitTenantID, "verifiedDomains": []any{map[string]any{
		"capabilities": "Email, OfficeCommunicationsOnline", "isDefault": true, "isInitial": true, "name": s.domain, "type": "Managed",
	}}}
	return s.list(kitGraphBase+"/organization?$select=id,verifiedDomains", "organization(id,verifiedDomains)",
		access(simDirectoryDenied, nil, []string{"Organization.Read.All", "Directory.Read.All"}), []any{org}, simUsersPage)
}

var simUserRead = []string{"User.Read.All", "Directory.Read.All"}

func (s *entraSim) userType(a roster.Account) string {
	if s.r.Guest(a) {
		return "Guest"
	}
	return "Member"
}

func (s *entraSim) users() []collectortest.Response {
	items := make([]any, 0, len(s.r.Accounts))
	for _, a := range s.r.Accounts {
		items = append(items, map[string]any{"id": simID("user", a.Key), "accountEnabled": a.Enabled, "userType": s.userType(a)})
	}
	return s.list(kitGraphBase+"/users?$select=id,accountEnabled,userType&$top=999", "users(id,accountEnabled,userType)",
		access(simDirectoryDenied, nil, simUserRead), items, simUsersPage)
}

// usersWithSignInActivity answers with each user's signInActivity, which
// is null for a user who has never signed in.
func (s *entraSim) usersWithSignInActivity() []collectortest.Response {
	items := make([]any, 0, len(s.r.Accounts))
	for _, a := range s.r.Accounts {
		var activity any
		if a.SignedInDaysAgo != nil {
			at := s.now.AddDate(0, 0, -*a.SignedInDaysAgo).UTC().Format(time.RFC3339)
			requestID := simID("signin", a.Key)
			activity = map[string]any{
				"lastSignInDateTime":                at,
				"lastSignInRequestId":               requestID,
				"lastNonInteractiveSignInDateTime":  "0001-01-01T00:00:00Z",
				"lastNonInteractiveSignInRequestId": "",
				"lastSuccessfulSignInDateTime":      at,
				"lastSuccessfulSignInRequestId":     requestID,
			}
		}
		items = append(items, map[string]any{"id": simID("user", a.Key), "accountEnabled": a.Enabled, "userType": s.userType(a), "signInActivity": activity})
	}
	return s.list(kitGraphBase+"/users?$select=id,accountEnabled,userType,signInActivity&$top=999", "users(id,accountEnabled,userType,signInActivity)",
		access(simDirectoryDenied, &simNonPremium, simUserRead, []string{"AuditLog.Read.All"}), items, simSignInPage)
}

// registrationDetails lists the enabled users, since the report leaves out
// disabled ones, less any the roster marks as missing from it.
func (s *entraSim) registrationDetails() []collectortest.Response {
	var items []any
	for _, a := range s.r.Accounts {
		listed := true
		if _, err := a.Extra.Get("in_registration_report", &listed); err != nil {
			panic(err)
		}
		if !a.Enabled || !listed {
			continue
		}
		class := s.r.MFAClass(a)
		methods := a.Methods
		if methods == nil {
			methods = []string{}
		}
		preferred := "none"
		if class != roster.MFANone {
			preferred = "push"
		}
		items = append(items, map[string]any{
			"id":                    simID("user", a.Key),
			"userPrincipalName":     s.upn(a),
			"userDisplayName":       a.Key,
			"userType":              strings.ToLower(s.userType(a)),
			"isAdmin":               s.isAdmin(a),
			"isSsprRegistered":      len(a.Methods) > 0,
			"isSsprEnabled":         false,
			"isSsprCapable":         false,
			"isMfaRegistered":       class != roster.MFANone,
			"isMfaCapable":          class != roster.MFANone,
			"isPasswordlessCapable": slices.ContainsFunc(a.Methods, func(m string) bool { return slices.Contains(simPasswordlessMethods, m) }),
			"methodsRegistered":     methods,
			"isSystemPreferredAuthenticationMethodEnabled":  true,
			"systemPreferredAuthenticationMethods":          []string{},
			"userPreferredMethodForSecondaryAuthentication": preferred,
			"lastUpdatedDateTime":                           s.now.Add(-20 * time.Hour).UTC().Format(time.RFC3339Nano),
		})
	}
	return s.list(kitGraphBase+"/reports/authenticationMethods/userRegistrationDetails", "reports/authenticationMethods/userRegistrationDetails",
		access(simReportDenied, &simNonPremium, []string{"AuditLog.Read.All"}), items, simRegistrationPage)
}

// simPasswordlessMethods are the methods that make a user passwordless
// capable, which the registration report's page gives as FIDO2, Windows
// Hello for Business and Microsoft Authenticator's passwordless sign-in.
// Passkeys are FIDO2 credentials.
var simPasswordlessMethods = []string{"fido2SecurityKey", "windowsHelloForBusiness", "microsoftAuthenticatorPasswordless",
	"passKeyDeviceBound", "passKeyDeviceBoundAuthenticator", "passKeyDeviceBoundWindowsHello"}

func (s *entraSim) isAdmin(a roster.Account) bool {
	return slices.ContainsFunc(s.r.HeldRoles(a), func(role string) bool { return s.r.Terms.Roles[role] != roster.RoleNone })
}

func (s *entraSim) upn(a roster.Account) string {
	name := strings.ReplaceAll(a.Key, "_", ".")
	if a.Kind == "creator" {
		return name + "_outlook.com#EXT#@" + s.domain
	}
	return name + "@" + s.domain
}

var simConditionalAccessLicense = simAccess{p1: true, licenseStatus: http.StatusForbidden,
	licenseCode: "AadPremiumLicenseRequired", licenseMessage: "Tenant does not have a premium license."}

// securityDefaultsPolicy reports whether a sign-in policy is one of the
// rules security defaults turn on, which Graph shows as one flag rather than
// as Conditional Access policies.
func securityDefaultsPolicy(p roster.Policy) bool {
	defaults := false
	if _, err := p.Extra.Get("security_defaults", &defaults); err != nil {
		panic(err)
	}
	return defaults
}

func (s *entraSim) conditionalAccess() []collectortest.Response {
	var items []any
	for _, p := range s.r.Policies {
		if !securityDefaultsPolicy(p) {
			items = append(items, s.policy(p))
		}
	}
	return s.list(kitGraphBase+"/identity/conditionalAccess/policies", "identity/conditionalAccess/policies",
		access(simPolicyDenied, &simConditionalAccessLicense, []string{"Policy.Read.All"}), items, simUsersPage)
}

// policy renders a sign-in policy as a conditionalAccessPolicy.
func (s *entraSim) policy(p roster.Policy) map[string]any {
	ids := func(kind string, keys []string) []string {
		out := []string{}
		for _, k := range keys {
			out = append(out, simID(kind, k))
		}
		return out
	}
	roles := func(names []string) []string {
		out := []string{}
		for _, n := range names {
			out = append(out, s.roleIDs[n])
		}
		return out
	}
	includeUsers := ids("user", p.Include.Accounts)
	if p.Include.All {
		includeUsers = []string{"All"}
	}
	apps := []string{"All"}
	if len(p.Apps) > 0 {
		apps = p.Apps
	}
	clientApps := []string{"all"}
	if p.Blocks == "legacy_auth" {
		clientApps = []string{"exchangeActiveSync", "other"}
	}
	conditions := map[string]any{
		"userRiskLevels":             []string{},
		"signInRiskLevels":           []string{},
		"servicePrincipalRiskLevels": []string{},
		"clientAppTypes":             clientApps,
		"platforms":                  nil,
		"locations":                  nil,
		"times":                      nil,
		"deviceStates":               nil,
		"devices":                    nil,
		"clientApplications":         nil,
		"insiderRiskLevels":          nil,
		"authenticationFlows":        nil,
		"applications": map[string]any{
			"includeApplications": apps, "excludeApplications": append([]string{}, p.ExcludeApps...), "includeUserActions": []string{},
			"includeAuthenticationContextClassReferences": []string{}, "applicationFilter": nil,
		},
		"users": map[string]any{
			"includeUsers": includeUsers, "excludeUsers": ids("user", p.Exclude.Accounts),
			"includeGroups": ids("group", p.Include.Groups), "excludeGroups": ids("group", p.Exclude.Groups),
			"includeRoles": roles(p.Include.Roles), "excludeRoles": roles(p.Exclude.Roles),
			"includeGuestsOrExternalUsers": nil, "excludeGuestsOrExternalUsers": nil,
		},
	}
	// A rendering is an equivalent way Graph can show a policy, such as an
	// explicit list of every client app where the portal leaves the
	// condition unset.
	var renderings []string
	if _, err := p.Extra.Get("render", &renderings); err != nil {
		panic(err)
	}
	for _, c := range append(slices.Clone(p.Conditions), renderings...) {
		switch c {
		case "sign_in_risk":
			conditions["signInRiskLevels"] = []string{"high", "medium"}
		case "user_risk":
			conditions["userRiskLevels"] = []string{"high"}
		case "untrusted_location":
			conditions["locations"] = map[string]any{"includeLocations": []string{"All"}, "excludeLocations": []string{"AllTrusted"}}
		case "trusted_location":
			conditions["locations"] = map[string]any{"includeLocations": []string{"AllTrusted"}, "excludeLocations": []string{}}
		case "quiet_sign_in":
			conditions["signInRiskLevels"] = []string{"none", "low"}
		case "known_platforms":
			conditions["platforms"] = map[string]any{"includePlatforms": []string{"android", "iOS", "windows", "windowsPhone", "macOS", "linux"}, "excludePlatforms": []string{}}
		case "all_but_ios":
			conditions["platforms"] = map[string]any{"includePlatforms": []string{"all"}, "excludePlatforms": []string{"iOS"}}
		case "platform_ios":
			conditions["platforms"] = map[string]any{"includePlatforms": []string{"iOS"}, "excludePlatforms": []string{}}
		case "browser_only":
			conditions["clientAppTypes"] = []string{"browser"}
		case "modern_clients_only":
			conditions["clientAppTypes"] = []string{"browser", "mobileAppsAndDesktopClients"}
		case "other_clients_only":
			conditions["clientAppTypes"] = []string{"other"}
		case "device_filter":
			conditions["devices"] = map[string]any{"deviceFilter": map[string]any{"mode": "exclude", "rule": `device.trustType -eq "ServerAD"`}}
		case "all_locations":
			conditions["locations"] = map[string]any{"includeLocations": []string{"All"}, "excludeLocations": []string{}}
		case "all_platforms":
			conditions["platforms"] = map[string]any{"includePlatforms": []string{"all"}, "excludePlatforms": []string{}}
		case "every_client_app":
			conditions["clientAppTypes"] = []string{"browser", "mobileAppsAndDesktopClients", "exchangeActiveSync", "other"}
		default:
			panic("entraSim: no rendering for condition " + c)
		}
	}
	grant := s.grant(p)
	if p.Blocks == "legacy_auth" {
		grant["builtInControls"] = []string{"block"}
	}
	var name string
	if _, err := p.Extra.Get("display_name", &name); err != nil || name == "" {
		name = p.Key
	}
	return map[string]any{
		"id": simID("policy", p.Key), "templateId": nil, "displayName": name,
		"createdDateTime": "2026-03-01T00:00:00Z", "modifiedDateTime": nil, "state": p.State,
		"sessionControls": nil, "conditions": conditions, "grantControls": grant,
	}
}

// simStrengths are the built-in authentication strengths. Their IDs are
// the ones Graph gives built-in strengths, which the strengths page does not
// list. The combinations are a part of each strength's list.
var simStrengths = map[string]map[string]any{
	"mfaStrength": {"id": "00000000-0000-0000-0000-000000000002", "displayName": "Multifactor authentication", "policyType": "builtIn",
		"requirementsSatisfied": "mfa", "allowedCombinations": []string{"windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor", "deviceBasedPush",
			"temporaryAccessPassOneTime", "temporaryAccessPassMultiUse", "password,microsoftAuthenticatorPush", "password,softwareOath", "password,hardwareOath", "password,sms", "password,voice"}},
	"passwordlessMfa": {"id": "00000000-0000-0000-0000-000000000003", "displayName": "Passwordless MFA", "policyType": "builtIn",
		"requirementsSatisfied": "mfa", "allowedCombinations": []string{"windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor", "deviceBasedPush"}},
	"phishingResistantMfa": {"id": "00000000-0000-0000-0000-000000000004", "displayName": "Phishing-resistant MFA", "policyType": "builtIn",
		"requirementsSatisfied": "mfa", "allowedCombinations": []string{"windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"}},
}

// grant renders a policy's requirements as grant controls: AND when all are
// due and OR when any will do.
func (s *entraSim) grant(p roster.Policy) map[string]any {
	builtIn, termsOfUse := []string{}, []string{}
	var strength any
	for _, req := range p.Requires {
		switch req {
		case "mfa", "compliantDevice", "domainJoinedDevice", "passwordChange":
			builtIn = append(builtIn, req)
		case "termsOfUse":
			termsOfUse = append(termsOfUse, simID("terms", p.Key))
		default:
			if simStrengths[req] == nil {
				panic("entraSim: no grant control for " + req)
			}
			strength = simStrengths[req]
		}
	}
	operator := "OR"
	if len(p.Requires) > 1 && !p.RequireAny {
		operator = "AND"
	}
	return map[string]any{"operator": operator, "builtInControls": builtIn, "customAuthenticationFactors": []string{}, "termsOfUse": termsOfUse, "authenticationStrength": strength}
}

func (s *entraSim) securityDefaults() []collectortest.Response {
	route := kitGraphBase + "/policies/identitySecurityDefaultsEnforcementPolicy"
	if refused := s.refusal(access(simPolicyDenied, nil, []string{"Policy.Read.All"})); refused != nil {
		refused.URL = route
		return []collectortest.Response{*refused}
	}
	return []collectortest.Response{{URL: route, Body: kitJSON(map[string]any{
		"@odata.context": kitGraphBase + "/$metadata#policies/identitySecurityDefaultsEnforcementPolicy/$entity",
		"id":             "00000000-0000-0000-0000-000000000005",
		"displayName":    "Security Defaults",
		"description":    "Security defaults is a set of basic identity security mechanisms recommended by Microsoft.",
		"isEnabled":      s.defaults,
	})}}
}

// roleAssignments lists every directory role held now, by users, disabled
// ones included, and by groups.
func (s *entraSim) roleAssignments() []collectortest.Response {
	var items []any
	assign := func(principalID, role string, principal map[string]any) {
		items = append(items, map[string]any{
			"id":               simID("assignment", principalID+role),
			"principalId":      principalID,
			"directoryScopeId": "/",
			"roleDefinitionId": s.roleIDs[role],
			"principal":        principal,
		})
	}
	for _, a := range s.r.Accounts {
		id := simID("user", a.Key)
		for _, role := range a.Roles {
			assign(id, role, map[string]any{
				"@odata.type": "#microsoft.graph.user", "id": id, "accountEnabled": a.Enabled,
				"displayName": a.Key, "userPrincipalName": s.upn(a), "userType": s.userType(a),
			})
		}
	}
	for _, g := range s.r.Groups {
		id := simID("group", g.Key)
		for _, role := range g.Roles {
			assign(id, role, map[string]any{
				"@odata.type": "#microsoft.graph.group", "id": id, "displayName": g.Key,
				"isAssignableToRole": true, "securityEnabled": true, "mailEnabled": false,
			})
		}
	}
	return s.list(kitGraphBase+"/roleManagement/directory/roleAssignments?$expand=principal&$top=999", "roleManagement/directory/roleAssignments(principal())",
		access(simDirectoryDenied, nil, []string{"RoleManagement.Read.Directory", "Directory.Read.All"}), items, simUsersPage)
}

// roleDefinitions lists the directory roles the roster names, as Graph v1.0
// lists built-in roles: a read filtered on isPrivileged returns the roles
// Microsoft labels that way, with isPrivileged itself null, and each role
// allows one directory action, a write unless the role only reads. A role
// directory_role_labels doesn't list is labeled privileged and changes
// something when the terms map it to an admin class, and neither otherwise.
// https://learn.microsoft.com/en-us/graph/api/resources/unifiedroledefinition
func (s *entraSim) roleDefinitions() []collectortest.Response {
	labels := map[string]struct {
		Privileged bool `json:"privileged"`
		ReadOnly   bool `json:"read_only"`
	}{}
	if _, err := s.r.Extra.Get("directory_role_labels", &labels); err != nil {
		panic(err)
	}
	items := map[bool][]any{}
	for _, role := range slices.Sorted(maps.Keys(s.roleIDs)) {
		label, ok := labels[role]
		if !ok {
			class := s.r.Terms.Roles[role]
			label.Privileged = class == roster.RoleAdmin || class == roster.RoleSuperAdmin
		}
		action := "microsoft.directory/users/basic/update"
		if label.ReadOnly {
			action = "microsoft.directory/users/standard/read"
		}
		id := s.roleIDs[role]
		items[label.Privileged] = append(items[label.Privileged], map[string]any{
			"id": id, "templateId": id, "isPrivileged": nil,
			"rolePermissions": []any{map[string]any{"allowedResourceActions": []string{action}, "condition": nil, "excludedResourceActions": []string{}}},
		})
	}
	var out []collectortest.Response
	for _, privileged := range []bool{true, false} {
		out = append(out, s.list(kitRoleDefinitionsURL(privileged),
			"roleManagement/directory/roleDefinitions(id,templateId,isPrivileged,rolePermissions)",
			access(simDirectoryDenied, nil, []string{"RoleManagement.Read.Directory", "Directory.Read.All"}), items[privileged], simUsersPage)...)
	}
	return out
}

var simP2License = simAccess{p1: true, p2: true, licenseStatus: http.StatusBadRequest,
	licenseCode: "AadPremiumLicenseRequired", licenseMessage: "The tenant needs an AAD Premium 2 license."}

func (s *entraSim) eligibilitySchedules() []collectortest.Response {
	var items []any
	for _, a := range s.r.Accounts {
		for _, role := range a.EligibleRoles {
			id := s.roleIDs[role]
			items = append(items, map[string]any{
				"id": simID("eligibility", a.Key+role), "principalId": simID("user", a.Key), "roleDefinitionId": id,
				"directoryScopeId": "/", "appScopeId": nil, "createdUsing": simID("eligibility", a.Key+role),
				"createdDateTime": "2026-03-01T00:00:00Z", "modifiedDateTime": nil, "status": "Provisioned", "memberType": "Direct",
				"scheduleInfo": map[string]any{"startDateTime": "2026-03-01T00:00:00Z", "recurrence": nil,
					"expiration": map[string]any{"type": "noExpiration", "endDateTime": nil, "duration": nil}},
				"roleDefinition": map[string]any{"id": id, "description": role, "displayName": role, "isBuiltIn": true,
					"isEnabled": true, "resourceScopes": []string{"/"}, "templateId": id, "version": "1", "rolePermissions": []any{}},
			})
		}
	}
	return s.list(kitGraphBase+"/roleManagement/directory/roleEligibilitySchedules?$expand=roleDefinition&$top=999", "roleManagement/directory/roleEligibilitySchedules(roleDefinition())",
		access(simPolicyDenied, &simP2License, []string{"RoleEligibilitySchedule.Read.Directory", "RoleManagement.Read.Directory"}), items, simUsersPage)
}

var simAppRead = []string{"Application.Read.All", "Directory.Read.All"}

func (s *entraSim) servicePrincipals() []collectortest.Response {
	var items []any
	for _, a := range s.r.Apps {
		required := false
		if _, err := a.Extra.Get("assignment_required", &required); err != nil {
			panic(err)
		}
		var mode any
		if a.SSOMode != "" {
			mode = a.SSOMode
		}
		items = append(items, map[string]any{
			"id": simID("sp", a.Key), "appId": simID("app", a.Key), "accountEnabled": a.Enabled,
			"appRoleAssignmentRequired": required, "preferredSingleSignOnMode": mode, "servicePrincipalType": "Application",
			"passwordCredentials": []any{}, "keyCredentials": []any{},
		})
	}
	return s.list(kitServicePrincipalsURL, "servicePrincipals(id,appId,accountEnabled,appRoleAssignmentRequired,preferredSingleSignOnMode,servicePrincipalType,passwordCredentials,keyCredentials)",
		access(simDirectoryDenied, nil, simAppRead), items, simUsersPage)
}

func (s *entraSim) applications() []collectortest.Response {
	var items []any
	for _, a := range s.r.Apps {
		passwords, keys := []any{}, []any{}
		for _, c := range a.Credentials {
			keyID := simID("credential", a.Key+c.Key)
			switch c.Kind {
			case "password":
				passwords = append(passwords, map[string]any{"customKeyIdentifier": nil, "displayName": c.Key, "endDateTime": c.End,
					"hint": "abc", "keyId": keyID, "secretText": nil, "startDateTime": c.Start})
			case "certificate":
				keys = append(keys, map[string]any{"customKeyIdentifier": "QUJDREVG", "displayName": "CN=" + c.Key, "endDateTime": c.End,
					"key": nil, "keyId": keyID, "startDateTime": c.Start, "type": "AsymmetricX509Cert", "usage": "Verify"})
			}
		}
		items = append(items, map[string]any{"id": simID("application", a.Key), "appId": simID("app", a.Key), "passwordCredentials": passwords, "keyCredentials": keys})
	}
	return s.list(kitApplicationsURL, "applications(id,appId,passwordCredentials,keyCredentials)", access(simDirectoryDenied, nil, simAppRead), items, simUsersPage)
}

// logs answers the secure score and the sign-in and audit logs, which hold
// nothing the identity values read.
func (s *entraSim) logs() []collectortest.Response {
	since := s.now.Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)
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
	score := map[string]any{"id": kitTenantID + "_2026-05-26", "azureTenantId": kitTenantID, "createdDateTime": s.now.Add(-12 * time.Hour).UTC().Format(time.RFC3339),
		"currentScore": 31.5, "maxScore": 100.0, "activeUserCount": 0, "licensedUserCount": 0, "enabledServices": []string{}, "averageComparativeScores": []any{}, "controlScores": []any{}}
	auditLog := []string{"AuditLog.Read.All"}
	out := s.list(kitGraphBase+"/security/secureScores?$top=1", "security/secureScores", access(simDirectoryDenied, nil, []string{"SecurityEvents.Read.All"}), []any{score}, 1)
	out = append(out, s.list(kitGraphBase+"/auditLogs/signIns?"+signIns.Encode(), "auditLogs/signIns", access(simReportDenied, &simNonPremium, auditLog), nil, simUsersPage)...)
	return append(out, s.list(kitGraphBase+"/auditLogs/directoryAudits?"+audits.Encode(), "auditLogs/directoryAudits", access(simReportDenied, nil, auditLog), nil, simUsersPage)...)
}

// simID is a stable object ID for a roster key.
func simID(kind, key string) string {
	sum := sha256.Sum256([]byte(kind + "/" + key))
	h := fmt.Sprintf("%x", sum[:16])
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:32]
}

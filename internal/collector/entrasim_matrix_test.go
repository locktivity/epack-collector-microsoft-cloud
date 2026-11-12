package collector

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
)

// The simulated matrix varies the sandbox roster along the axes below, the
// settings the scenarios hold fixed. Each one-at-a-time row changes one
// setting, so a difference it shows belongs to that setting and is listed in
// simMatrixAlone with a verdict. The pairwise rows put every two settings
// together at least once, and a difference none of a row's settings shows
// alone must be listed in simMatrixTogether.

// simMatrixAdmin is an account the matrix adds to the sandbox, an enabled
// member with Authenticator push who signed in three days ago and holds no
// role until the admin axes give it one.
const simMatrixAdmin = "matrix_admin"

// simPrivilegedRoles maps the roles the matrix gives the extra account to
// their template IDs, with whether the permissions reference labels each
// one privileged and whether it only reads. A role is privileged in the
// normalized sense when it is labeled and does more than read; the terms
// map those to admin and the rest to none.
// https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
var simPrivilegedRoles = []struct {
	name, id          string
	labeled, readOnly bool
}{
	{"Privileged Role Administrator", "e8611ab8-c189-46e8-94e1-60213ab1f814", true, false},
	{"Helpdesk Administrator", "729827e3-9c14-49f7-bb1b-9608f156bbb8", true, false},
	{"Hybrid Identity Administrator", "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2", true, false},
	{"Partner Tier2 Support", "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8", true, false},
	{"Password Administrator", "966707d0-3269-4727-9be2-8c3a10f19b9d", true, false},
	{"Intune Administrator", "3a2c62db-5318-420d-8d74-23affee5d9d5", true, false},
	{"Global Reader", "f2ef992c-3afb-46b9-b7cf-a126ee74c451", true, true},
	{"Exchange Administrator", "29232cdf-9323-42fd-ade2-1d097af3e4de", false, false},
	{"Directory Readers", "88d8e3e3-8f55-4a1e-953a-9b9898b8876b", false, true},
}

// simMatrixMethods maps the methods the matrix registers to their class:
// the methods in the phishing-resistant strength, and Authenticator phone
// sign-in, which is passwordless but not phishing-resistant. Email is no
// MFA method.
// https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths
var simMatrixMethods = map[string]string{
	"email":                              roster.MFANone,
	"softwareOneTimePasscode":            roster.MFA,
	"microsoftAuthenticatorPasswordless": roster.MFA,
	"fido2SecurityKey":                   roster.MFAPhishingResistant,
	"windowsHelloForBusiness":            roster.MFAPhishingResistant,
	"passKeyDeviceBound":                 roster.MFAPhishingResistant,
	"passKeyDeviceBoundAuthenticator":    roster.MFAPhishingResistant,
}

// simMatrixRequirements maps the grant controls and authentication
// strengths the matrix requires. Passwordless MFA holds Authenticator phone
// sign-in, so it is MFA but not phishing-resistant.
var simMatrixRequirements = map[string]string{
	"mfaStrength":          roster.RequiresMFA,
	"passwordlessMfa":      roster.RequiresMFA,
	"phishingResistantMfa": roster.RequiresPhishingResistantMFA,
	"domainJoinedDevice":   roster.RequiresManagedDevice,
	"termsOfUse":           roster.RequiresOther,
}

// simCloudRoles are the Azure roles the matrix gives the extra account,
// with whether each makes an admin in the normalized sense: it can change
// who has access to the subscription, or change or delete any resource in
// it. Reservations Administrator is under Privileged on the built-in roles
// page, but it manages reservations, not the subscription's resources.
// https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/privileged
var simCloudRoles = []struct {
	name, id string
	admin    bool
}{
	{"Owner", "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", true},
	{"Contributor", "b24988ac-6180-42a0-ab88-20f7382dd24c", true},
	{"User Access Administrator", "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9", true},
	{"Role Based Access Control Administrator", "f58310d9-a9f6-439a-9e8d-f62e7b41a168", true},
	{"Reservations Administrator", "a8889054-8d42-49c9-bc1c-52486c10e7cd", false},
	{"Reader", "acdd72a7-3385-48ef-bd42-f606fba81ae7", false},
}

func simMatrixBase(t testing.TB) *roster.Roster {
	t.Helper()
	sandbox, err := roster.Load("testdata/simulator/microsoft-cloud.roster.json")
	if err != nil {
		t.Fatal(err)
	}
	realizations, err := sandbox.Realizations()
	if err != nil {
		t.Fatal(err)
	}
	r := realizations[0].Roster
	r.Terms.MFAMethods = maps.Clone(r.Terms.MFAMethods)
	maps.Copy(r.Terms.MFAMethods, simMatrixMethods)
	r.Terms.Requirements = maps.Clone(r.Terms.Requirements)
	maps.Copy(r.Terms.Requirements, simMatrixRequirements)
	r.Terms.Roles = maps.Clone(r.Terms.Roles)
	roleIDs := map[string]string{}
	if _, err := r.Extra.Get("directory_role_ids", &roleIDs); err != nil {
		t.Fatal(err)
	}
	labels := map[string]map[string]bool{}
	for _, role := range simPrivilegedRoles {
		r.Terms.Roles[role.name] = roster.RoleNone
		if role.labeled && !role.readOnly {
			r.Terms.Roles[role.name] = roster.RoleAdmin
		}
		roleIDs[role.name] = role.id
		labels[role.name] = map[string]bool{"privileged": role.labeled, "read_only": role.readOnly}
	}
	r.Extra = maps.Clone(r.Extra)
	setExtra(&r.Extra, "directory_role_ids", roleIDs)
	setExtra(&r.Extra, "directory_role_labels", labels)

	cloudRoleIDs := map[string]string{}
	r.Terms.CloudRoles = map[string]string{}
	for _, role := range simCloudRoles {
		cloudRoleIDs[role.name] = role.id
		r.Terms.CloudRoles[role.name] = roster.RoleNone
		if role.admin {
			r.Terms.CloudRoles[role.name] = roster.RoleAdmin
		}
	}
	setExtra(&r.Extra, "cloud_role_ids", cloudRoleIDs)
	knownPlatforms := []string{"android", "ios", "windows", "windows_phone", "macos", "linux"}
	r.Terms.Conditions = map[string]map[string][]string{
		"browser_only":        {roster.PartClient: {roster.ClientBrowser}},
		"modern_clients_only": {roster.PartClient: {roster.ClientBrowser, roster.ClientApps}},
		"other_clients_only":  {roster.PartClient: {roster.ClientLegacy}},
		"sign_in_risk":        {roster.PartSignInRisk: {"high", "medium"}},
		"quiet_sign_in":       {roster.PartSignInRisk: {"none", "low"}},
		"user_risk":           {roster.PartUserRisk: {"high"}},
		"untrusted_location":  {roster.PartLocation: {"untrusted"}},
		"trusted_location":    {roster.PartLocation: {"trusted"}},
		"platform_ios":        {roster.PartPlatform: {"ios"}},
		"known_platforms":     {roster.PartPlatform: knownPlatforms},
		"all_but_ios":         {roster.PartPlatform: {"android", "windows", "windows_phone", "macos", "linux", "other"}},
	}
	r.Terms.NetworkSources = maps.Clone(r.Terms.NetworkSources)
	r.Terms.NetworkSources["0.0.0.0/0"] = roster.SourceAny

	r.Accounts = append(r.Accounts, roster.Account{Key: simMatrixAdmin, Kind: "member", Enabled: true, Methods: []string{"microsoftAuthenticatorPush"}, SignedInDaysAgo: intPtr(3)})
	var everyone []string
	for _, a := range r.Accounts {
		everyone = append(everyone, a.Key)
	}
	r.Groups = append(r.Groups,
		roster.Group{Key: "all_accounts", Members: everyone},
		roster.Group{Key: "breakglass_group", Members: []string{"breakglass"}},
	)
	return validated(t, r)
}

func onAccount(key string, change func(*roster.Account)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		for i := range r.Accounts {
			if r.Accounts[i].Key == key {
				change(&r.Accounts[i])
			}
		}
	}
}

func onPolicy(key string, change func(*roster.Policy)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		for i := range r.Policies {
			if r.Policies[i].Key == key {
				change(&r.Policies[i])
			}
		}
	}
}

// split limits the MFA policy with one condition and adds a copy of it
// limited with another.
func split(condition, other string) func(*roster.Roster) {
	return func(r *roster.Roster) {
		for i := range r.Policies {
			if r.Policies[i].Key != "mfa_all" {
				continue
			}
			copied := r.Policies[i]
			copied.Key, copied.Conditions = "mfa_all_"+other, []string{other}
			copied.Extra = maps.Clone(copied.Extra)
			setExtra(&copied.Extra, "display_name", "Sandbox require MFA for all users, "+other)
			r.Policies[i].Conditions = []string{condition}
			r.Policies = append(r.Policies, copied)
			return
		}
	}
}

func render(renderings ...string) func(*roster.Policy) {
	return func(p *roster.Policy) {
		p.Extra = maps.Clone(p.Extra)
		setExtra(&p.Extra, "render", renderings)
	}
}

func onRule(group, rule string, change func(*roster.NetworkRule)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		for i := range r.SecurityGroups {
			for j := range r.SecurityGroups[i].Rules {
				if r.SecurityGroups[i].Key == group && r.SecurityGroups[i].Rules[j].Key == rule {
					change(&r.SecurityGroups[i].Rules[j])
				}
			}
		}
	}
}

func onStorage(key string, change func(*roster.Storage)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		for i := range r.Storage {
			if r.Storage[i].Key == key {
				change(&r.Storage[i])
			}
		}
	}
}

func simMatrixAxes() []roster.Axis {
	admin := func(change func(*roster.Account)) func(*roster.Roster) { return onAccount(simMatrixAdmin, change) }
	mfa := func(change func(*roster.Policy)) func(*roster.Roster) { return onPolicy("mfa_all", change) }
	legacy := func(change func(*roster.Policy)) func(*roster.Roster) { return onPolicy("block_legacy", change) }

	roles := []roster.Value{
		{Name: "none"},
		{Name: "Global Administrator", Change: admin(func(a *roster.Account) { a.Roles = []string{"Global Administrator"} })},
	}
	for _, role := range simPrivilegedRoles {
		roles = append(roles, roster.Value{Name: role.name, Change: admin(func(a *roster.Account) { a.Roles = []string{role.name} })})
	}
	methods := []roster.Value{{Name: "microsoftAuthenticatorPush"}}
	for _, m := range []string{"mobilePhone", "email", "softwareOneTimePasscode", "microsoftAuthenticatorPasswordless", "fido2SecurityKey",
		"windowsHelloForBusiness", "passKeyDeviceBound", "passKeyDeviceBoundAuthenticator"} {
		methods = append(methods, roster.Value{Name: m, Change: admin(func(a *roster.Account) { a.Methods = []string{m} })})
	}
	methods = append(methods,
		roster.Value{Name: "none", Change: admin(func(a *roster.Account) { a.Methods = nil })},
		roster.Value{Name: "push and email", Change: admin(func(a *roster.Account) { a.Methods = []string{"microsoftAuthenticatorPush", "email"} })},
	)
	requires := func(anyOne bool, reqs ...string) func(*roster.Roster) {
		return mfa(func(p *roster.Policy) { p.Requires, p.RequireAny = reqs, anyOne })
	}
	conditions := []roster.Value{{Name: "none"}}
	for _, c := range []string{"sign_in_risk", "user_risk", "untrusted_location", "platform_ios", "browser_only", "modern_clients_only", "device_filter"} {
		conditions = append(conditions, roster.Value{Name: c, Change: mfa(func(p *roster.Policy) { p.Conditions = []string{c} })})
	}

	cloudRoles := []roster.Value{{Name: "none"}}
	for _, role := range simCloudRoles {
		cloudRoles = append(cloudRoles, roster.Value{Name: role.name, Change: admin(func(a *roster.Account) { a.CloudRoles = []string{role.name} })})
	}
	cloudScope := func(scope string) func(*roster.Roster) {
		return admin(func(a *roster.Account) {
			scopes := map[string]string{}
			for _, role := range a.CloudRoles {
				scopes[role] = scope
			}
			a.Extra = maps.Clone(a.Extra)
			setExtra(&a.Extra, "cloud_role_scopes", scopes)
		})
	}
	ssh := func(change func(*roster.NetworkRule)) func(*roster.Roster) {
		return onRule("open", "allow-ssh-internet", change)
	}

	return []roster.Axis{
		{Name: "cloud.role", Values: cloudRoles},
		{Name: "cloud.scope", Values: []roster.Value{
			{Name: "subscription"},
			{Name: "resource group", Change: admin(func(a *roster.Account) { a.PartialCloudRoles, a.CloudRoles = a.CloudRoles, nil })},
			{Name: "management group", Change: cloudScope("management_group")},
			{Name: "through a group", Change: func(r *roster.Roster) {
				a, _ := r.Account(simMatrixAdmin)
				r.Groups = append(r.Groups, roster.Group{Key: "matrix_cloud_group", Members: []string{simMatrixAdmin}, CloudRoles: a.CloudRoles})
				onAccount(simMatrixAdmin, func(a *roster.Account) { a.CloudRoles = nil })(r)
			}},
		}},
		{Name: "nsg.ssh", Values: []roster.Value{
			{Name: "allowed from Internet"},
			{Name: "denied from anywhere first", Change: func(r *roster.Roster) {
				for i := range r.SecurityGroups {
					if r.SecurityGroups[i].Key == "open" {
						r.SecurityGroups[i].Rules = append(r.SecurityGroups[i].Rules, roster.NetworkRule{Key: "deny-ssh-any", Direction: roster.Inbound,
							Access: roster.Deny, Protocol: "*", Ports: []string{"22"}, Sources: []string{"*"}, Priority: 90})
					}
				}
			}},
			{Name: "denied from anywhere after", Change: func(r *roster.Roster) {
				for i := range r.SecurityGroups {
					if r.SecurityGroups[i].Key == "open" {
						r.SecurityGroups[i].Rules = append(r.SecurityGroups[i].Rules, roster.NetworkRule{Key: "deny-ssh-any", Direction: roster.Inbound,
							Access: roster.Deny, Protocol: "*", Ports: []string{"22"}, Sources: []string{"*"}, Priority: 4000})
					}
				}
			}},
			{Name: "port range", Change: ssh(func(rule *roster.NetworkRule) { rule.Ports = []string{"20-25"} })},
			{Name: "every port", Change: ssh(func(rule *roster.NetworkRule) { rule.Ports = []string{"*"} })},
			{Name: "two ports", Change: ssh(func(rule *roster.NetworkRule) { rule.Ports = []string{"443", "22"} })},
			{Name: "udp", Change: ssh(func(rule *roster.NetworkRule) { rule.Protocol = "Udp" })},
			{Name: "any protocol", Change: ssh(func(rule *roster.NetworkRule) { rule.Protocol = "*" })},
			{Name: "from 0.0.0.0/0", Change: ssh(func(rule *roster.NetworkRule) { rule.Sources = []string{"0.0.0.0/0"} })},
			{Name: "from a private range and Internet", Change: ssh(func(rule *roster.NetworkRule) { rule.Sources = []string{"10.0.0.0/8", "Internet"} })},
			{Name: "outbound", Change: ssh(func(rule *roster.NetworkRule) { rule.Direction = roster.Outbound })},
			{Name: "rendered as lists", Change: func(r *roster.Roster) {
				for i := range r.SecurityGroups {
					r.SecurityGroups[i].Extra = maps.Clone(r.SecurityGroups[i].Extra)
					setExtra(&r.SecurityGroups[i].Extra, "render", []string{"lists"})
				}
			}},
		}},
		{Name: "storage.public", Values: []roster.Value{
			{Name: "anonymous access allowed"},
			{Name: "allowBlobPublicAccess unset", Change: onStorage("public", func(st *roster.Storage) {
				st.Extra = maps.Clone(st.Extra)
				setExtra(&st.Extra, "render", []string{"unset"})
			})},
			{Name: "anonymous access off", Change: onStorage("public", func(st *roster.Storage) { st.AnonymousAccess = false })},
		}},
		{Name: "admin.role", Values: roles},
		{Name: "admin.state", Values: []roster.Value{
			{Name: "enabled member"},
			{Name: "disabled", Change: admin(func(a *roster.Account) { a.Enabled = false })},
			{Name: "guest", Change: admin(func(a *roster.Account) { a.Kind = "guest" })},
			{Name: "never signed in", Change: admin(func(a *roster.Account) { a.SignedInDaysAgo = nil })},
			{Name: "eligible only", Change: admin(func(a *roster.Account) { a.EligibleRoles, a.Roles = a.Roles, nil })},
			{Name: "role through a group", Change: func(r *roster.Roster) {
				a, _ := r.Account(simMatrixAdmin)
				r.Groups = append(r.Groups, roster.Group{Key: "matrix_role_group", Members: []string{simMatrixAdmin}, Roles: a.Roles})
				onAccount(simMatrixAdmin, func(a *roster.Account) { a.Roles = nil })(r)
			}},
		}},
		{Name: "admin.methods", Values: methods},
		{Name: "admin.signs_in", Values: []roster.Value{
			{Name: "entra"},
			{Name: "a federated domain", Change: federate(simPartnerDomain, simMatrixAdmin)},
			{Name: "entra, beside a federated domain", Change: federate(simPartnerDomain)},
		}},
		{Name: "mfa.state", Values: []roster.Value{
			{Name: "enabled"},
			{Name: "report-only", Change: mfa(func(p *roster.Policy) { p.State = "enabledForReportingButNotEnforced" })},
			{Name: "disabled", Change: mfa(func(p *roster.Policy) { p.State = "disabled" })},
		}},
		{Name: "mfa.users", Values: []roster.Value{
			{Name: "all"},
			{Name: "admin roles", Change: mfa(func(p *roster.Policy) {
				p.Include = roster.Audience{Roles: []string{"Global Administrator", "Security Administrator", "User Administrator"}}
			})},
			{Name: "a group of everyone", Change: mfa(func(p *roster.Policy) { p.Include = roster.Audience{Groups: []string{"all_accounts"}} })},
			{Name: "every account by name", Change: func(r *roster.Roster) {
				var keys []string
				for _, a := range r.Accounts {
					keys = append(keys, a.Key)
				}
				mfa(func(p *roster.Policy) { p.Include = roster.Audience{Accounts: keys} })(r)
			}},
		}},
		{Name: "mfa.exclusions", Values: []roster.Value{
			{Name: "breakglass"},
			{Name: "none", Change: mfa(func(p *roster.Policy) { p.Exclude = roster.Audience{} })},
			{Name: "breakglass by group", Change: mfa(func(p *roster.Policy) { p.Exclude = roster.Audience{Groups: []string{"breakglass_group"}} })},
			{Name: "Global Administrators", Change: mfa(func(p *roster.Policy) { p.Exclude = roster.Audience{Roles: []string{"Global Administrator"}} })},
		}},
		{Name: "mfa.apps", Values: []roster.Value{
			{Name: "all"},
			{Name: "Office365", Change: mfa(func(p *roster.Policy) { p.Apps = []string{"Office365"} })},
			{Name: "all but Office365", Change: mfa(func(p *roster.Policy) { p.ExcludeApps = []string{"Office365"} })},
			{Name: "MicrosoftAdminPortals", Change: mfa(func(p *roster.Policy) { p.Apps = []string{"MicrosoftAdminPortals"} })},
		}},
		{Name: "mfa.grant", Values: []roster.Value{
			{Name: "mfa"},
			{Name: "mfa strength", Change: requires(false, "mfaStrength")},
			{Name: "passwordless strength", Change: requires(false, "passwordlessMfa")},
			{Name: "phishing-resistant strength", Change: requires(false, "phishingResistantMfa")},
			{Name: "mfa and compliant device", Change: requires(false, "mfa", "compliantDevice")},
			{Name: "mfa or compliant device", Change: requires(true, "mfa", "compliantDevice")},
			{Name: "mfa or terms of use", Change: requires(true, "mfa", "termsOfUse")},
			{Name: "compliant or joined device", Change: requires(true, "compliantDevice", "domainJoinedDevice")},
		}},
		{Name: "mfa.conditions", Values: conditions},
		// Two policies that each cover part of the sign-ins, and between
		// them cover every one, or don't.
		{Name: "mfa.split", Values: []roster.Value{
			{Name: "none"},
			{Name: "trusted and untrusted locations", Change: split("untrusted_location", "trusted_location")},
			{Name: "risky and quiet sign-ins", Change: split("sign_in_risk", "quiet_sign_in")},
			{Name: "all platforms but iOS, and iOS", Change: split("all_but_ios", "platform_ios")},
			{Name: "every known platform listed", Change: mfa(func(p *roster.Policy) { p.Conditions = []string{"known_platforms"} })},
		}},
		{Name: "mfa.rendering", Values: []roster.Value{
			{Name: "plain"},
			{Name: "every location listed", Change: mfa(render("all_locations"))},
			{Name: "every platform listed", Change: mfa(render("all_platforms"))},
			{Name: "every client app listed", Change: mfa(render("every_client_app"))},
		}},
		{Name: "legacy", Values: []roster.Value{
			{Name: "blocked"},
			{Name: "other clients only", Change: legacy(func(p *roster.Policy) { p.Conditions = []string{"other_clients_only"} })},
			{Name: "report-only", Change: legacy(func(p *roster.Policy) { p.State = "enabledForReportingButNotEnforced" })},
			{Name: "Office365 only", Change: legacy(func(p *roster.Policy) { p.Apps = []string{"Office365"} })},
			{Name: "breakglass excluded by group", Change: legacy(func(p *roster.Policy) { p.Exclude = roster.Audience{Groups: []string{"breakglass_group"}} })},
			{Name: "on sign-in risk", Change: legacy(func(p *roster.Policy) { p.Conditions = []string{"sign_in_risk"} })},
			{Name: "no policy", Change: func(r *roster.Roster) {
				r.Policies = slices.DeleteFunc(r.Policies, func(p roster.Policy) bool { return p.Key == "block_legacy" })
			}},
		}},
	}
}

var (
	simPrivilegedCounts = []string{
		"/privileged_access/privileged_users_count", "/privileged_access/privileged_mfa_user_count", "/privileged_access/privileged_mfa_coverage_pct",
	}
	simPrivilegedStrong = []string{
		"/privileged_access/privileged_phishing_resistant_user_count", "/privileged_access/privileged_phishing_resistant_pct",
	}
	simCoverage    = []string{"/policy/mfa_required_coverage_pct", "/policy/mfa_required_user_count"}
	simCloudAdmins = func() []string {
		var out []string
		for _, at := range []string{"access-posture:", "access-posture:/scopes/0"} {
			out = append(out, at+"/admins/admin_count", at+"/admins/admin_share_pct")
		}
		return out
	}()
	simCloudMembers = func() []string {
		out := slices.Clone(simCloudAdmins)
		for _, at := range []string{"access-posture:", "access-posture:/scopes/0"} {
			out = append(out, at+"/members/member_count", at+"/members/external_member_count", at+"/members/inactive_member_count", at+"/members/inactive_pct")
		}
		return out
	}()
)

// simMatrixAlone lists, by setting, the values the collector reports
// otherwise when that setting alone changes.
var simMatrixAlone = func() map[string]map[string]simDifference {
	out := map[string]map[string]simDifference{}
	groupsOrRoles := simDifference{verdictGap, "not_read: the collector does not match a group's members or a role's holders to an MFA policy"}
	for _, setting := range []string{"mfa.users=admin roles", "mfa.users=a group of everyone", "mfa.exclusions=breakglass by group", "mfa.exclusions=Global Administrators"} {
		out[setting] = sameDifference(groupsOrRoles, simCoverage...)
	}
	out["mfa.conditions=device_filter"] = sameDifference(simDifference{verdictGap, "not_read: the collector can't tell which devices a device filter matches"},
		append([]string{"/policy/mfa_required"}, simCoverage...)...)
	return out
}()

// simMatrixTogether lists differences that show only when settings meet.
// A row with every one of a rule's settings may differ on its pointers.
var simMatrixTogether = func() []simMatrixRule {
	// A role held through a group differs only once the account has a role
	// the collector counts, as in the group-held role scenario.
	groupHeld := gapsFor("not_read: the collector does not read the members of a group that holds a role",
		append(append(slices.Clone(simPrivilegedCounts), simPrivilegedStrong...), "/privileged_access/super_admin_count", "/privileged_access/standing_privileged_users_count")...)
	return []simMatrixRule{
		{[]string{"admin.state=role through a group"}, groupHeld},
		// A cloud role held through a group differs only once the account
		// has a role.
		{[]string{"cloud.scope=through a group"}, gapsFor("not_read: the collector does not read the members of a group that holds an Azure role", simCloudMembers...)},
		// An MFA policy for modern clients covers a user only when legacy
		// sign-in is blocked for them too, and the block policy's group
		// exclusion leaves that unknown.
		{[]string{"mfa.conditions=modern_clients_only", "legacy=breakglass excluded by group"},
			gapsFor("not_read: whether the block on legacy sign-in covers a user depends on a group's members, which the collector does not read", simCoverage...)},
	}
}()

type simMatrixRule struct {
	settings    []string
	differences map[string]simDifference
}

func sameDifference(diff simDifference, pointers ...string) map[string]simDifference {
	out := map[string]simDifference{}
	for _, p := range pointers {
		out[p] = diff
	}
	return out
}

// differing returns the pointers whose collector value differs from the
// derived one, less the standing differences.
func differing(rows []simRow) ([]string, map[string]simRow) {
	var out []string
	byPointer := map[string]simRow{}
	for _, row := range rows {
		byPointer[row.pointer] = row
		if _, standing := simStanding[row.pointer]; !standing && !row.matches() {
			out = append(out, row.pointer)
		}
	}
	return out, byPointer
}

// simMFAPointers are the values roster.Derive leaves out when an account
// signs in through another identity provider: the first seven when a member
// does, the rest when an admin does.
var simMFAPointers = []string{
	"/user_security/mfa_user_count", "/user_security/phishing_resistant_user_count",
	"/user_security/mfa_coverage_pct", "/user_security/mfa_phishing_resistant_pct",
	"/policy/mfa_required", "/policy/mfa_required_user_count", "/policy/mfa_required_coverage_pct",
	"/privileged_access/privileged_mfa_user_count", "/privileged_access/privileged_phishing_resistant_user_count",
	"/privileged_access/privileged_mfa_coverage_pct", "/privileged_access/privileged_phishing_resistant_pct",
}

// TestSimulatedSignInElsewhere checks what the comparison with the derived
// values can't: that the collector leaves out each MFA value Derive leaves
// out, for an account that signs in through another identity provider. In
// the federated scenarios and the one-at-a-time admin.signs_in rows, its gap
// names the federated domain. In a pairwise row another gap can say why
// first, such as the one for a role a group holds.
func TestSimulatedSignInElsewhere(t *testing.T) {
	type check struct {
		sc    simScenario
		named bool
	}
	var checks []check
	for _, sc := range simScenarios(t) {
		if strings.Contains(sc.name, "federated") {
			checks = append(checks, check{sc, true})
		}
	}
	base, axes := simMatrixBase(t), simMatrixAxes()
	for _, set := range []struct {
		rows  []roster.Row
		named bool
	}{{roster.OneAtATime(axes), true}, {roster.Pairwise(axes), false}} {
		for _, row := range set.rows {
			if !slices.ContainsFunc(row.Choices(axes), func(c string) bool { return strings.HasPrefix(c, "admin.signs_in=") }) {
				continue
			}
			v, err := roster.Build(base, axes, row)
			if err != nil {
				t.Fatal(err)
			}
			checks = append(checks, check{simScenario{name: v.Name, roster: v.Roster}, set.named})
		}
	}
	for _, c := range checks {
		t.Run(c.sc.name, func(t *testing.T) {
			derived, err := roster.Derive(c.sc.roster)
			if err != nil {
				t.Fatal(err)
			}
			sim, err := newEntraSim(c.sc.roster, goldenTime)
			if err != nil {
				t.Fatal(err)
			}
			res := runInProcess(t, kitConfig(), kitSecrets(), sim.responses())
			if res.ExitCode != 0 || res.Result == nil {
				t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
			}
			var doc map[string]any
			for _, a := range res.Artifacts {
				if a.Path == idpPosturePath {
					if err := json.Unmarshal(a.Data, &doc); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, pointer := range simMFAPointers {
				if _, want := derived[roster.IDPPosture][pointer]; want {
					continue
				}
				i := slices.IndexFunc(res.Result.Gaps, func(g componentsdk.Gap) bool { return g.Path == idpPosturePath && g.Pointer == pointer })
				switch _, got := lookupPointer(doc, pointer); {
				case got:
					t.Errorf("%s: left out by Derive, collector wrote it", pointer)
				case i < 0:
					t.Errorf("%s: left out with no gap", pointer)
				case c.named && !strings.Contains(res.Result.Gaps[i].Detail, simPartnerDomain):
					t.Errorf("%s: left out with a gap that doesn't name %s: %s", pointer, simPartnerDomain, res.Result.Gaps[i].Detail)
				}
			}
		})
	}
}

func TestSimulatedMatrix(t *testing.T) {
	base := simMatrixBase(t)
	axes := simMatrixAxes()
	alone := map[string][]string{}
	for _, row := range roster.OneAtATime(axes) {
		v, err := roster.Build(base, axes, row)
		if err != nil {
			t.Fatal(err)
		}
		t.Run("alone/"+v.Name, func(t *testing.T) {
			differs, rows := differing(runSimulated(t, simScenario{name: v.Name, roster: v.Roster}))
			alone[v.Name] = differs
			listed := simMatrixAlone[v.Name]
			var table strings.Builder
			for _, pointer := range differs {
				diff, ok := listed[pointer]
				mark := string(diff.verdict)
				if !ok {
					mark = "NEW"
					t.Errorf("%s: derived %v, collector %s", pointer, fmt.Sprint(rows[pointer].want), rows[pointer].gotString())
				}
				fmt.Fprintf(&table, "  %-62s %-10s %-34s %s\n", pointer, fmt.Sprint(rows[pointer].want), rows[pointer].gotString(), mark)
			}
			for _, pointer := range slices.Sorted(maps.Keys(listed)) {
				if !slices.Contains(differs, pointer) {
					t.Errorf("%s: listed as %s (%s), but the collector now reports the derived %v", pointer, listed[pointer].verdict, listed[pointer].note, fmt.Sprint(rows[pointer].want))
				}
			}
			if table.Len() > 0 {
				t.Logf("%s\n%s", v.Name, table.String())
			}
		})
	}

	pairwise := roster.Pairwise(axes)
	together := 0
	for i, row := range pairwise {
		v, err := roster.Build(base, axes, row)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(fmt.Sprintf("together/%03d", i), func(t *testing.T) {
			differs, rows := differing(runSimulated(t, simScenario{name: v.Name, roster: v.Roster}))
			choices := row.Choices(axes)
			for _, pointer := range roster.Unexplained(axes, row, differs, alone) {
				explained := slices.ContainsFunc(simMatrixTogether, func(rule simMatrixRule) bool {
					_, listed := rule.differences[pointer]
					return listed && !slices.ContainsFunc(rule.settings, func(s string) bool { return !slices.Contains(choices, s) })
				})
				if explained {
					together++
					continue
				}
				t.Errorf("%s: derived %v, collector %s, with %s", pointer, fmt.Sprint(rows[pointer].want), rows[pointer].gotString(), v.Name)
			}
		})
	}
	t.Logf("%d one-at-a-time rows, %d pairwise rows, %d differences explained only together", len(roster.OneAtATime(axes)), len(pairwise), together)
}

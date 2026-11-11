package collector

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

// largeTenant is a tenant shaped like a big enterprise's: users by the
// hundred thousand, hundreds of Conditional Access policies naming dozens
// of locations, and every kind of condition. With split true no one policy
// requires MFA everywhere: one per location covers its office, one covers
// untrusted locations, and others cover the rest, so every sign-in needs
// several policies together. With groups true some policies include groups,
// whose members aren't read.
func largeTenant(users, policies, locations int, split, groups bool) *fakeGraph {
	enabled, disabled := true, false
	graph := fakeGraphClient()
	graph.users, graph.signInUsers, graph.registrations = nil, nil, nil
	for i := range users {
		id := fmt.Sprintf("u%06d", i)
		user := microsoft.User{ID: id, AccountEnabled: &enabled, UserType: "Member"}
		switch {
		case i%50 == 1:
			user.UserType = "Guest"
		case i%33 == 2:
			user.AccountEnabled = &disabled
		}
		graph.users = append(graph.users, user)
		signedIn := user
		if i%10 < 7 {
			signedIn.SignInActivity = &microsoft.SignInActivity{LastSuccessfulSignInDateTime: "2026-05-20T00:00:00Z"}
		}
		graph.signInUsers = append(graph.signInUsers, signedIn)
		methods := []string{"mobilePhone"}
		if i%10 == 0 {
			methods = []string{"fido2SecurityKey"}
		}
		graph.registrations = append(graph.registrations, microsoft.UserRegistrationDetail{ID: id, IsMFARegistered: i%5 != 0, MethodsRegistered: methods})
	}
	graph.roleAssignments = nil
	for i := range 200 {
		graph.roleAssignments = append(graph.roleAssignments, microsoft.UnifiedRoleAssignment{
			ID: fmt.Sprintf("ra%d", i), PrincipalID: fmt.Sprintf("u%06d", i*7), RoleDefinitionID: []string{globalAdministratorTemplateID, "194ae4cb-b126-40b2-bd5b-6091b380977d", "729827e3-9c14-49f7-bb1b-9608f156bbb8"}[i%3],
		})
	}
	for i := range locations {
		graph.namedLocations = append(graph.namedLocations, microsoft.NamedLocation{ODataType: "#microsoft.graph.ipNamedLocation", ID: fmt.Sprintf("loc%02d", i), IsTrusted: i%2 == 0})
	}

	policy := func(id string, change func(*microsoft.ConditionalAccessPolicy)) microsoft.ConditionalAccessPolicy {
		p := mfaAllUsersPolicy(id)
		p.Conditions.Users.ExcludeUsers = []string{"u000000", "u000001"}
		change(&p)
		return p
	}
	block := func(p *microsoft.ConditionalAccessPolicy) {
		p.GrantControls = &microsoft.ConditionalAccessGrantControls{Operator: "OR", BuiltInControls: []string{"block"}}
	}
	graph.policies = []microsoft.ConditionalAccessPolicy{
		legacyAuthBlockPolicy("legacy"),
		policy("unknown-platforms", func(p *microsoft.ConditionalAccessPolicy) {
			block(p)
			p.Conditions.Platforms = &microsoft.ConditionalAccessPlatforms{IncludePlatforms: []string{"all"}, ExcludePlatforms: []string{"android", "iOS", "windows", "macOS", "linux"}}
		}),
		policy("risky", func(p *microsoft.ConditionalAccessPolicy) { block(p); p.Conditions.SignInRiskLevels = []string{"high"} }),
		policy("user-risk", func(p *microsoft.ConditionalAccessPolicy) { p.Conditions.UserRiskLevels = []string{"high", "medium"} }),
		policy("insider", func(p *microsoft.ConditionalAccessPolicy) { block(p); p.Conditions.InsiderRiskLevels = "elevated" }),
		policy("device-code", func(p *microsoft.ConditionalAccessPolicy) {
			block(p)
			p.Conditions.AuthenticationFlows = &microsoft.ConditionalAccessAuthenticationFlows{TransferMethods: "deviceCodeFlow"}
		}),
	}
	if split {
		graph.policies = append(graph.policies, policy("untrusted", func(p *microsoft.ConditionalAccessPolicy) {
			p.Conditions.Locations = &microsoft.ConditionalAccessLocations{IncludeLocations: []string{"All"}, ExcludeLocations: []string{"AllTrusted"}}
		}))
		for i := range locations {
			if i%2 == 0 {
				graph.policies = append(graph.policies, policy(fmt.Sprintf("office%02d", i), func(p *microsoft.ConditionalAccessPolicy) {
					p.Conditions.Locations = &microsoft.ConditionalAccessLocations{IncludeLocations: []string{fmt.Sprintf("loc%02d", i)}}
				}))
			}
		}
	} else {
		graph.policies = append(graph.policies, policy("everyone", func(*microsoft.ConditionalAccessPolicy) {}))
	}
	for i := 0; len(graph.policies) < policies; i++ {
		location := fmt.Sprintf("loc%02d", i%max(locations, 1))
		listed := make([]string, 0, 50)
		for j := range 50 {
			listed = append(listed, fmt.Sprintf("u%06d", (i*50+j)%max(users, 1)))
		}
		switch i % 5 {
		case 0:
			graph.policies = append(graph.policies, policy(fmt.Sprintf("app%03d", i), func(p *microsoft.ConditionalAccessPolicy) {
				p.Conditions.Applications.IncludeApplications = []string{fmt.Sprintf("app-%03d", i)}
				p.Conditions.Users.IncludeUsers = listed
			}))
		case 1:
			graph.policies = append(graph.policies, policy(fmt.Sprintf("site%03d", i), func(p *microsoft.ConditionalAccessPolicy) {
				p.Conditions.Locations = &microsoft.ConditionalAccessLocations{IncludeLocations: []string{"All"}, ExcludeLocations: []string{location}}
				p.Conditions.Platforms = &microsoft.ConditionalAccessPlatforms{IncludePlatforms: []string{"iOS", "android"}}
			}))
		case 2:
			graph.policies = append(graph.policies, policy(fmt.Sprintf("group%03d", i), func(p *microsoft.ConditionalAccessPolicy) {
				if groups {
					p.Conditions.Users = &microsoft.ConditionalAccessUsers{IncludeGroups: []string{fmt.Sprintf("g%03d", i)}}
				} else {
					p.Conditions.Users.IncludeUsers = listed
				}
				p.Conditions.SignInRiskLevels = []string{"low"}
			}))
		case 3:
			graph.policies = append(graph.policies, policy(fmt.Sprintf("device%03d", i), func(p *microsoft.ConditionalAccessPolicy) {
				p.GrantControls = &microsoft.ConditionalAccessGrantControls{BuiltInControls: []string{"compliantDevice"}}
				p.Conditions.Platforms = &microsoft.ConditionalAccessPlatforms{IncludePlatforms: []string{"windows", "macOS"}}
			}))
		default:
			graph.policies = append(graph.policies, policy(fmt.Sprintf("report%03d", i), func(p *microsoft.ConditionalAccessPolicy) {
				p.State = "enabledForReportingButNotEnforced"
				p.Conditions.SignInRiskLevels = []string{"medium"}
			}))
		}
	}
	return graph
}

// A large tenant's policies are evaluated within a time budget. A tenant
// whose policies split every sign-in into too many cases gets a gap rather
// than a run that never ends.
func TestPolicyEvaluationAtScale(t *testing.T) {
	if testing.Short() {
		t.Skip("large tenants take seconds")
	}
	for _, tc := range []struct {
		name                       string
		users, policies, locations int
		split, groups              bool
	}{
		{"100,000 users, one policy for everyone", 100_000, 300, 50, false, true},
		{"100,000 users, policies split by location", 100_000, 300, 50, true, true},
		{"100,000 users named in policies, no groups", 100_000, 300, 50, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.GraphClient = largeTenant(tc.users, tc.policies, tc.locations, tc.split, tc.groups)
			rec := &componentsdk.Recorder{}
			cfg.Recorder = rec
			start := time.Now()
			p := collectTestArtifact(t, cfg).Policy
			elapsed := time.Since(start)
			coverage := "left out"
			if p.MFARequiredCoveragePct != nil {
				coverage = fmt.Sprint(*p.MFARequiredCoveragePct)
			}
			t.Logf("%s: mfa_required %s, coverage %s, legacy %s", elapsed.Round(time.Millisecond), showBool(p.MFARequired), coverage, showBool(p.LegacyAuthBlocked))
			if elapsed > 30*time.Second {
				t.Errorf("collecting took %s, over the 30s budget", elapsed)
			}
			for _, gap := range rec.Gaps() {
				if strings.Contains(gap.Detail, overBudgetDetail) {
					t.Errorf("%s: gave up over budget", gap.Pointer)
				}
			}
		})
	}
}

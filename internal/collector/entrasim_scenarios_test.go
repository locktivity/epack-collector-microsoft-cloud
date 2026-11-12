package collector

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
)

// The simulated tenants are rosters the Entra simulator answers for, each
// with the idp-posture values roster.Derive computes from it. A value the
// collector reports otherwise must be listed in the scenario's differences
// with a verdict, so a new difference fails the test and one that goes away
// does too.

// simVerdict says why the collector's value differs from the derived one.
// A difference that is a collector defect, or a question of what a schema
// field means, gets fixed or settled rather than listed.
type simVerdict string

const (
	// verdictKnown is a difference the collector's docs describe, such as a
	// share taken over the members Microsoft's report lists.
	verdictKnown simVerdict = "known"
	// verdictGap is a value the collector leaves out with a gap that says
	// why, where the roster determines it.
	verdictGap simVerdict = "gap"
)

type simDifference struct {
	verdict simVerdict
	note    string
}

type simScenario struct {
	name        string
	roster      *roster.Roster
	differences map[string]simDifference
}

// verdictUnwritten is a value the roster determines that the collector
// never writes, and leaves out with no gap.
const verdictUnwritten simVerdict = "unwritten"

// simStanding are differences that hold wherever the collector reads the
// value. A scenario can still match one by chance, such as an inactive share
// of 100 over either population, so they are not reported when they match.
var simStanding = map[string]simDifference{
	"/policy/phishing_resistant_required_for_privileged": {verdictUnwritten, "not computed"},
	"/device_access/managed_device_required":             {verdictUnwritten, "device_access is not written"},
	"/device_access/managed_device_required_for_admins":  {verdictUnwritten, "device_access is not written"},
}

// simInactiveMembers are access-posture's inactive values, which need the
// sign-in activity list.
var simInactiveMembers = []string{
	"access-posture:/members/inactive_member_count", "access-posture:/members/inactive_pct",
	"access-posture:/scopes/0/members/inactive_member_count", "access-posture:/scopes/0/members/inactive_pct",
}

// gapsFor lists pointers the collector leaves out with a gap that says why.
func gapsFor(note string, pointers ...string) map[string]simDifference {
	out := map[string]simDifference{}
	for _, p := range pointers {
		out[p] = simDifference{verdictGap, note}
	}
	return out
}

func with(diffs map[string]simDifference, more map[string]simDifference) map[string]simDifference {
	out := maps.Clone(diffs)
	maps.Copy(out, more)
	return out
}

var (
	registrationValues = []string{
		"/user_security/mfa_coverage_pct", "/user_security/mfa_phishing_resistant_pct",
		"/user_security/mfa_user_count", "/user_security/phishing_resistant_user_count",
		"/privileged_access/privileged_mfa_coverage_pct", "/privileged_access/privileged_mfa_user_count",
		"/privileged_access/privileged_phishing_resistant_pct", "/privileged_access/privileged_phishing_resistant_user_count",
	}
	// With security defaults off, the policies a tenant without a
	// Conditional Access license can't read decide these.
	noLicenseRegistrationGaps = with(
		gapsFor("not_licensed: the registration report and sign-in activity need Entra ID P1",
			append(append(registrationValues, "/user_security/inactive_pct", "/user_security/inactive_user_count"), simInactiveMembers...)...),
		gapsFor("not_licensed: PIM eligibility needs Entra ID P2", "/privileged_access/standing_privileged_users_count", "/privileged_access/standing_privileged_users_present"))
	noLicenseGaps = with(noLicenseRegistrationGaps,
		gapsFor("not_licensed, though without a Conditional Access license no policy applies, which is how the collector writes the coverage", "/policy/mfa_required", "/policy/legacy_auth_blocked"))
)

func simScenarios(t testing.TB) []simScenario {
	t.Helper()
	base, err := roster.Load("testdata/simulator/microsoft-cloud.roster.json")
	if err != nil {
		t.Fatal(err)
	}
	var out []simScenario
	realizations, err := base.Realizations()
	if err != nil {
		t.Fatal(err)
	}
	for _, real := range realizations {
		name := "baseline"
		if real.Name != "" {
			name += " " + real.Name
		}
		out = append(out, simScenario{name: name, roster: real.Roster})
	}
	first := realizations[0].Roster
	out = append(out,
		simScenario{name: "no license", roster: noLicenseRoster(t, first), differences: noLicenseGaps},
		simScenario{name: "5000 users", roster: manyUsersRoster(t, first, 5000)},
		simScenario{
			name: "group-held role", roster: groupRoleRoster(t, first),
			differences: gapsFor("not_read: the collector does not read the members of a group that holds a role",
				"/privileged_access/privileged_users_count", "/privileged_access/privileged_mfa_coverage_pct",
				"/privileged_access/privileged_mfa_user_count", "/privileged_access/privileged_phishing_resistant_pct",
				"/privileged_access/privileged_phishing_resistant_user_count", "/privileged_access/standing_privileged_users_count"),
		},
		simScenario{
			name: "partly listed report", roster: partlyListedRoster(t, first),
			// The users' share is taken over the members the report lists,
			// and an admin it doesn't list yet leaves the privileged MFA
			// values unknown.
			differences: with(with(
				map[string]simDifference{"/user_security/mfa_coverage_pct": {verdictKnown, "taken over the members the report lists"}},
				gapsFor("vendor_error: the registration report doesn't list every enabled member yet", "/user_security/mfa_user_count", "/user_security/phishing_resistant_user_count")),
				gapsFor("vendor_error: the registration report doesn't list every privileged user yet",
					"/privileged_access/privileged_mfa_coverage_pct", "/privileged_access/privileged_mfa_user_count",
					"/privileged_access/privileged_phishing_resistant_pct", "/privileged_access/privileged_phishing_resistant_user_count"),
			),
		},
		simScenario{
			name: "missing AuditLog.Read.All", roster: missingPermissionRoster(t, first, "AuditLog.Read.All"),
			differences: gapsFor("permission_denied naming AuditLog.Read.All", append(append(registrationValues, "/user_security/inactive_pct", "/user_security/inactive_user_count"), simInactiveMembers...)...),
		},
	)
	// Beyond the six: variants of the sandbox's sign-in policies.
	out = append(out,
		simScenario{name: "security defaults on", roster: securityDefaultsRoster(t, first, "AAD_PREMIUM_P2")},
		simScenario{
			name: "security defaults on, no license", roster: securityDefaultsRoster(t, noLicenseRoster(t, first), ""),
			differences: noLicenseRegistrationGaps,
		},
		simScenario{name: "MFA policy for one app", roster: oneAppMFARoster(t, first)},
	)
	// Members whose domain is federated with another identity provider.
	out = append(out,
		simScenario{name: "a member in a federated domain", roster: federatedRoster(t, first, simPartnerDomain, "user_mfa")},
		simScenario{name: "an admin in a federated domain", roster: federatedRoster(t, first, simPartnerDomain, "admin_mfa")},
		simScenario{name: "a federated domain no account is in", roster: federatedRoster(t, first, simPartnerDomain)},
	)
	return out
}

// simPartner is the identity provider the federated variants send members
// to, through the domain simPartnerDomain.
const (
	simPartner       = "partner"
	simPartnerDomain = "partner.example.com"
)

// federatedRoster federates domain with the partner identity provider and
// moves the accounts keys into it.
func federatedRoster(t testing.TB, base *roster.Roster, domain string, keys ...string) *roster.Roster {
	r := base.Clone()
	federate(domain, keys...)(r)
	return validated(t, r)
}

// federate federates domain with the partner identity provider and moves
// the members among keys into it.
func federate(domain string, keys ...string) func(*roster.Roster) {
	return func(r *roster.Roster) {
		r.Extra = maps.Clone(r.Extra)
		setExtra(&r.Extra, "identity_providers", map[string]simIdP{simPartner: {Domain: domain}})
		for i := range r.Accounts {
			if slices.Contains(keys, r.Accounts[i].Key) && r.Accounts[i].Kind == "member" {
				r.Accounts[i].SignsInThrough = simPartner
			}
		}
	}
}

// securityDefaultsRoster replaces the sandbox's Conditional Access policies
// with security defaults, as their documentation describes them: MFA on
// every sign-in for the admin roles it names, MFA for other users when
// Microsoft decides it's needed, and legacy authentication blocked for
// everyone.
// https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults
func securityDefaultsRoster(t testing.TB, base *roster.Roster, license string) *roster.Roster {
	r := base.Clone()
	setTenant(t, r, func(tenant map[string]any) { tenant["license"] = license })
	var defaults roster.Extra
	setExtra(&defaults, "security_defaults", true)
	r.Policies = []roster.Policy{
		{Key: "defaults_admins", State: "enabled", Include: roster.Audience{Roles: []string{"Global Administrator", "Security Administrator", "User Administrator"}}, Requires: []string{"mfa"}, Extra: defaults},
		{Key: "defaults_users", State: "enabled", Include: roster.Audience{All: true}, Requires: []string{"mfa"}, Conditions: []string{"when_necessary"}, Extra: defaults},
		{Key: "defaults_legacy", State: "enabled", Include: roster.Audience{All: true}, Blocks: "legacy_auth", Extra: defaults},
	}
	return validated(t, r)
}

// oneAppMFARoster narrows the sandbox's MFA policy for all users to Office
// 365, so users signing in to any other app need no MFA.
func oneAppMFARoster(t testing.TB, base *roster.Roster) *roster.Roster {
	r := base.Clone()
	for i := range r.Policies {
		if r.Policies[i].Key == "mfa_all" {
			r.Policies[i].Apps = []string{"Office365"}
		}
	}
	return validated(t, r)
}

// setExtra sets a vendor extra on an entry.
func setExtra(e *roster.Extra, name string, value any) {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	if *e == nil {
		*e = roster.Extra{}
	}
	(*e)[name] = raw
}

func setTenant(t testing.TB, r *roster.Roster, change func(map[string]any)) {
	t.Helper()
	tenant := map[string]any{}
	if _, err := r.Extra.Get("tenant", &tenant); err != nil {
		t.Fatal(err)
	}
	change(tenant)
	r.Extra = maps.Clone(r.Extra)
	setExtra(&r.Extra, "tenant", tenant)
}

func validated(t testing.TB, r *roster.Roster) *roster.Roster {
	t.Helper()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	return r
}

// noLicenseRoster is the sandbox on Entra ID Free. Conditional Access and
// PIM need a license, so it has no policies and no eligible roles, and
// security defaults are off as in the sandbox.
func noLicenseRoster(t testing.TB, base *roster.Roster) *roster.Roster {
	r := base.Clone()
	setTenant(t, r, func(tenant map[string]any) { tenant["license"] = "" })
	r.Policies = nil
	for i := range r.Accounts {
		r.Accounts[i].EligibleRoles = nil
	}
	return validated(t, r)
}

// manyUsersRoster adds members, guests and admins to the sandbox until it
// has n accounts, in a fixed mix of states: a tenth guests, a seventeenth
// disabled, sign-ins on either side of 90 days, and some admins, guests
// among them.
func manyUsersRoster(t testing.TB, base *roster.Roster, n int) *roster.Roster {
	r := base.Clone()
	r.Terms.MFAMethods = map[string]string{}
	for k, v := range base.Terms.MFAMethods {
		r.Terms.MFAMethods[k] = v
	}
	r.Terms.MFAMethods["fido2SecurityKey"] = roster.MFAPhishingResistant
	r.Terms.MFAMethods["email"] = roster.MFANone
	signIns := []*int{intPtr(1), intPtr(30), intPtr(89), intPtr(91), intPtr(400), nil}
	for i := len(r.Accounts); i < n; i++ {
		a := roster.Account{Key: fmt.Sprintf("user_%04d", i), Kind: "member", Enabled: i%17 != 0, SignedInDaysAgo: signIns[i%len(signIns)]}
		if i%10 == 9 {
			a.Kind = "guest"
		}
		switch i % 5 {
		case 1:
			a.Methods = []string{"mobilePhone"}
		case 2:
			a.Methods = []string{"microsoftAuthenticatorPush", "email"}
		case 3:
			a.Methods = []string{"email"}
		}
		if i%50 == 0 || i%50 == 19 {
			a.Methods = append(a.Methods, "fido2SecurityKey")
		}
		switch {
		case i%1000 == 0 || i%1000 == 9:
			a.Roles = []string{"Global Administrator"}
		case i%250 == 0 || i%250 == 1:
			a.Roles = []string{"Security Administrator"}
		case i%333 == 0:
			a.EligibleRoles = []string{"User Administrator"}
		}
		r.Accounts = append(r.Accounts, a)
	}
	return validated(t, r)
}

// groupRoleRoster gives User Administrator to a role-assignable group whose
// members are the sandbox's two ordinary members.
func groupRoleRoster(t testing.TB, base *roster.Roster) *roster.Roster {
	r := base.Clone()
	r.Groups = append(r.Groups, roster.Group{Key: "helpdesk_admins", Members: []string{"user_mfa", "user_nomfa"}, Roles: []string{"User Administrator"}})
	return validated(t, r)
}

// partlyListedRoster leaves two enabled members, one of them a Global
// Administrator, out of the registration report, as a report that lags the
// user list does.
func partlyListedRoster(t testing.TB, base *roster.Roster) *roster.Roster {
	r := base.Clone()
	for i := range r.Accounts {
		if r.Accounts[i].Key == "admin_mfa" || r.Accounts[i].Key == "user_mfa" {
			r.Accounts[i].Extra = maps.Clone(r.Accounts[i].Extra)
			setExtra(&r.Accounts[i].Extra, "in_registration_report", false)
		}
	}
	return validated(t, r)
}

// missingPermissionRoster takes one Graph permission from the collector's
// app.
func missingPermissionRoster(t testing.TB, base *roster.Roster, permission string) *roster.Roster {
	r := base.Clone()
	i := slices.IndexFunc(r.Apps, func(a roster.App) bool { return a.Key == "collector" })
	var permissions []string
	if _, err := r.Apps[i].Extra.Get("graph_permissions", &permissions); err != nil {
		t.Fatal(err)
	}
	r.Apps[i].Extra = maps.Clone(r.Apps[i].Extra)
	setExtra(&r.Apps[i].Extra, "graph_permissions", slices.DeleteFunc(permissions, func(p string) bool { return p == permission }))
	return validated(t, r)
}

// simRow is one derived value beside what the collector reported.
type simRow struct {
	pointer string
	want    any
	got     any
	written bool
	gap     string
}

func (row simRow) matches() bool {
	if !row.written {
		return false
	}
	return sameJSONValue(row.want, row.got)
}

func sameJSONValue(want, got any) bool {
	switch w := want.(type) {
	case int:
		g, ok := got.(float64)
		return ok && g == float64(w)
	case nil:
		return got == nil
	default:
		return want == got
	}
}

func (row simRow) gotString() string {
	switch {
	case row.written && row.got == nil:
		return "null"
	case row.written:
		if f, ok := row.got.(float64); ok && f == math.Trunc(f) {
			return fmt.Sprint(int(f))
		}
		return fmt.Sprint(row.got)
	case row.gap != "":
		return "absent, " + row.gap
	default:
		return "absent, no gap"
	}
}

// simArtifacts are the collector's artifacts for each schema Derive gives
// values for. A row's pointer is the bare pointer for idp-posture, and the
// schema's short name and the pointer for the others, as in
// access-posture:/members/member_count.
var simArtifacts = []struct{ schema, prefix, path string }{
	{roster.IDPPosture, "", idpPosturePath},
	{roster.CloudPosture, "cloud-posture:", cloudPosturePath},
	{roster.AccessPosture, "access-posture:", accessPosturePath},
}

// runSimulated runs the collector at the internal level against a
// scenario's simulated tenant and lines its normalized artifacts up with the
// derived values.
func runSimulated(t *testing.T, sc simScenario) []simRow {
	t.Helper()
	derived, err := roster.Derive(sc.roster)
	if err != nil {
		t.Fatal(err)
	}
	sim, err := newEntraSim(sc.roster, goldenTime)
	if err != nil {
		t.Fatal(err)
	}
	res := runInProcess(t, kitConfig(), kitSecrets(), sim.responses())
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	var rows []simRow
	for _, artifact := range simArtifacts {
		values := derived[artifact.schema]
		var doc map[string]any
		for _, a := range res.Artifacts {
			if a.Path == artifact.path {
				if err := json.Unmarshal(a.Data, &doc); err != nil {
					t.Fatal(err)
				}
			}
		}
		for _, pointer := range slices.Sorted(maps.Keys(values)) {
			row := simRow{pointer: artifact.prefix + pointer, want: values[pointer]}
			row.got, row.written = lookupPointer(doc, pointer)
			if !row.written {
				row.gap = gapAt(res.Result.Gaps, artifact.path, pointer)
			}
			rows = append(rows, row)
		}
	}
	return rows
}

func lookupPointer(doc map[string]any, pointer string) (any, bool) {
	var node any = doc
	for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		switch n := node.(type) {
		case map[string]any:
			var ok bool
			if node, ok = n[part]; !ok {
				return nil, false
			}
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(n) {
				return nil, false
			}
			node = n[i]
		default:
			return nil, false
		}
	}
	return node, true
}

func gapAt(gaps []componentsdk.Gap, path, pointer string) string {
	for _, g := range gaps {
		if g.Path == path && (g.Pointer == "" || g.Pointer == pointer || strings.HasPrefix(pointer, g.Pointer+"/")) {
			if g.MissingPermission != "" {
				return string(g.Code) + " (" + g.MissingPermission + ")"
			}
			return string(g.Code)
		}
	}
	return ""
}

func TestSimulatedTenants(t *testing.T) {
	for _, sc := range simScenarios(t) {
		t.Run(sc.name, func(t *testing.T) {
			rows := runSimulated(t, sc)
			var table strings.Builder
			for _, row := range rows {
				diff, listed := sc.differences[row.pointer]
				_, standing := simStanding[row.pointer]
				if !listed {
					diff, listed = simStanding[row.pointer]
				}
				mark := "ok"
				switch {
				case !row.matches() && !listed:
					mark = "NEW"
					t.Errorf("%s: derived %v, collector %s", row.pointer, fmt.Sprint(row.want), row.gotString())
				case !row.matches():
					mark = string(diff.verdict)
				case listed && !standing:
					t.Errorf("%s: listed as %s (%s), but the collector now reports the derived %v", row.pointer, diff.verdict, diff.note, fmt.Sprint(row.want))
				}
				fmt.Fprintf(&table, "  %-62s %-10s %-34s %s\n", row.pointer, fmt.Sprint(row.want), row.gotString(), mark)
			}
			t.Logf("%s\n%s", sc.name, table.String())
		})
	}
}

// TestSimulatedTenantsKit runs the kit's checks over the simulated tenants:
// the fault matrix and the rest on the first baseline, and each scenario's
// derived values as Expect, less the listed differences.
func TestSimulatedTenantsKit(t *testing.T) {
	var scenarios []collectortest.Scenario
	for _, sc := range simScenarios(t) {
		derived, err := roster.Derive(sc.roster)
		if err != nil {
			t.Fatal(err)
		}
		sim, err := newEntraSim(sc.roster, goldenTime)
		if err != nil {
			t.Fatal(err)
		}
		expect := map[string]any{}
		for pointer, value := range derived[roster.IDPPosture] {
			_, listed := sc.differences[pointer]
			_, standing := simStanding[pointer]
			if !listed && !standing {
				expect[pointer] = value
			}
		}
		scenarios = append(scenarios, collectortest.Scenario{
			Name:      sc.name,
			Responses: sim.responses(),
			Expect:    map[string]map[string]any{idpPosturePath: expect},
		})
	}
	collectortest.Run(t, collectortest.Suite{
		Spec:      Spec("test", "collectortest"),
		Run:       Run,
		Name:      "microsoft-cloud-simulated",
		Config:    kitConfig(),
		Secrets:   kitSecrets(),
		Clock:     goldenTime,
		Scenarios: scenarios,
		Required:  []string{"github.id_token.get", "login.token.create", "graph.organization.get"},
		Ignore: map[string][]string{
			entraPath: {"/diagnostics"},
			azurePath: {"/diagnostics"},
		},
		Semantics: []collectortest.Semantic{
			{Operation: "arm.subscriptions.get", Fault: "404", Meaning: "the subscription does not exist or the app cannot see it"},
			{Operation: "arm.defender.secure_score.get", Fault: "404", Meaning: "Defender for Cloud has no secure score for the subscription"},
			{Operation: "graph.secure_scores.list", Fault: "404", Meaning: "the tenant has no identity secure score"},
		},
		// The Azure side is an empty subscription, which never reaches the
		// calls made per resource. The committed trace map is generated from
		// the fixtures' tenant, and an empty subscription and sign-in log show
		// dependencies it lacks.
		SkipChecks:  []string{"coverage", "tracemap"},
		Insensitive: []string{"login.token.create"},
	})
}

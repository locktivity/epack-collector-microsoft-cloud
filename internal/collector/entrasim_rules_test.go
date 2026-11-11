package collector

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest/roster"
)

// The rules below must hold whatever the right values are. Each changes a
// roster in a way that must leave some values as they are, or move them
// only one way, and compares the collector's output before and after. They
// need no derived values, so they run on random rosters made from the
// matrix's axes, and a broken rule is a bug with no verdict to settle.

// simRuleRosters is how many random rosters the rules run on. The seed is
// fixed, so a failure names a roster that can be built again.
const simRuleRosters = 40

func TestSimulatedRules(t *testing.T) {
	base := simMatrixBase(t)
	axes := simMatrixAxes()
	rng := rand.New(rand.NewPCG(20261111, 1))
	for i := range simRuleRosters {
		row := make(roster.Row, len(axes))
		for j := range axes {
			row[j] = rng.IntN(len(axes[j].Values))
		}
		v, err := roster.Build(base, axes, row)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(fmt.Sprintf("%02d", i), func(t *testing.T) {
			t.Logf("roster: %s", v.Name)
			before := simOutput(t, v.Roster, 0)
			for _, rule := range simRules {
				changed := v.Roster.Clone()
				pageSize := rule.change(changed, rng)
				if err := changed.Validate(); err != nil {
					t.Fatalf("%s: %v", rule.name, err)
				}
				after := simOutput(t, changed, pageSize)
				for _, broken := range rule.check(before, after) {
					t.Errorf("%s: %s", rule.name, broken)
				}
			}
		})
	}
}

type simRule struct {
	name string
	// change changes the roster and returns a page size to answer with, or
	// 0 for Graph's own.
	change func(*roster.Roster, *rand.Rand) int
	check  func(before, after map[string]any) []string
}

var simRules = []simRule{
	{
		name: "a disabled account changes no value but the lifecycle counts",
		change: func(r *roster.Roster, _ *rand.Rand) int {
			r.Accounts = append(r.Accounts, roster.Account{Key: "rule_disabled", Kind: "member", Roles: []string{"Global Administrator"}})
			return 0
		},
		check: func(before, after map[string]any) []string {
			return unchanged(before, after, func(key string) bool { return !strings.Contains(key, "/lifecycle/") })
		},
	},
	{
		name: "a report-only policy changes nothing",
		change: func(r *roster.Roster, rng *rand.Rand) int {
			p := r.Policies[rng.IntN(len(r.Policies))]
			p.Key, p.State = "rule_report_only", "enabledForReportingButNotEnforced"
			p.Include, p.Exclude, p.Conditions = roster.Audience{All: true}, roster.Audience{}, nil
			r.Policies = append(r.Policies, p)
			return 0
		},
		check: func(before, after map[string]any) []string { return unchanged(before, after, nil) },
	},
	{
		name: "reordering accounts, groups and policies, and smaller pages, change nothing",
		change: func(r *roster.Roster, rng *rand.Rand) int {
			rng.Shuffle(len(r.Accounts), func(i, j int) { r.Accounts[i], r.Accounts[j] = r.Accounts[j], r.Accounts[i] })
			rng.Shuffle(len(r.Groups), func(i, j int) { r.Groups[i], r.Groups[j] = r.Groups[j], r.Groups[i] })
			rng.Shuffle(len(r.Policies), func(i, j int) { r.Policies[i], r.Policies[j] = r.Policies[j], r.Policies[i] })
			return 2
		},
		check: func(before, after map[string]any) []string { return unchanged(before, after, nil) },
	},
	{
		name: "another MFA method never lowers an MFA value",
		change: func(r *roster.Roster, rng *rand.Rand) int {
			var enabled []int
			for i, a := range r.Accounts {
				if a.Enabled {
					enabled = append(enabled, i)
				}
			}
			a := &r.Accounts[enabled[rng.IntN(len(enabled))]]
			a.Methods = append(slices.Clone(a.Methods), "fido2SecurityKey")
			return 0
		},
		check: func(before, after map[string]any) []string {
			return neverLower(before, after, "/user_security/mfa_coverage_pct", "/user_security/mfa_phishing_resistant_pct",
				"/user_security/mfa_user_count", "/user_security/phishing_resistant_user_count",
				"/privileged_access/privileged_mfa_coverage_pct", "/privileged_access/privileged_phishing_resistant_pct")
		},
	},
	{
		name: "narrowing a policy never makes a sign-in rule hold",
		change: func(r *roster.Roster, rng *rand.Rand) int {
			p := &r.Policies[rng.IntN(len(r.Policies))]
			p.Conditions = append(slices.Clone(p.Conditions), "sign_in_risk")
			return 0
		},
		check: func(before, after map[string]any) []string {
			broken := neverHigher(before, after, "/policy/mfa_required_coverage_pct", "/policy/mfa_required_user_count")
			for _, flag := range []string{"/policy/mfa_required", "/policy/legacy_auth_blocked"} {
				key := "idp-posture:" + flag
				if before[key] == false && after[key] == true {
					broken = append(broken, fmt.Sprintf("%s went from false to true", flag))
				}
			}
			return broken
		},
	},
}

// unchanged lists the values keep accepts that differ between two outputs,
// written in one and absent in the other included.
func unchanged(before, after map[string]any, keep func(string) bool) []string {
	var out []string
	for _, key := range slices.Sorted(func(yield func(string) bool) {
		seen := map[string]bool{}
		for _, m := range []map[string]any{before, after} {
			for k := range m {
				if !seen[k] && !yield(k) {
					return
				}
				seen[k] = true
			}
		}
	}) {
		if keep != nil && !keep(key) {
			continue
		}
		b, inBefore := before[key]
		a, inAfter := after[key]
		if inBefore != inAfter || !sameJSONValue(b, a) {
			out = append(out, fmt.Sprintf("%s was %s and is %s", key, simShow(b, inBefore), simShow(a, inAfter)))
		}
	}
	return out
}

// neverLower lists the idp-posture values that fell, or that were numbers
// and are no longer.
func neverLower(before, after map[string]any, pointers ...string) []string {
	return compareNumbers(before, after, pointers, func(b, a float64) bool { return a < b }, "fell")
}

func neverHigher(before, after map[string]any, pointers ...string) []string {
	return compareNumbers(before, after, pointers, func(b, a float64) bool { return a > b }, "rose")
}

func compareNumbers(before, after map[string]any, pointers []string, wrong func(b, a float64) bool, verb string) []string {
	var out []string
	for _, pointer := range pointers {
		key := "idp-posture:" + pointer
		b, ok := before[key].(float64)
		if !ok {
			continue
		}
		a, ok := after[key].(float64)
		if !ok {
			out = append(out, fmt.Sprintf("%s was %v and is %s", pointer, b, simShow(after[key], after[key] != nil)))
			continue
		}
		if wrong(b, a) {
			out = append(out, fmt.Sprintf("%s %s from %v to %v", pointer, verb, b, a))
		}
	}
	return out
}

func simShow(v any, written bool) string {
	if !written {
		return "absent"
	}
	if v == nil {
		return "null"
	}
	return fmt.Sprint(v)
}

// simOutput runs the collector at the internal level against a simulated
// tenant and returns every leaf value of its normalized artifacts, keyed by
// the artifact's short name and the pointer, as in
// idp-posture:/user_security/user_count.
func simOutput(t *testing.T, r *roster.Roster, pageSize int) map[string]any {
	t.Helper()
	sim, err := newEntraSim(r, goldenTime)
	if err != nil {
		t.Fatal(err)
	}
	sim.pageSize = pageSize
	res := runInProcess(t, kitConfig(), kitSecrets(), sim.responses())
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	out := map[string]any{}
	for _, artifact := range []struct{ name, path string }{
		{"idp-posture", idpPosturePath}, {"cloud-posture", cloudPosturePath}, {"access-posture", accessPosturePath},
	} {
		for _, a := range res.Artifacts {
			if a.Path != artifact.path {
				continue
			}
			var doc any
			if err := json.Unmarshal(a.Data, &doc); err != nil {
				t.Fatal(err)
			}
			flatten(doc, artifact.name+":", out)
		}
	}
	return out
}

func flatten(node any, at string, out map[string]any) {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if k == "collected_at" {
				continue
			}
			flatten(v, at+"/"+k, out)
		}
	case []any:
		for i, v := range n {
			flatten(v, fmt.Sprintf("%s/%d", at, i), out)
		}
	default:
		out[strings.Replace(at, ":/", ":/", 1)] = n
	}
}

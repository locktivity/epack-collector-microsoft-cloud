package collector

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

// bruteForceCovers checks every combination of every part's values, the
// slow way covers avoids, for comparison.
func bruteForceCovers(s *signInSpace, policies []microsoft.ConditionalAccessPolicy, clients []string, protect func(microsoft.ConditionalAccessPolicy, bool) bool, best bool) bool {
	in := policiesThat(policies, func(p microsoft.ConditionalAccessPolicy) bool {
		if !forUserSignIns(p) || !protect(p, best) {
			return false
		}
		return best || (len(p.Conditions.Unrecognized) == 0 && !hasDeviceFilter(p.Conditions))
	})
	var named []string
	for _, p := range in {
		if l := p.Conditions.Locations; l != nil {
			named = append(named, namedLocationIDs(l)...)
		}
	}
	s.locations = append(named, trustedElsewhere, untrustedElsewhere)
	var walk func(parts []signInPart, applying []microsoft.ConditionalAccessPolicy) bool
	walk = func(parts []signInPart, applying []microsoft.ConditionalAccessPolicy) bool {
		if len(parts) == 0 {
			return coverEveryApp(applying, best)
		}
		part := parts[0]
		for _, value := range part.values(s, in, clients) {
			next := policiesThat(applying, func(p microsoft.ConditionalAccessPolicy) bool {
				return !part.limits(p) || part.allows(s, p, value, best)
			})
			if !walk(parts[1:], next) {
				return false
			}
		}
		return true
	}
	return walk(signInParts, in)
}

// randomPolicy is a policy for everyone with a random mix of the conditions
// and grants the collector reads, the ones it can't evaluate included.
func randomPolicy(rng *rand.Rand, i int) microsoft.ConditionalAccessPolicy {
	p := mfaAllUsersPolicy(fmt.Sprintf("p%d", i))
	pick := func(options ...[]string) []string { return options[rng.IntN(len(options))] }
	p.Conditions.ClientAppTypes = pick([]string{"all"}, []string{"browser", "mobileAppsAndDesktopClients"}, []string{"exchangeActiveSync", "other"}, []string{"browser"}, nil)
	if rng.IntN(3) == 0 {
		p.Conditions.Platforms = &microsoft.ConditionalAccessPlatforms{IncludePlatforms: pick([]string{"all"}, []string{"iOS", "android"}, []string{"windows", "macOS", "linux"}), ExcludePlatforms: pick(nil, []string{"iOS"})}
	}
	if rng.IntN(3) == 0 {
		p.Conditions.Locations = &microsoft.ConditionalAccessLocations{IncludeLocations: pick([]string{"All"}, []string{"AllTrusted"}, []string{"office"}, []string{"branch"}), ExcludeLocations: pick(nil, []string{"AllTrusted"}, []string{"office"})}
	}
	if rng.IntN(3) == 0 {
		p.Conditions.SignInRiskLevels = pick([]string{"high"}, []string{"medium", "high"}, []string{"none", "low"})
	}
	if rng.IntN(4) == 0 {
		p.Conditions.UserRiskLevels = pick([]string{"high"}, []string{"none", "low", "medium"})
	}
	if rng.IntN(6) == 0 {
		p.Conditions.AuthenticationFlows = &microsoft.ConditionalAccessAuthenticationFlows{TransferMethods: "deviceCodeFlow"}
	}
	if rng.IntN(8) == 0 {
		p.Conditions.Devices = &microsoft.ConditionalAccessDevices{DeviceFilter: &microsoft.ConditionalAccessFilter{Mode: "exclude", Rule: `device.isCompliant -eq True`}}
	}
	if rng.IntN(4) == 0 {
		p.Conditions.Applications = &microsoft.ConditionalAccessApplications{IncludeApplications: pick([]string{"All"}, []string{"Office365"}), ExcludeApplications: pick(nil, []string{"Office365"})}
	}
	switch rng.IntN(5) {
	case 0:
		p.GrantControls = &microsoft.ConditionalAccessGrantControls{BuiltInControls: []string{"block"}}
	case 1:
		p.GrantControls = &microsoft.ConditionalAccessGrantControls{Operator: "OR", BuiltInControls: []string{"mfa", "quantumKey"}}
	}
	return p
}

// Splitting only where policies differ, and stopping once a set of policies
// covers everything, gives the same answer as checking every combination.
func TestCoversMatchesEveryCombination(t *testing.T) {
	rng := rand.New(rand.NewPCG(20261111, 2))
	trusted := map[string]bool{"office": true}
	for trial := range 600 {
		var policies []microsoft.ConditionalAccessPolicy
		for i := range 1 + rng.IntN(6) {
			policies = append(policies, randomPolicy(rng, i))
		}
		for _, clients := range [][]string{clientAppTypes, legacyClientTypes} {
			for _, best := range []bool{false, true} {
				for name, protect := range map[string]func(microsoft.ConditionalAccessPolicy, bool) bool{"protects": protectsAt, "blocks": blocksAt} {
					got := newSignInSpace(trusted).covers(policies, clients, protect, best)
					want := bruteForceCovers(newSignInSpace(trusted), policies, clients, protect, best)
					if got != want {
						t.Fatalf("trial %d, %s, clients %v, best %v: covers = %v, every combination says %v", trial, name, clients, best, got, want)
					}
				}
			}
		}
	}
}

// A check that runs over its budget gives up, and the value it was for is
// left out with a gap that says so.
func TestCoversGivesUpOverBudget(t *testing.T) {
	var policies []microsoft.ConditionalAccessPolicy
	for i, location := range []string{"office", "branch", "AllTrusted"} {
		p := mfaAllUsersPolicy(fmt.Sprintf("p%d", i))
		p.Conditions.Locations = &microsoft.ConditionalAccessLocations{IncludeLocations: []string{location}}
		p.Conditions.SignInRiskLevels = []string{"none", "low", "medium", "high"}
		policies = append(policies, p)
	}
	space := newSignInSpace(map[string]bool{"office": true})
	space.budget = 3
	got, why := space.settle(policies, clientAppTypes, protectsAt)
	if got != nil || why == nil || why.detail != overBudgetDetail {
		t.Fatalf("settle = %v, %+v, want it left out over budget", got, why)
	}
}

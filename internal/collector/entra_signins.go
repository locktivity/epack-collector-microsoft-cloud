package collector

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

// The values each part of a sign-in can take, for the parts Conditional
// Access policies condition on. Exchange ActiveSync and other clients use
// legacy authentication, which can't do MFA. A device platform Microsoft
// doesn't recognize is covered by a policy for all platforms, never by a
// list of them.
// https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-conditions
var (
	clientAppTypes    = []string{"browser", "mobileAppsAndDesktopClients", "exchangeActiveSync", "other"}
	legacyClientTypes = []string{"exchangeActiveSync", "other"}
	devicePlatforms   = []string{"android", "iOS", "windows", "windowsPhone", "macOS", "linux", unrecognizedPlatform}
	riskLevels        = []string{"none", "low", "medium", "high"}
	insiderRiskLevels = []string{"none", "minor", "moderate", "elevated"}
	transferMethods   = []string{"none", "deviceCodeFlow", "authenticationTransfer"}
)

// The values a policy can name that the collector recognizes, where they
// differ from the values above.
var (
	knownClientAppTypes = []string{"all", "browser", "mobileAppsAndDesktopClients", "exchangeActiveSync", "other"}
	knownPlatforms      = []string{"all", "android", "iOS", "windows", "windowsPhone", "macOS", "linux"}
)

const (
	unrecognizedPlatform = "unrecognized platform"
	// A sign-in from no named location a policy names is from a trusted
	// location or an untrusted one.
	trustedElsewhere   = "trusted elsewhere"
	untrustedElsewhere = "untrusted elsewhere"
)

// signInSpace checks whether policies cover every kind of sign-in. It splits
// the sign-ins only by the parts some policy in play limits, one part at a
// time, and stops splitting once the policies that limit nothing left cover
// every app. A tenant whose policies would make it check more than budget
// kinds of sign-in sets overBudget, and the values that needed the check are
// left out. trusted holds whether each named location is trusted, and has
// no entry for one whose trust wasn't read.
type signInSpace struct {
	trusted    map[string]bool
	budget     int
	steps      int
	overBudget bool
	// locations are the named locations the policies being checked name,
	// and trusted and untrusted elsewhere. Every branch checks them all,
	// since one whose trust wasn't read differs from both elsewheres.
	locations []string
}

// signInSpaceBudget is how many kinds of sign-in one run checks at most. A
// large tenant's policies need far fewer.
const signInSpaceBudget = 2_000_000

// overBudgetDetail is the detail of the gap on a value the check gave up on.
const overBudgetDetail = "The tenant's Conditional Access policies split sign-ins into more kinds than this collector checks, so it can't tell whether they cover every one."

func newSignInSpace(trusted map[string]bool) *signInSpace {
	return &signInSpace{trusted: trusted, budget: signInSpaceBudget}
}

// signInPart is a part of a sign-in a policy condition can limit: whether a
// policy's condition leaves out some of its values, the values a sign-in can
// take with the given policies in play, and whether a policy covers a value.
type signInPart struct {
	limits func(microsoft.ConditionalAccessPolicy) bool
	values func(*signInSpace, []microsoft.ConditionalAccessPolicy, []string) []string
	allows func(*signInSpace, microsoft.ConditionalAccessPolicy, string, bool) bool
}

func fixed(values []string) func(*signInSpace, []microsoft.ConditionalAccessPolicy, []string) []string {
	return func(*signInSpace, []microsoft.ConditionalAccessPolicy, []string) []string { return values }
}

// limitsList reports whether include and exclude lists leave out some
// values: an exclude list does, and an include list does unless it names all.
func limitsList(include, exclude []string, all string) bool {
	return len(exclude) > 0 || (len(include) > 0 && (all == "" || !containsFold(include, all)))
}

func listPart(list func(microsoft.ConditionalAccessConditionSet) (include, exclude []string), all string, values, known []string) signInPart {
	return signInPart{
		limits: func(p microsoft.ConditionalAccessPolicy) bool {
			include, exclude := list(p.Conditions)
			return limitsList(include, exclude, all)
		},
		values: fixed(values),
		allows: func(_ *signInSpace, p microsoft.ConditionalAccessPolicy, value string, best bool) bool {
			include, exclude := list(p.Conditions)
			return matches(include, exclude, value, all, known, best)
		},
	}
}

// signInParts are the parts of a sign-in policies can limit: the client app
// type, the device platform, the location, the sign-in, user and insider
// risk levels, and the authentication flow. The client's values are the
// clients being checked.
var signInParts = []signInPart{
	{
		limits: func(p microsoft.ConditionalAccessPolicy) bool {
			return limitsList(p.Conditions.ClientAppTypes, nil, "all")
		},
		values: func(_ *signInSpace, _ []microsoft.ConditionalAccessPolicy, clients []string) []string { return clients },
		allows: func(_ *signInSpace, p microsoft.ConditionalAccessPolicy, client string, best bool) bool {
			return matches(p.Conditions.ClientAppTypes, nil, client, "all", knownClientAppTypes, best)
		},
	},
	listPart(func(c microsoft.ConditionalAccessConditionSet) ([]string, []string) {
		if c.Platforms == nil {
			return nil, nil
		}
		return c.Platforms.IncludePlatforms, c.Platforms.ExcludePlatforms
	}, "all", devicePlatforms, knownPlatforms),
	{
		limits: func(p microsoft.ConditionalAccessPolicy) bool {
			l := p.Conditions.Locations
			return l != nil && limitsList(l.IncludeLocations, l.ExcludeLocations, "All")
		},
		values: func(s *signInSpace, _ []microsoft.ConditionalAccessPolicy, _ []string) []string { return s.locations },
		allows: func(s *signInSpace, p microsoft.ConditionalAccessPolicy, location string, best bool) bool {
			return s.locationMatches(p.Conditions.Locations, location, best)
		},
	},
	listPart(func(c microsoft.ConditionalAccessConditionSet) ([]string, []string) { return c.SignInRiskLevels, nil }, "", riskLevels, riskLevels),
	listPart(func(c microsoft.ConditionalAccessConditionSet) ([]string, []string) { return c.UserRiskLevels, nil }, "", riskLevels, riskLevels),
	listPart(func(c microsoft.ConditionalAccessConditionSet) ([]string, []string) { return insiderLevels(c), nil }, "", insiderRiskLevels, insiderRiskLevels),
	listPart(func(c microsoft.ConditionalAccessConditionSet) ([]string, []string) { return flowMethods(c), nil }, "", transferMethods, transferMethods),
}

func namedLocationIDs(l *microsoft.ConditionalAccessLocations) []string {
	var out []string
	for _, id := range append(slices.Clone(l.IncludeLocations), l.ExcludeLocations...) {
		if !strings.EqualFold(id, "All") && !strings.EqualFold(id, "AllTrusted") {
			out = append(out, id)
		}
	}
	return out
}

func insiderLevels(c microsoft.ConditionalAccessConditionSet) []string {
	return splitFlags(c.InsiderRiskLevels)
}

// flowMethods lists the authentication flows a policy is limited to, or
// none when it isn't.
func flowMethods(c microsoft.ConditionalAccessConditionSet) []string {
	if c.AuthenticationFlows == nil {
		return nil
	}
	methods := splitFlags(c.AuthenticationFlows.TransferMethods)
	if len(methods) == 1 && strings.EqualFold(methods[0], "none") {
		return nil
	}
	return methods
}

func splitFlags(flags string) []string {
	var out []string
	for _, flag := range strings.Split(flags, ",") {
		if flag = strings.TrimSpace(flag); flag != "" {
			out = append(out, flag)
		}
	}
	return out
}

// forUserSignIns reports whether a policy applies to users signing in. A
// policy for a user action, such as registering security information, or
// for workload identities doesn't.
func forUserSignIns(policy microsoft.ConditionalAccessPolicy) bool {
	c := policy.Conditions
	if c.Applications != nil && len(c.Applications.IncludeUserActions) > 0 {
		return false
	}
	if c.ClientApplications != nil && len(c.ClientApplications.IncludeServicePrincipals) > 0 {
		return false
	}
	return len(c.ServicePrincipalRiskLevels) == 0
}

// matches reports whether a condition's include and exclude lists let a
// value through. With both lists empty the condition isn't set, and an
// empty include list with an exclude list includes everything else. A value
// in a list that isn't one of known could be anything: at best it includes
// the value and excludes nothing, and at worst the reverse.
func matches(include, exclude []string, value, all string, known []string, best bool) bool {
	if len(include)+len(exclude) == 0 {
		return true
	}
	included := len(include) == 0 || (all != "" && containsFold(include, all)) || containsFold(include, value) ||
		(best && hasUnrecognized(include, known))
	excluded := containsFold(exclude, value) || (!best && hasUnrecognized(exclude, known))
	return included && !excluded
}

func hasUnrecognized(values, known []string) bool {
	return slices.ContainsFunc(values, func(v string) bool { return !containsFold(known, v) })
}

// locationMatches reports whether a policy's location condition lets a
// sign-in from location through. All covers every location, and AllTrusted
// the trusted ones.
func (s *signInSpace) locationMatches(l *microsoft.ConditionalAccessLocations, location string, best bool) bool {
	if l == nil || len(l.IncludeLocations)+len(l.ExcludeLocations) == 0 {
		return true
	}
	trusted, known := s.isTrusted(location)
	names := func(list []string, ifUnknown bool) bool {
		if containsFold(list, "All") || containsFold(list, location) {
			return true
		}
		if !containsFold(list, "AllTrusted") {
			return false
		}
		if known {
			return trusted
		}
		return ifUnknown
	}
	included := len(l.IncludeLocations) == 0 || names(l.IncludeLocations, best)
	return included && !names(l.ExcludeLocations, !best)
}

func (s *signInSpace) isTrusted(location string) (trusted, known bool) {
	switch location {
	case trustedElsewhere:
		return true, true
	case untrustedElsewhere:
		return false, true
	}
	trusted, known = s.trusted[location]
	return trusted, known
}

func hasDeviceFilter(c microsoft.ConditionalAccessConditionSet) bool {
	return c.Devices != nil && c.Devices.DeviceFilter != nil && strings.TrimSpace(c.Devices.DeviceFilter.Rule) != ""
}

func hasAppFilter(policy microsoft.ConditionalAccessPolicy) bool {
	apps := policy.Conditions.Applications
	return apps != nil && apps.ApplicationFilter != nil && strings.TrimSpace(apps.ApplicationFilter.Rule) != ""
}

// covers reports whether the policies, between them, cover every sign-in
// from each client in clients, to every app, whatever its other parts. A
// policy covers the sign-ins it applies to when protect says it does. Some
// conditions can't be evaluated: a device filter, a condition the collector
// doesn't recognize, a value it doesn't recognize, and a named location whose
// trust wasn't read. With best true each is taken in the way that lets the
// policy apply, and with best false in the way that doesn't.
func (s *signInSpace) covers(policies []microsoft.ConditionalAccessPolicy, clients []string, protect func(microsoft.ConditionalAccessPolicy, bool) bool, best bool) bool {
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
	slices.Sort(named)
	s.locations = append(slices.Compact(named), trustedElsewhere, untrustedElsewhere)
	return s.coverFrom(in, signInParts, clients, best)
}

// coverFrom checks the sign-ins whose parts other than those in parts are
// already settled. When the policies that limit none of those parts cover
// every app, every such sign-in is covered. Otherwise it splits on the part
// the most policies limit and checks each of its values.
func (s *signInSpace) coverFrom(policies []microsoft.ConditionalAccessPolicy, parts []signInPart, clients []string, best bool) bool {
	if s.steps++; s.steps > s.budget {
		s.overBudget = true
		return false
	}
	var free []microsoft.ConditionalAccessPolicy
	limitedBy := make([]int, len(parts))
	for _, p := range policies {
		limited := false
		for i, part := range parts {
			if part.limits(p) {
				limitedBy[i]++
				limited = true
			}
		}
		if !limited {
			free = append(free, p)
		}
	}
	if coverEveryApp(free, best) {
		return true
	}
	split := 0
	for i := range parts {
		if limitedBy[i] > limitedBy[split] {
			split = i
		}
	}
	if len(parts) == 0 || limitedBy[split] == 0 {
		return false
	}
	part := parts[split]
	rest := slices.Delete(slices.Clone(parts), split, split+1)
	for _, value := range part.values(s, policies, clients) {
		sub := policiesThat(policies, func(p microsoft.ConditionalAccessPolicy) bool {
			return !part.limits(p) || part.allows(s, p, value, best)
		})
		if !s.coverFrom(sub, rest, clients, best) {
			return false
		}
	}
	return true
}

// coverEveryApp reports whether the policies, between them, cover sign-ins
// to every app. A policy that includes All covers every app but those it
// excludes, and one that lists apps covers those. An app filter matches
// apps the collector can't name: at best the policy covers them all, and at
// worst it adds nothing. Each app that every policy including All excludes
// must be one another policy lists.
func coverEveryApp(policies []microsoft.ConditionalAccessPolicy, best bool) bool {
	var excluded map[string]struct{}
	listed := map[string]struct{}{}
	for _, policy := range policies {
		apps := policy.Conditions.Applications
		if apps == nil || (!best && hasAppFilter(policy)) || containsFold(apps.ExcludeApplications, "All") {
			continue
		}
		if !containsFold(apps.IncludeApplications, "All") {
			for _, app := range apps.IncludeApplications {
				if !containsFold(apps.ExcludeApplications, app) {
					listed[strings.ToLower(app)] = struct{}{}
				}
			}
			continue
		}
		mine := map[string]struct{}{}
		for _, app := range apps.ExcludeApplications {
			mine[strings.ToLower(app)] = struct{}{}
		}
		if excluded == nil {
			excluded = mine
			continue
		}
		for app := range excluded {
			if _, ok := mine[app]; !ok {
				delete(excluded, app)
			}
		}
	}
	if excluded == nil {
		return false
	}
	for app := range excluded {
		if _, ok := listed[app]; !ok {
			return false
		}
	}
	return true
}

// protectsAt reports whether a policy requires MFA for, or blocks, the
// sign-ins it covers. Either way, no one signs in there with a password
// alone. A grant control the collector doesn't recognize counts as MFA with
// best true and not with best false.
func protectsAt(policy microsoft.ConditionalAccessPolicy, best bool) bool {
	return blocks(policy) || grantRequires(policy, func(control grantControl) bool {
		known, mfa := classifyControl(control)
		if !known {
			return best
		}
		return mfa
	})
}

func blocksAt(policy microsoft.ConditionalAccessPolicy, _ bool) bool {
	return blocks(policy)
}

func blocks(policy microsoft.ConditionalAccessPolicy) bool {
	return grantRequires(policy, func(control grantControl) bool { return strings.EqualFold(control.builtIn, "block") })
}

// classifyControl reports whether the collector recognizes a grant control,
// and whether it requires MFA. An authentication strength requires MFA when
// Microsoft says it satisfies the MFA requirement. Custom controls and terms
// of use don't.
// https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols
func classifyControl(control grantControl) (known, mfa bool) {
	if control.strength != nil {
		switch strings.ToLower(control.strength.RequirementsSatisfied) {
		case "mfa":
			return true, true
		case "none":
			return true, false
		}
		return false, false
	}
	switch strings.ToLower(control.builtIn) {
	case "mfa":
		return true, true
	case "", "block", "compliantdevice", "domainjoineddevice", "approvedapplication", "compliantapplication", "passwordchange":
		return true, false
	}
	return false, false
}

// settle works out whether the policies cover every sign-in from clients, at
// worst and at best. When the two agree it returns the answer, and when they
// don't, or the check ran over its budget, it returns why it isn't known.
func (s *signInSpace) settle(policies []microsoft.ConditionalAccessPolicy, clients []string, protect func(microsoft.ConditionalAccessPolicy, bool) bool) (*bool, *missing) {
	worst := s.covers(policies, clients, protect, false)
	best := s.covers(policies, clients, protect, true)
	if s.overBudget {
		return nil, notRead(overBudgetDetail)
	}
	if worst == best {
		return boolPtr(worst), nil
	}
	return nil, notRead(s.doubtsAbout(policies, false))
}

// doubtsAbout says why the policies' reach isn't certain, from what each
// names that the collector can't evaluate or doesn't recognize. With
// members true it adds group and role membership.
func (s *signInSpace) doubtsAbout(policies []microsoft.ConditionalAccessPolicy, members bool) string {
	doubts := map[string]struct{}{}
	add := func(format string, args ...any) { doubts[fmt.Sprintf(format, args...)] = struct{}{} }
	for _, policy := range policies {
		c := policy.Conditions
		if members && c.Users != nil && len(c.Users.IncludeGroups)+len(c.Users.ExcludeGroups)+len(c.Users.IncludeRoles)+len(c.Users.ExcludeRoles) > 0 {
			add("%s", groupOrRoleMembersUnread)
		}
		if len(c.Unrecognized) > 0 {
			add("A policy has a condition this collector doesn't recognize: %s.", strings.Join(c.Unrecognized, ", "))
		}
		if hasDeviceFilter(c) {
			add("A policy has a device filter, and this collector can't tell which devices it matches.")
		}
		if hasAppFilter(policy) {
			add("A policy has an app filter, and this collector can't tell which apps it matches.")
		}
		var platforms []string
		if c.Platforms != nil {
			platforms = append(slices.Clone(c.Platforms.IncludePlatforms), c.Platforms.ExcludePlatforms...)
		}
		for _, list := range []struct {
			name          string
			values, known []string
		}{
			{"client app", c.ClientAppTypes, knownClientAppTypes},
			{"device platform", platforms, knownPlatforms},
			{"sign-in risk", c.SignInRiskLevels, riskLevels},
			{"user risk", c.UserRiskLevels, riskLevels},
			{"insider risk", insiderLevels(c), insiderRiskLevels},
			{"authentication flow", flowMethods(c), transferMethods},
		} {
			for _, v := range list.values {
				if !containsFold(list.known, v) {
					add("A policy has a value this collector doesn't recognize in its %s condition: %s.", list.name, v)
				}
			}
		}
		if c.Locations != nil {
			for _, id := range namedLocationIDs(c.Locations) {
				if _, known := s.trusted[id]; !known {
					add("A policy names a location whose trust this collector couldn't read.")
				}
			}
		}
		for _, control := range grantControls(policy) {
			if known, _ := classifyControl(control); !known {
				name := control.builtIn
				if control.strength != nil {
					name = "an authentication strength that satisfies " + control.strength.RequirementsSatisfied
				}
				add("A policy's grant has a control this collector doesn't recognize: %s.", name)
			}
		}
	}
	out := make([]string, 0, len(doubts))
	for doubt := range doubts {
		out = append(out, doubt)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

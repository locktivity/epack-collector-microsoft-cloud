package collector

import (
	"maps"
	"slices"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

// signInElsewhere names the federated domains that hold an enabled member's
// user principal name, and those that hold a privileged user's. Microsoft
// hands a federated domain's sign-ins to the identity provider it is
// federated with, and that provider decides whether its users use MFA.
type signInElsewhere struct {
	members, admins []string
}

func signsInElsewhere(org *microsoft.Organization, users []microsoft.User, members map[string]struct{}, privileged *PrivilegedAccess) signInElsewhere {
	federated := org.FederatedDomains()
	if len(federated) == 0 {
		return signInElsewhere{}
	}
	byID := usersByID(users)
	out := signInElsewhere{members: federatedDomainsOf(members, byID, federated)}
	if privileged != nil {
		out.admins = federatedDomainsOf(privileged.userIDs, byID, federated)
	}
	return out
}

// federatedDomainsOf lists, sorted, the federated domains that hold the user
// principal name of a user ids names.
func federatedDomainsOf(ids map[string]struct{}, users map[string]microsoft.User, federated []string) []string {
	found := map[string]bool{}
	for id := range ids {
		upn := strings.ToLower(users[id].UserPrincipalName)
		if at := strings.LastIndex(upn, "@"); at >= 0 && slices.Contains(federated, upn[at+1:]) {
			found[upn[at+1:]] = true
		}
	}
	return slices.Sorted(maps.Keys(found))
}

// The normalized values left out when members, or admins, sign in through a
// federated domain. The counts are audit-level fields.
var (
	membersElsewhere = []struct {
		pointer string
		audit   bool
	}{
		{"/policy/mfa_required", false},
		{"/policy/mfa_required_coverage_pct", false},
		{"/policy/mfa_required_user_count", true},
		{"/user_security/mfa_coverage_pct", false},
		{"/user_security/mfa_phishing_resistant_pct", false},
		{"/user_security/mfa_user_count", true},
		{"/user_security/phishing_resistant_user_count", true},
	}
	adminsElsewhere = []struct {
		pointer string
		audit   bool
	}{
		{"/privileged_access/privileged_mfa_coverage_pct", false},
		{"/privileged_access/privileged_mfa_user_count", true},
		{"/privileged_access/privileged_phishing_resistant_pct", false},
		{"/privileged_access/privileged_phishing_resistant_user_count", true},
	}
)

// markSignInElsewhere records why ToIDPPosture left the MFA values out when
// members or admins sign in through a federated domain, with an
// unsupported gap that names the domains. Only audit and higher runs write
// the counts.
func (c *Collector) markSignInElsewhere(entra *EntraArtifact, level componentsdk.Level) {
	for _, group := range []struct {
		who     string
		domains []string
		values  []struct {
			pointer string
			audit   bool
		}
	}{
		{"members", entra.elsewhere.members, membersElsewhere},
		{"admins", entra.elsewhere.admins, adminsElsewhere},
	} {
		if len(group.domains) == 0 {
			continue
		}
		detail := "Some " + group.who + " sign in through another identity provider, since their user principal names are in a federated domain: " +
			strings.Join(group.domains, ", ") + ". That provider decides whether they use MFA, and Microsoft's registration report doesn't show it."
		for _, v := range group.values {
			if v.audit && !level.AtLeast(componentsdk.LevelAudit) {
				continue
			}
			c.gaps.rec.NotCollectedCode(componentsdk.Location{Path: idpPosturePath, Pointer: v.pointer}, componentsdk.CodeUnsupported, detail)
		}
	}
}

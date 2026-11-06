package collector

import (
	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

// The block in this file is the one epack v0.10.0 moved out of
// cloud-posture, into access-posture. The schema keeps it as deprecated, and
// the collector writes it as v0.1 did, so profiles written before v0.10.0
// grade the same. A later minor removes it.

// CloudPostureIAM holds the tenant's MFA values, written in each
// subscription's entry. RootMFAEnabled and RootAccessProtected are both
// whether every Global Administrator has MFA registered.
type CloudPostureIAM struct {
	MFACoveragePct      *int  `json:"mfa_coverage_pct,omitempty"`
	RootMFAEnabled      *bool `json:"root_mfa_enabled,omitempty"`
	RootAccessProtected *bool `json:"root_access_protected,omitempty"`
}

// globalAdminsMFARegistered reports whether every Global Administrator in
// superAdminIDs is registered for MFA. It is true when there are none.
func globalAdminsMFARegistered(superAdminIDs map[string]struct{}, registrations []microsoft.UserRegistrationDetail) *bool {
	registered := map[string]bool{}
	for _, registration := range registrations {
		registered[registration.ID] = registration.IsMFARegistered
	}
	for id := range superAdminIDs {
		if !registered[id] {
			return boolPtr(false)
		}
	}
	return boolPtr(true)
}

// addDeprecatedIAM writes the iam block in each of posture's subscriptions.
// The MFA coverage is a copy of the Entra artifact's, so a gap on it carries
// over. The Global Administrator values carry the gap of the read that left
// them out.
func (c *Collector) addDeprecatedIAM(posture *CloudPosture, entra *EntraArtifact) {
	if posture == nil || entra == nil {
		return
	}
	pa := entra.PrivilegedAccess
	var rootMFA *bool
	if pa != nil {
		rootMFA = pa.globalAdminsMFA
	}
	for i := range posture.Accounts {
		at := func(field string) componentsdk.Location {
			return componentsdk.Location{Path: cloudPosturePath, Pointer: accountPointer(i, "iam/"+field)}
		}
		c.gaps.rec.Mirror(componentsdk.Location{Path: entraPath, Pointer: "/posture/mfa_coverage"}, at("mfa_coverage_pct"))
		switch {
		case pa == nil:
			for _, field := range []string{"root_mfa_enabled", "root_access_protected"} {
				c.gaps.rec.Mirror(componentsdk.Location{Path: entraPath, Pointer: "/privileged_access"}, at(field))
			}
		case rootMFA == nil:
			c.gaps.leaveOut(cloudPosturePath, pa.globalAdminsMFAUnread,
				accountPointer(i, "iam/root_mfa_enabled"), accountPointer(i, "iam/root_access_protected"))
		}
		iam := CloudPostureIAM{MFACoveragePct: entra.Posture.MFACoverage, RootMFAEnabled: rootMFA, RootAccessProtected: rootMFA}
		if iam != (CloudPostureIAM{}) {
			posture.Accounts[i].IAM = &iam
		}
	}
}

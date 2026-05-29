package collector

type IDPPosture struct {
	SchemaVersion    string                      `json:"schema_version"`
	CollectedAt      string                      `json:"collected_at"`
	Provider         string                      `json:"provider"`
	OrgDomain        string                      `json:"org_domain"`
	UserSecurity     IDPPostureUserSecurity      `json:"user_security"`
	AppSecurity      *IDPPostureAppSecurity      `json:"app_security,omitempty"`
	PrivilegedAccess *IDPPosturePrivilegedAccess `json:"privileged_access,omitempty"`
	Lifecycle        *IDPPostureLifecycle        `json:"lifecycle,omitempty"`
	Policy           *IDPPosturePolicy           `json:"policy,omitempty"`
}

type IDPPostureUserSecurity struct {
	MFACoveragePct          *int `json:"mfa_coverage_pct,omitempty"`
	MFAPhishingResistantPct *int `json:"mfa_phishing_resistant_pct,omitempty"`
	InactivePct             *int `json:"inactive_pct,omitempty"`
}

type IDPPostureAppSecurity struct {
	SSOCoveragePct *int `json:"sso_coverage_pct,omitempty"`
}

type IDPPosturePrivilegedAccess struct {
	PrivilegedUsersCount     *int `json:"privileged_users_count,omitempty"`
	SuperAdminCount          *int `json:"super_admin_count,omitempty"`
	PrivilegedMFACoveragePct *int `json:"privileged_mfa_coverage_pct,omitempty"`
}

type IDPPostureLifecycle struct {
	SuspendedPct *int `json:"suspended_pct,omitempty"`
}

type IDPPosturePolicy struct {
	MFARequired            *bool `json:"mfa_required,omitempty"`
	MFARequiredCoveragePct *int  `json:"mfa_required_coverage_pct,omitempty"`
	LegacyAuthBlocked      *bool `json:"legacy_auth_blocked,omitempty"`
}

func (e *EntraArtifact) ToIDPPosture() *IDPPosture {
	if e == nil || !e.hasNormalizedIDPEvidence() {
		return nil
	}
	policy := e.normalizedPolicy()
	appSecurity := e.normalizedAppSecurity()
	privilegedAccess := e.normalizedPrivilegedAccess()
	lifecycle := e.normalizedLifecycle()
	return &IDPPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   e.CollectedAt,
		Provider:      "entra",
		OrgDomain:     e.OrgDomain,
		UserSecurity: IDPPostureUserSecurity{
			MFACoveragePct:          e.Posture.MFACoverage,
			MFAPhishingResistantPct: e.Posture.MFAPhishingResistant,
			InactivePct:             e.Users.InactivePct,
		},
		AppSecurity:      appSecurity,
		PrivilegedAccess: privilegedAccess,
		Lifecycle:        lifecycle,
		Policy:           policy,
	}
}

func (e *EntraArtifact) hasNormalizedIDPEvidence() bool {
	if e.Posture.MFACoverage != nil || e.Posture.MFAPhishingResistant != nil || e.Users.InactivePct != nil {
		return true
	}
	return e.normalizedPolicy() != nil ||
		e.normalizedAppSecurity() != nil ||
		e.normalizedPrivilegedAccess() != nil ||
		e.normalizedLifecycle() != nil
}

func (e *EntraArtifact) normalizedPolicy() *IDPPosturePolicy {
	if e == nil || e.Policy == nil {
		return nil
	}
	policy := &IDPPosturePolicy{
		MFARequired:            e.Policy.MFARequired,
		MFARequiredCoveragePct: e.Policy.MFARequiredCoveragePct,
		LegacyAuthBlocked:      e.Policy.LegacyAuthBlocked,
	}
	if policy.MFARequired == nil && policy.MFARequiredCoveragePct == nil && policy.LegacyAuthBlocked == nil {
		return nil
	}
	return policy
}

func (e *EntraArtifact) normalizedAppSecurity() *IDPPostureAppSecurity {
	if e == nil || e.Posture.SSOCoverage == nil {
		return nil
	}
	return &IDPPostureAppSecurity{SSOCoveragePct: e.Posture.SSOCoverage}
}

func (e *EntraArtifact) normalizedPrivilegedAccess() *IDPPosturePrivilegedAccess {
	if e == nil || e.PrivilegedAccess == nil {
		return nil
	}
	privilegedUsersCount := intPtr(e.PrivilegedAccess.PrivilegedUsersCount)
	superAdminCount := intPtr(e.PrivilegedAccess.SuperAdminCount)
	out := &IDPPosturePrivilegedAccess{
		PrivilegedUsersCount:     privilegedUsersCount,
		SuperAdminCount:          superAdminCount,
		PrivilegedMFACoveragePct: e.PrivilegedAccess.PrivilegedMFACoveragePct,
	}
	if out.PrivilegedUsersCount == nil && out.SuperAdminCount == nil && out.PrivilegedMFACoveragePct == nil {
		return nil
	}
	return out
}

func (e *EntraArtifact) normalizedLifecycle() *IDPPostureLifecycle {
	if e == nil || e.Users.DisabledPct == nil {
		return nil
	}
	return &IDPPostureLifecycle{SuspendedPct: e.Users.DisabledPct}
}

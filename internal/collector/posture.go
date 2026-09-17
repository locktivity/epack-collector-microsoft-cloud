package collector

const SchemaVersion = "1.0.0"

type EntraArtifact struct {
	SchemaVersion     string             `json:"schema_version"`
	CollectedAt       string             `json:"collected_at"`
	CollectedAtLevel  string             `json:"collected_at_level"`
	TenantID          string             `json:"tenant_id"`
	OrgDomain         string             `json:"org_domain"`
	Posture           Posture            `json:"posture"`
	Users             Users              `json:"users"`
	Policy            *Policy            `json:"policy,omitempty"`
	SecurityDefaults  *SecurityDefaults  `json:"security_defaults,omitempty"`
	PrivilegedAccess  *PrivilegedAccess  `json:"privileged_access,omitempty"`
	Apps              *Apps              `json:"apps,omitempty"`
	SecureScore       *SecureScore       `json:"secure_score,omitempty"`
	DirectoryActivity *DirectoryActivity `json:"directory_activity,omitempty"`
	SignInMonitoring  *SignInMonitoring  `json:"sign_in_monitoring,omitempty"`
	Diagnostics       Diagnostics        `json:"diagnostics"`
}

type Posture struct {
	MFACoverage                   *int `json:"mfa_coverage"`
	MFAPhishingResistant          *int `json:"mfa_phishing_resistant"`
	MFAWeakMethodOnly             *int `json:"mfa_weak_method_only"`
	SSPRRegistered                *int `json:"sspr_registered"`
	SSOCoverage                   *int `json:"sso_coverage"`
	DenominatorEnabledMemberUsers int  `json:"denominator_enabled_member_users"`
}

type Users struct {
	TotalCount              int  `json:"total_count"`
	EnabledMemberUsersCount int  `json:"enabled_member_users_count"`
	GuestPct                *int `json:"guest_pct"`
	DisabledPct             *int `json:"disabled_pct"`
	InactivePct             *int `json:"inactive_pct"`
	InactiveGuestPct        *int `json:"inactive_guest_pct"`
}

type Policy struct {
	MFARequired             *bool `json:"mfa_required"`
	MFARequiredCoveragePct  *int  `json:"mfa_required_coverage_pct"`
	AdminPortalsMFARequired *bool `json:"admin_portals_mfa_required"`
	AllCloudAppsMFARequired *bool `json:"all_cloud_apps_mfa_required"`
	CompliantDeviceRequired *bool `json:"compliant_device_required"`
	LegacyAuthBlocked       *bool `json:"legacy_auth_blocked"`
	PolicyCount             *int  `json:"policy_count"`
}

type SecurityDefaults struct {
	Enabled bool `json:"enabled"`
}

type PrivilegedAccess struct {
	SuperAdminCount                int   `json:"super_admin_count"`
	PrivilegedUsersCount           int   `json:"privileged_users_count"`
	PrivilegedMFACoveragePct       *int  `json:"privileged_mfa_coverage_pct"`
	PrivilegedPhishingResistantPct *int  `json:"privileged_phishing_resistant_pct"`
	PIMEligiblePct                 *int  `json:"pim_eligible_pct"`
	StandingAssignmentCount        *int  `json:"standing_assignment_count"`
	InactivePrivilegedUsersCount   *int  `json:"inactive_privileged_users_count"`
	PrivilegedGuestCount           int   `json:"privileged_guest_count"`
	RootMFAEnabled                 *bool `json:"-"`
}

type Apps struct {
	EnabledEnterpriseAppsCount int  `json:"enabled_enterprise_apps_count"`
	AssignmentRequiredPct      *int `json:"assignment_required_pct"`
	CredentialsExpiringCount   int  `json:"credentials_expiring_count"`
	CredentialsExpiredCount    int  `json:"credentials_expired_count"`
	CredentialsOver365dCount   int  `json:"credentials_over_365d_count"`
	PasswordCredentialsPct     *int `json:"password_credentials_pct"`
	SSOCoveragePct             *int `json:"-"`
}

type SecureScore struct {
	IdentityPct *int `json:"identity_pct"`
}

type DirectoryActivity struct {
	LookbackHours           int `json:"lookback_hours"`
	EventsCount             int `json:"events_count"`
	FailureCount            int `json:"failure_count"`
	DeleteEventsCount       int `json:"delete_events_count"`
	UserChangeEventsCount   int `json:"user_change_events_count"`
	GroupChangeEventsCount  int `json:"group_change_events_count"`
	AppChangeEventsCount    int `json:"app_change_events_count"`
	RoleChangeEventsCount   int `json:"role_change_events_count"`
	PolicyChangeEventsCount int `json:"policy_change_events_count"`
	PIMEventsCount          int `json:"pim_events_count"`
}

type SignInMonitoring struct {
	LookbackHours                    int                      `json:"lookback_hours"`
	SignInsCount                     int                      `json:"sign_ins_count"`
	FailureCount                     int                      `json:"failure_count"`
	UniqueUsersCount                 int                      `json:"unique_users_count"`
	UniqueAppsCount                  int                      `json:"unique_apps_count"`
	LegacyClientSignInsCount         int                      `json:"legacy_client_sign_ins_count"`
	RiskySignInsCount                int                      `json:"risky_sign_ins_count"`
	ConditionalAccessSuccessCount    int                      `json:"conditional_access_success_count"`
	ConditionalAccessFailureCount    int                      `json:"conditional_access_failure_count"`
	ConditionalAccessNotAppliedCount int                      `json:"conditional_access_not_applied_count"`
	AppliedPoliciesCount             int                      `json:"applied_policies_count"`
	AppliedPolicyEvaluationsCount    int                      `json:"applied_policy_evaluations_count"`
	AppliedPolicySuccessCount        int                      `json:"applied_policy_success_count"`
	AppliedPolicyFailureCount        int                      `json:"applied_policy_failure_count"`
	AppliedPolicyNotAppliedCount     int                      `json:"applied_policy_not_applied_count"`
	AppliedPolicyReportOnlyFailCount int                      `json:"applied_policy_report_only_fail_count"`
	TopFailureCodes                  []SignInFailureCodeCount `json:"top_failure_codes"`
}

type SignInFailureCodeCount struct {
	Code  int `json:"code"`
	Count int `json:"count"`
}

type Result struct {
	Entra             *EntraArtifact
	EntraIDPPosture   *IDPPosture
	Azure             *AzureArtifact
	AzureCloudPosture *CloudPosture
	Diagnostics       Diagnostics
}

type AzureArtifact struct {
	SchemaVersion    string         `json:"schema_version"`
	CollectedAt      string         `json:"collected_at"`
	CollectedAtLevel string         `json:"collected_at_level"`
	Accounts         []AzureAccount `json:"accounts"`
	Diagnostics      Diagnostics    `json:"diagnostics"`
}

type AzureAccount struct {
	AccountID string          `json:"account_id"`
	Defender  *AzureDefender  `json:"defender,omitempty"`
	RBAC      *AzureRBAC      `json:"rbac,omitempty"`
	Policy    *AzurePolicy    `json:"policy,omitempty"`
	Storage   *AzureStorage   `json:"storage,omitempty"`
	KeyVault  *AzureKeyVault  `json:"keyvault,omitempty"`
	SQL       *AzureSQL       `json:"sql,omitempty"`
	Compute   *AzureCompute   `json:"compute,omitempty"`
	Backup    *AzureBackup    `json:"backup,omitempty"`
	Network   *AzureNetwork   `json:"network,omitempty"`
	Logging   *AzureLogging   `json:"logging,omitempty"`
	Inventory *AzureInventory `json:"inventory,omitempty"`
}

type AzureDefender struct {
	SecureScorePct *int `json:"secure_score_pct"`
	UnpatchedPct   *int `json:"unpatched_pct"`
}

type AzureRBAC struct {
	OwnerCount                 int `json:"owner_count"`
	OwnerServicePrincipalCount int `json:"owner_service_principal_count"`
}

type AzurePolicy struct {
	AssignmentsCount           int  `json:"assignments_count"`
	CompliantPct               *int `json:"compliant_pct"`
	NoncompliantResourcesCount *int `json:"noncompliant_resources_count"`
}

type AzureStorage struct {
	StorageAccountsCount        int  `json:"storage_accounts_count"`
	HTTPSOnlyPct                *int `json:"https_only_pct"`
	MinTLS12Pct                 *int `json:"min_tls12_pct"`
	EncryptionCMKPct            *int `json:"encryption_cmk_pct"`
	InfrastructureEncryptionPct *int `json:"infrastructure_encryption_pct"`
	PublicAccessBlockedPct      *int `json:"public_access_blocked_pct"`
}

type AzureKeyVault struct {
	VaultsCount          int  `json:"vaults_count"`
	PurgeProtectionPct   *int `json:"purge_protection_pct"`
	RBACAuthorizationPct *int `json:"rbac_authorization_pct"`
}

type AzureSQL struct {
	ServersCount            int  `json:"servers_count"`
	DatabasesCount          int  `json:"databases_count"`
	TDEEnabledPct           *int `json:"tde_enabled_pct"`
	MinTLS12Pct             *int `json:"min_tls12_pct"`
	PublicAccessDisabledPct *int `json:"public_access_disabled_pct"`
}

type AzureCompute struct {
	VirtualMachinesCount int  `json:"virtual_machines_count"`
	DiskEncryptionPct    *int `json:"disk_encryption_pct"`
	PublicIPPct          *int `json:"public_ip_pct"`
}

type AzureNetwork struct {
	NetworkSecurityGroupsCount int  `json:"network_security_groups_count"`
	PublicIPAddressesCount     int  `json:"public_ip_addresses_count"`
	SSHOpenToWorldPct          *int `json:"ssh_open_to_world_pct"`
	RDPOpenToWorldPct          *int `json:"rdp_open_to_world_pct"`
}

type AzureLogging struct {
	SubscriptionDiagnosticSettingsEnabled *bool `json:"subscription_diagnostic_settings_enabled"`
	ActivityLogAdministrativeExported     *bool `json:"activity_log_administrative_exported"`
	DiagnosticSettingsCoveragePct         *int  `json:"diagnostic_settings_coverage_pct"`
	MonitoredResourcesCount               int   `json:"monitored_resources_count"`
	ResourcesWithoutDiagnosticsCount      *int  `json:"resources_without_diagnostics_count"`
}

type AzureInventory struct {
	ResourcesCount            int                      `json:"resources_count"`
	ResourceGroupsCount       int                      `json:"resource_groups_count"`
	RegionsCount              int                      `json:"regions_count"`
	OwnerTagCoveragePct       *int                     `json:"owner_tag_coverage_pct"`
	EnvironmentTagCoveragePct *int                     `json:"environment_tag_coverage_pct"`
	ProductionResourcesPct    *int                     `json:"production_resources_pct"`
	TopResourceTypes          []AzureResourceTypeCount `json:"top_resource_types"`
}

type AzureResourceTypeCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type AzureBackup struct {
	RetentionDaysMin                  *int `json:"retention_days_min"`
	ProtectedResourcePct              *int `json:"protected_resource_pct"`
	LatestSuccessfulBackupAgeHoursMax *int `json:"latest_successful_backup_age_hours_max"`
	FailedJobs7dCount                 *int `json:"failed_jobs_7d_count"`
	VaultSoftDeletePct                *int `json:"vault_soft_delete_pct"`
	VaultImmutabilityPct              *int `json:"vault_immutability_pct"`
}

package microsoft

type Organization struct {
	ID              string           `json:"id"`
	VerifiedDomains []VerifiedDomain `json:"verifiedDomains"`
}

type VerifiedDomain struct {
	Name      string `json:"name"`
	IsDefault bool   `json:"isDefault"`
	IsInitial bool   `json:"isInitial"`
	Type      string `json:"type"`
}

func (o Organization) PrimaryDomain() string {
	for _, domain := range o.VerifiedDomains {
		if domain.IsDefault && domain.Name != "" {
			return domain.Name
		}
	}
	for _, domain := range o.VerifiedDomains {
		if !domain.IsInitial && domain.Name != "" {
			return domain.Name
		}
	}
	for _, domain := range o.VerifiedDomains {
		if domain.Name != "" {
			return domain.Name
		}
	}
	return ""
}

type User struct {
	ID             string          `json:"id"`
	AccountEnabled *bool           `json:"accountEnabled"`
	UserType       string          `json:"userType"`
	SignInActivity *SignInActivity `json:"signInActivity"`
}

func (u User) EnabledMember() bool {
	return u.AccountEnabled != nil && *u.AccountEnabled && u.UserType == "Member"
}

type UserRegistrationDetail struct {
	ID                string   `json:"id"`
	UserPrincipalName string   `json:"userPrincipalName"`
	UserType          string   `json:"userType"`
	IsMFARegistered   bool     `json:"isMfaRegistered"`
	IsSSPRRegistered  bool     `json:"isSsprRegistered"`
	MethodsRegistered []string `json:"methodsRegistered"`
}

type SignInActivity struct {
	LastSignInDateTime string `json:"lastSignInDateTime"`
}

type ConditionalAccessPolicy struct {
	ID            string                          `json:"id"`
	DisplayName   string                          `json:"displayName"`
	State         string                          `json:"state"`
	Conditions    ConditionalAccessConditionSet   `json:"conditions"`
	GrantControls *ConditionalAccessGrantControls `json:"grantControls"`
}

type ConditionalAccessConditionSet struct {
	Applications   *ConditionalAccessApplications `json:"applications"`
	Users          *ConditionalAccessUsers        `json:"users"`
	ClientAppTypes []string                       `json:"clientAppTypes"`
}

type ConditionalAccessApplications struct {
	IncludeApplications []string `json:"includeApplications"`
	ExcludeApplications []string `json:"excludeApplications"`
	IncludeUserActions  []string `json:"includeUserActions"`
}

type ConditionalAccessUsers struct {
	IncludeUsers  []string `json:"includeUsers"`
	ExcludeUsers  []string `json:"excludeUsers"`
	IncludeGroups []string `json:"includeGroups"`
	ExcludeGroups []string `json:"excludeGroups"`
	IncludeRoles  []string `json:"includeRoles"`
	ExcludeRoles  []string `json:"excludeRoles"`
}

type ConditionalAccessGrantControls struct {
	Operator        string   `json:"operator"`
	BuiltInControls []string `json:"builtInControls"`
}

type IdentitySecurityDefaultsEnforcementPolicy struct {
	IsEnabled bool `json:"isEnabled"`
}

type UnifiedRoleAssignment struct {
	ID               string              `json:"id"`
	PrincipalID      string              `json:"principalId"`
	RoleDefinitionID string              `json:"roleDefinitionId"`
	Principal        *DirectoryPrincipal `json:"principal"`
}

type UnifiedRoleEligibilitySchedule struct {
	ID               string                 `json:"id"`
	PrincipalID      string                 `json:"principalId"`
	RoleDefinitionID string                 `json:"roleDefinitionId"`
	RoleDefinition   *UnifiedRoleDefinition `json:"roleDefinition"`
}

type UnifiedRoleDefinition struct {
	ID         string `json:"id"`
	TemplateID string `json:"templateId"`
}

type DirectoryPrincipal struct {
	ODataType      string `json:"@odata.type"`
	ID             string `json:"id"`
	AccountEnabled *bool  `json:"accountEnabled"`
	UserType       string `json:"userType"`
}

type ServicePrincipal struct {
	ID                        string               `json:"id"`
	AccountEnabled            *bool                `json:"accountEnabled"`
	AppRoleAssignmentRequired *bool                `json:"appRoleAssignmentRequired"`
	PreferredSingleSignOnMode string               `json:"preferredSingleSignOnMode"`
	ServicePrincipalType      string               `json:"servicePrincipalType"`
	PasswordCredentials       []PasswordCredential `json:"passwordCredentials"`
	KeyCredentials            []KeyCredential      `json:"keyCredentials"`
}

func (sp ServicePrincipal) EnabledEnterpriseApp() bool {
	if sp.ServicePrincipalType != "" && sp.ServicePrincipalType != "Application" {
		return false
	}
	return sp.AccountEnabled == nil || *sp.AccountEnabled
}

type Application struct {
	ID                  string               `json:"id"`
	PasswordCredentials []PasswordCredential `json:"passwordCredentials"`
	KeyCredentials      []KeyCredential      `json:"keyCredentials"`
}

type PasswordCredential struct {
	KeyID         string `json:"keyId"`
	StartDateTime string `json:"startDateTime"`
	EndDateTime   string `json:"endDateTime"`
}

type KeyCredential struct {
	KeyID         string `json:"keyId"`
	StartDateTime string `json:"startDateTime"`
	EndDateTime   string `json:"endDateTime"`
}

type SecureScore struct {
	CurrentScore float64 `json:"currentScore"`
	MaxScore     float64 `json:"maxScore"`
}

type SignIn struct {
	ID                               string                           `json:"id"`
	CreatedDateTime                  string                           `json:"createdDateTime"`
	UserID                           string                           `json:"userId"`
	AppID                            string                           `json:"appId"`
	Status                           SignInStatus                     `json:"status"`
	ConditionalAccessStatus          string                           `json:"conditionalAccessStatus"`
	AppliedConditionalAccessPolicies []AppliedConditionalAccessPolicy `json:"appliedConditionalAccessPolicies"`
	ClientAppUsed                    string                           `json:"clientAppUsed"`
	RiskLevelAggregated              string                           `json:"riskLevelAggregated"`
	RiskLevelDuringSignIn            string                           `json:"riskLevelDuringSignIn"`
}

type SignInStatus struct {
	ErrorCode int    `json:"errorCode"`
	Reason    string `json:"failureReason"`
}

type AppliedConditionalAccessPolicy struct {
	ID     string `json:"id"`
	Result string `json:"result"`
}

type DirectoryAudit struct {
	ID                  string                `json:"id"`
	ActivityDateTime    string                `json:"activityDateTime"`
	ActivityDisplayName string                `json:"activityDisplayName"`
	Category            string                `json:"category"`
	LoggedByService     string                `json:"loggedByService"`
	OperationType       string                `json:"operationType"`
	Result              string                `json:"result"`
	TargetResources     []AuditTargetResource `json:"targetResources"`
}

type AuditTargetResource struct {
	Type string `json:"type"`
}

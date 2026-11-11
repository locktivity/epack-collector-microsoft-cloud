package microsoft

import (
	"bytes"
	"encoding/json"
	"slices"
)

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

// Disabled reports whether the user's accountEnabled is false. A user with no
// accountEnabled value is not disabled.
func (u User) Disabled() bool {
	return u.AccountEnabled != nil && !*u.AccountEnabled
}

type UserRegistrationDetail struct {
	ID                string   `json:"id"`
	UserPrincipalName string   `json:"userPrincipalName"`
	UserType          string   `json:"userType"`
	IsMFARegistered   bool     `json:"isMfaRegistered"`
	IsSSPRRegistered  bool     `json:"isSsprRegistered"`
	MethodsRegistered []string `json:"methodsRegistered"`
}

// SignInActivity holds the time of a user's last successful sign-in,
// interactive or not. Failed attempts do not change it.
type SignInActivity struct {
	LastSuccessfulSignInDateTime string `json:"lastSuccessfulSignInDateTime"`
}

type ConditionalAccessPolicy struct {
	ID            string                          `json:"id"`
	DisplayName   string                          `json:"displayName"`
	State         string                          `json:"state"`
	Conditions    ConditionalAccessConditionSet   `json:"conditions"`
	GrantControls *ConditionalAccessGrantControls `json:"grantControls"`
}

// ConditionalAccessConditionSet holds the conditions that govern when a
// policy applies. A risk level, location, platform, device or authentication
// flow condition limits a policy to the sign-ins that meet it.
// insiderRiskLevels and transferMethods each hold their flags in one
// comma-separated string. Unrecognized names the conditions Graph sent that
// this type has no field for, such as one Microsoft adds later.
// https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset
type ConditionalAccessConditionSet struct {
	Applications               *ConditionalAccessApplications        `json:"applications"`
	Users                      *ConditionalAccessUsers               `json:"users"`
	ClientAppTypes             []string                              `json:"clientAppTypes"`
	SignInRiskLevels           []string                              `json:"signInRiskLevels"`
	UserRiskLevels             []string                              `json:"userRiskLevels"`
	ServicePrincipalRiskLevels []string                              `json:"servicePrincipalRiskLevels"`
	InsiderRiskLevels          string                                `json:"insiderRiskLevels"`
	Locations                  *ConditionalAccessLocations           `json:"locations"`
	Platforms                  *ConditionalAccessPlatforms           `json:"platforms"`
	Devices                    *ConditionalAccessDevices             `json:"devices"`
	AuthenticationFlows        *ConditionalAccessAuthenticationFlows `json:"authenticationFlows"`
	ClientApplications         *ConditionalAccessClientApplications  `json:"clientApplications"`
	Unrecognized               []string                              `json:"-"`
}

// knownConditions are the conditions ConditionalAccessConditionSet reads, and
// the deprecated ones Graph still sends as null.
var knownConditions = []string{
	"@odata.type", "applications", "users", "clientAppTypes", "signInRiskLevels", "userRiskLevels",
	"servicePrincipalRiskLevels", "insiderRiskLevels", "locations", "platforms", "devices",
	"authenticationFlows", "clientApplications",
}

func (c *ConditionalAccessConditionSet) UnmarshalJSON(data []byte) error {
	type plain ConditionalAccessConditionSet
	if err := json.Unmarshal(data, (*plain)(c)); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	c.Unrecognized = nil
	for name, value := range fields {
		if !slices.Contains(knownConditions, name) && !emptyJSON(value) {
			c.Unrecognized = append(c.Unrecognized, name)
		}
	}
	slices.Sort(c.Unrecognized)
	return nil
}

// emptyJSON reports whether a value is null, or an empty string, list or
// object, which sets no condition.
func emptyJSON(value json.RawMessage) bool {
	switch string(bytes.TrimSpace(value)) {
	case "null", `""`, "[]", "{}":
		return true
	}
	return false
}

// ConditionalAccessClientApplications holds the service principals a policy
// for workload identities covers.
type ConditionalAccessClientApplications struct {
	IncludeServicePrincipals []string `json:"includeServicePrincipals"`
}

// NamedLocation is a location Conditional Access policies can name. An IP
// location says whether it is trusted. A country location never is.
// https://learn.microsoft.com/en-us/graph/api/resources/namedlocation
type NamedLocation struct {
	ODataType string `json:"@odata.type"`
	ID        string `json:"id"`
	IsTrusted bool   `json:"isTrusted"`
}

type ConditionalAccessApplications struct {
	IncludeApplications []string                 `json:"includeApplications"`
	ExcludeApplications []string                 `json:"excludeApplications"`
	ApplicationFilter   *ConditionalAccessFilter `json:"applicationFilter"`
	IncludeUserActions  []string                 `json:"includeUserActions"`
}

// ConditionalAccessLocations holds named location IDs, All or AllTrusted.
type ConditionalAccessLocations struct {
	IncludeLocations []string `json:"includeLocations"`
	ExcludeLocations []string `json:"excludeLocations"`
}

// ConditionalAccessPlatforms holds device platforms, or all.
type ConditionalAccessPlatforms struct {
	IncludePlatforms []string `json:"includePlatforms"`
	ExcludePlatforms []string `json:"excludePlatforms"`
}

type ConditionalAccessDevices struct {
	DeviceFilter *ConditionalAccessFilter `json:"deviceFilter"`
}

// ConditionalAccessFilter is a rule over device or app properties. Its mode
// is include or exclude.
type ConditionalAccessFilter struct {
	Mode string `json:"mode"`
	Rule string `json:"rule"`
}

type ConditionalAccessAuthenticationFlows struct {
	TransferMethods string `json:"transferMethods"`
}

type ConditionalAccessUsers struct {
	IncludeUsers  []string `json:"includeUsers"`
	ExcludeUsers  []string `json:"excludeUsers"`
	IncludeGroups []string `json:"includeGroups"`
	ExcludeGroups []string `json:"excludeGroups"`
	IncludeRoles  []string `json:"includeRoles"`
	ExcludeRoles  []string `json:"excludeRoles"`
}

// ConditionalAccessGrantControls are the controls a policy grants access
// with. With operator AND every control is required, and with OR one of them
// is.
type ConditionalAccessGrantControls struct {
	Operator                    string                        `json:"operator"`
	BuiltInControls             []string                      `json:"builtInControls"`
	CustomAuthenticationFactors []string                      `json:"customAuthenticationFactors"`
	TermsOfUse                  []string                      `json:"termsOfUse"`
	AuthenticationStrength      *AuthenticationStrengthPolicy `json:"authenticationStrength"`
}

// AuthenticationStrengthPolicy is the authentication strength a policy
// requires. RequirementsSatisfied is mfa when the strength grants the MFA
// claim, for a built-in or a custom strength.
type AuthenticationStrengthPolicy struct {
	ID                    string `json:"id"`
	DisplayName           string `json:"displayName"`
	PolicyType            string `json:"policyType"`
	RequirementsSatisfied string `json:"requirementsSatisfied"`
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

// UnifiedRoleDefinition is a directory role. IsPrivileged is Microsoft's
// classification, which GraphClient.RoleDefinitions sets from the filter it
// read the role with, since Graph v1.0 returns it as null.
// https://learn.microsoft.com/en-us/graph/api/resources/unifiedroledefinition
type UnifiedRoleDefinition struct {
	ID              string                  `json:"id"`
	TemplateID      string                  `json:"templateId"`
	IsPrivileged    *bool                   `json:"isPrivileged"`
	RolePermissions []UnifiedRolePermission `json:"rolePermissions"`
}

type UnifiedRolePermission struct {
	AllowedResourceActions []string `json:"allowedResourceActions"`
}

type DirectoryPrincipal struct {
	ODataType      string `json:"@odata.type"`
	ID             string `json:"id"`
	AccountEnabled *bool  `json:"accountEnabled"`
	UserType       string `json:"userType"`
}

type ServicePrincipal struct {
	ID                        string               `json:"id"`
	AppID                     string               `json:"appId"`
	AccountEnabled            *bool                `json:"accountEnabled"`
	AppRoleAssignmentRequired *bool                `json:"appRoleAssignmentRequired"`
	PreferredSingleSignOnMode string               `json:"preferredSingleSignOnMode"`
	ServicePrincipalType      string               `json:"servicePrincipalType"`
	PasswordCredentials       []PasswordCredential `json:"passwordCredentials"`
	KeyCredentials            []KeyCredential      `json:"keyCredentials"`
}

// Disabled reports whether the service principal's accountEnabled is false.
// A disabled service principal cannot get a token.
// https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/app-integration/error-code-aadsts7000112-application-is-disabled
func (sp ServicePrincipal) Disabled() bool {
	return sp.AccountEnabled != nil && !*sp.AccountEnabled
}

func (sp ServicePrincipal) EnabledEnterpriseApp() bool {
	if sp.ServicePrincipalType != "" && sp.ServicePrincipalType != "Application" {
		return false
	}
	return sp.AccountEnabled == nil || *sp.AccountEnabled
}

type Application struct {
	ID                  string               `json:"id"`
	AppID               string               `json:"appId"`
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

package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

type GraphAPI interface {
	Organization(context.Context) (*microsoft.Organization, error)
	Users(context.Context) ([]microsoft.User, error)
	UsersWithSignInActivity(context.Context) ([]microsoft.User, error)
	UserRegistrationDetails(context.Context) ([]microsoft.UserRegistrationDetail, error)
	ConditionalAccessPolicies(context.Context) ([]microsoft.ConditionalAccessPolicy, error)
	SecurityDefaults(context.Context) (*microsoft.IdentitySecurityDefaultsEnforcementPolicy, error)
	RoleAssignments(context.Context) ([]microsoft.UnifiedRoleAssignment, error)
	RoleDefinitions(context.Context) ([]microsoft.UnifiedRoleDefinition, error)
	NamedLocations(context.Context) ([]microsoft.NamedLocation, error)
	RoleEligibilitySchedules(context.Context) ([]microsoft.UnifiedRoleEligibilitySchedule, error)
	ServicePrincipals(context.Context) ([]microsoft.ServicePrincipal, error)
	Applications(context.Context) ([]microsoft.Application, error)
	SecureScores(context.Context) ([]microsoft.SecureScore, error)
	SignIns(context.Context, time.Time) ([]microsoft.SignIn, error)
	DirectoryAudits(context.Context, time.Time) ([]microsoft.DirectoryAudit, error)
}

type ARMAPI interface {
	Subscription(context.Context, string) (*microsoft.Subscription, error)
	Resources(context.Context, string) ([]microsoft.ARMResource, error)
	DefenderSecureScore(context.Context, string) (*microsoft.ARMSecureScore, error)
	DefenderAssessments(context.Context, string) ([]microsoft.SecurityAssessment, error)
	RoleAssignments(context.Context, string) ([]microsoft.ARMRoleAssignment, error)
	PolicyAssignments(context.Context, string) ([]microsoft.PolicyAssignment, error)
	PolicyStateSummary(context.Context, string) (*microsoft.PolicyStateSummaryResult, error)
	StorageAccounts(context.Context, string) ([]microsoft.StorageAccount, error)
	KeyVaults(context.Context, string) ([]microsoft.KeyVault, error)
	SQLServers(context.Context, string) ([]microsoft.SQLServer, error)
	SQLDatabases(context.Context, string) ([]microsoft.SQLDatabase, error)
	SQLTransparentDataEncryption(context.Context, string) (*microsoft.SQLTransparentDataEncryption, error)
	VirtualMachines(context.Context, string) ([]microsoft.VirtualMachine, error)
	PublicIPAddresses(context.Context, string) ([]microsoft.PublicIPAddress, error)
	NetworkSecurityGroups(context.Context, string) ([]microsoft.NetworkSecurityGroup, error)
	DiagnosticSettings(context.Context, string) ([]microsoft.DiagnosticSetting, error)
	SubscriptionDiagnosticSettings(context.Context, string) ([]microsoft.DiagnosticSetting, error)
	RecoveryServicesVaults(context.Context, string) ([]microsoft.RecoveryServicesVault, error)
	BackupProtectedItems(context.Context, string) ([]microsoft.BackupProtectedItem, error)
	BackupPolicies(context.Context, string) ([]microsoft.BackupPolicy, error)
	BackupJobs(context.Context, string, string) ([]microsoft.BackupJob, error)
}

type Collector struct {
	config Config
	graph  GraphAPI
	arm    ARMAPI
	clock  Clock
	gaps   *gapLog

	graphToken *microsoft.TokenSource
	armToken   *microsoft.TokenSource
}

func New(config Config) (*Collector, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	c := &Collector{config: config, clock: config.Clock, gaps: newGapLog(config.Recorder)}
	if c.clock == nil {
		c.clock = realClock{}
	}
	if config.GraphClient != nil {
		c.graph = config.GraphClient
	} else {
		tokenSource, err := config.tokenSource(microsoft.GraphScope)
		if err != nil {
			return nil, err
		}
		c.graphToken = tokenSource
		c.graph = config.graphClient(tokenSource)
	}
	if config.ARMClient != nil {
		c.arm = config.ARMClient
	} else {
		tokenSource, err := config.tokenSource(microsoft.ARMScope)
		if err != nil {
			return nil, err
		}
		c.armToken = tokenSource
		c.arm = config.armClient(tokenSource)
	}
	return c, nil
}

// Collect returns an error only when sign-in fails. Any value it cannot read
// after that is left out of the artifacts and recorded as a gap.
func (c *Collector) Collect(ctx context.Context, level componentsdk.Level) (*Result, error) {
	if c.config.OnStatus != nil {
		c.config.OnStatus("Collecting Entra tenant posture")
	}
	org, err := c.signIn(ctx)
	if err != nil {
		return nil, err
	}

	diagnostics := NewDiagnostics()
	entra := c.collectEntra(ctx, level, org, &diagnostics)
	azure := c.collectAzure(ctx, level, &diagnostics)
	entra.Diagnostics = diagnostics
	azure.Diagnostics = diagnostics

	result := &Result{
		Entra:       entra,
		Azure:       azure,
		Diagnostics: diagnostics,
	}
	result.EntraIDPPosture = entra.ToIDPPosture()
	if result.EntraIDPPosture != nil {
		c.markUnlistedMembers(entra, idpPosturePath, "/user_security/mfa_coverage_pct", "/user_security/mfa_phishing_resistant_pct")
		if level.AtLeast(componentsdk.LevelAudit) {
			c.markUnlistedMembers(entra, idpPosturePath, "/user_security/mfa_user_count", "/user_security/phishing_resistant_user_count")
		}
		c.markPartlyListedMembers(entra, level)
		c.markIDPPostureUnsupported(level)
		c.mirrorIDPPostureGaps(result.EntraIDPPosture)
	}
	result.AzureCloudPosture = azure.ToCloudPosture()
	c.mirrorCloudPostureGaps(azure)
	c.addDeprecatedIAM(result.AzureCloudPosture, entra)
	result.AzureAccessPosture = c.accessPosture(level, azure, entra)
	return result, nil
}

// signIn acquires both access tokens and looks up the organization. These
// are the only calls whose failure fails the run.
func (c *Collector) signIn(ctx context.Context) (*microsoft.Organization, error) {
	if c.graphToken != nil {
		if _, err := c.graphToken.AccessToken(ctx); err != nil {
			return nil, fmt.Errorf("signing in to Microsoft Graph: %w", err)
		}
		c.gaps.rec.SignedInAs(componentsdk.Principal{
			Provider: "microsoft-entra",
			Kind:     "service_principal",
			TenantID: c.config.TenantID,
			Scopes:   c.graphToken.Roles(),
			ID:       c.config.ClientID,
		})
	}
	if c.armToken != nil {
		if _, err := c.armToken.AccessToken(ctx); err != nil {
			return nil, fmt.Errorf("signing in to Azure Resource Manager: %w", err)
		}
	}
	org, err := c.graph.Organization(ctx)
	if err != nil {
		return nil, fmt.Errorf("looking up the organization: %w", err)
	}
	return org, nil
}

func (r *Result) Artifacts() []componentsdk.CollectedArtifact {
	if r == nil {
		return nil
	}
	artifacts := []componentsdk.CollectedArtifact{}
	if r.Entra != nil {
		artifacts = append(artifacts, componentsdk.CollectedArtifact{Data: r.Entra, Schema: entraSchema, Path: entraPath})
	}
	if r.EntraIDPPosture != nil {
		artifacts = append(artifacts, componentsdk.CollectedArtifact{Data: r.EntraIDPPosture, Schema: idpPostureSchema, Path: idpPosturePath})
	}
	if r.Azure != nil {
		artifacts = append(artifacts, componentsdk.CollectedArtifact{Data: r.Azure, Schema: azureSchema, Path: azurePath})
	}
	if r.AzureCloudPosture != nil {
		artifacts = append(artifacts, componentsdk.CollectedArtifact{Data: r.AzureCloudPosture, Schema: cloudPostureSchema, Path: cloudPosturePath})
	}
	if r.AzureAccessPosture != nil {
		artifacts = append(artifacts, componentsdk.CollectedArtifact{Data: r.AzureAccessPosture, Schema: accessPostureSchema, Path: accessPosturePath})
	}
	return artifacts
}

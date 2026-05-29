package collector

import (
	"context"
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
}

func New(config Config) (*Collector, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	graph, err := config.graphClient()
	if err != nil {
		return nil, err
	}
	arm, err := config.armClient()
	if err != nil {
		return nil, err
	}
	clock := config.Clock
	if clock == nil {
		clock = realClock{}
	}
	return &Collector{config: config, graph: graph, arm: arm, clock: clock}, nil
}

func (c *Collector) Collect(ctx context.Context, level componentsdk.Level) (*Result, error) {
	if c.config.OnStatus != nil {
		c.config.OnStatus("Collecting Entra tenant posture")
	}

	diagnostics := NewDiagnostics()
	entra, err := c.collectEntra(ctx, level, &diagnostics)
	if err != nil {
		return nil, err
	}

	result := &Result{
		Entra:       entra,
		Diagnostics: diagnostics,
	}
	result.EntraIDPPosture = entra.ToIDPPosture()
	azure, err := c.collectAzure(ctx, level, &diagnostics)
	if err != nil {
		return nil, err
	}
	result.Diagnostics = diagnostics
	result.Entra.Diagnostics = diagnostics
	result.Azure = azure
	result.AzureCloudPosture = azure.ToCloudPosture(entra)
	return result, nil
}

func (r *Result) Artifacts() []componentsdk.CollectedArtifact {
	if r == nil {
		return nil
	}
	artifacts := []componentsdk.CollectedArtifact{}
	if r.Entra != nil {
		artifacts = append(artifacts, componentsdk.CollectedArtifact{
			Data: r.Entra,
			Path: "artifacts/microsoft-cloud.entra.json",
		})
	}
	if r.EntraIDPPosture != nil {
		artifacts = append(artifacts, componentsdk.CollectedArtifact{
			Data:   r.EntraIDPPosture,
			Schema: "evidencepack/idp-posture@v1",
			Path:   "artifacts/microsoft-cloud.idp-posture.json",
		})
	}
	if r.Azure != nil {
		artifacts = append(artifacts, componentsdk.CollectedArtifact{
			Data: r.Azure,
			Path: "artifacts/microsoft-cloud.azure.json",
		})
	}
	if r.AzureCloudPosture != nil {
		artifacts = append(artifacts, componentsdk.CollectedArtifact{
			Data:   r.AzureCloudPosture,
			Schema: "evidencepack/cloud-posture@v1",
			Path:   "artifacts/microsoft-cloud.cloud-posture.json",
		})
	}
	return artifacts
}

package collector

import (
	"time"

	"github.com/locktivity/epack-collector-microsoft-cloud/docs/schema"
	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

// Spec describes the collector to componentsdk.RunCollector.
func Spec(version, commit string) componentsdk.CollectorSpec {
	return componentsdk.CollectorSpec{
		Name:        collectorName,
		Version:     version,
		Commit:      commit,
		Description: "Collects Microsoft Entra ID and Azure security posture metrics",
		Timeout:     30 * time.Minute,
		Schemas:     schema.Schemas(entraSchema, azureSchema),
		Methods:     schema.Methods(),
		TraceMap:    schema.TraceMap,
		Writes:      []string{entraSchema, idpPostureSchema, azureSchema, cloudPostureSchema, accessPostureSchema},
	}
}

// Run is the collector's handler. It fails only for invalid configuration or
// a failed sign-in, and otherwise emits what it collected with a gap recorded
// for each value it could not read.
func Run(ctx componentsdk.CollectorContext) error {
	cfg := ctx.Config()
	config := Config{
		TenantID:           getString(cfg, "tenant_id"),
		ClientID:           getString(cfg, "client_id"),
		AuthMode:           getString(cfg, "auth_mode"),
		SubscriptionIDs:    getStringSlice(cfg, "subscription_ids"),
		AzureEnvironment:   getString(cfg, "azure_environment"),
		ClientSecret:       ctx.Secret("AZURE_CLIENT_SECRET"),
		OIDCRequestURL:     ctx.Secret("ACTIONS_ID_TOKEN_REQUEST_URL"),
		OIDCRequestToken:   ctx.Secret("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
		FederatedTokenFile: ctx.Secret(microsoft.FederatedTokenFileEnv),
		Recorder:           componentsdk.Records(ctx),
		OnStatus:           ctx.Status,
		OnProgress:         ctx.Progress,
		Clock:              runClock{ctx: ctx},
	}
	if err := config.Validate(); err != nil {
		return err
	}
	config.HTTPClient = componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{
		CredentialHosts: config.CredentialHosts(),
		TemplateRoute:   microsoft.TemplateRoute,
	})

	c, err := New(config)
	if err != nil {
		return err
	}
	result, err := c.Collect(ctx.Context(), ctx.Level())
	if err != nil {
		return err
	}
	declareTargets(config.Recorder)
	return ctx.Emit(result.Artifacts())
}

// declareTargets declares the tenant the run signed in to, which the Entra
// artifact describes, named by its ID and labelled by its default domain,
// and the subscriptions it was configured for. Every configured subscription
// keeps its entry, so one the collector can't read leaves the subscriptions
// incomplete.
func declareTargets(rec *componentsdk.Recorder) {
	rec.Targets(componentsdk.TargetTenant, componentsdk.Location{Path: entraPath, Pointer: ""}, "/tenant_id").
		ChosenBy(componentsdk.ChosenByConfig, "tenant_id").
		Label("/org_domain")
	rec.Targets(componentsdk.TargetSubscription, componentsdk.Location{Path: azurePath, Pointer: "/accounts"}, "/account_id").
		ChosenBy(componentsdk.ChosenByConfig, "subscription_ids")
}

// runClock reads the run's clock, which tests pin.
type runClock struct {
	ctx componentsdk.CollectorContext
}

func (c runClock) Now() time.Time { return componentsdk.Now(c.ctx).UTC() }

func getString(cfg map[string]any, key string) string {
	if cfg == nil {
		return ""
	}
	if v, ok := cfg[key].(string); ok {
		return v
	}
	return ""
}

func getStringSlice(cfg map[string]any, key string) []string {
	if cfg == nil {
		return nil
	}

	raw, ok := cfg[key].([]any)
	if !ok {
		return nil
	}

	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

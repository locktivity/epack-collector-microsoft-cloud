package collector

import (
	"slices"
	"testing"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// targetsRun runs the collector at level over subscriptions and returns its
// target declarations by kind. It fails t when the run fails, when a kind is
// declared twice, or when the artifacts don't bear a declaration out.
func targetsRun(t *testing.T, level string, responses []collectortest.Response, subscriptions ...any) map[componentsdk.TargetKind]componentsdk.ResultTarget {
	t.Helper()
	config := kitConfig()
	config["level"] = level
	config["subscription_ids"] = subscriptions
	res := runInProcess(t, config, kitSecrets(), responses)
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, f := range res.Result.Checks {
		if f.Check == componentsdk.CheckTargets {
			t.Errorf("targets finding %+v", f)
		}
	}
	out := map[componentsdk.TargetKind]componentsdk.ResultTarget{}
	for _, d := range res.Result.Targets {
		if _, ok := out[d.Kind]; ok {
			t.Errorf("%s targets are declared twice", d.Kind)
		}
		out[d.Kind] = d
	}
	if len(out) != 2 {
		t.Fatalf("targets = %+v, want the tenant and subscriptions", res.Result.Targets)
	}
	return out
}

var (
	tenantAt        = componentsdk.Location{Schema: entraSchema, Path: entraPath, Pointer: ""}
	subscriptionsAt = componentsdk.Location{Schema: azureSchema, Path: azurePath, Pointer: "/accounts"}
)

func countIs(n *int, want int) bool { return n != nil && *n == want }

func completeIs(b *bool, want bool) bool { return b != nil && *b == want }

// An audit run declares the configured tenant and subscription, each counted
// and complete.
func TestTargetsAtAudit(t *testing.T) {
	got := targetsRun(t, "audit", kitResponses(), kitSubscriptionID)

	tenant := got[componentsdk.TargetTenant]
	if tenant.ChosenBy != componentsdk.ChosenByConfig || tenant.ConfigKey != "tenant_id" {
		t.Errorf("tenant chosen by %q with %q, want %q with tenant_id", tenant.ChosenBy, tenant.ConfigKey, componentsdk.ChosenByConfig)
	}
	if tenant.At == nil || *tenant.At != tenantAt || !slices.Equal(tenant.Name, []string{"/tenant_id"}) || tenant.Label != "/org_domain" {
		t.Errorf("tenant at %+v named by %q with label %q, want %+v named by /tenant_id with /org_domain", tenant.At, tenant.Name, tenant.Label, tenantAt)
	}
	if !countIs(tenant.Count, 1) || !completeIs(tenant.Complete, true) {
		t.Errorf("tenant count %v, complete %v; want 1 and true", tenant.Count, tenant.Complete)
	}

	subscriptions := got[componentsdk.TargetSubscription]
	if subscriptions.ChosenBy != componentsdk.ChosenByConfig || subscriptions.ConfigKey != "subscription_ids" {
		t.Errorf("subscriptions chosen by %q with %q, want %q with subscription_ids", subscriptions.ChosenBy, subscriptions.ConfigKey, componentsdk.ChosenByConfig)
	}
	if subscriptions.At == nil || *subscriptions.At != subscriptionsAt || !slices.Equal(subscriptions.Name, []string{"/account_id"}) || subscriptions.Label != "" {
		t.Errorf("subscriptions at %+v named by %q with label %q, want %+v named by /account_id", subscriptions.At, subscriptions.Name, subscriptions.Label, subscriptionsAt)
	}
	if !countIs(subscriptions.Count, 1) || !completeIs(subscriptions.Complete, true) {
		t.Errorf("subscriptions count %v, complete %v; want 1 and true", subscriptions.Count, subscriptions.Complete)
	}
}

// A trust run writes no tenant ID, so the tenant is known by its domain
// alone. The tenant and subscriptions keep where they sit and whether they
// are complete, without a count.
func TestTargetsAtTrust(t *testing.T) {
	got := targetsRun(t, "trust", kitResponses(), kitSubscriptionID)

	tenant := got[componentsdk.TargetTenant]
	if tenant.At == nil || *tenant.At != tenantAt || tenant.Label != "/org_domain" || tenant.Count != nil || !completeIs(tenant.Complete, true) {
		t.Errorf("tenant = %+v at trust, want it at %+v with its domain label, uncounted and complete", tenant, tenantAt)
	}

	subscriptions := got[componentsdk.TargetSubscription]
	if subscriptions.At == nil || *subscriptions.At != subscriptionsAt || subscriptions.Count != nil || !completeIs(subscriptions.Complete, true) {
		t.Errorf("subscriptions = %+v at trust, want them at %+v, uncounted and complete", subscriptions, subscriptionsAt)
	}
}

// A subscription ARM refuses keeps its entry, so both subscriptions are
// declared and they are incomplete at every level.
func TestTargetsWithARefusedSubscription(t *testing.T) {
	responses := append(kitResponses(), refusedSubscriptionResponse())
	for _, level := range []string{"audit", "trust"} {
		t.Run(level, func(t *testing.T) {
			got := targetsRun(t, level, responses, kitSubscriptionID, kitRefusedSubscriptionID)
			subscriptions := got[componentsdk.TargetSubscription]
			if !completeIs(subscriptions.Complete, false) {
				t.Errorf("subscriptions complete %v, want false with a refused subscription", subscriptions.Complete)
			}
			if level == "audit" && !countIs(subscriptions.Count, 2) {
				t.Errorf("subscriptions count %v, want 2", subscriptions.Count)
			}
			if tenant := got[componentsdk.TargetTenant]; level == "audit" && !completeIs(tenant.Complete, true) {
				t.Errorf("tenant complete %v, want true", tenant.Complete)
			}
		})
	}
}

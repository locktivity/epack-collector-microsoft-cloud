//go:build record

package collector

import (
	"maps"
	"net/url"
	"os"
	"slices"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// TestRecord records a sandbox, a Microsoft tenant and subscription kept
// with known settings, to testdata/recordings/microsoft-cloud.json, which
// TestSimulatorMatchesRecording compares with the Entra simulator. It signs
// in as a GitHub Actions job does, trading the job's identity token for a
// token of the epack-sandbox-collector app. It reads the tenant, the app's
// client ID, and the subscription from SANDBOX_MICROSOFT_TENANT_ID,
// SANDBOX_MICROSOFT_COLLECTOR_CLIENT_ID, and
// SANDBOX_MICROSOFT_SUBSCRIPTION_ID, the tenant's initial domain from
// SANDBOX_MICROSOFT_DOMAIN, the tenant creator's display name from
// SANDBOX_MICROSOFT_CREATOR_NAME, and the token request's URL and bearer
// token from ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN,
// which a job with id-token: write gets. It skips when any is not set. The
// tenant, app, subscription, and domain become the kit's, the value of any
// other SANDBOX_ variable becomes a stable fake, and Record writes nothing if
// one remains. The role template IDs the collector compares against and the
// built-in authentication strengths' IDs stay as they are:
//
//	SANDBOX_MICROSOFT_TENANT_ID=... SANDBOX_MICROSOFT_COLLECTOR_CLIENT_ID=... \
//	SANDBOX_MICROSOFT_SUBSCRIPTION_ID=... SANDBOX_MICROSOFT_DOMAIN=... SANDBOX_MICROSOFT_CREATOR_NAME=... \
//	go test -tags record -run 'TestRecord/^microsoft-cloud$' -count=1 ./internal/collector/
func TestRecord(t *testing.T) {
	t.Run("microsoft-cloud", func(t *testing.T) {
		vars := []string{"SANDBOX_MICROSOFT_TENANT_ID", "SANDBOX_MICROSOFT_COLLECTOR_CLIENT_ID", "SANDBOX_MICROSOFT_SUBSCRIPTION_ID",
			"SANDBOX_MICROSOFT_DOMAIN", "SANDBOX_MICROSOFT_CREATOR_NAME", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"}
		for _, name := range vars {
			if os.Getenv(name) == "" {
				t.Skipf("set %v to record", vars)
			}
		}
		requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
		requested, err := url.Parse(requestURL)
		if err != nil {
			t.Fatalf("ACTIONS_ID_TOKEN_REQUEST_URL: %v", err)
		}
		kit, err := url.Parse(kitGitHubTokenURL)
		if err != nil {
			t.Fatal(err)
		}
		report, err := collectortest.Record(collectortest.RecordOptions{
			Spec: Spec("record", "collectortest"),
			Run:  Run,
			Config: map[string]any{
				"tenant_id":        os.Getenv("SANDBOX_MICROSOFT_TENANT_ID"),
				"client_id":        os.Getenv("SANDBOX_MICROSOFT_COLLECTOR_CLIENT_ID"),
				"auth_mode":        "oidc",
				"subscription_ids": []any{os.Getenv("SANDBOX_MICROSOFT_SUBSCRIPTION_ID")},
				"level":            "audit",
			},
			Secrets: map[string]string{
				"ACTIONS_ID_TOKEN_REQUEST_URL":   requestURL,
				"ACTIONS_ID_TOKEN_REQUEST_TOKEN": os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
			},
			Out: "testdata/recordings/microsoft-cloud.json",
			Scrub: collectortest.ScrubRules{
				Identifiers: collectortest.EnvIdentifiers("SANDBOX_", map[string]string{
					"SANDBOX_MICROSOFT_TENANT_ID":           kitTenantID,
					"SANDBOX_MICROSOFT_COLLECTOR_CLIENT_ID": kitClientID,
					"SANDBOX_MICROSOFT_SUBSCRIPTION_ID":     kitSubscriptionID,
					"SANDBOX_MICROSOFT_DOMAIN":              kitDomain,
				}),
				Literals: map[string]string{requested.Host: kit.Host, requested.Path: kit.Path},
				Patterns: recordScrubPatterns,
				Keep: append(slices.Sorted(maps.Keys(testRoles)),
					"00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000003", "00000000-0000-0000-0000-000000000004"),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if report.ExitCode != 0 {
			t.Errorf("the recorded run exited %d: %+v", report.ExitCode, report.Failure)
		}
		t.Logf("recorded %d responses", report.Responses)
	})
}

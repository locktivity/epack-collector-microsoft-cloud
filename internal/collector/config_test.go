package collector

import (
	"errors"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func TestConfig(t *testing.T) {
	valid := testConfig()
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid config: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing tenant", func(c *Config) { c.TenantID = "" }},
		{"tenant common", func(c *Config) { c.TenantID = "common" }},
		{"tenant organizations", func(c *Config) { c.TenantID = "organizations" }},
		{"bad tenant", func(c *Config) { c.TenantID = "not-a-guid" }},
		{"missing client", func(c *Config) { c.ClientID = "" }},
		{"bad auth", func(c *Config) { c.AuthMode = "delegated" }},
		{"missing subscriptions", func(c *Config) { c.SubscriptionIDs = nil }},
		{"bad subscription", func(c *Config) { c.SubscriptionIDs = []string{"not-a-guid"} }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("expected error")
			}
			var configErr componentsdk.ConfigError
			if !errors.As(err, &configErr) {
				t.Fatalf("expected componentsdk.ConfigError, got %T", err)
			}
		})
	}
}

func testConfig() Config {
	return Config{
		TenantID:        "72f988bf-86f1-41af-91ab-2d7cd011db47",
		ClientID:        "11111111-2222-3333-4444-555555555555",
		AuthMode:        "client_secret",
		SubscriptionIDs: []string{"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		ClientSecret:    "secret",
		GraphClient:     fakeGraphClient(),
		ARMClient:       fakeARMClient(),
	}
}

package microsoft

import "testing"

func TestARMToken(t *testing.T) {
	if err := validateAppOnlyToken(signedJWT(map[string]any{
		"tid": testTenantID,
		"oid": "service-principal-object-id",
	}), testTenantID, ARMScope); err != nil {
		t.Fatalf("expected ARM token without app roles to be accepted: %v", err)
	}

	if err := validateAppOnlyToken(signedJWT(map[string]any{
		"tid": testTenantID,
		"scp": "user_impersonation",
	}), testTenantID, ARMScope); err == nil {
		t.Fatal("expected delegated ARM token to be rejected")
	}
}

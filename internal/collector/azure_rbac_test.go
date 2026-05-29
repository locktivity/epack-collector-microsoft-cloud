package collector

import "testing"

func TestOwnerCounts(t *testing.T) {
	artifact := collectTestAzureArtifact(t, testConfig())
	if artifact.Accounts[0].RBAC == nil {
		t.Fatal("expected RBAC metrics")
	}
	if artifact.Accounts[0].RBAC.OwnerCount != 2 {
		t.Fatalf("expected two owners, got %d", artifact.Accounts[0].RBAC.OwnerCount)
	}
	if artifact.Accounts[0].RBAC.OwnerServicePrincipalCount != 1 {
		t.Fatalf("expected one service-principal owner, got %d", artifact.Accounts[0].RBAC.OwnerServicePrincipalCount)
	}
}

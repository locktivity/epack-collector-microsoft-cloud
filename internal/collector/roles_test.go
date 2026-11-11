package collector

import (
	"maps"
	"slices"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

// testRoles are built-in directory roles by template ID, as Microsoft's
// permissions reference lists them: whether Microsoft labels each one
// privileged, and whether every directory action it allows only reads.
// https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
var testRoles = map[string]struct {
	name                 string
	privileged, readOnly bool
}{
	globalAdministratorTemplateID:          {"Global Administrator", true, false},
	"e8611ab8-c189-46e8-94e1-60213ab1f814": {"Privileged Role Administrator", true, false},
	"194ae4cb-b126-40b2-bd5b-6091b380977d": {"Security Administrator", true, false},
	"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": {"Application Administrator", true, false},
	"fe930be7-5e62-47db-91af-98c3a49a38b1": {"User Administrator", true, false},
	"729827e3-9c14-49f7-bb1b-9608f156bbb8": {"Helpdesk Administrator", true, false},
	"8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": {"Hybrid Identity Administrator", true, false},
	"e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8": {"Partner Tier2 Support", true, false},
	"966707d0-3269-4727-9be2-8c3a10f19b9d": {"Password Administrator", true, false},
	"3a2c62db-5318-420d-8d74-23affee5d9d5": {"Intune Administrator", true, false},
	"f2ef992c-3afb-46b9-b7cf-a126ee74c451": {"Global Reader", true, true},
	"5d6b6bb7-de71-4623-b4af-96380a352509": {"Security Reader", true, true},
	"29232cdf-9323-42fd-ade2-1d097af3e4de": {"Exchange Administrator", false, false},
	"f28a1f50-f6e7-4571-818b-6a12f2af6b6c": {"SharePoint Administrator", false, false},
	"88d8e3e3-8f55-4a1e-953a-9b9898b8876b": {"Directory Readers", false, true},
}

// testRoleDefinitions are the role definitions Microsoft Graph lists for
// testRoles, each with one sample action: a write for a role that changes
// something, and a read, or Global Reader's restrictedRead, for one that
// doesn't.
func testRoleDefinitions() []microsoft.UnifiedRoleDefinition {
	var out []microsoft.UnifiedRoleDefinition
	for _, id := range slices.Sorted(maps.Keys(testRoles)) {
		role := testRoles[id]
		action := "microsoft.directory/users/basic/update"
		if role.readOnly {
			action = "microsoft.directory/users/authenticationMethods/standard/restrictedRead"
		}
		out = append(out, roleDefinition(id, &role.privileged, action))
	}
	return append(out, roleDefinition("not-privileged", new(bool), "microsoft.directory/users/basic/update"))
}

func roleDefinition(id string, privileged *bool, actions ...string) microsoft.UnifiedRoleDefinition {
	return microsoft.UnifiedRoleDefinition{
		ID: id, TemplateID: id, IsPrivileged: privileged,
		RolePermissions: []microsoft.UnifiedRolePermission{{AllowedResourceActions: actions}},
	}
}

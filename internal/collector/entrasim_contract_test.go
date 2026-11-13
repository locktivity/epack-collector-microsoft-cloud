package collector

import (
	"cmp"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
)

// simRecording is the sandbox's recording, which TestRecord writes and the
// sandboxes repository's refresh workflow proposes again each month.
const simRecording = "testdata/recordings/microsoft-cloud.json"

// simContractOptions line the simulator's Graph answers up with the
// recording's. The vocabulary fields are those whose spelling the simulator
// makes up from Microsoft's documentation: enums, method and control names,
// and the well-known IDs the collector compares against.
var simContractOptions = collectortest.CompareOptions{
	Items:  "value",
	Ignore: []string{"@odata.nextLink"},
	Vocabulary: []string{
		"value[].userType",
		"value[].methodsRegistered[]",
		"value[].systemPreferredAuthenticationMethods[]",
		"value[].userPreferredMethodForSecondaryAuthentication",
		"value[].state",
		"value[].conditions.clientAppTypes[]",
		"value[].conditions.applications.includeApplications[]",
		"value[].grantControls.operator",
		"value[].grantControls.builtInControls[]",
		"value[].grantControls.authenticationStrength.id",
		"value[].grantControls.authenticationStrength.requirementsSatisfied",
		"value[].grantControls.authenticationStrength.allowedCombinations[]",
		"value[].principal.@odata.type",
		"value[].directoryScopeId",
		"value[].roleDefinitionId",
		"value[].status",
		"value[].memberType",
		"value[].servicePrincipalType",
		"value[].preferredSingleSignOnMode",
		"value[].verifiedDomains[].type",
		"value[].keyCredentials[].type",
		"value[].keyCredentials[].usage",
		"error.code",
	},
}

// simContractKnown lists the ways the simulator is known to differ from
// the recording, as each difference's String, with why it is left.
var simContractKnown = map[string]string{
	"GET graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails: count (recorded 0, simulated 8)":                                                                                                                       "Microsoft hasn't built the sandbox tenant's registration report yet, so Graph lists no one.",
	"GET graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails value[]: extra (recorded nothing, simulated object)":                                                                                                    "Microsoft hasn't built the sandbox tenant's registration report yet, so Graph lists no one.",
	"GET graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$filter=isPrivileged eq false&$select=id,templateId,isPrivileged,rolePermissions value[]: missing (recorded object, simulated nothing)":                              "The roster names no role Microsoft leaves unprivileged.",
	"GET graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$filter=isPrivileged eq true&$select=id,templateId,isPrivileged,rolePermissions value[].rolePermissions[].condition: type (recorded null or string, simulated null)": "Only built-in roles the roster doesn't name scope a permission with a condition.",
}

// simContractUncounted lists the calls whose item counts are left out of
// the comparison, with why. Their lists hold Microsoft's own entries, whose
// number Microsoft decides, besides the roster's.
var simContractUncounted = map[string]string{
	"GET graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$filter=isPrivileged eq true&$select=id,templateId,isPrivileged,rolePermissions":                                                                                             "Graph lists every built-in role, and the simulator the roles the roster names.",
	"GET graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$filter=isPrivileged eq false&$select=id,templateId,isPrivileged,rolePermissions":                                                                                            "Graph lists every built-in role, and the simulator the roles the roster names.",
	"GET graph.microsoft.com/v1.0/servicePrincipals?$filter=servicePrincipalType eq 'Application'&$select=id,appId,accountEnabled,appRoleAssignmentRequired,preferredSingleSignOnMode,servicePrincipalType,passwordCredentials,keyCredentials&$top=999": "Graph lists Microsoft's own enterprise apps besides the sandbox's four.",
	"GET graph.microsoft.com/v1.0/security/secureScores?$top=1": "The collector follows nextLink through a score for each day, and the simulator answers one.",
}

// TestSimulatorMatchesRecording compares the simulator's answers for the
// sandbox roster with a recording of the sandbox, so the simulator cannot
// drift from Graph unseen: a field, type, value, or count it gets wrong
// fails here, in the pull request that brings a new recording. Values are
// compared only for the vocabulary fields, so the roster's unsettled
// attributes need not be settled first. A call only the simulator answers
// is left out, since it answers the calls of every level and the sandbox
// records at audit. The roster's unsettled attributes all hold in the
// realization compared, so the sign-ins the sandbox records have a shape to
// compare with. ENTRA_SIM_RECORDING names another recording to compare.
func TestSimulatorMatchesRecording(t *testing.T) {
	path := cmp.Or(os.Getenv("ENTRA_SIM_RECORDING"), simRecording)
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		t.Skipf("no recording at %s; TestRecord/microsoft-cloud writes one", path)
	}
	scenario, err := collectortest.LoadScenario(path)
	if err != nil {
		t.Fatal(err)
	}
	recordedAt := recordingTime(t, path)
	r, err := roster.Load("testdata/simulator/microsoft-cloud.roster.json")
	if err != nil {
		t.Fatal(err)
	}
	realizations, err := r.Realizations()
	if err != nil {
		t.Fatal(err)
	}
	sim, err := newEntraSim(realizations[len(realizations)-1].Roster, recordedAt)
	if err != nil {
		t.Fatal(err)
	}
	diffs := collectortest.CompareResponses(graphResponses(scenario.Responses), graphResponses(sim.responses()), simContractOptions)
	uncounted := map[string]bool{}
	diffs = slices.DeleteFunc(diffs, func(d collectortest.ResponseDifference) bool {
		if _, ok := simContractUncounted[d.Call]; ok && d.Kind == collectortest.CountDiffers {
			uncounted[d.Call] = true
			return true
		}
		return d.Kind == collectortest.OnlySimulated
	})
	for _, call := range slices.Sorted(maps.Keys(simContractUncounted)) {
		if !uncounted[call] {
			t.Errorf("listed as uncounted, but the simulator and the recording now hold as many items: %s", call)
		}
	}
	seen := map[string]bool{}
	for _, d := range diffs {
		seen[d.String()] = true
		if why, known := simContractKnown[d.String()]; known {
			t.Logf("known: %s (%s)", d, why)
			continue
		}
		t.Errorf("%s", d)
	}
	for _, d := range slices.Sorted(maps.Keys(simContractKnown)) {
		if !seen[d] {
			t.Errorf("listed as known, but the simulator now matches the recording: %s", d)
		}
	}
}

func recordingTime(t *testing.T, path string) time.Time {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var head struct {
		RecordedAt time.Time `json:"recorded_at"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		t.Fatal(err)
	}
	return cmp.Or(head.RecordedAt, goldenTime)
}

// graphResponses keeps the answers from Microsoft Graph. The simulator's
// sign-in is the kit's and its Resource Manager answers are empty.
func graphResponses(responses []collectortest.Response) []collectortest.Response {
	return slices.DeleteFunc(slices.Clone(responses), func(r collectortest.Response) bool {
		u, err := url.Parse(r.URL)
		return err != nil || !strings.EqualFold(u.Host, "graph.microsoft.com")
	})
}

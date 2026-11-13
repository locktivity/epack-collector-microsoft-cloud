package collector

import (
	"regexp"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// kitDomain is the tenant's initial domain in recordings and the
// simulator.
const kitDomain = "example0000.onmicrosoft.com"

// recordScrubPatterns remove what the kit's built-in rules miss and a public
// repository must not hold. A guest's user name keeps the address it was
// invited with, as first.last_outlook.com#EXT#, where the underscore stands
// for the @ the email rule looks for. A user's phone numbers come from the
// profile of the account behind it, such as the tenant creator's personal
// Microsoft account.
var recordScrubPatterns = []collectortest.ScrubPattern{
	{Pattern: regexp.MustCompile(`[A-Za-z0-9._%+-]+_[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}#EXT#`), Replace: "guest_example.com#EXT#"},
	{Pattern: regexp.MustCompile(`"businessPhones"\s*:\s*\["[^\]]*\]`), Replace: `"businessPhones":["555-0100"]`},
	{Pattern: regexp.MustCompile(`"mobilePhone"\s*:\s*"[^"]*"`), Replace: `"mobilePhone":"555-0100"`},
}

func TestRecordScrubPatterns(t *testing.T) {
	in := `{"businessPhones":["+1 206 555 0182","206 555 0199"],"mobilePhone":"+1 206 555 0173",` +
		`"userPrincipalName":"pat.lee_outlook.com#EXT#@` + kitDomain + `","mail":null},{"businessPhones":[],"mobilePhone":null}`
	for _, p := range recordScrubPatterns {
		in = p.Pattern.ReplaceAllString(in, p.Replace)
	}
	if want := `{"businessPhones":["555-0100"],"mobilePhone":"555-0100",` +
		`"userPrincipalName":"guest_example.com#EXT#@` + kitDomain + `","mail":null},{"businessPhones":[],"mobilePhone":null}`; in != want {
		t.Errorf("scrubbed to %s, want %s", in, want)
	}
}

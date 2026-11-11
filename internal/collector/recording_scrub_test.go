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
// for the @ the email rule looks for.
var recordScrubPatterns = []collectortest.ScrubPattern{
	{Pattern: regexp.MustCompile(`[A-Za-z0-9._%+-]+_[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}#EXT#`), Replace: "guest_example.com#EXT#"},
}

func TestRecordScrubPatterns(t *testing.T) {
	in := `{"userPrincipalName":"pat.lee_outlook.com#EXT#@` + kitDomain + `","mail":null}`
	for _, p := range recordScrubPatterns {
		in = p.Pattern.ReplaceAllString(in, p.Replace)
	}
	if want := `{"userPrincipalName":"guest_example.com#EXT#@` + kitDomain + `","mail":null}`; in != want {
		t.Errorf("scrubbed to %s, want %s", in, want)
	}
}

package collector

import (
	"errors"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func TestGapLogRecordsWhyEachValueIsLeftOut(t *testing.T) {
	rec := &componentsdk.Recorder{}
	log := newGapLog(rec)
	log.leaveOut(azurePath, failed(componentsdk.CodeError(componentsdk.CodePermissionDenied, errors.New("denied"))), "/accounts/0/storage")
	log.leaveOut(entraPath, unlicensed("no report"), "/posture/mfa_coverage")
	log.partial(azurePath, 2, failed(componentsdk.CodeError(componentsdk.CodeVendorError, errors.New("down"))), "/accounts/0/backup/retention_days_min")
	log.leaveOut(azurePath, nil, "/accounts/0/network")

	if got := len(rec.Gaps()); got != 3 {
		t.Fatalf("expected three gaps, got %#v", rec.Gaps())
	}
	assertGap(t, rec, azurePath, "/accounts/0/storage", componentsdk.CodePermissionDenied)
	if license := assertGap(t, rec, entraPath, "/posture/mfa_coverage", componentsdk.CodeNotLicensed); license.Detail != "no report" {
		t.Fatalf("expected the license gap to keep its detail, got %#v", license)
	}
	backup := assertGap(t, rec, azurePath, "/accounts/0/backup/retention_days_min", componentsdk.CodeVendorError)
	if backup.Status != componentsdk.GapPartial || backup.Unmeasured != 2 {
		t.Fatalf("expected a partial gap over two items, got %#v", backup)
	}
}

func assertGap(t *testing.T, rec *componentsdk.Recorder, path, pointer string, code componentsdk.Code) componentsdk.Gap {
	t.Helper()
	for _, gap := range rec.Gaps() {
		if gap.Path == path && gap.Pointer == pointer {
			if gap.Code != code {
				t.Fatalf("gap at %s %s has code %s, want %s", path, pointer, gap.Code, code)
			}
			return gap
		}
	}
	t.Fatalf("no gap at %s %s; gaps: %#v", path, pointer, rec.Gaps())
	return componentsdk.Gap{}
}

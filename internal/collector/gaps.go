package collector

import (
	"fmt"

	"github.com/locktivity/epack/componentsdk"
)

// collectorName is the collector's own name, which names its artifacts.
const collectorName = "microsoft-cloud"

// The schema IDs of the artifacts the collector writes. Each detailed file
// has a schema ID of its own, so each has its own kind and path.
const (
	entraSchema         = "microsoft-cloud/entra@v1"
	azureSchema         = "microsoft-cloud/azure@v1"
	idpPostureSchema    = "evidencepack/idp-posture@v1"
	cloudPostureSchema  = "evidencepack/cloud-posture@v1"
	accessPostureSchema = "evidencepack/access-posture@v1"
)

var (
	entraPath         = componentsdk.ArtifactPath(collectorName, entraSchema)
	idpPosturePath    = componentsdk.ArtifactPath(collectorName, idpPostureSchema)
	azurePath         = componentsdk.ArtifactPath(collectorName, azureSchema)
	cloudPosturePath  = componentsdk.ArtifactPath(collectorName, cloudPostureSchema)
	accessPosturePath = componentsdk.ArtifactPath(collectorName, accessPostureSchema)
)

// missing says why a value was left out: the error that stopped its read,
// or, when err is nil, a code and detail. The code is not_licensed for a
// feature the tenant or subscription does not have, unsupported for a value
// Microsoft never reports, and not_read for one Microsoft reports in a place
// the collector does not read.
type missing struct {
	err    error
	code   componentsdk.Code
	detail string
}

func failed(err error) *missing { return &missing{err: err} }

func unlicensed(detail string) *missing {
	return &missing{code: componentsdk.CodeNotLicensed, detail: detail}
}

func unsupported(detail string) *missing {
	return &missing{code: componentsdk.CodeUnsupported, detail: detail}
}

func notRead(detail string) *missing {
	return &missing{code: componentsdk.CodeNotRead, detail: detail}
}

func firstMissing(reasons ...*missing) *missing {
	for _, reason := range reasons {
		if reason != nil {
			return reason
		}
	}
	return nil
}

// gapLog records each value the collector leaves out in the run's recorder.
type gapLog struct {
	rec *componentsdk.Recorder
}

func newGapLog(rec *componentsdk.Recorder) *gapLog {
	if rec == nil {
		rec = &componentsdk.Recorder{}
	}
	return &gapLog{rec: rec}
}

// leaveOut records the values at pointers as left out for why. A nil why
// records nothing, so callers can pass the outcome of a read as it is.
func (l *gapLog) leaveOut(path string, why *missing, pointers ...string) {
	for _, pointer := range pointers {
		l.record(path, pointer, why, 0)
	}
}

func (l *gapLog) partial(path string, unmeasured int, why *missing, pointers ...string) {
	for _, pointer := range pointers {
		l.record(path, pointer, why, unmeasured)
	}
}

func (l *gapLog) record(path, pointer string, why *missing, unmeasured int) {
	if why == nil {
		return
	}
	at := componentsdk.Location{Path: path, Pointer: pointer}
	switch {
	case why.err == nil:
		l.rec.NotCollectedCode(at, why.code, why.detail)
	case unmeasured > 0:
		l.rec.Partial(at, unmeasured, why.err)
	default:
		l.rec.NotCollected(at, why.err)
	}
}

func accountPointer(index int, field string) string {
	return fmt.Sprintf("/accounts/%d/%s", index, field)
}

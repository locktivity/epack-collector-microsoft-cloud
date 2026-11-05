// epack-collector-microsoft-cloud collects Microsoft Cloud security posture.
package main

import (
	"github.com/locktivity/epack-collector-microsoft-cloud/internal/collector"
	"github.com/locktivity/epack/componentsdk"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	componentsdk.RunCollector(collector.Spec(Version, Commit), collector.Run)
}

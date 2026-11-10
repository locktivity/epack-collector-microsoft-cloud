package collector

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
	"github.com/locktivity/epack/componentsdk"
)

type Diagnostics struct {
	TenantErrors       []string              `json:"tenant_errors"`
	SubscriptionErrors []string              `json:"subscription_errors"`
	Warnings           []string              `json:"warnings"`
	Truncation         map[string]Truncation `json:"truncation"`
	License            LicenseDiagnostics    `json:"license"`
}

type Truncation struct {
	Truncated    bool `json:"truncated"`
	DroppedCount int  `json:"dropped_count"`
}

type LicenseDiagnostics struct {
	EntraTier               string   `json:"entra_tier"`
	CapabilitiesUnavailable []string `json:"capabilities_unavailable"`
}

func NewDiagnostics() Diagnostics {
	return Diagnostics{
		TenantErrors:       []string{},
		SubscriptionErrors: []string{},
		Warnings:           []string{},
		Truncation:         map[string]Truncation{},
		License: LicenseDiagnostics{
			EntraTier:               "unknown",
			CapabilitiesUnavailable: []string{},
		},
	}
}

func (d *Diagnostics) Warn(message string) {
	d.Warnings = append(d.Warnings, message)
}

func (d *Diagnostics) MarkCapabilityUnavailable(capability string) {
	d.License.CapabilitiesUnavailable = append(d.License.CapabilitiesUnavailable, capability)
}

func (d *Diagnostics) warnNotCollected(surface string, err error) {
	d.Warn(fmt.Sprintf("%s not collected (%s)", surface, componentsdk.Classify(err)))
}

// warnSubscription adds the "unavailable" warning older readers know for a
// 403 or 404 from an Azure surface, and names the code for anything else.
// subscription is the subscription's name in diagnostics text.
func (d *Diagnostics) warnSubscription(surface, subscription string, err error) {
	if surfaceUnavailable(err) {
		d.Warn(surface + " unavailable for subscription " + subscription)
		return
	}
	d.warnNotCollected(surface+" for subscription "+subscription, err)
}

func apiStatus(err error) int {
	var apiErr *microsoft.APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode
	}
	return 0
}

func permissionDenied(err error) bool {
	return componentsdk.Classify(err) == componentsdk.CodePermissionDenied
}

func surfaceUnavailable(err error) bool {
	switch apiStatus(err) {
	case http.StatusForbidden, http.StatusNotFound:
		return true
	default:
		return false
	}
}

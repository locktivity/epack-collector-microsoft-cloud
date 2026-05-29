package collector

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

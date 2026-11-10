package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

type computeReads struct {
	virtualMachines     []microsoft.VirtualMachine
	virtualMachinesMiss *missing
	publicIPs           []microsoft.PublicIPAddress
	publicIPsMiss       *missing
}

func (c *Collector) collectCompute(ctx context.Context, scope subscriptionScope, diagnostics *Diagnostics) (*AzureCompute, computeReads) {
	var reads computeReads
	virtualMachines, err := c.arm.VirtualMachines(ctx, scope.id)
	if err != nil {
		diagnostics.warnSubscription("Virtual machine inventory", scope.name, err)
		reads.virtualMachinesMiss = failed(err)
		c.gaps.leaveOut(azurePath, reads.virtualMachinesMiss, scope.pointer("compute"))
	}
	reads.virtualMachines = virtualMachines

	publicIPs, err := c.arm.PublicIPAddresses(ctx, scope.id)
	if err != nil {
		diagnostics.warnSubscription("Public IP inventory", scope.name, err)
		reads.publicIPsMiss = failed(err)
	}
	reads.publicIPs = publicIPs

	if reads.virtualMachinesMiss != nil {
		return nil, reads
	}
	c.gaps.leaveOut(azurePath, reads.publicIPsMiss, scope.pointer("compute/public_ip_pct"))
	return computePosture(virtualMachines, publicIPs, reads.publicIPsMiss == nil), reads
}

func computePosture(virtualMachines []microsoft.VirtualMachine, publicIPs []microsoft.PublicIPAddress, publicIPKnown bool) *AzureCompute {
	out := &AzureCompute{VirtualMachinesCount: len(virtualMachines)}
	if len(virtualMachines) == 0 {
		return out
	}

	encrypted := 0
	publicAttached := 0
	publicNICs := publicIPNICIDs(publicIPs)
	for _, vm := range virtualMachines {
		if vmDisksEncrypted(vm) {
			encrypted++
		}
		if publicIPKnown && vmHasPublicIP(vm, publicNICs) {
			publicAttached++
		}
	}
	out.DiskEncryptionPct = PercentInt(encrypted, len(virtualMachines))
	if publicIPKnown {
		out.PublicIPPct = PercentInt(publicAttached, len(virtualMachines))
	}
	return out
}

func vmDisksEncrypted(vm microsoft.VirtualMachine) bool {
	if !diskEncrypted(vm.Properties.StorageProfile.OSDisk) {
		return false
	}
	for _, disk := range vm.Properties.StorageProfile.DataDisks {
		if !diskEncrypted(disk) {
			return false
		}
	}
	return true
}

func diskEncrypted(disk microsoft.VirtualMachineDisk) bool {
	if disk.ManagedDisk != nil && disk.ManagedDisk.ID != "" {
		return true
	}
	return disk.EncryptionSettings != nil && disk.EncryptionSettings.Enabled != nil && *disk.EncryptionSettings.Enabled
}

func publicIPNICIDs(publicIPs []microsoft.PublicIPAddress) map[string]struct{} {
	out := map[string]struct{}{}
	for _, publicIP := range publicIPs {
		if publicIP.Properties.IPConfiguration == nil {
			continue
		}
		nicID := nicIDFromIPConfigurationID(publicIP.Properties.IPConfiguration.ID)
		if nicID != "" {
			out[strings.ToLower(nicID)] = struct{}{}
		}
	}
	return out
}

func vmHasPublicIP(vm microsoft.VirtualMachine, publicNICs map[string]struct{}) bool {
	for _, nic := range vm.Properties.NetworkProfile.NetworkInterfaces {
		if _, ok := publicNICs[strings.ToLower(nic.ID)]; ok {
			return true
		}
	}
	return false
}

func nicIDFromIPConfigurationID(id string) string {
	lower := strings.ToLower(id)
	index := strings.Index(lower, "/ipconfigurations/")
	if index < 0 {
		return ""
	}
	return id[:index]
}

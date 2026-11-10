package collector

import (
	"context"
	"strconv"
	"strings"

	"github.com/locktivity/epack-collector-microsoft-cloud/internal/microsoft"
)

func (c *Collector) collectNetwork(ctx context.Context, scope subscriptionScope, publicIPs []microsoft.PublicIPAddress, publicIPsMiss *missing, diagnostics *Diagnostics) *AzureNetwork {
	out := &AzureNetwork{}
	if publicIPsMiss == nil {
		out.PublicIPAddressesCount = intPtr(len(publicIPs))
	}
	c.gaps.leaveOut(azurePath, publicIPsMiss, scope.pointer("network/public_ip_addresses_count"))

	nsgs, err := c.arm.NetworkSecurityGroups(ctx, scope.id)
	if err != nil {
		diagnostics.warnSubscription("Network security groups", scope.name, err)
		c.gaps.leaveOut(azurePath, failed(err),
			scope.pointer("network/network_security_groups_count"),
			scope.pointer("network/ssh_open_to_world_pct"),
			scope.pointer("network/rdp_open_to_world_pct"))
		return out
	}
	out.NetworkSecurityGroupsCount = intPtr(len(nsgs))
	out.sshOpenCount, out.rdpOpenCount = intPtr(0), intPtr(0)
	if len(nsgs) == 0 {
		return out
	}

	sshOpen := 0
	rdpOpen := 0
	for _, nsg := range nsgs {
		if nsgOpenToWorld(nsg, 22) {
			sshOpen++
		}
		if nsgOpenToWorld(nsg, 3389) {
			rdpOpen++
		}
	}
	out.SSHOpenToWorldPct = PercentInt(sshOpen, len(nsgs))
	out.RDPOpenToWorldPct = PercentInt(rdpOpen, len(nsgs))
	out.sshOpenCount, out.rdpOpenCount = intPtr(sshOpen), intPtr(rdpOpen)
	return out
}

func nsgOpenToWorld(nsg microsoft.NetworkSecurityGroup, port int) bool {
	for _, rule := range nsg.Properties.SecurityRules {
		props := rule.Properties
		if !strings.EqualFold(props.Access, "Allow") || !strings.EqualFold(props.Direction, "Inbound") {
			continue
		}
		if !securityRuleProtocolIncludesTCP(props.Protocol) || !securityRuleSourceIsWorld(props) {
			continue
		}
		if securityRulePortsInclude(props.DestinationPortRange, props.DestinationPortRanges, port) {
			return true
		}
	}
	return false
}

func securityRuleProtocolIncludesTCP(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "*", "any", "tcp":
		return true
	default:
		return false
	}
}

func securityRuleSourceIsWorld(props microsoft.SecurityRuleProperties) bool {
	return securityRulePrefixesIncludeWorld(append([]string{props.SourceAddressPrefix}, props.SourceAddressPrefixes...))
}

func securityRulePrefixesIncludeWorld(prefixes []string) bool {
	for _, prefix := range prefixes {
		switch strings.ToLower(strings.TrimSpace(prefix)) {
		case "*", "any", "internet", "0.0.0.0/0", "::/0":
			return true
		}
	}
	return false
}

func securityRulePortsInclude(single string, ranges []string, port int) bool {
	ports := append([]string{single}, ranges...)
	for _, candidate := range ports {
		if securityRulePortIncludes(candidate, port) {
			return true
		}
	}
	return false
}

func securityRulePortIncludes(candidate string, port int) bool {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return false
	}
	if candidate == "*" {
		return true
	}
	if strings.Contains(candidate, ",") {
		for _, part := range strings.Split(candidate, ",") {
			if securityRulePortIncludes(part, port) {
				return true
			}
		}
		return false
	}
	if strings.Contains(candidate, "-") {
		parts := strings.SplitN(candidate, "-", 2)
		start, startErr := strconv.Atoi(strings.TrimSpace(parts[0]))
		end, endErr := strconv.Atoi(strings.TrimSpace(parts[1]))
		return startErr == nil && endErr == nil && port >= start && port <= end
	}
	value, err := strconv.Atoi(candidate)
	return err == nil && value == port
}

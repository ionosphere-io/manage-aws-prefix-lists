package main

// This file provides data types for extracting values out of the AWS ip-ranges.json document.

// IPRanges is the structure of the ip-ranges.json document.
type IPRanges struct {
	SyncToken    string       `json:"syncToken"`
	CreateDate   string       `json:"createDate"`
	Prefixes     []IPv4Prefix `json:"prefixes"`
	IPv6Prefixes []IPv6Prefix `json:"ipv6_prefixes"`
}

// IPPrefix is a common interface for IPv4Prefix and IPv6Prefix
type IPPrefix interface {
	GetAddressType() AddressFamily
	GetPrefix() string
	GetRegion() string
	GetService() string
	GetNetworkBorderGroup() string
}

// IPv4Prefix is the structure of an IPv4 prefix in the ip-ranges.json document.
type IPv4Prefix struct {
	IPPrefix           string `json:"ip_prefix"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}

// IPv6Prefix is the structure of an IPv6 prefix in the ip-ranges.json document.
type IPv6Prefix struct {
	IPv6Prefix         string `json:"ipv6_prefix"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}

// GetAddressType returns the address type (IPv4 or IPv6) of this prefix.
func (ip *IPv4Prefix) GetAddressType() AddressFamily {
	return AddressFamilyIPv4
}

// GetPrefix returns the IP prefix.
func (ip *IPv4Prefix) GetPrefix() string {
	return ip.IPPrefix
}

// GetRegion returns the AWS region this prefix applies to.
func (ip *IPv4Prefix) GetRegion() string {
	return ip.Region
}

// GetService returns the AWS service this prefix applies to.
func (ip *IPv4Prefix) GetService() string {
	return ip.Service
}

// GetNetworkBorderGroup returns the AWS network border group this prefix applies to.
// This is different than the region for local regions (us-west-2-lax-1) and AWS Wavelength zones.
func (ip *IPv4Prefix) GetNetworkBorderGroup() string {
	return ip.NetworkBorderGroup
}

// GetAddressType returns the address type (IPv4 or IPv6) of this prefix.
func (ip *IPv6Prefix) GetAddressType() AddressFamily {
	return AddressFamilyIPv6
}

// GetPrefix returns the IP prefix.
func (ip *IPv6Prefix) GetPrefix() string {
	return ip.IPv6Prefix
}

// GetRegion returns the AWS region this prefix applies to.
func (ip *IPv6Prefix) GetRegion() string {
	return ip.Region
}

// GetService returns the AWS service this prefix applies to.
func (ip *IPv6Prefix) GetService() string {
	return ip.Service
}

// GetNetworkBorderGroup returns the AWS network border group this prefix applies to.
// This is different than the region for local regions (us-west-2-lax-1) and AWS Wavelength zones.
func (ip *IPv6Prefix) GetNetworkBorderGroup() string {
	return ip.NetworkBorderGroup
}

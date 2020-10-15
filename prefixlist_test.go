package main

import (
	"context"
	"encoding/json"
	"log"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
)

type testingLogger struct {
	testContext *testing.T
}

func (tl *testingLogger) Write(p []byte) (int, error) {
	tl.testContext.Log(string(p))
	return len(p), nil
}

func createLoggerFromTesting(c *testing.T) *log.Logger {
	writer := &testingLogger{testContext: c}
	return log.New(writer, "", 0)
}

const awsTagFormat string = `[
	{"Key": "Key1", "Value": "Value1"},
	{"Key": "Key2", "Value": "Value2"},
	{"Key": "Key3", "Value": "Value3"}
]`

const terraformTagFormat string = `{
	"Key1": "Value1",
	"Key2": "Value2",
	"Key3": "Value3"
}`

// TestTagMapOk tests the unmarshalling function of TagMap.
func TestTagMapOk(c *testing.T) {
	var err error
	var result TagMap

	result = make(TagMap)
	if err = json.Unmarshal([]byte(awsTagFormat), &result); err != nil {
		c.Errorf("Failed to unmarshal AWS tag format: %v", err)
	} else {
		if len(result) != 3 {
			c.Errorf("Unmarshalling AWS tag format resulted in %d elements instead of 3", len(result))
		}
		if result["Key1"] != "Value1" {
			c.Errorf("AWS tag format: Expected Key1 to contain \"Value1\"")
		}
		if result["Key2"] != "Value2" {
			c.Errorf("AWS tag format: Expected Key2 to contain \"Value2\"")
		}
		if result["Key3"] != "Value3" {
			c.Errorf("AWS tag format: Expected Key3 to contain \"Value3\"")
		}
	}

	result = make(TagMap)
	if err = json.Unmarshal([]byte(terraformTagFormat), &result); err != nil {
		c.Errorf("Failed to unmarshal Terraform tag format: %v", err)
	} else {
		if len(result) != 3 {
			c.Errorf("Unmarshalling Terraform tag format resulted in %d elements instead of 3", len(result))
		}
		if result["Key1"] != "Value1" {
			c.Errorf("Terraform tag format: Expected Key1 to contain \"Value1\"")
		}
		if result["Key2"] != "Value2" {
			c.Errorf("Terraform tag format: Expected Key2 to contain \"Value2\"")
		}
		if result["Key3"] != "Value3" {
			c.Errorf("Terraform tag format: Expected Key3 to contain \"Value3\"")
		}
	}

	result = make(TagMap)
	if err = json.Unmarshal([]byte(`[]`), &result); err != nil {
		c.Errorf("Failed to unmarshal empty AWS tag format: %v", err)
	} else if len(result) != 0 {
		c.Errorf("Unmarshalling empty AWS tag format resulted in %d elements instead of 0", len(result))
	}

	result = make(TagMap)
	if err = json.Unmarshal([]byte(`{}`), &result); err != nil {
		c.Errorf("Failed to unmarshal empty Terraform tag format: %v", err)
	} else if len(result) != 0 {
		c.Errorf("Unmarshalling empty Terraform tag format resulted in %d elements instead of 0", len(result))
	}
}

// TestTagMapBad ensures the unmarshalling function of TagMap returns errors if a map is malformed.
func TestTagMapBad(c *testing.T) {
	var err error
	var result TagMap

	result = make(TagMap)
	if err = json.Unmarshal([]byte(`[{"Key": "a", "Value": "b", "Bad": "c"}]`), &result); err == nil {
		c.Error("Unmarshalling AWS tag format with extra parameter did not result in an error")
	}

	if err = json.Unmarshal([]byte(`[{"Value": "b", "Bad": "c"}]`), &result); err == nil {
		c.Error("Unmarshalling AWS tag format with missing key did not result in an error")
	}

	result = make(TagMap)
	if err = json.Unmarshal([]byte(`[{"Key": "a", "Bad": "c"}]`), &result); err == nil {
		c.Error("Unmarshalling AWS tag format with missing value did not result in an error")
	}

	if err = json.Unmarshal([]byte(`[{"Key": 1, "Value": "b"}]`), &result); err == nil {
		c.Error("Unmarshalling AWS tag format with integer key did not result in an error")
	}

	if err = json.Unmarshal([]byte(`[{"Key": "a", "Value": 2}]`), &result); err == nil {
		c.Error("Unmarshalling AWS tag format with integer value did not result in an error")
	}

	if err = json.Unmarshal([]byte(`["Key=a,Value=b"]`), &result); err == nil {
		c.Error("Unmarshalling AWS tag format with non-object element did not result in an error")
	}

	if err = json.Unmarshal([]byte(`{1: "b"}`), &result); err == nil {
		c.Error("Unmarshalling Terraform tag format with integer key did not result in an error")
	}

	if err = json.Unmarshal([]byte(`{"a": 2}`), &result); err == nil {
		c.Error("Unmarshalling Terraform tag format with integer value did not result in an error")
	}

	if err = json.Unmarshal([]byte(`"Key=a,Value=b"`), &result); err == nil {
		c.Error("Unmarshalling a string did not result in an error")
	}
}

func TestAddressFamily(c *testing.T) {
	var err error
	var af AddressFamily

	if err = json.Unmarshal([]byte(`"IPv4"`), &af); err != nil {
		c.Errorf(`Unmarshalling "IPv4" resulted in an error: %v`, err)
	} else if af != AddressFamilyIPv4 {
		c.Errorf(`Unmarshalling "IPv4" should have resulted in AddressFamlyIPv4, got %d`, af)
	}

	if err = json.Unmarshal([]byte(`"IPv6"`), &af); err != nil {
		c.Errorf(`Unmarshalling "IPv6" resulted in an error: %v`, err)
	} else if af != AddressFamilyIPv6 {
		c.Errorf(`Unmarshalling "IPv6" should have resulted in AddressFamlyIPv6, got %d`, af)
	}

	if err = json.Unmarshal([]byte(`"ALL"`), &af); err != nil {
		c.Errorf(`Unmarshalling "ALL" resulted in an error: %v`, err)
	} else if af != AddressFamilyAll {
		c.Errorf(`Unmarshalling "ALL" should have resulted in AddressFamlyAll, got %d`, af)
	}

	if err = json.Unmarshal([]byte(`"Wrong"`), &af); err == nil {
		c.Errorf(`Unmarshalling an unrecognized address family did not result in an error`)
	}

	if err = json.Unmarshal([]byte(`""`), &af); err == nil {
		c.Errorf(`Unmarshalling an empty address family did not result in an error`)
	}

	if err = json.Unmarshal([]byte(`1`), &af); err == nil {
		c.Errorf(`Unmarshalling an integer address family value did not result in an error`)
	}

	if err = json.Unmarshal([]byte(`[]`), &af); err == nil {
		c.Errorf(`Unmarshalling an array address family value did not result in an error`)
	}
}

func TestTierEnum(c *testing.T) {
	var err error
	var tier TierEnum

	if err = json.Unmarshal([]byte(`"Standard"`), &tier); err != nil {
		c.Errorf(`Unmarshalling "Standard" resulted in an error: %v`, err)
	} else if tier != TierStandard {
		c.Errorf(`Unmarshalling "Standard" should have resulted in TierStandard, got %d`, tier)
	}

	if err = json.Unmarshal([]byte(`"Advanced"`), &tier); err != nil {
		c.Errorf(`Unmarshalling "Advanced" resulted in an error: %v`, err)
	} else if tier != TierAdvanced {
		c.Errorf(`Unmarshalling "Advanced" should have resulted in TierAdvanced, got %d`, tier)
	}

	if err = json.Unmarshal([]byte(`"Intelligent-Tiering"`), &tier); err != nil {
		c.Errorf(`Unmarshalling "Intelligent-Tiering" resulted in an error: %v`, err)
	} else if tier != TierIntelligentTiering {
		c.Errorf(`Unmarshalling "Intelligent-Tiering" should have resulted in TierIntelligentTiering, got %d`, tier)
	}

	if err = json.Unmarshal([]byte(`"Wrong"`), &tier); err == nil {
		c.Errorf(`Unmarshalling an unrecognized tier did not result in an error`)
	}

	if err = json.Unmarshal([]byte(`""`), &tier); err == nil {
		c.Errorf(`Unmarshalling an empty tier did not result in an error`)
	}

	if err = json.Unmarshal([]byte(`1`), &tier); err == nil {
		c.Errorf(`Unmarshalling an integer tier value did not result in an error`)
	}

	if err = json.Unmarshal([]byte(`[]`), &tier); err == nil {
		c.Errorf(`Unmarshalling an array tier value did not result in an error`)
	}
}

func TestBasicPrefixList(c *testing.T) {
	prefixesIPv4 := []IPv4Prefix{
		{IPPrefix: "10.20.0.0/16", Region: "us-west-2", Service: "EC2", NetworkBorderGroup: "us-west-2"},
		{IPPrefix: "10.21.0.0/16", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPPrefix: "192.168.0.0/24", Region: "us-west-1", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-1"},
		{IPPrefix: "192.168.1.0/24", Region: "us-west-1", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-1"},
		{IPPrefix: "192.168.2.0/24", Region: "us-west-1", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-1"},
		{IPPrefix: "192.168.3.0/25", Region: "us-west-1", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-1"},
		{IPPrefix: "192.168.3.128/25", Region: "us-west-1", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-1"},
	}
	prefixesIPv6 := []IPv6Prefix{
		{IPv6Prefix: "fc00:20::/64", Region: "us-west-2", Service: "EC2", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:21::/64", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:0::/64", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:1::/64", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:2:0::/65", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:2:8000::/66", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:2:c000::/66", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:3::/64", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
	}
	ipRanges := IPRanges{SyncToken: "1", CreateDate: "2000-01-01-00-00-00", Prefixes: prefixesIPv4, IPv6Prefixes: prefixesIPv6}
	server, err := StartIPRangesServer(c, &ipRanges)
	if err != nil {
		c.Fatalf("Unable to start IP ranges server: %v", err)
		return
	}
	defer server.Shutdown()

	ec2Mock := &EC2Mock{}
	ctx := context.WithValue(context.Background(), EC2ClientKey, ec2Mock)
	ctx = context.WithValue(ctx, SSMClientKey, &SSMMock{})
	ctx = context.WithValue(ctx, STSClientKey, &STSMock{})
	req := ManageAWSPrefixListsRequest{}
	if err = json.Unmarshal([]byte(`{
	"PrefixListNameBase": "cloudfront",
	"Filters": [
		{"Service": "CLOUDFRONT"}
	]
}`), &req); err != nil {
		c.Fatalf("Failed to create request: %v", err)
	}

	req.IPRangesURL = server.GetURL()

	response, error := HandleLambdaRequest(ctx, req)
	if error != nil {
		c.Errorf("Failed to handle request: %v\n", error)
	}
	responseDecoded := make(map[string]interface{})
	error = json.Unmarshal([]byte(response), &responseDecoded)
	if error != nil {
		c.Errorf("Failed to unmarshal response as JSON: %v\n", error)
	}

	// Make sure aggregation happened as expected
	if len(ec2Mock.managedPrefixLists) != 2 {
		c.Errorf("Expected 2 managed prefix lists; got %d", len(ec2Mock.managedPrefixLists))
	}

	for _, mpl := range ec2Mock.managedPrefixLists {
		switch aws.StringValue(mpl.PrefixList.AddressFamily) {
		case "IPv4":
			if len(mpl.Entries) != 2 {
				c.Errorf("Expected 2 CIDRs in IPv4 range: %v", mpl.Entries)
			} else {
				if aws.StringValue(mpl.Entries[1].Cidr) != "192.168.0.0/22" {
					c.Errorf("Expected aggregation to result in 192.168.0.0/22: %v", mpl.Entries[1].Cidr)
				}
			}

		case "IPv6":
			if len(mpl.Entries) != 2 {
				c.Errorf("Expected 2 CIDRs in IPv6 range: %v", mpl.Entries)
			} else {
				if aws.StringValue(mpl.Entries[1].Cidr) != "fc00:22::/62" {
					c.Errorf("Expected aggregation to result in fc00:22::/62: %v", mpl.Entries[1].Cidr)
				}
			}
		}
	}
}

func TestIPv4OnlyPrefixList(c *testing.T) {
	prefixesIPv4 := []IPv4Prefix{
		{IPPrefix: "10.20.0.0/16", Region: "us-west-2", Service: "EC2", NetworkBorderGroup: "us-west-2"},
		{IPPrefix: "10.21.0.0/16", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPPrefix: "192.168.0.0/24", Region: "us-west-1", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-1"},
		{IPPrefix: "192.168.1.0/24", Region: "us-west-1", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-1"},
		{IPPrefix: "192.168.2.0/24", Region: "us-west-1", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-1"},
		{IPPrefix: "192.168.3.0/25", Region: "us-west-1", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-1"},
		{IPPrefix: "192.168.3.128/25", Region: "us-west-1", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-1"},
	}
	prefixesIPv6 := []IPv6Prefix{
		{IPv6Prefix: "fc00:20::/64", Region: "us-west-2", Service: "EC2", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:21::/64", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:0::/64", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:1::/64", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:2:0::/65", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:2:8000::/66", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:2:c000::/66", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:3::/64", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
	}
	ipRanges := IPRanges{SyncToken: "1", CreateDate: "2000-01-01-00-00-00", Prefixes: prefixesIPv4, IPv6Prefixes: prefixesIPv6}
	server, err := StartIPRangesServer(c, &ipRanges)
	if err != nil {
		c.Fatalf("Unable to start IP ranges server: %v", err)
		return
	}
	defer server.Shutdown()

	ec2Mock := &EC2Mock{}
	ctx := context.WithValue(context.Background(), EC2ClientKey, ec2Mock)
	ctx = context.WithValue(ctx, SSMClientKey, &SSMMock{})
	ctx = context.WithValue(ctx, STSClientKey, &STSMock{})
	req := ManageAWSPrefixListsRequest{}
	if err = json.Unmarshal([]byte(`{
	"PrefixListNameBase": "cloudfront",
	"Filters": [
		{"Service": "CLOUDFRONT", "AddressFamily": "IPv4"}
	],
	"SSMParameters": {
		"IPv4Parameters": ["SSMParamIPv4"]
	}
}`), &req); err != nil {
		c.Fatalf("Failed to create request: %v", err)
	}

	req.IPRangesURL = server.GetURL()

	response, error := HandleLambdaRequest(ctx, req)
	if error != nil {
		c.Errorf("Failed to handle request: %v\n", error)
		return
	}
	responseDecoded := make(map[string]interface{})
	error = json.Unmarshal([]byte(response), &responseDecoded)
	if error != nil {
		c.Errorf("Failed to unmarshal response as JSON: %v\n", error)
	}

	// Make sure aggregation happened as expected
	if len(ec2Mock.managedPrefixLists) != 1 {
		c.Errorf("Expected 1 managed prefix list; got %d", len(ec2Mock.managedPrefixLists))
	} else {
		mpl := ec2Mock.managedPrefixLists[0]
		if aws.StringValue(mpl.PrefixList.AddressFamily) != "IPv4" {
			c.Errorf("Expected prefix list to be an IPv4 prefix list")
		} else {
			if len(mpl.Entries) != 2 {
				c.Errorf("Expected 2 CIDRs in IPv4 range: %v", mpl.Entries)
			} else {
				if aws.StringValue(mpl.Entries[1].Cidr) != "192.168.0.0/22" {
					c.Errorf("Expected aggregation to result in 192.168.0.0/22: %v", mpl.Entries[1].Cidr)
				}
			}
		}
	}
}

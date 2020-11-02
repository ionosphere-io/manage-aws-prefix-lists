package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
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
	snsMock := &SNSMock{}
	ctx := context.WithValue(context.Background(), EC2ClientKey, ec2Mock)
	ctx = context.WithValue(ctx, SNSClientKey, snsMock)
	ctx = context.WithValue(ctx, SSMClientKey, &SSMMock{})
	ctx = context.WithValue(ctx, STSClientKey, &STSMock{})
	req := ManageAWSPrefixListsRequest{}
	if err = json.Unmarshal([]byte(`{
	"PrefixListNameBase": "cloudfront",
	"Filters": [
		{"Service": "CLOUDFRONT"}
	],
	"SNSTopicArns": ["arn:aws:sns:us-west-2:123456789012:topic"]
}`), &req); err != nil {
		c.Fatalf("Failed to create request: %v", err)
	}

	req.IPRangesURL = server.GetURL()

	response, err := HandleLambdaRequest(ctx, Invoke{ManageRequest: &req})
	if err != nil {
		c.Errorf("Failed to handle request: %v\n", err)
	}
	responseDecoded := make(map[string]interface{})
	err = json.Unmarshal([]byte(response), &responseDecoded)
	if err != nil {
		c.Errorf("Failed to unmarshal response as JSON: %v\n", err)
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

	// Expect an entry for IPv4 and IPv6 in the SNS notification.
	notifications := snsMock.NotificationsByTopicARN["arn:aws:sns:us-west-2:123456789012:topic"]
	if len(notifications) != 1 {
		c.Errorf("Expected 1 notification from SNS; got %d", len(notifications))
	} else {
		notification := notifications[0]
		messageStr := aws.StringValue(notification.Message)
		message := PrefixListNotification{}
		if err = json.Unmarshal([]byte(messageStr), &message); err != nil {
			c.Logf("Message: %s", messageStr)
			c.Errorf("Failed to unmarshal notification: %v", err)
		} else {
			if message.PrefixListNameBase != "cloudfront" {
				c.Errorf(`Expected PrefixListNameBase to be "cloudfront": %v`, message.PrefixListNameBase)
			}

			if message.IPv4 == nil {
				c.Errorf("Expected notification IPv4 to be non-nil")
			} else if len(message.IPv4.PrefixListIDs) != 1 {
				c.Errorf("Expected 1 prefix list ID in IPv4 notification: %v", message.IPv4.PrefixListIDs)
			}

			if len(message.IPv4.UpdatedPrefixListIDs) != 0 {
				c.Errorf("Expected no IPv4 prefix list updates; got %d", len(message.IPv4.UpdatedPrefixListIDs))
			}

			if len(message.IPv4.ReplacedPrefixLists) != 0 {
				c.Errorf("Expected no IPv4 prefix list replacements; got %d", len(message.IPv4.ReplacedPrefixLists))
			}

			if message.IPv6 == nil {
				c.Errorf("Expected notification IPv6 to be non-nil")
			} else if len(message.IPv6.PrefixListIDs) != 1 {
				c.Errorf("Expected 1 prefix list ID in IPv6 notification: %v", message.IPv6.PrefixListIDs)
			}

			if len(message.IPv6.UpdatedPrefixListIDs) != 0 {
				c.Errorf("Expected no IPv6 prefix list updates; got %d", len(message.IPv6.UpdatedPrefixListIDs))
			}

			if len(message.IPv6.ReplacedPrefixLists) != 0 {
				c.Errorf("Expected no IPv6 prefix list replacements; got %d", len(message.IPv6.ReplacedPrefixLists))
			}
		}
	}
}

func comparePrefixes(prefixes []*ec2.PrefixListEntry, expected []string) (bool, string) {
	actual := make([]string, 0, len(prefixes))
	foundInExpected := make(map[string]bool)

	for _, prefix := range expected {
		foundInExpected[prefix] = false
	}

	for _, prefix := range prefixes {
		actual = append(actual, *prefix.Cidr)
	}

	for _, prefix := range actual {
		if _, present := foundInExpected[prefix]; !present {
			return false, fmt.Sprintf("Prefix found that wasn't expected: %#v; expected=%#v, actual=%#v", prefix, expected, actual)
		}

		foundInExpected[prefix] = true
	}

	for prefix, found := range foundInExpected {
		if !found {
			return false, fmt.Sprintf("Prefix missing that was expected: %#v; expected=%#v, actual=%#v", prefix, expected, actual)
		}
	}

	return true, ""
}

func TestIPv4ReplacedRangesIPv4IPv6PrefixList(c *testing.T) {
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
		{IPv6Prefix: "fc00:22:0:2::/64", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:3::/65", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:3:8000::/65", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
	}

	// Expected aggregation results
	ipv4ExpectedAgg1 := []string{"10.21.0.0/16", "192.168.0.0/22"}
	ipv4ExpectedAgg2 := []string{"10.21.0.0/16", "192.168.0.0/23", "192.168.2.0/24", "192.168.3.128/25"}
	ipv6ExpectedAgg2 := []string{"fc00:21::/64", "fc00:22::/63", "fc00:22:0:2::/64", "fc00:22:0:3:8000::/65"}

	ipRanges := IPRanges{SyncToken: "1", CreateDate: "2000-01-01-00-00-00", Prefixes: prefixesIPv4, IPv6Prefixes: prefixesIPv6}
	server, err := StartIPRangesServer(c, &ipRanges)
	if err != nil {
		c.Fatalf("Unable to start IP ranges server: %v", err)
		return
	}
	defer server.Shutdown()

	ec2Mock := &EC2Mock{}
	snsMock := &SNSMock{}
	ssmMock := &SSMMock{}
	ctx := context.WithValue(context.Background(), EC2ClientKey, ec2Mock)
	ctx = context.WithValue(ctx, SNSClientKey, snsMock)
	ctx = context.WithValue(ctx, SSMClientKey, ssmMock)
	ctx = context.WithValue(ctx, STSClientKey, &STSMock{})
	req := ManageAWSPrefixListsRequest{}
	if err = json.Unmarshal([]byte(`{
	"PrefixListNameBase": "cloudfront",
	"PrefixListTags": [{"Key": "Service", "Value": "Cloudfront"}],
	"Filters": [
		{"Service": "CLOUDFRONT", "AddressFamily": "IPv4"}
	],
	"SNSTopicARNs": ["arn:aws:sns:us-west-2:123456789012:topic"],
	"SSMParameters": {
		"IPv4Parameters": ["SSMParamIPv4"],
		"Tags": {"Service": "Cloudfront"}
	}
}`), &req); err != nil {
		c.Fatalf("Failed to create request: %v", err)
	}

	req.IPRangesURL = server.GetURL()

	response, error := HandleLambdaRequest(ctx, Invoke{ManageRequest: &req})
	if error != nil {
		c.Errorf("Failed to handle request: %v\n", error)
		return
	}
	responseDecoded := make(map[string]interface{})
	error = json.Unmarshal([]byte(response), &responseDecoded)
	if error != nil {
		c.Errorf("Failed to unmarshal response as JSON: %v\n", error)
	}

	var origIPv4PrefixListID string

	// Make sure aggregation happened as expected
	if len(ec2Mock.managedPrefixLists) != 1 {
		c.Errorf("Expected 1 managed prefix list; got %d", len(ec2Mock.managedPrefixLists))
	} else {
		var mpl *managedPrefixListAndEntries
		for prefixListID, item := range ec2Mock.managedPrefixLists {
			origIPv4PrefixListID = prefixListID
			mpl = item
			break
		}

		if aws.StringValue(mpl.PrefixList.AddressFamily) != "IPv4" {
			c.Errorf("Expected prefix list to be an IPv4 prefix list")
		} else {
			ok, msg := comparePrefixes(mpl.Entries, ipv4ExpectedAgg1)
			if !ok {
				c.Errorf("Mismatch in case 1 prefixes: %s", msg)
			}
		}

		// Make sure SNS has the expected notification
		notifications := snsMock.NotificationsByTopicARN["arn:aws:sns:us-west-2:123456789012:topic"]
		if len(notifications) != 1 {
			c.Errorf("Expected 1 SNS notification; got %d", len(notifications))
		} else {
			notification := notifications[0]
			messageStr := aws.StringValue(notification.Message)
			message := PrefixListNotification{}
			if err = json.Unmarshal([]byte(messageStr), &message); err != nil {
				c.Logf("Message: %s", messageStr)
				c.Errorf("Failed to unmarshal notification: %v", err)
			} else {
				if message.PrefixListNameBase != "cloudfront" {
					c.Errorf(`Expected PrefixListNameBase to be "cloudfront": %v`, message.PrefixListNameBase)
				}

				if message.IPv4 == nil {
					c.Errorf("Expected notification IPv4 to be non-nil")
				} else if len(message.IPv4.PrefixListIDs) != 1 {
					c.Errorf("Expected 1 prefix list ID in IPv4 notification: %v", message.IPv4.PrefixListIDs)
				}

				if len(message.IPv4.UpdatedPrefixListIDs) != 0 {
					c.Errorf("Expected no IPv4 prefix list updates; got %d", len(message.IPv4.UpdatedPrefixListIDs))
				}

				if len(message.IPv4.ReplacedPrefixLists) != 0 {
					c.Errorf("Expected no IPv4 prefix list replacements; got %d", len(message.IPv4.ReplacedPrefixLists))
				}

				if message.IPv6 == nil {
					c.Errorf("Expected notification IPv6 to be non-nil")
				} else if len(message.IPv6.PrefixListIDs) != 0 {
					c.Errorf("Expected no prefix list ID in IPv6 notification: %v", message.IPv6.PrefixListIDs)
				}

				if len(message.IPv6.UpdatedPrefixListIDs) != 0 {
					c.Errorf("Expected no IPv6 prefix list updates; got %d", len(message.IPv6.UpdatedPrefixListIDs))
				}

				if len(message.IPv6.ReplacedPrefixLists) != 0 {
					c.Errorf("Expected no IPv6 prefix list replacements; got %d", len(message.IPv6.ReplacedPrefixLists))
				}
			}
		}

		// Clear the notifications
		snsMock.NotificationsByTopicARN = nil

		// Make sure SSM contains the expected parameters.
		if len(ssmMock.parameters) != 1 {
			c.Errorf("Expected SSM to contain 1 parameter instead of %d", len(ssmMock.parameters))
		} else {
			param := ssmMock.parameters["SSMParamIPv4"]
			if param == nil || aws.StringValue(param.Name) != "SSMParamIPv4" {
				c.Errorf("Expected SSM paramter name to be SSMParamIPv4: %v", aws.StringValue(param.Name))
			}
			if param != nil && aws.StringValue(param.Type) != "StringList" {
				c.Errorf("Expected SSM parameter type to be StringList: %v", aws.StringValue(param.Type))
			}
			if param != nil && aws.StringValue(param.Value) != aws.StringValue(mpl.PrefixList.PrefixListId) {
				c.Errorf("Expected SSM paramteter value to match the prefix list id: expected %v, got %v",
					aws.StringValue(mpl.PrefixList.PrefixListId), aws.StringValue(param.Value))
			}
		}
	}

	// Update the prefixes -- remove one needed for aggregation.
	prefixesIPv4 = append(prefixesIPv4[0:5], prefixesIPv4[6:]...)
	prefixesIPv6 = append(prefixesIPv6[0:5], prefixesIPv6[6:]...)
	ipRanges.Prefixes = prefixesIPv4
	ipRanges.IPv6Prefixes = prefixesIPv6

	server.UpdateIPRanges(&ipRanges)

	req.Filters[0].AddressFamily = AddressFamilyAll
	req.SSMParameters.IPv6Parameters = []string{"SSMParamIPv6"}
	req.SSMParameters.Tags["Hello"] = "World"

	response, error = HandleLambdaRequest(ctx, Invoke{ManageRequest: &req})
	if error != nil {
		c.Errorf("Failed to handle request: %v\n", error)
		return
	}
	responseDecoded = make(map[string]interface{})
	error = json.Unmarshal([]byte(response), &responseDecoded)
	if error != nil {
		c.Errorf("Failed to unmarshal response as JSON: %v\n", error)
	}

	// Make sure aggregation happened as expected
	if len(ec2Mock.managedPrefixLists) != 2 {
		c.Errorf("Expected 2 managed prefix list; got %d", len(ec2Mock.managedPrefixLists))
	} else {
		var ipv4PrefixListID string
		var ipv6PrefixListID string

		for prefixListID, mpl := range ec2Mock.managedPrefixLists {
			prefixListAddressFamily := aws.StringValue(mpl.PrefixList.AddressFamily)
			if prefixListAddressFamily == "IPv4" {
				ipv4PrefixListID = prefixListID

				if ipv4PrefixListID != origIPv4PrefixListID {
					c.Errorf("Expected prefix list id for IPv4 to remain the same: orig=%v new=%v", origIPv4PrefixListID, ipv4PrefixListID)
				}

				if ok, msg := comparePrefixes(mpl.Entries, ipv4ExpectedAgg2); !ok {
					c.Errorf("Mismatch in case 2 IPv4 prefixes: %s", msg)
				}
			} else if prefixListAddressFamily == "IPv6" {
				ipv6PrefixListID = prefixListID

				if ok, msg := comparePrefixes(mpl.Entries, ipv6ExpectedAgg2); !ok {
					c.Errorf("Mismatch in case 2 IPv6 prefixes: %s", msg)
				}
			}
		}

		if ipv4PrefixListID == "" {
			c.Errorf("Did not see IPv4 prefix list")
		}
		if ipv6PrefixListID == "" {
			c.Errorf("Did not see IPv6 prefix list")
		}

		if ipv4PrefixListID != "" && ipv6PrefixListID != "" {
			// Make sure SNS contains the expected notification
			notifications := snsMock.NotificationsByTopicARN["arn:aws:sns:us-west-2:123456789012:topic"]
			if len(notifications) != 1 {
				c.Errorf("Expected 1 SNS notificaiton")
			} else {
				notification := notifications[0]
				messageStr := aws.StringValue(notification.Message)
				message := PrefixListNotification{}
				if err = json.Unmarshal([]byte(messageStr), &message); err != nil {
					c.Logf("Message: %s", messageStr)
					c.Errorf("Failed to unmarshal notification: %v", err)
				} else {
					if message.PrefixListNameBase != "cloudfront" {
						c.Errorf(`Expected PrefixListNameBase to be "cloudfront": %v`, message.PrefixListNameBase)
					}

					if message.IPv4 == nil {
						c.Errorf("Expected notification IPv4 to be non-nil")
					} else if len(message.IPv4.PrefixListIDs) != 1 {
						c.Errorf("Expected 1 prefix list ID in IPv4 notification: %v", message.IPv4.PrefixListIDs)
					}

					if len(message.IPv4.UpdatedPrefixListIDs) != 1 {
						c.Errorf("Expected 1 IPv4 prefix list updates; got %d", len(message.IPv4.UpdatedPrefixListIDs))
					}

					if len(message.IPv4.ReplacedPrefixLists) != 0 {
						c.Errorf("Expected no IPv4 prefix list replacements; got %d", len(message.IPv4.ReplacedPrefixLists))
					}

					if message.IPv6 == nil {
						c.Errorf("Expected notification IPv6 to be non-nil")
					} else if len(message.IPv6.PrefixListIDs) != 1 {
						c.Errorf("Expected 1 prefix list ID in IPv6 notification: %v", message.IPv6.PrefixListIDs)
					}

					if len(message.IPv6.UpdatedPrefixListIDs) != 0 {
						c.Errorf("Expected no IPv6 prefix list updates; got %d", len(message.IPv6.UpdatedPrefixListIDs))
					}

					if len(message.IPv6.ReplacedPrefixLists) != 0 {
						c.Errorf("Expected no IPv6 prefix list replacements; got %d", len(message.IPv6.ReplacedPrefixLists))
					}
				}
			}

			// Make sure SSM contains the expected parameters.
			if len(ssmMock.parameters) != 2 {
				c.Errorf("Expected SSM to contain 2 parameters instead of %d", len(ssmMock.parameters))
			} else {
				param := ssmMock.parameters["SSMParamIPv4"]
				if param == nil {
					c.Errorf("SSM parameter SSMParamIPv4 not found")
				} else {
					if aws.StringValue(param.Name) != "SSMParamIPv4" {
						c.Errorf("Expected SSM paramter name to be SSMParamIPv4: %v", aws.StringValue(param.Name))
					}
					if aws.StringValue(param.Type) != "StringList" {
						c.Errorf("Expected SSM parameter type to be StringList: %v", aws.StringValue(param.Type))
					}
					if aws.StringValue(param.Value) != ipv4PrefixListID {
						c.Errorf("Expected SSM paramteter value to match the prefix list id: expected %v, got %v",
							ipv4PrefixListID, aws.StringValue(param.Value))
					}
				}

				param = ssmMock.parameters["SSMParamIPv6"]
				if param == nil {
					c.Errorf("SSM parameter SSMParamIPv6 not found")
				} else {
					if aws.StringValue(param.Name) != "SSMParamIPv6" {
						c.Errorf("Expected SSM paramter name to be SSMParamIPv6: %v", aws.StringValue(param.Name))
					}
					if aws.StringValue(param.Type) != "StringList" {
						c.Errorf("Expected SSM parameter type to be StringList: %v", aws.StringValue(param.Type))
					}
					if aws.StringValue(param.Value) != ipv6PrefixListID {
						c.Errorf("Expected SSM paramteter value to match the prefix list id: expected %v, got %v",
							ipv6PrefixListID, aws.StringValue(param.Value))
					}
				}
			}
		}
	}
}

func TestReplacePrefixList(c *testing.T) {
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
	ssmMock := &SSMMock{}
	ctx := context.WithValue(context.Background(), EC2ClientKey, ec2Mock)
	ctx = context.WithValue(ctx, SSMClientKey, ssmMock)
	ctx = context.WithValue(ctx, STSClientKey, &STSMock{})
	req := ManageAWSPrefixListsRequest{}
	if err = json.Unmarshal([]byte(`{
	"PrefixListNameBase": "cloudfront",
	"Filters": [
		{"Service": "CLOUDFRONT", "AddressFamily": "IPv4"}
	],
	"SSMParameters": {
		"IPv4Parameters": ["SSMParamIPv4"]
	},
	"GroupSize": 10
}`), &req); err != nil {
		c.Fatalf("Failed to create request: %v", err)
	}

	req.IPRangesURL = server.GetURL()

	response, error := HandleLambdaRequest(ctx, Invoke{ManageRequest: &req})
	if error != nil {
		c.Errorf("Failed to handle request: %v\n", error)
		return
	}
	responseDecoded := make(map[string]interface{})
	error = json.Unmarshal([]byte(response), &responseDecoded)
	if error != nil {
		c.Errorf("Failed to unmarshal response as JSON: %v\n", error)
		return
	}

	var origPrefixListID string
	// Make sure aggregation happened as expected
	if len(ec2Mock.managedPrefixLists) != 1 {
		c.Errorf("Expected 1 managed prefix list; got %d", len(ec2Mock.managedPrefixLists))
		return
	}

	var mpl *managedPrefixListAndEntries
	for _, item := range ec2Mock.managedPrefixLists {
		mpl = item
		break
	}

	origPrefixListID = *mpl.PrefixList.PrefixListId
	if aws.Int64Value(mpl.PrefixList.MaxEntries) != 10 {
		c.Errorf("Expected original prefix list to have a maximum of 10 entries.")
	}

	// Make sure SSM contains the expected parameters.
	if len(ssmMock.parameters) != 1 {
		c.Errorf("Expected SSM to contain 1 parameter instead of %d", len(ssmMock.parameters))
	} else {
		param := ssmMock.parameters["SSMParamIPv4"]
		if param == nil || aws.StringValue(param.Name) != "SSMParamIPv4" {
			c.Errorf("Expected SSM paramter name to be SSMParamIPv4: %v", aws.StringValue(param.Name))
		}
		if param != nil && aws.StringValue(param.Type) != "StringList" {
			c.Errorf("Expected SSM parameter type to be StringList: %v", aws.StringValue(param.Type))
		}
		if param != nil && aws.StringValue(param.Value) != origPrefixListID {
			c.Errorf("Expected SSM paramteter value to match the prefix list id: expected %v, got %v", origPrefixListID,
				aws.StringValue(param.Value))
		}
	}

	req.GroupSize = 20
	response, error = HandleLambdaRequest(ctx, Invoke{ManageRequest: &req})

	if error != nil {
		c.Errorf("Failed to handle request: %v\n", error)
		return
	}
	responseDecoded = make(map[string]interface{})
	error = json.Unmarshal([]byte(response), &responseDecoded)
	if error != nil {
		c.Errorf("Failed to unmarshal response as JSON: %v\n", error)
		return
	}

	var newPrefixListID string
	// Make sure aggregation happened as expected
	if len(ec2Mock.managedPrefixLists) != 1 {
		c.Errorf("Expected 1 managed prefix list; got %d", len(ec2Mock.managedPrefixLists))
		return
	}

	for _, item := range ec2Mock.managedPrefixLists {
		mpl = item
		break
	}

	newPrefixListID = *mpl.PrefixList.PrefixListId
	if aws.Int64Value(mpl.PrefixList.MaxEntries) != 20 {
		c.Errorf("Expected new prefix list to have a maximum of 10 entries.")
	}

	if origPrefixListID == newPrefixListID {
		c.Errorf("Expected prefix list id to change from %v", origPrefixListID)
	}

	// Make sure SSM contains the expected parameters.
	if len(ssmMock.parameters) != 1 {
		c.Errorf("Expected SSM to contain 1 parameter instead of %d", len(ssmMock.parameters))
	} else {
		param := ssmMock.parameters["SSMParamIPv4"]
		if param == nil || aws.StringValue(param.Name) != "SSMParamIPv4" {
			c.Errorf("Expected SSM paramter name to be SSMParamIPv4: %v", aws.StringValue(param.Name))
		}
		if param != nil && aws.StringValue(param.Type) != "StringList" {
			c.Errorf("Expected SSM parameter type to be StringList: %v", aws.StringValue(param.Type))
		}
		if param != nil && aws.StringValue(param.Value) != newPrefixListID {
			c.Errorf("Expected SSM paramteter value to match the prefix list id: expected %v, got %v", newPrefixListID,
				aws.StringValue(param.Value))
		}
	}
}

func TestReplaceSecurityGroupRules(c *testing.T) {
	prefixesIPv4 := []IPv4Prefix{
		{IPPrefix: "10.20.0.0/16", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPPrefix: "10.22.0.0/16", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPPrefix: "10.23.0.0/16", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2-lax-1"},
	}
	prefixesIPv6 := []IPv6Prefix{
		{IPv6Prefix: "fc00:20::/64", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22::/64", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:23::/64", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2-lax-1"},
	}

	ipRanges := IPRanges{SyncToken: "1", CreateDate: "2000-01-01-00-00-00", Prefixes: prefixesIPv4, IPv6Prefixes: prefixesIPv6}
	server, err := StartIPRangesServer(c, &ipRanges)
	if err != nil {
		c.Fatalf("Unable to start IP ranges server: %v", err)
		return
	}
	defer server.Shutdown()

	cwMock := &CloudWatchMock{}
	ec2Mock := &EC2Mock{}
	snsMock := &SNSMock{}
	ssmMock := &SSMMock{}
	ctx := context.WithValue(context.Background(), CloudWatchClientKey, cwMock)
	ctx = context.WithValue(ctx, EC2ClientKey, ec2Mock)
	ctx = context.WithValue(ctx, SNSClientKey, snsMock)
	ctx = context.WithValue(ctx, SSMClientKey, ssmMock)
	ctx = context.WithValue(ctx, STSClientKey, &STSMock{})
	req := ManageAWSPrefixListsRequest{}
	if err = json.Unmarshal([]byte(`{
	"PrefixListNameBase": "cloudfront",
	"PrefixListTags": [{"Key": "Service", "Value": "Cloudfront"}],
	"Filters": [
		{"Service": "CLOUDFRONT", "RegionRegex": "us-.*", "NetworkBorderGroupRegex": "^us-[^-]+-[0-9]+$"}
	],
	"Metrics": {
		"Namespace": "Test",
		"Verbosity": 1
	},
	"GroupSize": 10
}`), &req); err != nil {
		c.Fatalf("Failed to create request: %v", err)
	}
	req.IPRangesURL = server.GetURL()
	response, error := HandleLambdaRequest(ctx, Invoke{ManageRequest: &req})

	if error != nil {
		c.Errorf("Failed to handle request: %v\n", error)
		return
	}
	responseDecoded := make(map[string]interface{})
	error = json.Unmarshal([]byte(response), &responseDecoded)
	if error != nil {
		c.Errorf("Failed to unmarshal response as JSON: %v\n", error)
		return
	}

	if len(ec2Mock.managedPrefixLists) != 2 {
		c.Errorf("Expected 2 prefix lists to be created, got %d", len(ec2Mock.managedPrefixLists))
		return
	}

	var ipv4PrefixListID string
	var ipv6PrefixListID string

	for prefixListID, mpl := range ec2Mock.managedPrefixLists {
		switch *mpl.PrefixList.AddressFamily {
		case "IPv4":
			ipv4PrefixListID = prefixListID
			if ok, msg := comparePrefixes(mpl.Entries, []string{"10.20.0.0/16", "10.22.0.0/16"}); !ok {
				c.Errorf("IPv4 prefix list incorrect: %s", msg)
				return
			}
		case "IPv6":
			ipv6PrefixListID = prefixListID
			if ok, msg := comparePrefixes(mpl.Entries, []string{"fc00:20::/64", "fc00:22::/64"}); !ok {
				c.Errorf("IPv6 prefix list incorrect: %s", msg)
				return
			}
		}
	}

	// Create a security group and have it reference these prefix lists
	if ec2Mock.securityGroups == nil {
		ec2Mock.securityGroups = make(map[string]*ec2.SecurityGroup)
	}
	ec2Mock.securityGroups["sg-00000001"] = &ec2.SecurityGroup{
		GroupId: aws.String("sg-00000001"), GroupName: aws.String("TestGroup"), Description: aws.String("TestGroup"),
		OwnerId: aws.String("123456789012"), VpcId: aws.String("vpc-00000001"),
		IpPermissions: []*ec2.IpPermission{
			{
				FromPort: aws.Int64(443), ToPort: aws.Int64(443), IpProtocol: aws.String("tcp"),
				PrefixListIds: []*ec2.PrefixListId{
					{PrefixListId: &ipv4PrefixListID},
					{PrefixListId: &ipv6PrefixListID},
				},
			},
			{
				FromPort: aws.Int64(-1), ToPort: aws.Int64(-1), IpProtocol: aws.String("-1"),
				IpRanges: []*ec2.IpRange{
					{CidrIp: aws.String("10.199.0.0/16")},
				},
			},
		},
		IpPermissionsEgress: []*ec2.IpPermission{
			{
				FromPort: aws.Int64(443), ToPort: aws.Int64(443), IpProtocol: aws.String("tcp"),
				PrefixListIds: []*ec2.PrefixListId{
					{PrefixListId: &ipv4PrefixListID},
					{PrefixListId: &ipv6PrefixListID},
				},
			},
		},
	}

	// Change the prefix list group size
	req.GroupSize = 20
	response, error = HandleLambdaRequest(ctx, Invoke{ManageRequest: &req})

	if error != nil {
		c.Errorf("Failed to handle request: %v\n", error)
		return
	}
	responseDecoded = make(map[string]interface{})
	error = json.Unmarshal([]byte(response), &responseDecoded)
	if error != nil {
		c.Errorf("Failed to unmarshal response as JSON: %v\n", error)
		return
	}

	if len(ec2Mock.managedPrefixLists) != 2 {
		c.Errorf("Expected 2 prefix lists to be created, got %d", len(ec2Mock.managedPrefixLists))
		return
	}

	var newIPv4PrefixListID string
	var newIPv6PrefixListID string

	for prefixListID, mpl := range ec2Mock.managedPrefixLists {
		switch *mpl.PrefixList.AddressFamily {
		case "IPv4":
			newIPv4PrefixListID = prefixListID
			if ok, msg := comparePrefixes(mpl.Entries, []string{"10.20.0.0/16", "10.22.0.0/16"}); !ok {
				c.Errorf("IPv4 prefix list incorrect: %s", msg)
				return
			}
		case "IPv6":
			newIPv6PrefixListID = prefixListID
			if ok, msg := comparePrefixes(mpl.Entries, []string{"fc00:20::/64", "fc00:22::/64"}); !ok {
				c.Errorf("IPv6 prefix list incorrect: %s", msg)
				return
			}
		}
	}

	sg := ec2Mock.securityGroups["sg-00000001"]
	foundStaticCidr := false
	ipv4PrefixListSeen := false
	ipv6PrefixListSeen := false

	for _, perm := range sg.IpPermissions {
		c.Logf("Considering permission %v", perm)
		fromPort := aws.Int64Value(perm.FromPort)
		if fromPort == 443 {
			for _, prefixListID := range perm.PrefixListIds {
				plID := aws.StringValue(prefixListID.PrefixListId)

				if plID == newIPv4PrefixListID {
					ipv4PrefixListSeen = true
				} else if plID == newIPv6PrefixListID {
					ipv6PrefixListSeen = true
				} else if plID == ipv4PrefixListID {
					c.Errorf("Old IPv4 prefix list found in security group: %v instead of new prefix list %v", ipv4PrefixListID, newIPv4PrefixListID)
				} else if plID == ipv6PrefixListID {
					c.Errorf("Old IPv6 prefix list found in security group: %v instead of new prefix list %v", ipv6PrefixListID, newIPv6PrefixListID)
				} else {
					c.Errorf("Unexpected prefix list in security group: %v", plID)
				}
			}
		} else if fromPort == -1 {
			for _, ipRange := range perm.IpRanges {
				cidrIP := aws.StringValue(ipRange.CidrIp)
				if cidrIP == "10.199.0.0/16" {
					foundStaticCidr = true
				}
			}
		}
	}

	if !ipv4PrefixListSeen {
		c.Errorf("Failed to find new IPv4PrefixListId (%s) in security group: %v", newIPv4PrefixListID, sg)
	}
	if !ipv6PrefixListSeen {
		c.Errorf("Failed to find new IPv6PrefixListId (%s) in security group: %v", newIPv6PrefixListID, sg)
	}
	if !foundStaticCidr {
		c.Errorf("Failed to find security group rule containing static IPs")
	}

	// Check CloudWatch metrics
	if cwMock.metrics == nil {
		c.Errorf("No CloudWatch metrics written")
	} else {
		metrics := cwMock.metrics["Test"]
		if metrics == nil {
			c.Errorf("No CloudWatch metrics written to Test namespace")
		}
	}
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
)

// PrefixListManager is the main structure for holding the state of the prefix list manager application.
type PrefixListManager struct {
	// ctx is the context passed to us.
	ctx context.Context

	// partition is the AWS partition we're operating in.
	partition string

	// accountID is the 12-digit account identifier for this account
	accountID string

	// ec2 is a handle to the EC2 service.
	ec2 ec2iface.EC2API

	// ssm is a handle to the SSM service
	ssm ssmiface.SSMAPI

	// request is the incoming request we're handling
	request *ManageAWSPrefixListsRequest

	// ipv4 is the IPv4 related information
	ipv4 *PrefixListAddressFamilyManager

	// ipv6 is the IPv6 related information
	ipv6 *PrefixListAddressFamilyManager
}

// NewPrefixListManagerFromRequest creates a new PrefixListManager object using the data from a ManageAWSPrefixListsRequest event.
func NewPrefixListManagerFromRequest(ctx context.Context, request *ManageAWSPrefixListsRequest) (*PrefixListManager, error) {
	if request == nil {
		return nil, fmt.Errorf("Incoming request cannot be nil")
	}

	plm := new(PrefixListManager)

	awsSession := session.New()
	var present bool

	var ec2Client ec2iface.EC2API
	var ssmClient ssmiface.SSMAPI
	var stsClient stsiface.STSAPI

	// Retrieve interfaces from the context if they're present (for testing).
	if ec2Client, present = ctx.Value(EC2ClientKey).(ec2iface.EC2API); !present {
		ec2Client = ec2.New(awsSession)
	}

	if ssmClient, present = ctx.Value(SSMClientKey).(ssmiface.SSMAPI); !present {
		ssmClient = ssm.New(awsSession)
	}

	if stsClient, present = ctx.Value(STSClientKey).(stsiface.STSAPI); !present {
		stsClient = sts.New(awsSession)
	}

	plm.ec2 = ec2Client
	plm.ssm = ssmClient

	// Figure out our account id and partition
	callerID, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		log.Printf("Unable to get our identity: %v", err)
		return nil, err
	}
	plm.accountID = aws.StringValue(callerID.Account)
	callerIDARN, err := arn.Parse(aws.StringValue(callerID.Arn))
	if err != nil {
		log.Printf("Unable to parse caller ARN: %s: %v", aws.StringValue(callerID.Arn), err)
		return nil, err
	}

	plm.partition = callerIDARN.Partition
	plm.request = request

	plm.ipv4 = NewPrefixListAddressFamilyManager(plm.partition, plm.accountID, plm.ec2, plm.ssm, "IPv4", plm.request.GroupSize, plm.request.PrefixListTags)
	plm.ipv6 = NewPrefixListAddressFamilyManager(plm.partition, plm.accountID, plm.ec2, plm.ssm, "IPv6", plm.request.GroupSize, plm.request.PrefixListTags)

	return plm, nil
}

// LoadIPRanges makes an HTTP request to the ip-ranges.json endpoint and parses the returned data.
func (plm *PrefixListManager) LoadIPRanges() error {
	resp, err := http.Get(plm.request.IPRangesURL)

	if err != nil {
		log.Printf("Failed to GET %s: %v", plm.request.IPRangesURL, err)
		return fmt.Errorf("Failed to GET %s: %v", plm.request.IPRangesURL, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("Failed to GET %s: HTTP status %#v returned", plm.request.IPRangesURL, resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body for %s: %v", plm.request.IPRangesURL, err)
		return fmt.Errorf("Error while reading response body from %s: %v", plm.request.IPRangesURL, err)
	}

	var ipRanges IPRanges
	if err = json.Unmarshal(body, &ipRanges); err != nil {
		log.Printf("Failed to parse ip-ranges.json from %s: %v", plm.request.IPRangesURL, err)
		return fmt.Errorf("Failed to parse ip-ranges.json from %s: %v", plm.request.IPRangesURL, err)
	}

	plm.ipv4.allPrefixes = make([]IPPrefix, len(ipRanges.Prefixes))
	for i := 0; i < len(ipRanges.Prefixes); i++ {
		plm.ipv4.allPrefixes[i] = &ipRanges.Prefixes[i]
	}

	plm.ipv6.allPrefixes = make([]IPPrefix, len(ipRanges.IPv6Prefixes))
	for i := 0; i < len(ipRanges.IPv6Prefixes); i++ {
		plm.ipv6.allPrefixes[i] = &ipRanges.IPv6Prefixes[i]
	}

	return nil
}

// Process ensures that the managed prefix lists are in-sync with the ip-ranges.json data.
// LoadIPRanges must be called before invoking this method.
func (plm *PrefixListManager) Process() ([]PrefixListManagementOp, error) {
	if err := plm.ipv4.filterAndAggregatePrefixes(plm.request.Filters, plm.request.GroupSize); err != nil {
		return nil, err
	}

	if err := plm.ipv6.filterAndAggregatePrefixes(plm.request.Filters, plm.request.GroupSize); err != nil {
		return nil, err
	}

	// Get the prefix list names -- this may fail, so we want to capture any errors before we make modifications to AWS.
	if err := plm.ipv4.generatePrefixListNames(plm.request.PrefixListNameBase, plm.request.PrefixListNameTemplate); err != nil {
		return nil, err
	}

	if err := plm.ipv6.generatePrefixListNames(plm.request.PrefixListNameBase, plm.request.PrefixListNameTemplate); err != nil {
		return nil, err
	}

	// Get the existing managed prefix lists
	if err := plm.ipv4.mapPrefixListNamesToExistingPrefixLists(); err != nil {
		return nil, err
	}

	if err := plm.ipv6.mapPrefixListNamesToExistingPrefixLists(); err != nil {
		return nil, err
	}

	// And perform updates.
	var ops []PrefixListManagementOp
	ops = append(ops, plm.ipv4.updateManagedPrefixLists()...)
	ops = append(ops, plm.ipv6.updateManagedPrefixLists()...)

	// Copy any results to SSM.
	ops = append(ops, plm.ipv4.updateSSMWithPrefixListIDs(plm.request.SSMParameters.IPv4Parameters, plm.request.SSMParameters.Tags,
		plm.request.SSMParameters.Tier)...)
	ops = append(ops, plm.ipv6.updateSSMWithPrefixListIDs(plm.request.SSMParameters.IPv6Parameters, plm.request.SSMParameters.Tags,
		plm.request.SSMParameters.Tier)...)

	return ops, nil
}

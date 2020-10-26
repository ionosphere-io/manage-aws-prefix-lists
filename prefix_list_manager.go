package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/cloudwatch/cloudwatchiface"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
)

// PrefixListManager is the main structure for holding the state of the prefix list manager application.
type PrefixListManager struct {
	// partition is the AWS partition we're operating in.
	partition string

	// accountID is the 12-digit account identifier for this account.
	accountID string

	// cw is a handle to the AWS CloudWatch metrics service.
	cw cloudwatchiface.CloudWatchAPI

	// ec2 is a handle to the AWS EC2 (Elasitc Compute Cloud) service.
	ec2 ec2iface.EC2API

	// ssm is a handle to the AWS SSM ((Simple) Systems Manager) service.
	ssm ssmiface.SSMAPI

	// sns is a handle to the SNS (Simple Notification Service) service.
	sns snsiface.SNSAPI

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

	awsSession, err := session.NewSession(&aws.Config{MaxRetries: aws.Int(int(MaxRetries))})
	if err != nil {
		log.Printf("Failed to create an AWS session: %v", err)
		return nil, err
	}
	var present bool

	var cwClient cloudwatchiface.CloudWatchAPI
	var ec2Client ec2iface.EC2API
	var ssmClient ssmiface.SSMAPI
	var stsClient stsiface.STSAPI
	var snsClient snsiface.SNSAPI

	// Retrieve interfaces from the context if they're present (for testing); otherwise, create a client to the real service.
	if cwClient, present = ctx.Value(CloudWatchClientKey).(cloudwatchiface.CloudWatchAPI); !present {
		cwClient = cloudwatch.New(awsSession)
	}

	if ec2Client, present = ctx.Value(EC2ClientKey).(ec2iface.EC2API); !present {
		ec2Client = ec2.New(awsSession)
	}

	if ssmClient, present = ctx.Value(SSMClientKey).(ssmiface.SSMAPI); !present {
		ssmClient = ssm.New(awsSession)
	}

	if stsClient, present = ctx.Value(STSClientKey).(stsiface.STSAPI); !present {
		stsClient = sts.New(awsSession)
	}

	if snsClient, present = ctx.Value(SNSClientKey).(snsiface.SNSAPI); !present {
		snsClient = sns.New(awsSession)
	}

	plm.cw = cwClient
	plm.ec2 = ec2Client
	plm.ssm = ssmClient
	plm.sns = snsClient

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

	plm.ipv4 = NewPrefixListAddressFamilyManager(plm.partition, plm.accountID, plm.request.PrefixListNameBase, plm.ec2, plm.ssm, "IPv4", plm.request.GroupSize, plm.request.PrefixListTags)
	plm.ipv6 = NewPrefixListAddressFamilyManager(plm.partition, plm.accountID, plm.request.PrefixListNameBase, plm.ec2, plm.ssm, "IPv6", plm.request.GroupSize, plm.request.PrefixListTags)

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
func (plm *PrefixListManager) Process() error {
	if err := plm.ipv4.filterAndAggregatePrefixes(plm.request.Filters, plm.request.GroupSize); err != nil {
		return err
	}

	if err := plm.ipv6.filterAndAggregatePrefixes(plm.request.Filters, plm.request.GroupSize); err != nil {
		return err
	}

	if len(plm.ipv4.keptPrefixes) == 0 && len(plm.ipv6.keptPrefixes) == 0 {
		log.Printf("Filters returned no prefixes")
		return fmt.Errorf("Filters returned no prefixes")
	}

	// Get the prefix list names -- this may fail, so we want to capture any errors before we make modifications to AWS.
	if err := plm.ipv4.generatePrefixListNames(plm.request.PrefixListNameTemplate); err != nil {
		return err
	}

	if err := plm.ipv6.generatePrefixListNames(plm.request.PrefixListNameTemplate); err != nil {
		return err
	}

	// Get the existing managed prefix lists
	if err := plm.ipv4.mapPrefixListNamesToExistingPrefixLists(); err != nil {
		return err
	}

	if err := plm.ipv6.mapPrefixListNamesToExistingPrefixLists(); err != nil {
		return err
	}

	// And perform updates.
	plm.ipv4.updateManagedPrefixLists()
	plm.ipv6.updateManagedPrefixLists()

	// Copy any results to SSM.
	plm.ipv4.updateSSMWithPrefixListIDs(plm.request.SSMParameters.IPv4Parameters, plm.request.SSMParameters.Tags,
		plm.request.SSMParameters.Tier)
	plm.ipv6.updateSSMWithPrefixListIDs(plm.request.SSMParameters.IPv6Parameters, plm.request.SSMParameters.Tags,
		plm.request.SSMParameters.Tier)

	plm.writeCloudWatchMetrics()

	// Create notifications for SNS
	plm.notifySNS()

	return nil
}

func (plm *PrefixListManager) writeCloudWatchMetrics() {
	// Skip this if we're not writing metrics (MetricsNamespace is empty)
	if plm.request.Metrics.Namespace == nil {
		return
	}

	metrics := make([]*cloudwatch.MetricDatum, 0, len(plm.ipv4.metrics)+len(plm.ipv6.metrics)+2)

	now := time.Now().UTC()

	// Add detailed metrics only if requested.
	if plm.request.Metrics.Verbosity > 0 {
		metrics = append(metrics, plm.ipv4.metrics...)
		metrics = append(metrics, plm.ipv6.metrics...)
	}

	// Determine whether the run was successful.
	success := 1.0
	if len(plm.ipv4.errors) != 0 || len(plm.ipv6.errors) != 0 {
		success = 0.0
	}

	// Add metrics indicating the total number of operations and the number of operations that failed.
	metrics = append(metrics,
		&cloudwatch.MetricDatum{
			MetricName: aws.String(MetricProcessRuns),
			Dimensions: []*cloudwatch.Dimension{DimPrefixListNameBase(plm.request.PrefixListNameBase)},
			Timestamp:  &now,
			Value:      aws.Float64(1.0),
			Unit:       aws.String(UnitCount),
		},
		&cloudwatch.MetricDatum{
			MetricName: aws.String(MetricProcessRunsSuccess),
			Dimensions: []*cloudwatch.Dimension{DimPrefixListNameBase(plm.request.PrefixListNameBase)},
			Timestamp:  &now,
			Value:      aws.Float64(success),
			Unit:       aws.String(UnitCount),
		})

	// Send metrics in batches (20 is the limit for the number of metrics accepted in a single PutMetrics call).
	nMetrics := uint(len(metrics))
	for i := uint(0); i < nMetrics; i += MetricsBatchSize {
		end := i + 20
		if end > nMetrics {
			end = nMetrics
		}

		batch := metrics[i:end]
		_, err := plm.cw.PutMetricData(&cloudwatch.PutMetricDataInput{
			Namespace: plm.request.Metrics.Namespace, MetricData: batch})
		if err != nil {
			log.Printf("Failed to write metrics batch to CloudWatch: %v", err)
		}
	}
}

// NotifySNS publishes a notification to SNS from the operations performed.
func (plm *PrefixListManager) notifySNS() {
	// Don't notify if we didn't perform updates
	if !plm.ipv4.updatesPerformed && !plm.ipv6.updatesPerformed {
		return
	}

	notification, err := json.Marshal(PrefixListNotification{
		PrefixListNameBase: plm.request.PrefixListNameBase,
		IPv4:               &plm.ipv4.notification,
		IPv6:               &plm.ipv6.notification,
	})

	if err != nil {
		log.Printf("Failed to marshal notification structure: %v", err)
		return
	}

	notificationStr := string(notification)

	for _, topicARN := range plm.request.SNSTopicARNs {
		result, err := plm.sns.Publish(
			&sns.PublishInput{TopicArn: &topicARN, Subject: &plm.request.SNSSubject, Message: &notificationStr})
		if err != nil {
			log.Printf("Failed to send notification to %s: %v", topicARN, err)
		} else {
			log.Printf("Notification sent to %s (message id: %s)", topicARN, aws.StringValue(result.MessageId))
		}
	}
}

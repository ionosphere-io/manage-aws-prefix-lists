package main

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
)

// DefaultPrefixListNameTemplate is the default template used when a template is not specified.
const DefaultPrefixListNameTemplate string = "{{.PrefixListNameBase}}.{{lower .AddressFamily}}.{{.GroupID}}"

// DefaultSNSSubject is the default subject used when an SNS subject is not specified.
const DefaultSNSSubject string = "ManageAWSPrefixLists Update"

// DefaultIPRangesURL is the default URL used to retrieve ip-ranges.json
const DefaultIPRangesURL string = "https://ip-ranges.amazonaws.com/ip-ranges.json"

// DefaultGroupSize is the default group size used when the group size is not specified.
const DefaultGroupSize uint = 60

// MaxRetries is the maximum number of times to retry an API call
const MaxRetries uint = 5

// MetricsBatchSize is the number of metrics to write to CloudWatch in a single PutMetrics call.
const MetricsBatchSize uint = 20

// SleepDuration is the amount of time to sleep before refreshing state
const SleepDuration time.Duration = 200 * time.Millisecond

const (
	// DimNameAddressFamily is the CloudWatch metrics dimension name for the AddressFamily dimension.
	DimNameAddressFamily string = "AddressFamily"

	// DimNameGroupID is the CloudWatch metrics dimension name for the GroupId dimension.
	DimNameGroupID string = "GroupID"

	// DimNamePrefixListNameBase is the CloudWatch metrics dimension name for the PrefixListNameBase dimension.
	DimNamePrefixListNameBase string = "PrefixListNameBase"

	// MetricAggregatedPrefixes is the CloudWatch metrics name for the AggregatedPrefixes metric.
	// This is the number of IP prefixes after aggregation has been performed and has an associated unit of Count.
	MetricAggregatedPrefixes string = "AggregatedPrefixes"

	// MetricCreatePrefixListGroup is the CloudWatch metrics name for the CreatePrefixListGroup metric.
	// This measures the total amount of time required to create a prefix list and has an associated unit of Milliseconds.
	// Measuring the SampleCount statistic will return the number of prefix list creation attempts.
	MetricCreatePrefixListGroup string = "CreatePrefixListGroup"

	// MetricCreatePrefixListGroupSuccess is the CloudWatch metrics name for the CreatePrefixListGroup:Success metric.
	// This measures the total amount of time required on calls that successfully created a prefix list and has an associated unit
	// of Milliseconds. Measuring the SampleCount statistic will return the number of prefix lists created.
	MetricCreatePrefixListGroupSuccess string = "CreatePrefixListGroup:Success"

	// MetricDescribeSecurityGroups is the CloudWatch Metrics name for the DescribeSecurityGroups metric.
	// This measures the total amount of time required to describe the security groups associated with a prefix list and has
	// an associated unit of Milliseconds. Measuring the SampleCount statistic will return the number of times security groups
	// were described.
	MetricDescribeSecurityGroups string = "DescribeSecurityGroups"

	// MetricExaminePrefixListGroup is the CloudWatch Metrics name for the ExaminePrefixListGroup metric.
	// This measures the total amount of time required to examine a prefix list and perform any update or replacement operations
	// that are needed, and has an associated unit of Milliseconds. Measuring the SampleCount statistic will return the number of
	// attempts made to examine a prefix list.
	MetricExaminePrefixListGroup string = "ExaminePrefixList"

	// MetricGetManagedPrefixListEntries is the CloudWatch Metrics name for the GetManagedPrefixListEntries metric.
	// This measures the amount of time taken to retrieve the prefix list entries for a given prefix list (which can be multiple
	// AWS API calls under the hood) and has an associated unit of Milliseconds. Measuring the SampleCount statistic will return
	// the number of attempts made to get the prefix list entries.
	MetricGetManagedPrefixListEntries string = "GetManagedPrefixListEntries"

	// MetricGetManagedPrefixListEntriesSuccess is the CloudWatch Metrics name for the
	// GetManagedPrefixListEntries:Success metric.
	//
	// This measures the amount of time taken for a successful call to retrieve the prefix list entries for a given prefix list
	// (which can be multiple AWS API calls under the hood) and has an associated unit of Milliseconds. Measuring the SampleCount
	// statistic will return the number of successful calls at getting the prefix list entries.
	MetricGetManagedPrefixListEntriesSuccess string = "GetManagedPrefixListEntries:Success"

	// MetricGetPrefixListAssociations is the CloudWatch Metrics name for the GetPrefixListAssociations metric.
	//
	// This measures the amount of time taken to retrieve the security groups associated with a prefix list and has an associated
	// unit of Milliseconds. Measuring the SampleCount statistic will return the number of times this operation was performed.
	MetricGetPrefixListAssociations string = "GetPrefixListAssociations"

	// MetricGetPrefixListAssociationsSuccess is the CloudWatch Metrics name for the GetPrefixListAssociations:Success metric.
	//
	// This measures the amount of time taken for a successfull call to retrieve the security groups associated with a prefix list
	// and has an associated unit of Milliseconds. Measuring the SampleCount statistic will return the number of times this
	// operation was performed.
	MetricGetPrefixListAssociationsSuccess string = "GetPrefixListAssociations:Success"

	// MetricGroups is the CloudWatch metrics name for the Groups metric.
	//
	// This measures the number of groups a prefix list is divided into and has an associated unit of Count.
	MetricGroups string = "Groups"

	// MetricOperationsAttempted is the CloudWatch Metrics name for the OperationsAttempted metric.
	//
	// This measures the number of operations that were attempted in a single run of the prefix list manager.
	MetricOperationsAttempted string = "OperationsAttempted"

	// MetricOperationsSucceeded is the CloudWatch Metrics name for the OperationsSucceeded metric.
	//
	// This measures the number of operations that were attempted in a single run of the prefix list manager.
	MetricOperationsSucceeded string = "OperationsSucceeded"

	// MetricPrefixes is the CloudWatch metrics name for the Prefixes metric.
	//
	// This measures the number of IP prefixes returned by an operation, either the total number in ip-ranges.json (with no
	// associated dimensions or after filtering (with AddressFamily and PrefixListNameBase dimensions) and has an associated unit
	// of Count.
	MetricPrefixes string = "Prefixes"

	// MetricReplacePrefixListGroup is the CloudWatch metrics name for the ReplacePrefixListGroup metric.
	// This indicates that a prefix list group had to be replaced and measures the amount of time taken to perform this operation.
	// Measuring the SampleCount statistic will return the number of times a prefix list group had to be replaced.
	MetricReplacePrefixListGroup string = "ReplacePrefixListGroup"

	// MetricUpdatePrefixListGroup is the CloudWatch metrics name for the UpdatePrefixListGroup metric.
	// This indicates that a prefix list group had entries that needed to be updated and measures the amount of time taken to
	// perform this operation. Measuring the SampleCount statistic will return the number of times a prefix list group had to be
	// updated.
	MetricUpdatePrefixListGroup string = "UpdatePrefixListGroup"

	// MetricUpdatePrefixListGroupSuccess is the CloudWatch metrics name for the UpdatePrefixListGroup:Success metric.
	// This indicates that a prefix list group successfully had entries updated and measures the amount of time taken to perform
	// this operation. Measuring the SampleCount statistic will return the number of times a prefix list group was successfully
	// updated.
	MetricUpdatePrefixListGroupSuccess string = "UpdatePrefixListGroup:Success"

	// FilterOwnerID is the EC2 filter name for filtering based on owner account numbers.
	FilterOwnerID string = "owner-id"

	// FilterPrefixListName is the EC2 filter name for filtering based on prefix list names.
	FilterPrefixListName string = "prefix-list-name"

	// FilterTagGroupID is the EC2 filter name for filtering based on GroupId tag values.
	FilterTagGroupID string = "tag:GroupId"

	// UnitCount is the CloudWatch metrics unit name for counted metrics.
	UnitCount string = "Count"

	// UnitMilliseconds is the CloudWatch metrics unit name for millisecond-based metrics.
	UnitMilliseconds string = "Milliseconds"
)

// ManageAWSPrefixListsRequest is the structure an incoming event is expected to adhere to.
type ManageAWSPrefixListsRequest struct {
	// PrefixListNameBase is the base name of the prefix lists that will be created. PrefixListNameTemplate is used to generate the
	// full name of the prefix list.
	PrefixListNameBase string

	// PrefixListNameTemplate is a text template to use to generate a prefix list name. The template may contain the following
	// parameters:
	// {{.PrefixListNameBase}} -- the value of PrefixListNameBase.
	// {{.AddressFamily}} -- either IPv4 or IPv6. This is typically used lowercased with {{lower .AddressFamily}}.
	// {{.GroupID}} -- an integer group number for this address type, starting from 0.
	// {{.GroupCount}} -- the total number of groups for this address type.
	//
	// The standard Go template functions are available (notably print and printf). In addition, the following functions are
	// defined:
	// {{upper v}} -- v uppercased ({{upper "aSDf qWERty"}} -> "ASDF QWERTY").
	// {{lower v}} -- v lowercased ({{lower "aSDf qWERty"}} -> "asdf qwerty").
	// {{title v}} -- v titlecased ({{title "aSDf qWERty"}} -> "Asdf Qwerty").
	// {{trim v}} -- v with whitespace at the beginning and end removed ({{trim " asdf\n\t "}} -> "asdf").
	// {{trimleft v}} -- v with whitespace at the beginning removed ({{trimleft " asdf\n\t "}} -> "asdf\n\t ").
	// {{trimright v}} -- v with whitespace at the end removed ({{trimright " asdf\n\t "}} -> "asdf\n\t ").
	// {{trim v x}} -- v with characters from x at the beginning and end removed ({{trim " asdf\n\t " " \n"}} -> "asdf\t").
	// {{trimleft v x}} -- v with characters from x at the beginning removed ({{trimleft " asdf\n\t " " a"}} -> "sdf\n\t ").
	// {{trimright v x}} -- v with characters from x at the end removed ({{trimright " asdf\n\t " " \n"}} -> " asdf\n\t").
	// {{replace v x y}} -- v with occurences of x replaced with y ({{replace "asdf qwerty" " " ""}} -> "asdfqwerty").
	//
	// The default PrefixListNameTemplate is "{{.PrefixListNameBase}}.{{lower .AddressFamily}}.{{.GroupID}}"
	PrefixListNameTemplate *template.Template

	// PrefixListTags is a mapping of tags to apply when creating or updating a prefix list
	PrefixListTags TagMap

	// Filters is a list of filters to apply to ip-ranges.json to filter the results. At least one filter must be specified.
	Filters []IPRangesFilter

	// Metrics contains information about the metrics to write.
	Metrics PrefixListMetrics

	// SSMParameters contains information about AWS Systems Manager parameters to write to. If unspecified or null, SSM parameters
	// are not written.
	SSMParameters SSMParameters

	// SNSSubject is the subject to use when publishing notifications to AWS Simple Notification Service (SNS). If unspecified,
	// "ManageAWSPrefixLists Update" is used.
	SNSSubject string

	// SNSTopicARNs is a list of SNS topic ARNs to publish notifications to. If unspecified, SNS notifications are not sent.
	SNSTopicARNs []string

	// IPRangesURL is the URL to retrieve the ip-ranges.json document from. This defaults to
	// "https://ip-ranges.amazonaws.com/ip-ranges.json".
	IPRangesURL string

	// GroupSize is the maximum number of CIDR blocks to create in a prefix list. This defaults to 60.
	GroupSize uint
}

type manageAWSPrefixListsRequestRaw struct {
	PrefixListNameBase     string             `json:"PrefixListNameBase"`
	PrefixListNameTemplate *string            `json:"PrefixListNameTemplate"`
	PrefixListTags         TagMap             `json:"PrefixListTags"`
	Filters                []IPRangesFilter   `json:"Filters"`
	Metrics                *PrefixListMetrics `json:"Metrics"`
	SSMParameters          *SSMParameters     `json:"SSMParameters"`
	SNSSubject             *string            `json:"SNSSubject"`
	SNSTopicARNs           []string           `json:"SNSTopicARNs"`
	IPRangesURL            *string            `json:"IPRangesURL"`
	GroupSize              *uint              `json:"GroupSize"`
}

// UnmarshalJSON converts JSON data to a ManageAWSPrefixListsRequest
func (req *ManageAWSPrefixListsRequest) UnmarshalJSON(data []byte) error {
	var raw manageAWSPrefixListsRequestRaw
	raw.PrefixListTags = make(TagMap)
	raw.SSMParameters = new(SSMParameters)

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	var templateBody string
	if raw.PrefixListNameTemplate == nil {
		templateBody = DefaultPrefixListNameTemplate
	} else {
		templateBody = *raw.PrefixListNameTemplate
	}

	tpl, err := template.New("PrefixListNameTemplate").Option("missingkey=error").Funcs(TemplateFuncs).Parse(templateBody)
	if err != nil {
		return fmt.Errorf("Invalid PrefixListNameTemplate: %s: %v", templateBody, err)
	}

	if len(raw.Filters) == 0 {
		return fmt.Errorf("At least one filter must be specified in Filters")
	}

	metrics := PrefixListMetrics{}
	if raw.Metrics != nil {
		metrics = *raw.Metrics
	}

	var ssmParameters SSMParameters
	if raw.SSMParameters != nil {
		log.Printf("Got SSMParameters: %T %v", raw.SSMParameters, raw.SSMParameters)
		ssmParameters = *raw.SSMParameters
	}

	var snsSubject string
	if raw.SNSSubject == nil {
		snsSubject = DefaultSNSSubject
	} else if len(*raw.SNSSubject) == 0 {
		return fmt.Errorf("SNSSubject cannot be empty")
	} else {
		snsSubject = *raw.SNSSubject
	}

	for _, topicARN := range raw.SNSTopicARNs {
		parsedARN, err := arn.Parse(topicARN)
		if err != nil {
			return fmt.Errorf("Invalid SNSTopicARN: %s: %v", topicARN, err)
		}

		if parsedARN.Service != "sns" {
			return fmt.Errorf("SNSTopicARN is not an SNS ARN: %s", topicARN)
		}
	}

	var ipRangesURL string
	if raw.IPRangesURL == nil {
		ipRangesURL = DefaultIPRangesURL
	} else {
		ipRangesURL = *raw.IPRangesURL
	}

	var groupSize uint
	if raw.GroupSize == nil {
		groupSize = DefaultGroupSize
	} else {
		groupSize = *raw.GroupSize
		if groupSize == 0 || groupSize > 1000 {
			return fmt.Errorf("GroupSize must be between 1 and 1000: %v", groupSize)
		}
	}

	req.PrefixListNameBase = raw.PrefixListNameBase
	req.PrefixListNameTemplate = tpl
	req.PrefixListTags = raw.PrefixListTags
	req.Filters = raw.Filters
	req.Metrics = metrics
	req.SSMParameters = ssmParameters
	req.SNSSubject = snsSubject
	req.SNSTopicARNs = raw.SNSTopicARNs
	req.IPRangesURL = ipRangesURL
	req.GroupSize = groupSize

	return nil
}

// IPRangesFilter is a filter for the ip-ranges.json file.
type IPRangesFilter struct {
	AddressFamily           AddressFamily
	RegionRegex             *regexp.Regexp
	ServiceRegex            *regexp.Regexp
	NetworkBorderGroupRegex *regexp.Regexp
}

// ipRangesFilterRaw represents the raw JSON message passed to us for an IPRangesFilter expression.
type ipRangesFilterRaw struct {
	AddressFamily           AddressFamily `json:"AddressFamily"`
	Region                  *string       `json:"Region"`
	RegionRegex             *string       `json:"RegionRegex"`
	Service                 *string       `json:"Service"`
	ServiceRegex            *string       `json:"ServiceRegex"`
	NetworkBorderGroup      *string       `json:"NetworkBorderGroup"`
	NetworkBorderGroupRegex *string       `json:"NetworkBorderGroupRegex"`
}

// UnmarshalJSON converts JSON data to an IPRangesFilter.
func (irf *IPRangesFilter) UnmarshalJSON(data []byte) error {
	var raw ipRangesFilterRaw

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	regionRegex, err := parseStringOrRegexp("Region", raw.Region, raw.RegionRegex)
	if err != nil {
		return err
	}

	serviceRegex, err := parseStringOrRegexp("Service", raw.Service, raw.ServiceRegex)
	if err != nil {
		return err
	}

	networkBorderGroupRegex, err := parseStringOrRegexp("NetworkBorderGroup", raw.NetworkBorderGroup, raw.NetworkBorderGroupRegex)
	if err != nil {
		return err
	}

	irf.AddressFamily = raw.AddressFamily
	irf.RegionRegex = regionRegex
	irf.ServiceRegex = serviceRegex
	irf.NetworkBorderGroupRegex = networkBorderGroupRegex

	return nil
}

func parseStringOrRegexp(parameterName string, stringValue *string, regexValue *string) (*regexp.Regexp, error) {
	if stringValue == nil {
		if regexValue == nil {
			return MatchAllRegex, nil
		}

		re, err := regexp.Compile(*regexValue)
		if err != nil {
			return nil, fmt.Errorf("Invalid regular expression for %sRegexp: %s: %v", parameterName, *regexValue, err)
		}
		return re, nil
	}

	if regexValue == nil {
		return regexp.MustCompile(fmt.Sprintf("^%s$", regexp.QuoteMeta(*stringValue))), nil
	}

	return nil, fmt.Errorf("Cannot specify both %s and %sRegexp parameters in filter", parameterName, parameterName)
}

// AddressFamily is an enumeration of the possible types of IP addresses to filter on.
type AddressFamily uint

const (
	// AddressFamilyAll indicates all types of IP addresses (IPv4, IPv6) should be queried
	AddressFamilyAll AddressFamily = iota

	// AddressFamilyIPv4 indicates only IPv4 addresses should be queried
	AddressFamilyIPv4

	// AddressFamilyIPv6 indicates only IPv6 addresses should be queried
	AddressFamilyIPv6
)

// UnmarshalJSON converts JSON string to an AddressFamily.
func (ipate *AddressFamily) UnmarshalJSON(data []byte) error {
	var rawValue string
	if err := json.Unmarshal(data, &rawValue); err != nil {
		return err
	}

	switch rawValue {
	case "ALL":
		*ipate = AddressFamilyAll
	case "IPv4":
		*ipate = AddressFamilyIPv4
	case "IPv6":
		*ipate = AddressFamilyIPv6
	default:
		return fmt.Errorf("Invalid value for AddressFamily; expected \"ALL\", \"IPv4\", or \"IPv6\": %v", string(data))
	}

	return nil
}

// PrefixListMetrics contains information about where and what type of metrics to write.
type PrefixListMetrics struct {
	Namespace *string `json:"Namespace"`
	Verbosity int     `json:"Verbosity"`
}

type rawPrefixListMetrics PrefixListMetrics

func (plm *PrefixListMetrics) UnmarshalJSON(data []byte) error {
	var raw rawPrefixListMetrics
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if raw.Namespace != nil {
		if len(*raw.Namespace) == 0 {
			return fmt.Errorf("Metrics.Namespace cannot be empty")
		}
		if strings.HasPrefix(*raw.Namespace, ":") {
			return fmt.Errorf("Metrics.Namespace cannot start with ':'")
		}
	}

	plm.Namespace = raw.Namespace
	plm.Verbosity = raw.Verbosity

	return nil
}

// SSMParameters contains information about the SSM parameters to write to.
type SSMParameters struct {
	// IPv4Parameters is a list of SSM parameter names to write IPv4 prefix list IDs to.
	IPv4Parameters []string `json:"IPv4Parameters"`

	// IPv6Parametes is a list of SSM parameter names to write IPv6 prefix list IDs to.
	IPv6Parameters []string `json:"IPv6Parameters"`

	// Tags is a map of key-value pairs OR a list of {"Key": key, "Value": value} tuples.
	Tags TagMap `json:"Tags"`

	// Tier is the SSM tier to use: "Standard", "Advanced", or "Intelligent-Tiering". If unspecified, this defaults to "Standard".
	Tier string `json:"Tier"`
}

type ssmParametersRaw struct {
	// IPv4Parameters is a list of SSM parameter names to write IPv4 prefix list IDs to.
	IPv4Parameters []string `json:"IPv4Parameters"`

	// IPv6Parametes is a list of SSM parameter names to write IPv6 prefix list IDs to.
	IPv6Parameters []string `json:"IPv6Parameters"`

	// Tags is a map of key-value pairs OR a list of {"Key": key, "Value": value} tuples.
	Tags TagMap `json:"Tags"`

	// Tier is the SSM tier to use: "Standard", "Advanced", or "Intelligent-Tiering". If unspecified, this defaults to "Standard".
	Tier string `json:"Tier"`
}

// UnmarshalJSON converts a JSON value to an SSMParameters struct
func (sp *SSMParameters) UnmarshalJSON(data []byte) error {
	raw := ssmParametersRaw{Tags: make(TagMap)}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	sp.IPv4Parameters = raw.IPv4Parameters
	sp.IPv6Parameters = raw.IPv6Parameters
	sp.Tags = raw.Tags
	sp.Tier = raw.Tier

	return nil
}

// TagMap is a mapping of key-value pairs.
type TagMap map[string]string

// UnmarshalJSON converts JSON data to a TagMap.
//
// This is customized to allow two different formats:
//
// * The AWS format, containing an array of JSON objects in the form: [{"Key": "tagKey", "Value": "tagValue"}, ...]
// * The Terraform format, consisting of a JSON object in the form: {"tagKey": "tagValue", ...}
func (tm *TagMap) UnmarshalJSON(data []byte) error {
	var value interface{}

	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	if listOfKV, ok := value.([]interface{}); ok {
		for _, el := range listOfKV {
			if kv, ok := el.(map[string]interface{}); ok {
				keyAny, keyPresent := kv["Key"]
				valueAny, valuePresent := kv["Value"]

				if !keyPresent || !valuePresent || len(kv) != 2 {
					return fmt.Errorf("Invalid element for Tags: expected a map containing a string \"Key\" and string \"Value\": %v", el)
				}

				key, keyOk := keyAny.(string)
				value, valueOk := valueAny.(string)
				if !keyOk || !valueOk {
					return fmt.Errorf("Invalid element for Tags: expected a map containing a string \"Key\" and string \"Value\": %v", el)
				}

				(*tm)[key] = value
			} else {
				return fmt.Errorf("Invalid element for Tags: expected a map containing a string \"Key\" and string \"Value\": %v", el)
			}
		}
	} else if mapOfKV, ok := value.(map[string]interface{}); ok {
		for key, valueAny := range mapOfKV {
			value, valueOk := valueAny.(string)
			if !valueOk {
				return fmt.Errorf("Invalid value for Tags[%s]: value is not a string: %#v", key, valueAny)
			}
			(*tm)[key] = value
		}
	} else {
		return fmt.Errorf("Invalid value for Tags: expected a list of maps containing \"Key\" and \"Value\" pairs or a map of keys-to-values: %v", string(data))
	}

	return nil
}

// TierEnum is an enumeration of the possible SSM tiers.
type TierEnum uint

const (
	// TierStandard represents the standard SSM tier.
	TierStandard TierEnum = iota

	// TierAdvanced represents the advanced SSM tier.
	TierAdvanced

	// TierIntelligentTiering represents the intelligent tiering SSM tier.
	TierIntelligentTiering
)

// UnmarshalJSON converts JSON data to a TierEnum.
func (te *TierEnum) UnmarshalJSON(data []byte) error {
	var rawValue string
	if err := json.Unmarshal(data, &rawValue); err != nil {
		return err
	}

	switch rawValue {
	case "Standard":
		*te = TierStandard
	case "Advanced":
		*te = TierAdvanced
	case "Intelligent-Tiering":
		*te = TierIntelligentTiering
	default:
		return fmt.Errorf(`Invalid value for Tier; expected "Standard", "Advanced", or "Intelligent-Tiering": %v`, string(data))
	}

	return nil
}

// ManageAWSPrefixListsResponse is the response message returned by the handler
type ManageAWSPrefixListsResponse struct {
	Status     string
	Operations []PrefixListManagementOp
}

// PrefixListTemplateVars is a structure holding the variables needed to render the prefix list name from a template.
type PrefixListTemplateVars struct {
	PrefixListNameBase string
	AddressFamily      string
	GroupID            string
	GroupCount         string
}

// MetricRecorder is an interface implemented by types that can hold or report metric datums to CloudWatch.
// This is implemented by PrefixListAddressManager and PrefixListAddressFamilyManager.
type MetricRecorder interface {
	AddMetric(*cloudwatch.MetricDatum)
	CreateMetric() *cloudwatch.MetricDatum
}

// AddMetric records a metric on any type that implmenets MetricRecorder.
// This creates a CloudWatch metric datum with the specified name, value, and unit and saves it to the metric recorder.
func AddMetric(mr MetricRecorder, name string, value float64, unit string, dimensions ...*cloudwatch.Dimension) {
	datum := mr.CreateMetric().SetMetricName(name).SetValue(value).SetUnit(unit)
	datum.Dimensions = append(datum.Dimensions, dimensions...)
	mr.AddMetric(datum)
}

// MetricTimer represents a time metric (either in-progress or completed).
type MetricTimer struct {
	MetricRecorder MetricRecorder
	Datum          *cloudwatch.MetricDatum
	StartTime      time.Time
	Elapsed        time.Duration
}

// Time starts a time metric with the specified metric name. It returns a callback to complete the timer.
func Time(mr MetricRecorder, name string, dimensions ...*cloudwatch.Dimension) *MetricTimer {
	datum := mr.CreateMetric().SetMetricName(name).SetUnit(UnitMilliseconds)
	datum.Dimensions = append(datum.Dimensions, dimensions...)

	return &MetricTimer{
		MetricRecorder: mr, Datum: datum, StartTime: time.Now().UTC(),
	}
}

// Done completes a time metric
func (mt *MetricTimer) Done() {
	mt.Elapsed = time.Now().UTC().Sub(mt.StartTime)
	mt.Datum.SetValue(float64(mt.Elapsed.Milliseconds()))
	mt.MetricRecorder.AddMetric(mt.Datum)
}

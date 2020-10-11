package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"
	"unicode"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// MatchAllRegex is a regular expression that matches everything.
var MatchAllRegex *regexp.Regexp

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

// SleepDuration is the amount of time to sleep before refreshing state
const SleepDuration time.Duration = 200 * time.Millisecond

// TemplateFuncs is a map of template functions.
var TemplateFuncs template.FuncMap

func init() {
	MatchAllRegex = regexp.MustCompile(".*")

	TemplateFuncs = make(template.FuncMap)
	TemplateFuncs["upper"] = strings.ToUpper
	TemplateFuncs["lower"] = strings.ToLower
	TemplateFuncs["title"] = strings.Title
	TemplateFuncs["replace"] = strings.Replace
	TemplateFuncs["trim"] = func(args ...string) (string, error) {
		switch len(args) {
		case 0:
			return "", nil
		case 1:
			return strings.TrimFunc(args[0], unicode.IsSpace), nil
		case 2:
			return strings.Trim(args[0], args[1]), nil
		default:
			return "", fmt.Errorf("Too many arguments passed to trim function: %v", args)
		}
	}
	TemplateFuncs["trimleft"] = func(args ...string) (string, error) {
		switch len(args) {
		case 0:
			return "", nil
		case 1:
			return strings.TrimLeftFunc(args[0], unicode.IsSpace), nil
		case 2:
			return strings.TrimLeft(args[0], args[1]), nil
		default:
			return "", fmt.Errorf("Too many arguments passed to trim function: %v", args)
		}
	}
	TemplateFuncs["trimright"] = func(args ...string) (string, error) {
		switch len(args) {
		case 0:
			return "", nil
		case 1:
			return strings.TrimRightFunc(args[0], unicode.IsSpace), nil
		case 2:
			return strings.TrimRight(args[0], args[1]), nil
		default:
			return "", fmt.Errorf("Too many arguments passed to trim function: %v", args)
		}
	}
}

// IPRanges is the structure of the ip-ranges.json document.
type IPRanges struct {
	SyncToken    string       `json:"syncToken"`
	CreateDate   string       `json:"createDate"`
	Prefixes     []IPv4Prefix `json:"prefixes"`
	IPv6Prefixes []IPv6Prefix `json:"ipv6_prefixes"`
}

// IPPrefix is a common interface for IPv4Prefix and IPv6Prefix
type IPPrefix interface {
	GetAddressType() IPAddressTypeEnum
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
func (ip *IPv4Prefix) GetAddressType() IPAddressTypeEnum {
	return IPAddressTypeIPv4
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
func (ip *IPv6Prefix) GetAddressType() IPAddressTypeEnum {
	return IPAddressTypeIPv6
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

	// MetricsNamespace is the CloudWatch metrics namespace to write metrics to. If unspecified or null, metrics are not published.
	MetricsNamespace string

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
	PrefixListNameBase     string           `json:"PrefixListNameBase"`
	PrefixListNameTemplate *string          `json:"PrefixListNameTemplate"`
	PrefixListTags         TagMap           `json:"PrefixListTags"`
	Filters                []IPRangesFilter `json:"Filters"`
	MetricsNamespace       *string          `json:"MetricsNamespace"`
	SSMParameters          *SSMParameters   `json:"SSMParameters"`
	SNSSubject             *string          `json:"SNSSubject"`
	SNSTopicARNs           []string         `json:"SNSTopicARNs"`
	IPRangesURL            *string          `json:"IPRangesURL"`
	GroupSize              *uint            `json:"GroupSize"`
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

	var metricsNamespace string
	if raw.MetricsNamespace != nil {
		if len(*raw.MetricsNamespace) == 0 {
			return fmt.Errorf("MetricsNamespace cannot be empty")
		}
		if strings.HasPrefix(*raw.MetricsNamespace, ":") {
			return fmt.Errorf("MetricsNamespace cannot start with ':'")
		}

		metricsNamespace = *raw.MetricsNamespace
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
	req.MetricsNamespace = metricsNamespace
	req.SSMParameters = ssmParameters
	req.SNSSubject = snsSubject
	req.SNSTopicARNs = raw.SNSTopicARNs
	req.IPRangesURL = ipRangesURL
	req.GroupSize = groupSize

	return nil
}

// IPRangesFilter is a filter for the ip-ranges.json file.
type IPRangesFilter struct {
	IPAddressType           IPAddressTypeEnum
	RegionRegex             *regexp.Regexp
	ServiceRegex            *regexp.Regexp
	NetworkBorderGroupRegex *regexp.Regexp
}

// ipRangesFilterRaw represents the raw JSON message passed to us for an IPRangesFilter expression.
type ipRangesFilterRaw struct {
	IPAddressType           IPAddressTypeEnum `json:"IPAddressType"`
	Region                  *string           `json:"Region"`
	RegionRegex             *string           `json:"RegionRegex"`
	Service                 *string           `json:"Service"`
	ServiceRegex            *string           `json:"ServiceRegex"`
	NetworkBorderGroup      *string           `json:"NetworkBorderGroup"`
	NetworkBorderGroupRegex *string           `json:"NetworkBorderGroupRegex"`
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

	irf.IPAddressType = raw.IPAddressType
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

// IPAddressTypeEnum is an enumeration of the possible types of IP addresses to filter on.
type IPAddressTypeEnum uint

const (
	// IPAddressTypeAll indicates all types of IP addresses (IPv4, IPv6) should be queried
	IPAddressTypeAll IPAddressTypeEnum = iota

	// IPAddressTypeIPv4 indicates only IPv4 addresses should be queried
	IPAddressTypeIPv4

	// IPAddressTypeIPv6 indicates only IPv6 addresses should be queried
	IPAddressTypeIPv6
)

// UnmarshalJSON converts JSON data to an IPAddressTypeEnum
func (ipate *IPAddressTypeEnum) UnmarshalJSON(data []byte) error {
	var rawValue string
	if err := json.Unmarshal(data, &rawValue); err != nil {
		return err
	}

	switch rawValue {
	case "ALL":
		*ipate = IPAddressTypeAll
	case "IPv4":
		*ipate = IPAddressTypeIPv4
	case "IPv6":
		*ipate = IPAddressTypeIPv6
	default:
		return fmt.Errorf("Invalid value for IPAddressTypeEnum; expected \"ALL\", \"IPv4\", or \"IPv6\": %v", string(data))
	}

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
func (tm *TagMap) UnmarshalJSON(data []byte) error {
	var value interface{}

	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	if listOfKV, ok := value.([]interface{}); ok {
		for _, el := range listOfKV {
			if kv, ok := el.(map[string]string); ok {
				key, keyPresent := kv["Key"]
				value, valuePresent := kv["Value"]

				if !keyPresent || !valuePresent {
					return fmt.Errorf("Invalid element for Tags: expected a map containing \"Key\" and \"Value\": %v", el)
				}
				(*tm)[key] = value
			} else {
				return fmt.Errorf("Invalid element for Tags: expected a map containing \"Key\" and \"Value\": %v", el)
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
		return fmt.Errorf("Invalid value for IPAddressTypeEnum; expected \"ALL\", \"IPv4\", or \"IPv6\": %v", string(data))
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

// PrefixListManagementOp describes the result of a prefix list management operation.
type PrefixListManagementOp struct {
	PrefixListName       string
	AddressFamily        string
	Operation            OperationType
	ExistingPrefixListID string
	NewPrefixListID      string
	SecurityGroupID      string
	SSMParameterName     string
	Error                error
}

type prefixListManagementOpJSON struct {
	Operation            OperationType     `json:"Operation"`
	AddressFamily        string            `json:"AddressFamily"`
	PrefixListName       string            `json:"PrefixListName,omitempty"`
	ExistingPrefixListID string            `json:"ExistingPrefixListId,omitempty"`
	NewPrefixListID      string            `json:"NewPrefixListId,omitempty"`
	SecurityGroupID      string            `json:"SecurityGroupId,omitempty"`
	SSMParameterName     string            `json:"SSMParameterName,omitempty"`
	Error                map[string]string `json:"Error,omitempty"`
}

// MarshalJSON converts a PrefixListManagementOp to JSON format.
//
// This has special logic for formatting the Error field to a string.
func (plmop *PrefixListManagementOp) MarshalJSON() ([]byte, error) {
	raw := prefixListManagementOpJSON{
		PrefixListName: plmop.PrefixListName, AddressFamily: plmop.AddressFamily, Operation: plmop.Operation,
		ExistingPrefixListID: plmop.ExistingPrefixListID, NewPrefixListID: plmop.NewPrefixListID,
		SecurityGroupID: plmop.NewPrefixListID,
	}

	if plmop.Error != nil {
		raw.Error = make(map[string]string)

		if awsErr, ok := plmop.Error.(awserr.Error); ok {
			raw.Error["Type"] = "AWSError"
			raw.Error["Code"] = awsErr.Code()
			raw.Error["Message"] = awsErr.Message()

			if origErr := awsErr.OrigErr(); origErr != nil {
				raw.Error["Cause"] = fmt.Sprintf("%v", origErr)
			}
		} else {
			raw.Error["Type"] = fmt.Sprintf("%T", plmop.Error)
			raw.Error["Code"] = "InternalError"
			raw.Error["Message"] = fmt.Sprintf("%v", plmop.Error)

			if cause := errors.Unwrap(plmop.Error); cause != nil {
				raw.Error["Cause"] = fmt.Sprintf("%v", cause)
			}
		}
	}

	return json.Marshal(&raw)
}

// OperationType enumerates the types of operations we can perform on a prefix list.
// This requires enumer: go get github.com/alvaroloes/enumer
type OperationType uint

//go:generate enumer -json -type=OperationType

const (
	// OpNoModifyPrefixList indicates that no modification to an existing prefix list was required.
	// ExistingPrefixListID will contain the prefix list id that was considered; NewPrefixListID will be empty.
	OpNoModifyPrefixList OperationType = iota

	// OpCreatePrefixList indicates that an existing prefix list was not found and a new one was created.
	// ExistingPrefixListID will be empty; NewPrefixListID will contain the prefix list id that was created.
	OpCreatePrefixList

	// OpUpdatePrefixListEntries indicates that an existing prefix list was found but had entries that needed to be replaced.
	// ExistingPrefixListID will contain the prefix list id that was modified; NewPrefixListID will be empty.
	OpUpdatePrefixListEntries

	// OpReplacePrefixList indicates that an existing prefix list was found but had an incompatible configuration.
	// ExistingPrefixListID will contain the prefix list id that was deleted; NewPrefixListID will contain the prefix list id that
	// was created in its place.
	OpReplacePrefixList

	// OpPrefixListQueryFailedError indicates that an error occurred when querying attributes on an existing prefix list.
	// Error will be populated with the error that occurred. ExistingPrefixListID will contain the prefix list id that could
	// not be queried (if any).
	OpPrefixListQueryFailedError

	// OpPrefixListCreateFailedError indicates that an error occurred when trying to create a new prefix list.
	// Error will be populated with the error that occurred. ExistingPrefixListID and NewPrefixListID will be empty.
	OpPrefixListCreateFailedError

	// OpPrefixListDeleteFailedError indicates that an error occurred when trying to delete an existing prefix list.
	// Error will be populated with the error that occurred. ExistingPrefixListID will contain the prefix list id that failed
	// to delete.
	OpPrefixListDeleteFailedError

	// OpPrefixListUpdateFailedError indicates that an error occurred when trying to modify an existing prefix list.
	// Error will be populated with the error that occurred. ExistingPrefixListID will contain the prefix list id that could
	// not be modified.
	OpPrefixListUpdateFailedError

	// OpUpdateSecurityGroupIngress indicates that a security group had ingress rules updated to point to a new prefix list.
	OpUpdateSecurityGroupIngress

	// OpUpdateSecurityGroupEgress indicates that a security group had egress rules updated to point to a new prefix list.
	OpUpdateSecurityGroupEgress

	// OpSecurityGroupQueryFailedError indicates that a query on security groups failed.
	// Error will be populated with the error that occurred. ExistingPrefixListID will contain the prefix list id that contained
	// referenced security groups.
	OpSecurityGroupQueryFailedError

	// OpSecurityGroupUpdateFailedError indicates that a security group could not be updated.
	// Error will be populated with the error that occurred. ExistingPrefixListID will contain the prefix list id that contained
	// referenced security group, and SecurityGroupID will contain the security group id that failed to update.
	OpSecurityGroupUpdateFailedError

	// OpNoModifySSMParameterValue indicates that an SSM parameter was up-to-date.
	// SSMParameterName will contain the name of the parameter that was queried but left intact.
	OpNoModifySSMParameterValue

	// OpSSMParameterCreated indicates that an SSM parameter was created.
	// SSMParameterName will contain the name of the parameter that was created.
	OpSSMParameterCreated

	// OpSSMParameterValueUpdated indicates that an SSM parameter value was updated.
	// SSMParameterName will contain the name of the parameter that was updated.
	OpSSMParameterValueUpdated

	// OpNoModifySSMParameterTags indicates that an SSM parameter's tags were up-to-date.
	// SSMParameterName will contain the name of the parameter that was queried but left intact.
	OpNoModifySSMParameterTags

	// OpSSMParameterTagsUpdated indicates that an SSM parameter had tags added or updated.
	// SSMParameterName will contain the name of the parameter that was updated.
	OpSSMParameterTagsUpdated

	// OpSSMQueryFailedError indicates that one or more SSM parameters could not be queried.
	// Error will be populated with the error that occurred.
	OpSSMQueryFailedError

	// OpSSMParameterCreateFailedError indicates that an SSM parameter could not be created.
	// Error will be populated with the error that occurred. SSMParameterName will contain the name of the parameter that failed
	// to update.
	OpSSMParameterCreateFailedError

	// OpSSMParameterValueUpdateFailedError indicates that an SSM parameter value could not be updated.
	// Error will be populated with the error that occurred. SSMParameterName will contain the name of the parameter that failed
	// to update.
	OpSSMParameterValueUpdateFailedError

	// OpSSMParameterTagsUpdateFailedError indicates that an SSM parameter could not have its tags updated.
	// Error will be populated with the error that occurred. SSMParameterName will contain the name of the parameter that failed
	// to update.
	OpSSMParameterTagsUpdateFailedError
)

// MakeEC2Filter creates an EC2 filter specification with the specified key and values
func MakeEC2Filter(name string, values ...string) *ec2.Filter {
	filterValues := make([]*string, len(values))
	for i, value := range values {
		filterValues[i] = aws.String(value)
	}

	return &ec2.Filter{Name: aws.String(name), Values: filterValues}
}

// MakeEC2Tags converts a TagMap to an array of EC2 Tags.
func MakeEC2Tags(tagMap TagMap) []*ec2.Tag {
	result := make([]*ec2.Tag, 0, len(tagMap))
	for key, value := range tagMap {
		result = append(result, &ec2.Tag{Key: aws.String(key), Value: aws.String(value)})
	}
	return result
}

// MakeEC2TagSpec converts a TagMap to a tag specification applied to a single resource.
func MakeEC2TagSpec(tagMap TagMap, resourceType *string) []*ec2.TagSpecification {
	tagSpec := ec2.TagSpecification{ResourceType: resourceType, Tags: MakeEC2Tags(tagMap)}
	return []*ec2.TagSpecification{&tagSpec}
}

// CompareIPNets compares two IP networks, ordering them first by IP address, then by prefix.
//
// This returns -1 if a < b, +1 if a > b, and 0 if a == b.
func CompareIPNets(a, b *net.IPNet) int {
	ipCompare := bytes.Compare(a.IP, b.IP)
	if ipCompare != 0 {
		return ipCompare
	}

	return bytes.Compare(a.Mask, b.Mask)
}

// SortIPNets sorts a slice of net.IPNet objects and removes any duplicates found.
func SortIPNets(nets []*net.IPNet) {
	sort.Slice(nets, func(i, j int) bool { return CompareIPNets(nets[i], nets[j]) < 0 })
}

// AggregateNetworks finds the smallest set of prefixes that encompasses a slice of IPNets.
//
// This is loosely based on the Python ipaddress.collapse_addresses() implementation in Python 3.8.
func AggregateNetworks(nets []*net.IPNet) []*net.IPNet {
	SortIPNets(nets)

	// toConsider is a list of the networks to consider for merging
	toConsider := nets

	// incompleteSupernets is a map of supernet CIDRs to the first subnet seen in the supernet
	incompleteSupernets := make(map[string]*net.IPNet)

	for len(toConsider) > 0 {
		// The next round of toConsider nets -- taken from any supernets we generate here.
		nextToConsider := make([]*net.IPNet, 0)

		// Go over our current list of toConsider nets
		for _, candidate := range toConsider {
			// Is the candidate the all-zero network?
			if maskSize, _ := candidate.Mask.Size(); maskSize == 0 {
				// Yes; we're done. The entire Internet is in the aggregation
				return []*net.IPNet{candidate}
			}

			supernet := GetSupernet(candidate)
			supernetStr := supernet.String()

			// Is the supernet in our incomplete list?
			existing, found := incompleteSupernets[supernetStr]
			if !found {
				// Nope; create the supernet and mark this candidate for inclusion
				incompleteSupernets[supernetStr] = candidate
			} else if !existing.IP.Equal(candidate.IP) {
				// We needed to make sure the existing net isn't a duplicate of this net.
				// This completes the supernet -- remove it from the incomplete list and add it to the nextToConsider
				nextToConsider = append(nextToConsider, supernet)
				delete(incompleteSupernets, supernetStr)
			}
		}

		toConsider = nextToConsider
	}

	result := make([]*net.IPNet, 0, len(incompleteSupernets))
	var lastEntry *net.IPNet

	// We add each subnet in the incompleteSupernets to the result (not the supernets -- they're incomplete).
	// While doing so, we make sure we're not including a more specific network from something we've just seen.
	for _, subnet := range incompleteSupernets {
		if lastEntry == nil || !lastEntry.Contains(subnet.IP) {
			result = append(result, subnet)
			lastEntry = subnet
		}
	}

	return result
}

// GetSupernet returns the network one-mask-size larger than the specified network.
func GetSupernet(subnet *net.IPNet) *net.IPNet {
	maskSize, totalSize := subnet.Mask.Size()
	if maskSize == 0 {
		// No supernet possible
		return subnet
	}

	supernetMask := net.CIDRMask(maskSize-1, totalSize)
	supernetIP := subnet.IP.Mask(supernetMask)
	return &net.IPNet{IP: supernetIP, Mask: supernetMask}
}

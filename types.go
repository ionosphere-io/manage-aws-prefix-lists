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

// SleepDuration is the amount of time to sleep before refreshing state
const SleepDuration time.Duration = 200 * time.Millisecond

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

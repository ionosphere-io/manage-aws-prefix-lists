package main

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"unicode"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// MatchAllRegex is a regular expression that matches everything.
var MatchAllRegex *regexp.Regexp

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

// CopyAWSString copies an AWS-style string from one pointer to another.
func CopyAWSString(value *string) *string {
	if value == nil {
		return nil
	}
	return aws.String(aws.StringValue(value))
}

// CopyAWSInt64 copies an AWS-style int64 from one pointer to another.
func CopyAWSInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	return aws.Int64(aws.Int64Value(value))
}

// DimAddressFamily creates a CloudWatch metrics dimension for the address family.
func DimAddressFamily(addressFamily string) *cloudwatch.Dimension {
	return &cloudwatch.Dimension{Name: aws.String(DimNameAddressFamily), Value: aws.String(addressFamily)}
}

// DimGroupID creates a CloudWatch metrics dimension for the group ID.
func DimGroupID(groupID uint) *cloudwatch.Dimension {
	return &cloudwatch.Dimension{Name: aws.String(DimNameGroupID), Value: aws.String(strconv.FormatUint(uint64(groupID), 10))}
}

// DimPrefixListNameBase create a CloudWatch metrics dimension for the prefix list name base.
func DimPrefixListNameBase(prefixListNameBase string) *cloudwatch.Dimension {
	return &cloudwatch.Dimension{Name: aws.String(DimNamePrefixListNameBase), Value: aws.String(prefixListNameBase)}
}

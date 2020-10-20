package main

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
)

type EC2Mock struct {
	ec2iface.EC2API

	managedPrefixLists map[string]*managedPrefixListAndEntries
	securityGroups     map[string]*ec2.SecurityGroup
}

func (m *EC2Mock) CreateManagedPrefixList(input *ec2.CreateManagedPrefixListInput) (*ec2.CreateManagedPrefixListOutput, error) {
	af := aws.StringValue(input.AddressFamily)

	if af != "IPv4" && af != "IPv6" {
		return nil, fmt.Errorf("Invalid value for AddressFamily: expected IPv4 or IPv6")
	}

	plIDNum := rand.Uint64() & 0x0ffffffffffffffff
	plID := fmt.Sprintf("pl-%x", plIDNum)

	var tags []*ec2.Tag
	for _, tagSpec := range input.TagSpecifications {
		if aws.StringValue(tagSpec.ResourceType) == "prefix-list" {
			for _, tag := range tagSpec.Tags {
				tags = append(tags, &ec2.Tag{Key: CopyAWSString(tag.Key), Value: CopyAWSString(tag.Value)})
			}
		}
	}

	var entries []*ec2.PrefixListEntry
	for _, entry := range input.Entries {
		entries = append(entries, &ec2.PrefixListEntry{Cidr: entry.Cidr, Description: entry.Description})
	}

	mpl := managedPrefixListAndEntries{
		PrefixList: ec2.ManagedPrefixList{
			AddressFamily:  CopyAWSString(input.AddressFamily),
			MaxEntries:     CopyAWSInt64(input.MaxEntries),
			PrefixListArn:  aws.String(fmt.Sprintf("arn:aws:ec2:us-west-2:123456789012:prefix-list/%s", plID)),
			PrefixListName: CopyAWSString(input.PrefixListName),
			PrefixListId:   &plID,
			State:          aws.String("create-complete"),
			Tags:           tags,
			Version:        aws.Int64(0),
		},
		Entries: entries,
	}

	if m.managedPrefixLists == nil {
		m.managedPrefixLists = make(map[string]*managedPrefixListAndEntries)
	}

	m.managedPrefixLists[plID] = &mpl
	return &ec2.CreateManagedPrefixListOutput{PrefixList: &(mpl.PrefixList)}, nil
}

func (m *EC2Mock) DeleteManagedPrefixList(input *ec2.DeleteManagedPrefixListInput) (*ec2.DeleteManagedPrefixListOutput, error) {
	if input.PrefixListId == nil {
		return nil, fmt.Errorf("PrefixListId must be specified")
	}

	// If the map hasn't been created, go ahead and create it; this will error out when we check for the prefix list.
	if m.managedPrefixLists == nil {
		m.managedPrefixLists = make(map[string]*managedPrefixListAndEntries)
	}

	prefixListID := *input.PrefixListId
	mpl, present := m.managedPrefixLists[prefixListID]
	if !present {
		return nil, fmt.Errorf("Managed prefix list with PrefixListId %v not found", prefixListID)
	}

	delete(m.managedPrefixLists, prefixListID)
	output := ec2.DeleteManagedPrefixListOutput{PrefixList: &mpl.PrefixList}
	return &output, nil
}

func (m *EC2Mock) DescribeManagedPrefixListsPages(input *ec2.DescribeManagedPrefixListsInput, iter func(*ec2.DescribeManagedPrefixListsOutput, bool) bool) error {
	var results []*ec2.ManagedPrefixList
	var maxResults int64

	if input.MaxResults == nil {
		maxResults = 100
	} else {
		maxResults = aws.Int64Value(input.MaxResults)
	}

mplLoop:
	for _, mpl := range m.managedPrefixLists {
		if len(input.PrefixListIds) > 0 {
			// Filter by prefix list id
			keep := false

			for _, plID := range input.PrefixListIds {
				if aws.StringValue(plID) == aws.StringValue(mpl.PrefixList.PrefixListId) {
					keep = true
					break
				}
			}

			// Not found in the list of prefix lists ids supplied; skip it.
			if !keep {
				continue
			}
		}

		for _, filter := range input.Filters {
			keep := true
			filterName := aws.StringValue(filter.Name)

			if filterName == "prefix-list-id" {
				keep = false
				for _, filterValue := range filter.Values {
					if aws.StringValue(mpl.PrefixList.PrefixListId) == aws.StringValue(filterValue) {
						keep = true
						break
					}
				}
			} else if filterName == "prefix-list-name" {
				keep = false
				for _, filterValue := range filter.Values {
					if aws.StringValue(mpl.PrefixList.PrefixListName) == aws.StringValue(filterValue) {
						keep = true
						break
					}
				}
			} else if filterName == "owner-id" {
				keep = false
				for _, filterValue := range filter.Values {
					if "123456789012" == aws.StringValue(filterValue) {
						keep = true
						break
					}
				}
			} else if strings.HasPrefix(filterName, "tag:") {
				tagKey := filterName[4:]
				var tagValue string
				keep = false

				for _, tag := range mpl.PrefixList.Tags {
					if aws.StringValue(tag.Key) == tagKey {
						keep = true
						tagValue = aws.StringValue(tag.Value)
						break
					}
				}

				if keep {
					keep = false
					for _, filterValue := range filter.Values {
						if aws.StringValue(filterValue) == tagValue {
							keep = true
							break
						}
					}
				}
			}

			if !keep {
				continue mplLoop
			}
		}

		results = append(results, &mpl.PrefixList)
	}

	nResults := int64(len(results))

	for i := int64(0); i < nResults; i += maxResults {
		end := i + maxResults
		lastPage := false

		if end >= nResults {
			end = nResults
			lastPage = true
		}

		var nextToken *string
		if !lastPage {
			nextToken = aws.String(fmt.Sprintf("%d", end))
		}

		iterResult := iter(&ec2.DescribeManagedPrefixListsOutput{NextToken: nextToken, PrefixLists: results[i:end]}, lastPage)
		if !iterResult {
			break
		}
	}

	return nil
}

func (m *EC2Mock) GetManagedPrefixListAssociationsPages(input *ec2.GetManagedPrefixListAssociationsInput, iter func(*ec2.GetManagedPrefixListAssociationsOutput, bool) bool) error {
	if input.PrefixListId == nil {
		return fmt.Errorf("PrefixListId must be specified")
	}
	prefixListID := *input.PrefixListId
	output := ec2.GetManagedPrefixListAssociationsOutput{}
	startAt := int64(0)
	if input.NextToken != nil {
		var err error
		startAt, err = strconv.ParseInt(*input.NextToken, 10, 64)
		if err != nil {
			return fmt.Errorf("Invalid NextToken value")
		}
	}

	maxResults := int64(100)
	if input.MaxResults != nil {
		maxResults = *input.MaxResults
		if maxResults <= 0 || maxResults > 100 {
			return fmt.Errorf("MaxResults must be between 1 and 100, inclusive")
		}
	}

	var results []*ec2.PrefixListAssociation

sgLoop:
	for _, sg := range m.securityGroups {
		for _, perm := range sg.IpPermissions {
			for _, sgPrefixListID := range perm.PrefixListIds {
				if aws.StringValue(sgPrefixListID.PrefixListId) == prefixListID {
					results = append(results, &ec2.PrefixListAssociation{
						ResourceId: CopyAWSString(sg.GroupId), ResourceOwner: aws.String("123456789012"),
					})
					continue sgLoop
				}
			}
		}

		for _, perm := range sg.IpPermissionsEgress {
			for _, sgPrefixListID := range perm.PrefixListIds {
				if aws.StringValue(sgPrefixListID.PrefixListId) == prefixListID {
					results = append(results, &ec2.PrefixListAssociation{ResourceId: sg.GroupId, ResourceOwner: aws.String("123456789012")})
					continue sgLoop
				}
			}
		}
	}

	nResults := int64(len(results))
	for i := startAt; i < nResults; i += maxResults {
		end := i + maxResults
		lastPage := false

		if end >= nResults {
			end = nResults
			lastPage = true
		}

		output.SetPrefixListAssociations(results[i:end])
		if !iter(&output, lastPage) {
			break
		}
	}

	return nil
}

func (m *EC2Mock) GetManagedPrefixListEntriesPages(input *ec2.GetManagedPrefixListEntriesInput, iter func(*ec2.GetManagedPrefixListEntriesOutput, bool) bool) error {
	if input.PrefixListId == nil {
		return fmt.Errorf("PrefixListId must be specified")
	}

	prefixListID := *input.PrefixListId

	startAt := int64(0)
	if input.NextToken != nil {
		var err error
		startAt, err = strconv.ParseInt(*input.NextToken, 10, 64)
		if err != nil {
			return fmt.Errorf("Invalid NextToken value")
		}
	}

	maxResults := int64(100)
	if input.MaxResults != nil {
		maxResults = aws.Int64Value(input.MaxResults)
		if maxResults <= 0 || maxResults > 100 {
			return fmt.Errorf("MaxResults must be between 1 and 100 inclusive")
		}
	}

	mpl, present := m.managedPrefixLists[prefixListID]
	if !present {
		return fmt.Errorf("Managed prefix list with PrefixListId %v not found", prefixListID)
	}

	output := ec2.GetManagedPrefixListEntriesOutput{}
	nEntries := int64(len(mpl.Entries))

	for i := startAt; i < nEntries; i += maxResults {
		end := i + maxResults
		lastPage := false

		if end >= nEntries {
			end = nEntries
			lastPage = true
		}

		output.Entries = make([]*ec2.PrefixListEntry, 0, maxResults)

		for _, entry := range mpl.Entries[i:end] {
			output.Entries = append(output.Entries, &ec2.PrefixListEntry{
				Cidr: CopyAWSString(entry.Cidr), Description: CopyAWSString(entry.Description),
			})
		}

		if !iter(&output, lastPage) {
			break
		}
	}

	return nil
}

func (m *EC2Mock) ModifyManagedPrefixList(input *ec2.ModifyManagedPrefixListInput) (*ec2.ModifyManagedPrefixListOutput, error) {
	if input.PrefixListId == nil {
		return nil, fmt.Errorf("PrefixListId must be specified")
	}

	prefixListID := *input.PrefixListId
	mpl, present := m.managedPrefixLists[prefixListID]
	if !present {
		return nil, fmt.Errorf("Managed prefix list with PrefixListId %v not found", prefixListID)
	}

	newEntries := make([]*ec2.PrefixListEntry, len(mpl.Entries), len(mpl.Entries)+len(input.AddEntries))
	for i := 0; i < len(mpl.Entries); i++ {
		newEntries[i] = mpl.Entries[i]
	}

	for index, remoteEntry := range input.RemoveEntries {
		if remoteEntry.Cidr == nil {
			return nil, fmt.Errorf("RemoveEntries contains a null Cidr at entry %d", index)
		}

		cidr := *remoteEntry.Cidr
		found := false

		for i := 0; i < len(newEntries); i++ {
			if aws.StringValue(newEntries[i].Cidr) == cidr {
				// Found it. Remove it from the new entries slice.
				if i < len(newEntries)-1 {
					newEntries = append(newEntries[0:i], newEntries[i+1:]...)
				} else {
					newEntries = newEntries[0:i]
				}

				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("Managed prefix list %v does not contain entry with CIDR %v to remove", prefixListID, cidr)
		}
	}

	for index, addEntry := range input.AddEntries {
		if addEntry.Cidr == nil {
			return nil, fmt.Errorf("AddEntries contains a null Cidr at entry %d", index)
		}
		newEntries = append(newEntries, &ec2.PrefixListEntry{Cidr: CopyAWSString(addEntry.Cidr)})
	}

	if int64(len(newEntries)) > aws.Int64Value(mpl.PrefixList.MaxEntries) {
		return nil, fmt.Errorf("Managed prefix list %v additions would exceed MaxEntries: new length=%d, MaxEntries=%d",
			prefixListID, len(newEntries), aws.Int64Value(mpl.PrefixList.MaxEntries))
	}

	if input.PrefixListName != nil {
		if *input.PrefixListName == "" {
			return nil, fmt.Errorf("PrefixListName cannot be empty")
		}

		mpl.PrefixList.PrefixListName = CopyAWSString(input.PrefixListName)
	}
	mpl.Entries = newEntries

	output := ec2.ModifyManagedPrefixListOutput{PrefixList: &mpl.PrefixList}
	return &output, nil
}

func (m *EC2Mock) DescribeSecurityGroupsPages(input *ec2.DescribeSecurityGroupsInput, iter func(*ec2.DescribeSecurityGroupsOutput, bool) bool) error {
	if len(input.Filters) > 0 {
		return fmt.Errorf("Security group filters are not supported")
	}

	output := ec2.DescribeSecurityGroupsOutput{}
	startAt := int64(0)
	if input.NextToken != nil {
		var err error
		startAt, err = strconv.ParseInt(*input.NextToken, 10, 64)
		if err != nil {
			return fmt.Errorf("Invalid NextToken value")
		}
	}

	maxResults := int64(100)
	if input.MaxResults != nil {
		maxResults = *input.MaxResults
		if maxResults <= 0 || maxResults > 100 {
			return fmt.Errorf("MaxResults must be between 1 and 100, inclusive")
		}
	}

	var results []*ec2.SecurityGroup
	for _, sg := range m.securityGroups {
		groupID := *sg.GroupId
		for _, groupIDFilter := range input.GroupIds {
			if aws.StringValue(groupIDFilter) == groupID {
				results = append(results, sg)
				break
			}
		}
	}

	nResults := int64(len(results))
	for i := startAt; i < nResults; i += maxResults {
		end := i + maxResults
		lastPage := false

		if end >= nResults {
			end = nResults
			lastPage = true
		}

		output.SetSecurityGroups(results[i:end])
		if !iter(&output, lastPage) {
			break
		}
	}

	return nil
}

type ruleType int

const (
	ingress ruleType = iota
	egress
)

func (m *EC2Mock) AuthorizeSecurityGroupIngress(input *ec2.AuthorizeSecurityGroupIngressInput) (*ec2.AuthorizeSecurityGroupIngressOutput, error) {
	err := m.authorizeSecurityGroupRules(input.GroupId, input.IpPermissions, ingress)
	if err != nil {
		return nil, err
	}

	return &ec2.AuthorizeSecurityGroupIngressOutput{}, nil
}

func (m *EC2Mock) AuthorizeSecurityGroupEgress(input *ec2.AuthorizeSecurityGroupEgressInput) (*ec2.AuthorizeSecurityGroupEgressOutput, error) {
	err := m.authorizeSecurityGroupRules(input.GroupId, input.IpPermissions, egress)
	if err != nil {
		return nil, err
	}

	return &ec2.AuthorizeSecurityGroupEgressOutput{}, nil
}

func (m *EC2Mock) authorizeSecurityGroupRules(groupID *string, permissions []*ec2.IpPermission, ruleType ruleType) error {
	if groupID == nil {
		return fmt.Errorf("Security GroupId must be specified")
	}

	if m.securityGroups == nil {
		m.securityGroups = make(map[string]*ec2.SecurityGroup)
	}

	sg, found := m.securityGroups[*groupID]
	if !found {
		return fmt.Errorf("Security group with GroupId %v not found", *groupID)
	}

	for _, perm := range permissions {
		var ipRangesCopy []*ec2.IpRange
		var ipv6RangesCopy []*ec2.Ipv6Range
		var prefixListIDsCopy []*ec2.PrefixListId
		var userIDGroupPairsCopy []*ec2.UserIdGroupPair

		for _, ipRange := range perm.IpRanges {
			ipRangesCopy = append(ipRangesCopy, &ec2.IpRange{
				CidrIp: CopyAWSString(ipRange.CidrIp), Description: CopyAWSString(ipRange.Description),
			})
		}

		for _, ipv6Range := range perm.Ipv6Ranges {
			ipv6RangesCopy = append(ipv6RangesCopy, &ec2.Ipv6Range{
				CidrIpv6: CopyAWSString(ipv6Range.CidrIpv6), Description: CopyAWSString(ipv6Range.Description),
			})
		}

		for _, prefixListID := range perm.PrefixListIds {
			prefixListIDsCopy = append(prefixListIDsCopy, &ec2.PrefixListId{
				PrefixListId: CopyAWSString(prefixListID.PrefixListId), Description: CopyAWSString(prefixListID.Description),
			})
		}

		for _, userIDGroupPair := range perm.UserIdGroupPairs {
			userIDGroupPairsCopy = append(userIDGroupPairsCopy, &ec2.UserIdGroupPair{
				GroupId: CopyAWSString(userIDGroupPair.GroupId), GroupName: CopyAWSString(userIDGroupPair.GroupName),
				UserId: CopyAWSString(userIDGroupPair.UserId), VpcId: CopyAWSString(userIDGroupPair.VpcId),
				VpcPeeringConnectionId: CopyAWSString(userIDGroupPair.VpcPeeringConnectionId),
				PeeringStatus:          CopyAWSString(userIDGroupPair.PeeringStatus),
				Description:            CopyAWSString(userIDGroupPair.Description),
			})
		}

		permCopy := ec2.IpPermission{
			IpProtocol: CopyAWSString(perm.IpProtocol), FromPort: CopyAWSInt64(perm.FromPort), ToPort: CopyAWSInt64(perm.ToPort),
			IpRanges: ipRangesCopy, Ipv6Ranges: ipv6RangesCopy, PrefixListIds: prefixListIDsCopy,
			UserIdGroupPairs: userIDGroupPairsCopy,
		}

		if ruleType == ingress {
			sg.IpPermissions = append(sg.IpPermissions, &permCopy)
		} else {
			sg.IpPermissionsEgress = append(sg.IpPermissionsEgress, &permCopy)
		}
	}

	return nil
}

func (m *EC2Mock) RevokeSecurityGroupIngress(input *ec2.RevokeSecurityGroupIngressInput) (*ec2.RevokeSecurityGroupIngressOutput, error) {
	err := m.revokeSecurityGroupRules(input.GroupId, input.IpPermissions, ingress)
	if err != nil {
		return nil, err
	}

	return &ec2.RevokeSecurityGroupIngressOutput{}, nil
}

func (m *EC2Mock) RevokeSecurityGroupEgress(input *ec2.RevokeSecurityGroupEgressInput) (*ec2.RevokeSecurityGroupEgressOutput, error) {
	err := m.revokeSecurityGroupRules(input.GroupId, input.IpPermissions, egress)
	if err != nil {
		return nil, err
	}

	return &ec2.RevokeSecurityGroupEgressOutput{}, nil
}

func (m *EC2Mock) revokeSecurityGroupRules(groupID *string, permissions []*ec2.IpPermission, ruleType ruleType) error {
	if groupID == nil {
		return fmt.Errorf("Security GroupId must be specified")
	}

	if m.securityGroups == nil {
		m.securityGroups = make(map[string]*ec2.SecurityGroup)
	}

	sg, found := m.securityGroups[*groupID]
	if !found {
		return fmt.Errorf("Security group with GroupId %v not found", *groupID)
	}

	var sgPermissions []*ec2.IpPermission
	if ruleType == ingress {
		sgPermissions = sg.IpPermissions
	} else {
		sgPermissions = sg.IpPermissionsEgress
	}

	keptPerms := make([]*ec2.IpPermission, 0, len(sgPermissions))
	for _, perm := range sgPermissions {
		keptIPRanges := make([]*ec2.IpRange, 0, len(perm.IpRanges))
		keptIPv6Ranges := make([]*ec2.Ipv6Range, 0, len(perm.Ipv6Ranges))
		keptPrefixListIDs := make([]*ec2.PrefixListId, 0, len(perm.PrefixListIds))

		// Filter out IPv4 CIDR blocks that match
	ipRangeLoop:
		for _, existingIPRange := range perm.IpRanges {
			existingCIDRIP := aws.StringValue(existingIPRange.CidrIp)

			// Look for rules on the IpPermissions slice.
			for _, inputPerm := range permissions {
				// Does the protocol/port range match?
				if aws.Int64Value(perm.FromPort) != aws.Int64Value(inputPerm.FromPort) &&
					aws.Int64Value(perm.ToPort) != aws.Int64Value(inputPerm.ToPort) &&
					aws.StringValue(perm.IpProtocol) != aws.StringValue(inputPerm.IpProtocol) {
					continue
				}

				for _, inputIPRange := range inputPerm.IpRanges {
					if existingCIDRIP == aws.StringValue(inputIPRange.CidrIp) {
						// Rule matched -- don't include this IP range
						continue ipRangeLoop
					}
				}
			}

			// No rules matched; keep this CIDR block
			keptIPRanges = append(keptIPRanges, existingIPRange)
		}

		// Filter out IPv6 CIDR blocks that match
	ipv6RangeLoop:
		for _, existingIPv6Range := range perm.Ipv6Ranges {
			existingCIDRIPv6 := aws.StringValue(existingIPv6Range.CidrIpv6)

			// Look for rules on the IpPermissions slice.
			for _, inputPerm := range permissions {
				// Does the protocol/port range match?
				if aws.Int64Value(perm.FromPort) != aws.Int64Value(inputPerm.FromPort) &&
					aws.Int64Value(perm.ToPort) != aws.Int64Value(inputPerm.ToPort) &&
					aws.StringValue(perm.IpProtocol) != aws.StringValue(inputPerm.IpProtocol) {
					continue
				}

				for _, inputIPv6Range := range inputPerm.Ipv6Ranges {
					if existingCIDRIPv6 == aws.StringValue(inputIPv6Range.CidrIpv6) {
						// Rule matched -- don't include this IP range
						continue ipv6RangeLoop
					}
				}
			}

			// No rules matched; keep this CIDR block
			keptIPv6Ranges = append(keptIPv6Ranges, existingIPv6Range)
		}

		// And finally filter out prefix lists that match
	prefixListLoop:
		for _, existingPrefixListID := range perm.PrefixListIds {
			existingPLID := aws.StringValue(existingPrefixListID.PrefixListId)

			// Look for rules on the IpPermissions slice.
			for _, inputPerm := range permissions {
				// Does the protocol/port range match?
				if aws.Int64Value(perm.FromPort) != aws.Int64Value(inputPerm.FromPort) &&
					aws.Int64Value(perm.ToPort) != aws.Int64Value(inputPerm.ToPort) &&
					aws.StringValue(perm.IpProtocol) != aws.StringValue(inputPerm.IpProtocol) {
					continue
				}

				for _, inputPrefixListID := range inputPerm.PrefixListIds {
					if existingPLID == aws.StringValue(inputPrefixListID.PrefixListId) {
						// Rule matched -- don't include this IP range
						continue prefixListLoop
					}
				}
			}

			// No rules matched; keep this CIDR block
			keptPrefixListIDs = append(keptPrefixListIDs, existingPrefixListID)
		}

		// Don't keep empty permissions
		if len(keptIPRanges) > 0 || len(keptIPv6Ranges) > 0 || len(keptPrefixListIDs) > 0 {
			// Replace the permission's ranges with the items we kept
			perm.IpRanges = keptIPRanges
			perm.Ipv6Ranges = keptIPv6Ranges
			perm.PrefixListIds = keptPrefixListIDs

			keptPerms = append(keptPerms, perm)
		}
	}

	if ruleType == ingress {
		sg.IpPermissions = keptPerms
	} else {
		sg.IpPermissionsEgress = keptPerms
	}

	return nil
}

type SSMMock struct {
	ssmiface.SSMAPI

	parameters    map[string]*ssm.Parameter
	parameterTags map[string][]*ssm.Tag
}

func (m *SSMMock) GetParameters(input *ssm.GetParametersInput) (*ssm.GetParametersOutput, error) {
	var output ssm.GetParametersOutput

	for _, name := range input.Names {
		if m.parameters == nil {
			output.InvalidParameters = append(output.InvalidParameters, name)
		} else {
			param, present := m.parameters[aws.StringValue(name)]
			if !present {
				output.InvalidParameters = append(output.InvalidParameters, name)
			} else {
				output.Parameters = append(output.Parameters, param)
			}
		}
	}

	return &output, nil
}

func (m *SSMMock) PutParameter(input *ssm.PutParameterInput) (*ssm.PutParameterOutput, error) {
	name := aws.StringValue(input.Name)
	if len(name) == 0 {
		return nil, fmt.Errorf("Name cannot be empty")
	}

	if input.Type == nil {
		return nil, fmt.Errorf("Type cannot be empty")
	}
	typeStr := aws.StringValue(input.Type)
	if typeStr != "String" && typeStr != "StringList" && typeStr != "SecureString" {
		return nil, fmt.Errorf(`Type must be one of "String", "StringList", or "SecureString"`)
	}

	if m.parameters == nil {
		m.parameters = make(map[string]*ssm.Parameter)
	}
	if m.parameterTags == nil {
		m.parameterTags = make(map[string][]*ssm.Tag)
	}

	var dataType string
	if input.DataType != nil {
		dataType = aws.StringValue(input.DataType)
	} else {
		dataType = "text"
	}

	current, currentPresent := m.parameters[name]
	version := int64(0)
	if currentPresent {
		if !aws.BoolValue(input.Overwrite) {
			return nil, fmt.Errorf("Parameter present but Overwrite not specified")
		}

		if len(input.Tags) != 0 {
			return nil, fmt.Errorf("Cannot specify Tags when modifying a parameter; use AddTagsToResource instead")
		}

		version = aws.Int64Value(current.Version) + 1
	}

	var tier string
	if input.Tier != nil {
		tier = aws.StringValue(input.Tier)
		if tier != "Standard" && tier != "Advanced" && tier != "Intelligent-Tiering" {
			return nil, fmt.Errorf(`Invalid value for Tier; expected "Standard", "Advanced", or "Intelligent-Tiering"`)
		}
	} else {
		tier = "Standard"
	}

	arn := fmt.Sprintf("arn:aws:ssm:us-west-2:123456789012:parameter/%s", strings.TrimLeft(name, "/"))

	param := ssm.Parameter{
		ARN: &arn, Name: CopyAWSString(input.Name), Value: CopyAWSString(input.Value),
		DataType: &dataType, Version: &version, Type: CopyAWSString(input.Type),
	}
	m.parameters[name] = &param

	var tags []*ssm.Tag
	for _, tag := range input.Tags {
		tags = append(tags, &ssm.Tag{Key: CopyAWSString(tag.Key), Value: CopyAWSString(tag.Value)})
	}
	m.parameterTags[name] = tags
	return &ssm.PutParameterOutput{Tier: &tier, Version: &version}, nil
}

func (m *SSMMock) ListTagsForResource(input *ssm.ListTagsForResourceInput) (*ssm.ListTagsForResourceOutput, error) {
	if input.ResourceId == nil {
		return nil, fmt.Errorf("ResourceId must be specified")
	}
	resourceID := *input.ResourceId

	if input.ResourceType == nil {
		return nil, fmt.Errorf("ResourceType must be specified")
	}
	resourceType := *input.ResourceType

	if resourceType != "Parameter" {
		return nil, fmt.Errorf("ResourceType %v is not supported", resourceType)
	}

	tags, present := m.parameterTags[resourceID]
	if !present {
		return nil, fmt.Errorf("Resource %v of type %s not found", resourceID, resourceType)
	}

	output := ssm.ListTagsForResourceOutput{}
	for _, tag := range tags {
		output.TagList = append(output.TagList, &ssm.Tag{Key: CopyAWSString(tag.Key), Value: CopyAWSString(tag.Value)})
	}

	return &output, nil
}

func (m *SSMMock) AddTagsToResource(input *ssm.AddTagsToResourceInput) (*ssm.AddTagsToResourceOutput, error) {
	if input.ResourceId == nil {
		return nil, fmt.Errorf("ResourceId must be specified")
	}
	resourceID := *input.ResourceId

	if input.ResourceType == nil {
		return nil, fmt.Errorf("ResourceType must be specified")
	}
	resourceType := *input.ResourceType

	if resourceType != "Parameter" {
		return nil, fmt.Errorf("ResourceType %v is not supported", resourceType)
	}

	if _, present := m.parameters[resourceID]; !present {
		return nil, fmt.Errorf("Parameter with name %#v not found", resourceID)
	}

	if _, present := m.parameterTags[resourceID]; !present {
		m.parameterTags[resourceID] = make([]*ssm.Tag, 0, len(input.Tags))
	}

	for i, tag := range input.Tags {
		if tag.Key == nil {
			return nil, fmt.Errorf("Tag key %d cannot be null", i)
		}

		key := *tag.Key
		if key == "" {
			return nil, fmt.Errorf("Tag key %d cannot be empty", i)
		}

		if tag.Value == nil {
			for j := 0; j < len(m.parameterTags[resourceID]); j++ {
				if key == *m.parameterTags[resourceID][j].Key {
					// Found the tag to delete.
					if j < len(m.parameterTags[resourceID])-1 {
						m.parameterTags[resourceID] = append(m.parameterTags[resourceID][:i], m.parameterTags[resourceID][i+1:]...)
					} else {
						m.parameterTags[resourceID] = m.parameterTags[resourceID][:i]
					}
				}
			}
		} else {
			modified := false
			for _, resourceTag := range m.parameterTags[resourceID] {
				if key == *resourceTag.Key {
					// Found the tag to modify
					resourceTag.Value = CopyAWSString(tag.Value)
					modified = true
					break
				}
			}

			if !modified {
				// Need to append this parameter.
				m.parameterTags[resourceID] = append(m.parameterTags[resourceID], &ssm.Tag{
					Key: CopyAWSString(tag.Key), Value: CopyAWSString(tag.Value)})
			}
		}
	}

	output := ssm.AddTagsToResourceOutput{}
	return &output, nil
}

type STSMock struct {
	stsiface.STSAPI
}

func (m *STSMock) GetCallerIdentity(_ *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
	output := sts.GetCallerIdentityOutput{Account: aws.String("123456789012"),
		Arn: aws.String("arn:aws-test:iam::123456789012:user/test"), UserId: aws.String("AIDAAAAAAAEXAMPLEUSER")}
	return &output, nil
}

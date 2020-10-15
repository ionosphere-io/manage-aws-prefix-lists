package main

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
)

// PrefixListAddressFamilyManager handles the data related to a specific address family
type PrefixListAddressFamilyManager struct {
	// partition is the AWS partition we're operating in.
	partition string

	// accountID is the 12-digit account identifier for this account.
	accountID string

	// ec2 is a handle to the EC2 service.
	ec2 ec2iface.EC2API

	// ssm is a handle to the (Simple) Systems Manager service.
	ssm ssmiface.SSMAPI

	// addressFamily is the IP protocol, either "IPv4" or "IPv6"
	addressFamily string

	// groupSize is the size of the groups to create.
	groupSize uint

	// tags is a map of the tags that should be applied to the resulting prefix lists.
	tags TagMap

	// allPrefixes is the parsed ip-ranges.json data, unprocessed.
	allPrefixes []IPPrefix

	// keptPrefixes contains the CIDR blocks of the IPv4 prefixes we need (after filtering and aggregation).
	keptPrefixes []string

	// nGroups indicates the number of groups we need.
	nGroups uint

	// prefixListNames is a list of the generated prefix list names in the same order as the groups.
	prefixListNames []string

	// prefixListNamesToExistingPrefixLists maps prefix list names to EC2 prefix list objects.
	prefixListNamesToExistingPrefixLists map[string]*ec2.ManagedPrefixList

	// prefixListIds is the final set of prefix lists encompassing this filter.
	prefixListIDs []string
}

// NewPrefixListAddressFamilyManager creates a new PrefixListAddressFamilyManager object with the specified parameters.
func NewPrefixListAddressFamilyManager(partition string, accountID string, ec2Client ec2iface.EC2API, ssmClient ssmiface.SSMAPI,
	addressFamily string, groupSize uint, prefixListTags TagMap) *PrefixListAddressFamilyManager {
	return &PrefixListAddressFamilyManager{
		partition: partition, accountID: accountID, ec2: ec2Client, ssm: ssmClient, addressFamily: addressFamily,
		groupSize: groupSize, tags: prefixListTags,
	}
}

func (plafm *PrefixListAddressFamilyManager) filterAndAggregatePrefixes(filters []IPRangesFilter, groupSize uint) error {
	var filteredPrefixes []*net.IPNet

	for _, prefix := range plafm.allPrefixes {
		for _, filter := range filters {
			if filterMatches(&filter, prefix) {
				_, ipNet, err := net.ParseCIDR(prefix.GetPrefix())
				if err != nil {
					log.Printf("Failed to parse %s prefix %v: %v", plafm.addressFamily, prefix.GetPrefix(), err)
					return err
				}

				log.Printf("Filter accepts prefix %v", prefix)
				filteredPrefixes = append(filteredPrefixes, ipNet)
			}
		}
	}

	if len(filteredPrefixes) == 0 {
		log.Printf("No prefixes returned for filters: %v", filters)
		return nil
	}

	log.Printf("Filtered prefixes: %v", filteredPrefixes)

	aggregatedPrefixes := AggregateNetworks(filteredPrefixes)
	SortIPNets(aggregatedPrefixes)
	nAggregatedPrefixes := uint(len(aggregatedPrefixes))
	plafm.nGroups = nAggregatedPrefixes / groupSize
	if nAggregatedPrefixes%groupSize != 0 {
		plafm.nGroups++
	}

	log.Printf("Before aggregation: %s prefixes: total=%d, prefixes=%v", plafm.addressFamily, len(filteredPrefixes), filteredPrefixes)
	log.Printf("After aggregation: %s prefixes: total=%d, nGroups=%d, prefixes=%v", plafm.addressFamily, nAggregatedPrefixes, plafm.nGroups, aggregatedPrefixes)

	plafm.keptPrefixes = make([]string, 0, len(aggregatedPrefixes))
	for _, prefix := range aggregatedPrefixes {
		plafm.keptPrefixes = append(plafm.keptPrefixes, prefix.String())
	}

	return nil
}

// filterMatches indicates whether the specified filter matches the given prefix
func filterMatches(filter *IPRangesFilter, prefix IPPrefix) bool {
	if filter.AddressFamily != AddressFamilyAll && filter.AddressFamily != prefix.GetAddressType() {
		log.Printf("Filter %v rejects prefix %v: AddressFamily mismatch", filter, prefix)
		return false
	}

	if !filter.RegionRegex.MatchString(prefix.GetRegion()) {
		log.Printf("Filter %v rejects prefix %v: Region mismatch", filter, prefix)
		return false
	}

	if !filter.ServiceRegex.MatchString(prefix.GetService()) {
		log.Printf("Filter %v rejects prefix %v: Service mismatch", filter, prefix)
		return false
	}

	if !filter.NetworkBorderGroupRegex.MatchString(prefix.GetNetworkBorderGroup()) {
		log.Printf("Filter %v rejects prefix %v: NetworkBorderGroup mismstach", filter, prefix)
		return false
	}

	return true
}

// generatePrefixListNames generates a list of prefix list names over the given number of groups.
func (plafm *PrefixListAddressFamilyManager) generatePrefixListNames(prefixListNameBase string, tpl *template.Template) error {
	templateVars := PrefixListTemplateVars{
		PrefixListNameBase: prefixListNameBase, AddressFamily: plafm.addressFamily, GroupCount: strconv.FormatUint(uint64(plafm.nGroups), 10),
	}

	plafm.prefixListNames = make([]string, 0, plafm.nGroups)
	for groupID := uint(0); groupID < plafm.nGroups; groupID++ {
		nameBuilder := strings.Builder{}
		templateVars.GroupID = strconv.FormatUint(uint64(groupID), 10)
		if err := tpl.Execute(&nameBuilder, templateVars); err != nil {
			log.Printf("Failed to get prefix list name for %s group %d: %v", plafm.addressFamily, groupID, err)
			return err
		}

		plafm.prefixListNames = append(plafm.prefixListNames, nameBuilder.String())
	}

	return nil
}

func (plafm *PrefixListAddressFamilyManager) mapPrefixListNamesToExistingPrefixLists() error {
	plafm.prefixListNamesToExistingPrefixLists = make(map[string]*ec2.ManagedPrefixList)

	for groupID, prefixListName := range plafm.prefixListNames {
		var filters []*ec2.Filter

		filters = append(filters, MakeEC2Filter("prefix-list-name", prefixListName))
		filters = append(filters, MakeEC2Filter("owner-id", plafm.accountID))
		filters = append(filters, MakeEC2Filter("tag:GroupId", strconv.FormatInt(int64(groupID), 10)))

		for tagKey, tagValue := range plafm.tags {
			filters = append(filters, MakeEC2Filter(fmt.Sprintf("tag:%s", tagKey), tagValue))
		}

		describeInput := ec2.DescribeManagedPrefixListsInput{
			DryRun: aws.Bool(false), Filters: filters,
		}

		foundDuplicates := false
		err := plafm.ec2.DescribeManagedPrefixListsPages(&describeInput, func(describeOutput *ec2.DescribeManagedPrefixListsOutput, _ bool) bool {
			for _, prefixList := range describeOutput.PrefixLists {
				if aws.StringValue(prefixList.AddressFamily) != plafm.addressFamily {
					continue
				}

				existing, present := plafm.prefixListNamesToExistingPrefixLists[prefixListName]
				if present {
					log.Printf("Multiple prefix lists with name %s: %s %s", prefixListName, *existing.PrefixListId, *prefixList.PrefixListId)
					foundDuplicates = true
					return false
				}

				plafm.prefixListNamesToExistingPrefixLists[prefixListName] = prefixList
			}

			return true
		})

		if err != nil {
			fmt.Printf("Failed to describe managed prefix lists with name %s: %v", prefixListName, err)
			return err
		}

		if foundDuplicates {
			return fmt.Errorf("Multiple prefix lists with name %s", prefixListName)
		}
	}

	return nil
}

func (plafm *PrefixListAddressFamilyManager) updateManagedPrefixLists() []PrefixListManagementOp {
	nGroups := len(plafm.prefixListNames)
	var results []PrefixListManagementOp

	for i, groupID := uint(0), uint(0); groupID < uint(nGroups); i, groupID = i+plafm.groupSize, groupID+1 {
		end := i + plafm.groupSize
		if end > uint(len(plafm.keptPrefixes)) {
			end = uint(len(plafm.keptPrefixes))
		}

		prefixListName := plafm.prefixListNames[groupID]
		existingPrefixList := plafm.prefixListNamesToExistingPrefixLists[prefixListName]
		prefixBlock := plafm.keptPrefixes[i:end]

		results = append(results, plafm.managePrefixListBlock(groupID, prefixListName, existingPrefixList, prefixBlock)...)
	}

	return results
}

// managePrefixListBlock creates or upates a prefix list corresponding to a block of prefixes. This block may be a subset of the
// full set of prefixes returned by the filters -- it's always less than or equal to the group size.
func (plafm *PrefixListAddressFamilyManager) managePrefixListBlock(groupID uint, prefixListName string, existingPrefixList *ec2.ManagedPrefixList, prefixBlock []string) []PrefixListManagementOp {
	if existingPrefixList == nil {
		// No existing prefix list. Create one.
		prefixList, err := plafm.createPrefixList(groupID, prefixListName, prefixBlock)
		result := PrefixListManagementOp{
			PrefixListName: prefixListName, AddressFamily: plafm.addressFamily,
		}

		if err != nil {
			result.Operation = OpPrefixListCreateFailedError
			result.Error = err
		} else {
			result.Operation = OpCreatePrefixList
			result.NewPrefixListID = aws.StringValue(prefixList.PrefixListId)
			plafm.prefixListIDs = append(plafm.prefixListIDs, result.NewPrefixListID)
		}

		return []PrefixListManagementOp{result}
	}

	// See if the existing prefix list can be reused
	existingPrefixListID := *existingPrefixList.PrefixListId
	replacementNeeded := false

	// Keep a tally of which prefixes we've seen in the existing prefix list, and ones that are present in the existing prefix list
	// but shouldn't be.
	seenPrefixes := make(map[string]bool)
	var addEntries []*ec2.AddPrefixListEntry
	var removeEntries []*ec2.RemovePrefixListEntry
	var addEntriesStr []string
	var removeEntriesStr []string

	for _, prefix := range prefixBlock {
		seenPrefixes[prefix] = false
	}

	if uint(aws.Int64Value(existingPrefixList.MaxEntries)) != plafm.groupSize {
		// Group size is different -- we need a hard replacement.
		log.Printf("Prefix list %s (%s) group size is %d instead of %d -- replacement needed", existingPrefixListID, prefixListName, aws.Int64Value(existingPrefixList.MaxEntries), plafm.groupSize)
		replacementNeeded = true
	} else {
		// Enumerate the prefixes in the prefix list
		input := ec2.GetManagedPrefixListEntriesInput{
			DryRun: aws.Bool(false), PrefixListId: &existingPrefixListID,
		}

		err := plafm.ec2.GetManagedPrefixListEntriesPages(&input, func(output *ec2.GetManagedPrefixListEntriesOutput, _ bool) bool {
			for _, ple := range output.Entries {
				prefix := aws.StringValue(ple.Cidr)

				// Is this a prefix that should be in there?
				if _, present := seenPrefixes[prefix]; present {
					// Yes; mark it as seen
					seenPrefixes[prefix] = true
				} else {
					// No; add it to the list of prefixes to delete.
					removeEntries = append(removeEntries, &ec2.RemovePrefixListEntry{Cidr: ple.Cidr})
					removeEntriesStr = append(removeEntriesStr, *ple.Cidr)
				}
			}
			return true
		})

		// Failed to get the existing entries.
		if err != nil {
			log.Printf("Failed to get entries for prefix list %s (%s): %v", existingPrefixListID, prefixListName, err)
			result := PrefixListManagementOp{
				PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpPrefixListQueryFailedError,
				ExistingPrefixListID: existingPrefixListID, Error: err,
			}

			// Since we're not able to create or update a prefix list for this block, assume that this is ok for now. Otherwise,
			// the prefix list may fall out of SSM and other brokenness may happen.
			plafm.prefixListIDs = append(plafm.prefixListIDs, existingPrefixListID)

			return []PrefixListManagementOp{result}
		}
	}

	if replacementNeeded {
		// replacePrefixList will set the new id in plafm.prefixListIDs.
		return plafm.replacePrefixList(groupID, prefixListName, existingPrefixList, prefixBlock)
	}

	// We know that this prefix list will be retained at this point. Add it to the prefix lists that are considered final.
	plafm.prefixListIDs = append(plafm.prefixListIDs, existingPrefixListID)

	// Generate the entries to add to the CIDR block.
	for prefix, seen := range seenPrefixes {
		if !seen {
			addEntries = append(addEntries, &ec2.AddPrefixListEntry{Cidr: aws.String(prefix)})
			addEntriesStr = append(addEntriesStr, prefix)
		}
	}

	if len(addEntries) == 0 && len(removeEntries) == 0 {
		log.Printf("Prefix list %s (%s) is up-to-date; no modifications needed", existingPrefixListID, prefixListName)
		// Nothing to do -- report back a no-op
		return []PrefixListManagementOp{{
			PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpNoModifyPrefixList,
			ExistingPrefixListID: existingPrefixListID,
		}}
	}

	// The total should be under the group size.
	modify := ec2.ModifyManagedPrefixListInput{
		PrefixListId: existingPrefixList.PrefixListId, CurrentVersion: existingPrefixList.Version, DryRun: aws.Bool(false),
		PrefixListName: existingPrefixList.PrefixListName, AddEntries: addEntries, RemoveEntries: removeEntries,
	}

	log.Printf("Modifying prefix list %s (%s): AddEntries=%v, RemoveEntries=%v", existingPrefixListID, prefixListName, addEntriesStr, removeEntriesStr)

	if _, err := plafm.ec2.ModifyManagedPrefixList(&modify); err != nil {
		log.Printf("Failed to modify prefix list %s (%s): %v", existingPrefixListID, prefixListName, err)
		return []PrefixListManagementOp{{
			PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpPrefixListUpdateFailedError,
			ExistingPrefixListID: existingPrefixListID, Error: err,
		}}
	}

	return []PrefixListManagementOp{{
		PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpUpdatePrefixListEntries,
		ExistingPrefixListID: existingPrefixListID,
	}}
}

// createPrefixList creates a prefix list with the given name and block of IP addresses.
func (plafm *PrefixListAddressFamilyManager) createPrefixList(groupID uint, prefixListName string, prefixBlock []string) (*ec2.ManagedPrefixList, error) {
	var entries []*ec2.AddPrefixListEntry

	for _, prefix := range prefixBlock {
		entries = append(entries, &ec2.AddPrefixListEntry{Cidr: aws.String(prefix)})
	}

	tagSpec := MakeEC2TagSpec(plafm.tags, aws.String("prefix-list"))
	groupIDTag := ec2.Tag{Key: aws.String("GroupId"), Value: aws.String(strconv.FormatUint(uint64(groupID), 10))}
	tagSpec[0].Tags = append(tagSpec[0].Tags, &groupIDTag)

	input := ec2.CreateManagedPrefixListInput{
		AddressFamily: aws.String(plafm.addressFamily), DryRun: aws.Bool(false), Entries: entries,
		MaxEntries: aws.Int64(int64(plafm.groupSize)), PrefixListName: aws.String(prefixListName), TagSpecifications: tagSpec,
	}
	output, err := plafm.ec2.CreateManagedPrefixList(&input)
	if err != nil {
		log.Printf("Failed to create managed prefix list %s: %v", prefixListName, err)
		return nil, err
	}

	log.Printf("Created new managed prefix list %s with id %s", prefixListName, aws.StringValue(output.PrefixList.PrefixListId))
	return output.PrefixList, nil
}

func (plafm *PrefixListAddressFamilyManager) replacePrefixList(groupID uint, prefixListName string, existingPrefixList *ec2.ManagedPrefixList, prefixBlock []string) []PrefixListManagementOp {
	existingPrefixListID := *existingPrefixList.PrefixListId
	results := make([]PrefixListManagementOp, 0, 1)

	// Need to perform a wholesale replacement of this prefix list. Let's see what security groups depend on it first.
	input := ec2.GetManagedPrefixListAssociationsInput{
		DryRun: aws.Bool(false), PrefixListId: aws.String(existingPrefixListID),
	}
	securityGroupIDs := make([]*string, 0)

	err := plafm.ec2.GetManagedPrefixListAssociationsPages(&input, func(output *ec2.GetManagedPrefixListAssociationsOutput, _ bool) bool {
		for _, pla := range output.PrefixListAssociations {
			if pla.ResourceOwner == nil {
				log.Printf("Got a nil ResourceOwner from GetManagedPrefixListAssociations")
				continue
			}

			if pla.ResourceId == nil {
				log.Printf("Got a nil ResourceId from GetManagedPrefixListAssociations")
				continue
			}

			if *pla.ResourceOwner != plafm.accountID {
				log.Printf("Can't update resource %s: owned by external account %s instead of %s", *pla.ResourceId, *pla.ResourceOwner, plafm.accountID)
			} else if !strings.HasPrefix(*pla.ResourceId, "sg-") {
				log.Printf("Can't update resource %s: not a security group", *pla.ResourceId)
			} else {
				log.Printf("Need to update security group %s", *pla.ResourceId)
				securityGroupIDs = append(securityGroupIDs, pla.ResourceId)
			}
		}

		return true
	})

	// We couldn't figure out who is referencing this list. Note the error and continue.
	if err != nil {
		log.Printf("Can't replace prefix list %s: GetManagedPrefixListAssociations failed: %v", existingPrefixListID, err)
		results = append(results, PrefixListManagementOp{
			PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpPrefixListQueryFailedError, ExistingPrefixListID: existingPrefixListID, Error: err,
		})
	}

	// Create a new prefix list first.
	newPrefixList, err := plafm.createPrefixList(groupID, prefixListName, prefixBlock)
	if err != nil {
		// This isn't a good situation. For now, mark the existing as final for this block so we don't drop rules.
		plafm.prefixListIDs = append(plafm.prefixListIDs, existingPrefixListID)

		results = append(results, PrefixListManagementOp{
			PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpPrefixListCreateFailedError, Error: err,
		})

		// Don't attempt to replace this.
		return results
	}

	// We were successful in creating the new prefix list. Add it to the list of final prefix lists.
	newPrefixListID := aws.StringValue(newPrefixList.PrefixListId)
	plafm.prefixListIDs = append(plafm.prefixListIDs, newPrefixListID)

	// Wait until the prefix list is ready before attempting to inject it into security groups.
outer:
	for {
		state := aws.StringValue(newPrefixList.State)
		switch state {
		case "create-complete":
			break outer
		case "create-failed":
			// Something happened during creation; bail out here.
			results = append(results, PrefixListManagementOp{
				PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpPrefixListCreateFailedError,
				NewPrefixListID: newPrefixListID,
				Error:           fmt.Errorf("Prefix list creation failed asynchronously for prefix list %s", newPrefixListID),
			})
			return results
		case "create-in-progress":
			// Refresh the state.
			time.Sleep(SleepDuration)
			input := ec2.DescribeManagedPrefixListsInput{
				DryRun: aws.Bool(false), Filters: []*ec2.Filter{MakeEC2Filter("prefix-list-id", newPrefixListID)},
			}

			var output *ec2.DescribeManagedPrefixListsOutput
			var err error
			if output, err = plafm.ec2.DescribeManagedPrefixLists(&input); err != nil {
				log.Printf("Failed to describe prefix list %s (%s): %v", existingPrefixListID, prefixListName, err)
				results = append(results, PrefixListManagementOp{
					PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpPrefixListQueryFailedError,
					NewPrefixListID: newPrefixListID, Error: err,
				})
				return results
			}

			// Make sure we have exactly one result
			if len(output.PrefixLists) == 0 {
				log.Printf("While querying status of prefix list %s (%s): prefix list disappeared from results", existingPrefixListID, prefixListName)
				err := fmt.Errorf("Prefix list state query failed for prefix list %s: prefix list not found", newPrefixListID)
				results = append(results, PrefixListManagementOp{
					PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpPrefixListQueryFailedError,
					NewPrefixListID: newPrefixListID, Error: err,
				})
				return results
			}

			if len(output.PrefixLists) > 1 {
				log.Printf("While querying status of prefix list %s (%s): query returned %d results", existingPrefixListID,
					prefixListName, len(output.PrefixLists))
				err := fmt.Errorf("Prefix list state query failed for prefix list %s: multiple prefix lists returned: %v",
					newPrefixListID, output.PrefixLists)
				results = append(results, PrefixListManagementOp{
					PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpPrefixListQueryFailedError,
					NewPrefixListID: newPrefixListID, Error: err,
				})
				return results
			}

			newPrefixList = output.PrefixLists[0]
		default:
			// We shouldn't enter into a different state, but if we do -- don't proceed with the replacement
			log.Printf("While querying status of prefix list %s (%s): entered unrecognized state %s", existingPrefixListID,
				prefixListName, state)
			err := fmt.Errorf("Prefix list creation for prefix list %s entered unrecognized state %s", newPrefixListID, state)
			results = append(results, PrefixListManagementOp{
				PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpPrefixListCreateFailedError,
				NewPrefixListID: newPrefixListID, Error: err,
			})
			return results
		}
	}

	// Move each security group to point to the new prefix list.
	err = plafm.ec2.DescribeSecurityGroupsPages(
		&ec2.DescribeSecurityGroupsInput{DryRun: aws.Bool(false), GroupIds: securityGroupIDs},
		func(output *ec2.DescribeSecurityGroupsOutput, _ bool) bool {
			for _, securityGroup := range output.SecurityGroups {
				results = append(results, plafm.replaceSecurityGroupReferences(
					securityGroup, prefixListName, existingPrefixListID, newPrefixListID)...)
			}
			return true
		})
	if err != nil {
		log.Printf("Failed to describe security groups related to prefix list %s (%s): %v", existingPrefixListID,
			prefixListName, err)
		results = append(results, PrefixListManagementOp{
			PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpSecurityGroupQueryFailedError,
			ExistingPrefixListID: existingPrefixListID, Error: err,
		})
	}

	// Delete the old prefix list.
	_, err = plafm.ec2.DeleteManagedPrefixList(&ec2.DeleteManagedPrefixListInput{DryRun: aws.Bool(false), PrefixListId: aws.String(existingPrefixListID)})
	if err != nil {
		log.Printf("Failed to delete old prefix list %s (%s): %v", existingPrefixListID, prefixListName, err)
		results = append(results, PrefixListManagementOp{
			PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpPrefixListDeleteFailedError,
			ExistingPrefixListID: existingPrefixListID, Error: err,
		})
	}

	results = append(results, PrefixListManagementOp{
		PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpReplacePrefixList,
		ExistingPrefixListID: existingPrefixListID, NewPrefixListID: newPrefixListID,
	})

	return results
}

func (plafm *PrefixListAddressFamilyManager) replaceSecurityGroupReferences(securityGroup *ec2.SecurityGroup, prefixListName, existingPrefixListID, newPrefixListID string) []PrefixListManagementOp {
	var revoke []*ec2.IpPermission
	var authorize []*ec2.IpPermission
	results := make([]PrefixListManagementOp, 0, 1)

	// Scan ingress for rules applying to this prefix list.
	for _, ingress := range securityGroup.IpPermissions {
		for _, plid := range ingress.PrefixListIds {
			if aws.StringValue(plid.PrefixListId) == existingPrefixListID {
				// Yep, found an existing rule. Mark it for replacement.
				revoke = append(revoke, &ec2.IpPermission{
					FromPort: ingress.FromPort, IpProtocol: ingress.IpProtocol, ToPort: ingress.ToPort,
					PrefixListIds: []*ec2.PrefixListId{plid},
				})
				authorizePLID := ec2.PrefixListId{PrefixListId: &newPrefixListID, Description: plid.Description}
				authorize = append(authorize, &ec2.IpPermission{
					FromPort: ingress.FromPort, IpProtocol: ingress.IpProtocol, ToPort: ingress.ToPort,
					PrefixListIds: []*ec2.PrefixListId{&authorizePLID},
				})
			}
		}
	}

	if len(revoke) > 0 {
		// We need to perform a revoke before we authorize to make sure we don't overflow the number of rules allowed. This is
		// non-ideal because there may be some interruption in connectivity. Ideally, AWS should have a Replace API for
		// security group rules.
		input := ec2.RevokeSecurityGroupIngressInput{
			DryRun: aws.Bool(false), GroupId: securityGroup.GroupId, IpPermissions: revoke,
		}

		if _, err := plafm.ec2.RevokeSecurityGroupIngress(&input); err != nil {
			log.Printf("Failed to revoke security groups %s ingress rule for prefix list %s (%s): %v", *securityGroup.GroupId,
				existingPrefixListID, prefixListName, err)
			results = append(results, PrefixListManagementOp{
				PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpSecurityGroupUpdateFailedError,
				ExistingPrefixListID: existingPrefixListID, SecurityGroupID: *securityGroup.GroupId, Error: err,
			})
		} else {
			input := ec2.AuthorizeSecurityGroupIngressInput{
				DryRun: aws.Bool(false), GroupId: securityGroup.GroupId, IpPermissions: authorize,
			}
			if _, err := plafm.ec2.AuthorizeSecurityGroupIngress(&input); err != nil {
				log.Printf("Failed to authorize security groups %s ingress rule for prefix list %s (%s): %v", *securityGroup.GroupId,
					newPrefixListID, prefixListName, err)
				results = append(results, PrefixListManagementOp{
					PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpSecurityGroupUpdateFailedError,
					NewPrefixListID: newPrefixListID, SecurityGroupID: *securityGroup.GroupId, Error: err,
				})
			} else {
				results = append(results, PrefixListManagementOp{
					PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpUpdateSecurityGroupIngress,
					ExistingPrefixListID: existingPrefixListID, NewPrefixListID: newPrefixListID, SecurityGroupID: *securityGroup.GroupId,
				})
			}
		}
	}

	revoke = nil
	authorize = nil

	// Do the same for egress rules
	for _, egress := range securityGroup.IpPermissionsEgress {
		for _, plid := range egress.PrefixListIds {
			if aws.StringValue(plid.PrefixListId) == existingPrefixListID {
				// Yep, found an existing rule. Mark it for replacement.
				revoke = append(revoke, &ec2.IpPermission{
					FromPort: egress.FromPort, IpProtocol: egress.IpProtocol, ToPort: egress.ToPort,
					PrefixListIds: []*ec2.PrefixListId{plid},
				})
				authorizePLID := ec2.PrefixListId{PrefixListId: &newPrefixListID, Description: plid.Description}
				authorize = append(authorize, &ec2.IpPermission{
					FromPort: egress.FromPort, IpProtocol: egress.IpProtocol, ToPort: egress.ToPort,
					PrefixListIds: []*ec2.PrefixListId{&authorizePLID},
				})
			}
		}
	}

	if len(revoke) > 0 {
		// Again, we need to revoke before authorizing.
		input := ec2.RevokeSecurityGroupEgressInput{
			DryRun: aws.Bool(false), GroupId: aws.String(existingPrefixListID), IpPermissions: revoke,
		}

		if _, err := plafm.ec2.RevokeSecurityGroupEgress(&input); err != nil {
			log.Printf("Failed to revoke security groups %s egress rule for prefix list %s (%s): %v", *securityGroup.GroupId,
				existingPrefixListID, prefixListName, err)
			results = append(results, PrefixListManagementOp{
				PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpSecurityGroupUpdateFailedError,
				ExistingPrefixListID: existingPrefixListID, SecurityGroupID: *securityGroup.GroupId, Error: err,
			})
		} else {
			input := ec2.AuthorizeSecurityGroupEgressInput{
				DryRun: aws.Bool(false), GroupId: aws.String(existingPrefixListID), IpPermissions: authorize,
			}
			if _, err := plafm.ec2.AuthorizeSecurityGroupEgress(&input); err != nil {
				log.Printf("Failed to authorize security groups %s egress rule for prefix list %s (%s): %v", *securityGroup.GroupId,
					newPrefixListID, prefixListName, err)
				results = append(results, PrefixListManagementOp{
					PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpSecurityGroupUpdateFailedError,
					NewPrefixListID: newPrefixListID, SecurityGroupID: *securityGroup.GroupId, Error: err,
				})
			} else {
				results = append(results, PrefixListManagementOp{
					PrefixListName: prefixListName, AddressFamily: plafm.addressFamily, Operation: OpUpdateSecurityGroupEgress,
					ExistingPrefixListID: existingPrefixListID, NewPrefixListID: newPrefixListID, SecurityGroupID: *securityGroup.GroupId,
				})
			}
		}
	}

	return results
}

// updateSSMWithPrefixListIDs updates the specified SSM parameters with the prefix list ids considered final.
func (plafm *PrefixListAddressFamilyManager) updateSSMWithPrefixListIDs(parameters []string, tags TagMap, tier string) []PrefixListManagementOp {
	// If there are no parameters, there's nothing to do. Short-circuit here so we don't have to keep validating for AWS.
	if len(parameters) == 0 {
		return nil
	}

	if tier == "" {
		tier = "Standard"
	}

	// The parameters in a string list are comma-separated.
	sort.Strings(plafm.prefixListIDs)
	expectedValue := strings.Join(plafm.prefixListIDs, ",")

	parameterPtrs := make([]*string, 0, len(parameters))
	for _, parameter := range parameters {
		parameterPtrs = append(parameterPtrs, aws.String(parameter))
	}

	output, err := plafm.ssm.GetParameters(&ssm.GetParametersInput{Names: parameterPtrs, WithDecryption: aws.Bool(false)})
	if err != nil {
		log.Printf("Failed to get SSM parameters %v: %v", parameters, err)
		return []PrefixListManagementOp{{
			Operation: OpSSMQueryFailedError, AddressFamily: plafm.addressFamily, Error: err,
		}}
	}

	var results []PrefixListManagementOp

	// Keep track of which parameters we've seen -- we'll create ones we haven't seen.
	unseenParameters := make(map[string]bool)
	for _, parameter := range parameters {
		unseenParameters[parameter] = true
	}

	for _, parameter := range output.Parameters {
		delete(unseenParameters, *parameter.Name)

		pValue := aws.StringValue(parameter.Value)
		// Make sure the values are correct.
		if aws.StringValue(parameter.Type) != "StringList" || pValue != expectedValue {
			// Update needed.
			log.Printf("Updating parameter value of %s from %s to %s", *parameter.Name, pValue, expectedValue)
			_, err := plafm.ssm.PutParameter(&ssm.PutParameterInput{Name: parameter.Name, Type: aws.String("StringList"),
				Value: &expectedValue, Overwrite: aws.Bool(true)})
			if err != nil {
				log.Printf("Failed to update parameter value for %s: %v", *parameter.Name, err)
				results = append(results, PrefixListManagementOp{
					AddressFamily: plafm.addressFamily, Operation: OpSSMParameterValueUpdateFailedError,
					SSMParameterName: *parameter.Name, Error: err,
				})
			} else {
				results = append(results, PrefixListManagementOp{
					AddressFamily: plafm.addressFamily, Operation: OpSSMParameterValueUpdated,
					SSMParameterName: *parameter.Name,
				})
			}
		} else {
			log.Printf("SSM parameter %s value is up-to-date", *parameter.Name)
		}

		// And check the tags for this resource
		output, err := plafm.ssm.ListTagsForResource(&ssm.ListTagsForResourceInput{
			ResourceId: parameter.Name, ResourceType: aws.String("Parameter")})
		if err != nil {
			log.Printf("Failed to get tags for SSM parameter %s: %v", *parameter.Name, err)
			results = append(results, PrefixListManagementOp{
				AddressFamily: plafm.addressFamily, Operation: OpSSMQueryFailedError, SSMParameterName: *parameter.Name,
				Error: err,
			})
		} else {
			tagsNotSeen := make(map[string]string)
			var tagsToAdd []*ssm.Tag

			for key, value := range tags {
				tagsNotSeen[key] = value
			}

			for _, tag := range output.TagList {
				expectedValue, present := tagsNotSeen[*tag.Key]

				// Ignore tags that have been added -- the user may have added them for additional tracking purposes.
				if !present {
					continue
				}

				delete(tagsNotSeen, *tag.Key)

				// If the value isn't correct, mark the tag for addition.
				if expectedValue != *tag.Value {
					tagsToAdd = append(tagsToAdd, &ssm.Tag{Key: tag.Key, Value: aws.String(expectedValue)})
				}
			}

			// Add any tags that weren't seen in our enumeration.
			for key, value := range tagsNotSeen {
				tagsToAdd = append(tagsToAdd, &ssm.Tag{Key: aws.String(key), Value: aws.String(value)})
			}

			if len(tagsToAdd) > 0 {
				// We need an update here.
				log.Printf("Adding/updating SSM parameter %s tags: %v", *parameter.Name, tags)
				_, err := plafm.ssm.AddTagsToResource(&ssm.AddTagsToResourceInput{
					ResourceId: parameter.Name, ResourceType: aws.String("Parameter"), Tags: tagsToAdd})
				if err != nil {
					log.Printf("Failed to add/update tags for parameter %s: %v", *parameter.Name, err)
					results = append(results, PrefixListManagementOp{
						Operation: OpSSMParameterTagsUpdateFailedError, AddressFamily: plafm.addressFamily,
						SSMParameterName: *parameter.Name, Error: err,
					})
				} else {
					results = append(results, PrefixListManagementOp{
						Operation: OpSSMParameterTagsUpdated, AddressFamily: plafm.addressFamily, SSMParameterName: *parameter.Name,
						Error: err,
					})
				}
			} else {
				log.Printf("SSM parameter %s tags are up-to-date", *parameter.Name)
				results = append(results, PrefixListManagementOp{
					Operation: OpNoModifySSMParameterTags, AddressFamily: plafm.addressFamily, SSMParameterName: *parameter.Name,
					Error: err,
				})
			}
		}
	}

	// Create any parameters that weren't seen
	var ssmTags []*ssm.Tag
	for key, value := range tags {
		ssmTags = append(ssmTags, &ssm.Tag{Key: aws.String(key), Value: aws.String(value)})
	}

	for parameterName := range unseenParameters {
		log.Printf("Creating SSM parameter %s with value %s and tags %v", parameterName, expectedValue, tags)
		_, err := plafm.ssm.PutParameter(&ssm.PutParameterInput{
			Name: aws.String(parameterName), Value: aws.String(expectedValue), Type: aws.String("StringList"),
			Tags: ssmTags, Tier: aws.String(tier), Overwrite: aws.Bool(false),
		})

		if err != nil {
			log.Printf("Failed to create SSM parameter %s: %v", parameterName, err)
			results = append(results, PrefixListManagementOp{
				Operation: OpSSMParameterCreateFailedError, AddressFamily: plafm.addressFamily, SSMParameterName: parameterName,
				Error: err,
			})
		} else {
			results = append(results, PrefixListManagementOp{
				Operation: OpSSMParameterCreated, AddressFamily: plafm.addressFamily, SSMParameterName: parameterName,
				Error: err,
			})
		}
	}

	return results
}

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
	"github.com/aws/aws-sdk-go/service/cloudwatch"
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

	// prefixListNameBase provides the root of the prefix list names
	prefixListNameBase string

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

	// metrics is a list of metrics to send to CloudWatch
	metrics []*cloudwatch.MetricDatum

	// errors is a list of errors encountered when making changes
	errors []error

	// updatesPerformed indicates whether updates were made to the prefix lists for this address family.
	updatesPerformed bool

	// notification is the structure to send if notifications are sent.
	notification PrefixListAddressFamilyNotification
}

// NewPrefixListAddressFamilyManager creates a new PrefixListAddressFamilyManager object with the specified parameters.
func NewPrefixListAddressFamilyManager(partition string, accountID string, prefixListNameBase string, ec2Client ec2iface.EC2API,
	ssmClient ssmiface.SSMAPI, addressFamily string, groupSize uint, prefixListTags TagMap) *PrefixListAddressFamilyManager {
	return &PrefixListAddressFamilyManager{
		partition: partition, accountID: accountID, prefixListNameBase: prefixListNameBase, ec2: ec2Client, ssm: ssmClient,
		addressFamily: addressFamily, groupSize: groupSize, tags: prefixListTags, updatesPerformed: false,
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

	// Save information for CloudWatch about the number of prefixes we kept.
	AddMetric(plafm, MetricPrefixes, float64(len(filteredPrefixes)), UnitCount)

	// Stop here if there are no prefixes.
	if len(filteredPrefixes) == 0 {
		// Save 0 for the AggregatedPrefixes and Groups metric.
		AddMetric(plafm, MetricAggregatedPrefixes, 0.0, UnitCount)
		AddMetric(plafm, MetricGroups, 0.0, UnitCount)

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

	// Save the number of prefixes in case we need to notify SNS.
	plafm.notification.PrefixCount = uint(len(plafm.keptPrefixes))

	// Save aggregation metrics.
	AddMetric(plafm, MetricAggregatedPrefixes, float64(len(plafm.keptPrefixes)), UnitCount)
	AddMetric(plafm, MetricGroups, float64(plafm.nGroups), UnitCount)

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
		log.Printf("Filter %v rejects prefix %v: NetworkBorderGroup mismatch", filter, prefix)
		return false
	}

	return true
}

// generatePrefixListNames generates a list of prefix list names over the given number of groups.
func (plafm *PrefixListAddressFamilyManager) generatePrefixListNames(tpl *template.Template) error {
	templateVars := PrefixListTemplateVars{
		PrefixListNameBase: plafm.prefixListNameBase, AddressFamily: plafm.addressFamily, GroupCount: strconv.FormatUint(uint64(plafm.nGroups), 10),
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

		filters = append(filters, MakeEC2Filter(FilterPrefixListName, prefixListName))
		filters = append(filters, MakeEC2Filter(FilterOwnerID, plafm.accountID))
		filters = append(filters, MakeEC2Filter(FilterTagGroupID, strconv.FormatInt(int64(groupID), 10)))

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

// updateManagedPrefixLists updates (either by replacing entries or replacing the prefix list itself -- see managePrefixListGroup)
// each group in a prefix list.
func (plafm *PrefixListAddressFamilyManager) updateManagedPrefixLists() {
	nGroups := len(plafm.prefixListNames)

	for i, groupID := uint(0), uint(0); groupID < uint(nGroups); i, groupID = i+plafm.groupSize, groupID+1 {
		end := i + plafm.groupSize
		if end > uint(len(plafm.keptPrefixes)) {
			end = uint(len(plafm.keptPrefixes))
		}

		prefixListName := plafm.prefixListNames[groupID]
		existingPrefixList := plafm.prefixListNamesToExistingPrefixLists[prefixListName]
		prefixBlock := plafm.keptPrefixes[i:end]

		plafm.managePrefixListGroup(groupID, prefixListName, existingPrefixList, prefixBlock)
	}
}

// managePrefixListGroup creates or upates a prefix list corresponding to a block of prefixes. This block may be a subset of the
// full set of prefixes returned by the filters -- it's always less than or equal to the group size.
func (plafm *PrefixListAddressFamilyManager) managePrefixListGroup(groupID uint, prefixListName string, existingPrefixList *ec2.ManagedPrefixList, prefixBlock []string) {
	defer Time(plafm, MetricExaminePrefixListGroup, DimGroupID(groupID)).Done()

	if existingPrefixList == nil {
		// No existing prefix list. Create one.
		plafm.updatesPerformed = true

		createPrefixListGroupTimer := Time(plafm, MetricCreatePrefixListGroup, DimGroupID(groupID))
		prefixList, err := plafm.createPrefixListGroup(groupID, prefixListName, prefixBlock)
		createPrefixListGroupTimer.Done()

		if err != nil {
			plafm.errors = append(plafm.errors, err)
			return
		}

		AddMetric(plafm, MetricCreatePrefixListGroupSuccess, float64(createPrefixListGroupTimer.Elapsed.Milliseconds()), UnitMilliseconds, DimGroupID(groupID))
		plafm.prefixListIDs = append(plafm.prefixListIDs, *prefixList.PrefixListId)
		plafm.notification.PrefixListIDs = append(plafm.notification.PrefixListIDs, *prefixList.PrefixListId)

		return
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

		getManagedPrefixListEntriesTimer := Time(plafm, MetricGetManagedPrefixListEntries, DimGroupID(groupID))
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
		getManagedPrefixListEntriesTimer.Done()

		// Failed to get the existing entries.
		if err != nil {
			log.Printf("Failed to get entries for prefix list %s (%s): %v", existingPrefixListID, prefixListName, err)
			plafm.errors = append(plafm.errors, err)

			// Since we're not able to create or update a prefix list for this block, assume that this is ok for now. Otherwise,
			// the prefix list may fall out of SSM and other brokenness may happen.
			plafm.prefixListIDs = append(plafm.prefixListIDs, existingPrefixListID)
			plafm.notification.PrefixListIDs = append(plafm.notification.PrefixListIDs, existingPrefixListID)
			return
		}

		AddMetric(plafm, MetricGetManagedPrefixListEntriesSuccess, float64(getManagedPrefixListEntriesTimer.Elapsed.Milliseconds()), UnitMilliseconds, DimGroupID(groupID))
	}

	if replacementNeeded {
		plafm.updatesPerformed = true
		defer Time(plafm, MetricReplacePrefixListGroup, DimGroupID(groupID)).Done()
		// replacePrefixList will set the new id in plafm.prefixListIDs.
		plafm.replacePrefixListGroup(groupID, prefixListName, existingPrefixList, prefixBlock)

		return
	}

	// We know that this prefix list will be retained at this point. Add it to the prefix lists that are considered final.
	plafm.prefixListIDs = append(plafm.prefixListIDs, existingPrefixListID)
	plafm.notification.PrefixListIDs = append(plafm.notification.PrefixListIDs, existingPrefixListID)

	// Generate the entries to add to the CIDR block.
	for prefix, seen := range seenPrefixes {
		if !seen {
			addEntries = append(addEntries, &ec2.AddPrefixListEntry{Cidr: aws.String(prefix)})
			addEntriesStr = append(addEntriesStr, prefix)
		}
	}

	if len(addEntries) == 0 && len(removeEntries) == 0 {
		// Nothing to do
		log.Printf("Prefix list %s (%s) is up-to-date; no modifications needed", existingPrefixListID, prefixListName)
		return
	}

	// Need to update the prefix list. Mark this as updated.
	plafm.updatesPerformed = true
	plafm.notification.UpdatedPrefixListIDs = append(plafm.notification.UpdatedPrefixListIDs, existingPrefixListID)
	updatePrefixListGroupTimer := Time(plafm, MetricUpdatePrefixListGroup, DimGroupID(groupID))

	// The total should be under the group size.
	modify := ec2.ModifyManagedPrefixListInput{
		PrefixListId: existingPrefixList.PrefixListId, CurrentVersion: existingPrefixList.Version, DryRun: aws.Bool(false),
		PrefixListName: existingPrefixList.PrefixListName, AddEntries: addEntries, RemoveEntries: removeEntries,
	}

	log.Printf("Modifying prefix list %s (%s): AddEntries=%v, RemoveEntries=%v", existingPrefixListID, prefixListName, addEntriesStr, removeEntriesStr)
	_, err := plafm.ec2.ModifyManagedPrefixList(&modify)
	updatePrefixListGroupTimer.Done()

	if err != nil {
		log.Printf("Failed to modify prefix list %s (%s): %v", existingPrefixListID, prefixListName, err)
		plafm.errors = append(plafm.errors, err)
	}

	AddMetric(plafm, MetricUpdatePrefixListGroupSuccess, float64(updatePrefixListGroupTimer.Elapsed.Milliseconds()), UnitMilliseconds, DimGroupID(groupID))
}

// createPrefixListGroup creates a prefix list with the given name and block of IP addresses.
func (plafm *PrefixListAddressFamilyManager) createPrefixListGroup(groupID uint, prefixListName string, prefixBlock []string) (*ec2.ManagedPrefixList, error) {
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

func (plafm *PrefixListAddressFamilyManager) replacePrefixListGroup(groupID uint, prefixListName string, existingPrefixList *ec2.ManagedPrefixList, prefixBlock []string) {
	existingPrefixListID := *existingPrefixList.PrefixListId

	// Need to perform a wholesale replacement of this prefix list. Let's see what security groups depend on it first.
	input := ec2.GetManagedPrefixListAssociationsInput{
		DryRun: aws.Bool(false), PrefixListId: aws.String(existingPrefixListID),
	}
	securityGroupIDs := make([]*string, 0)

	getPrefixListAssociationsTimer := Time(plafm, MetricGetPrefixListAssociations, DimGroupID(groupID))
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
	getPrefixListAssociationsTimer.Done()

	// We couldn't figure out who is referencing this list. Note the error and continue.
	if err != nil {
		log.Printf("Can't replace prefix list %s: GetManagedPrefixListAssociations failed: %v", existingPrefixListID, err)
		plafm.errors = append(plafm.errors, err)
	}

	AddMetric(plafm, MetricGetPrefixListAssociationsSuccess, float64(getPrefixListAssociationsTimer.Elapsed.Milliseconds()), UnitMilliseconds, DimGroupID(groupID))

	createPrefixListGroupTimer := Time(plafm, MetricCreatePrefixListGroup, DimGroupID(groupID))
	// Create a new prefix list first.
	newPrefixList, err := plafm.createPrefixListGroup(groupID, prefixListName, prefixBlock)
	createPrefixListGroupTimer.Done()

	if err != nil {
		// This isn't a good situation. Mark the existing as final for this block so we don't drop rules.
		plafm.prefixListIDs = append(plafm.prefixListIDs, existingPrefixListID)
		plafm.notification.PrefixListIDs = append(plafm.notification.PrefixListIDs, existingPrefixListID)
		plafm.errors = append(plafm.errors, err)
		return
	}

	AddMetric(plafm, MetricCreatePrefixListGroupSuccess, float64(createPrefixListGroupTimer.Elapsed.Milliseconds()), UnitMilliseconds, DimGroupID(groupID))

	// We were successful in creating the new prefix list. Add it to the list of final prefix lists.
	newPrefixListID := aws.StringValue(newPrefixList.PrefixListId)
	plafm.prefixListIDs = append(plafm.prefixListIDs, newPrefixListID)
	plafm.notification.PrefixListIDs = append(plafm.notification.PrefixListIDs, newPrefixListID)
	plafm.notification.ReplacedPrefixLists = append(plafm.notification.ReplacedPrefixLists, PrefixListReplacement{
		OldPrefixListID: existingPrefixListID, NewPrefixListID: newPrefixListID,
	})

	// Wait until the prefix list is ready before attempting to inject it into security groups.
outer:
	for {
		state := aws.StringValue(newPrefixList.State)
		switch state {
		case "create-complete":
			break outer
		case "create-failed":
			// Something happened during creation; bail out here.
			plafm.errors = append(plafm.errors, fmt.Errorf("Creation of prefix list %s failed asynchronously", newPrefixListID))
			return
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
				plafm.errors = append(plafm.errors, err)
				return
			}

			// Make sure we have exactly one result
			if len(output.PrefixLists) == 0 {
				log.Printf("While querying status of prefix list %s (%s): prefix list disappeared from results", existingPrefixListID, prefixListName)
				err := fmt.Errorf("Prefix list state query failed for prefix list %s: prefix list not found", newPrefixListID)
				plafm.errors = append(plafm.errors, err)
				return
			}

			if len(output.PrefixLists) > 1 {
				log.Printf("While querying status of prefix list %s (%s): query returned %d results", existingPrefixListID,
					prefixListName, len(output.PrefixLists))
				err := fmt.Errorf("Prefix list state query failed for prefix list %s: multiple prefix lists returned: %v",
					newPrefixListID, output.PrefixLists)
				plafm.errors = append(plafm.errors, err)
				return
			}

			newPrefixList = output.PrefixLists[0]
		default:
			// We shouldn't enter into a different state, but if we do -- don't proceed with the replacement
			log.Printf("While querying status of prefix list %s (%s): entered unrecognized state %s", existingPrefixListID,
				prefixListName, state)
			err := fmt.Errorf("Prefix list creation for prefix list %s entered unrecognized state %s", newPrefixListID, state)
			plafm.errors = append(plafm.errors, err)
			return
		}
	}

	// Move each security group to point to the new prefix list.
	describeSecurityGroupsTimer := Time(plafm, MetricDescribeSecurityGroups, DimGroupID(groupID))
	err = plafm.ec2.DescribeSecurityGroupsPages(
		&ec2.DescribeSecurityGroupsInput{DryRun: aws.Bool(false), GroupIds: securityGroupIDs},
		func(output *ec2.DescribeSecurityGroupsOutput, _ bool) bool {
			for _, securityGroup := range output.SecurityGroups {
				plafm.replaceSecurityGroupReferences(securityGroup, prefixListName, existingPrefixListID, newPrefixListID)
			}
			return true
		})
	describeSecurityGroupsTimer.Done()

	if err != nil {
		// We weren't able to describe the security groups; note the error, but carry on with deletion (which will still fail
		// if there actually are prefix lists attached.
		log.Printf("Failed to describe security groups related to prefix list %s (%s): %v", existingPrefixListID,
			prefixListName, err)
		plafm.errors = append(plafm.errors, err)
	}

	// Delete the old prefix list.
	_, err = plafm.ec2.DeleteManagedPrefixList(&ec2.DeleteManagedPrefixListInput{DryRun: aws.Bool(false), PrefixListId: aws.String(existingPrefixListID)})
	if err != nil {
		log.Printf("Failed to delete old prefix list %s (%s): %v", existingPrefixListID, prefixListName, err)
		plafm.errors = append(plafm.errors, err)
	}
}

func (plafm *PrefixListAddressFamilyManager) replaceSecurityGroupReferences(securityGroup *ec2.SecurityGroup, prefixListName, existingPrefixListID, newPrefixListID string) {
	var revoke []*ec2.IpPermission
	var authorize []*ec2.IpPermission

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
			plafm.errors = append(plafm.errors, err)
		} else {
			input := ec2.AuthorizeSecurityGroupIngressInput{
				DryRun: aws.Bool(false), GroupId: securityGroup.GroupId, IpPermissions: authorize,
			}
			if _, err := plafm.ec2.AuthorizeSecurityGroupIngress(&input); err != nil {
				log.Printf("Failed to authorize security groups %s ingress rule for prefix list %s (%s): %v", *securityGroup.GroupId,
					newPrefixListID, prefixListName, err)
				plafm.errors = append(plafm.errors, err)
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
			DryRun: aws.Bool(false), GroupId: securityGroup.GroupId, IpPermissions: revoke,
		}

		if _, err := plafm.ec2.RevokeSecurityGroupEgress(&input); err != nil {
			log.Printf("Failed to revoke security groups %s egress rule for prefix list %s (%s): %v", *securityGroup.GroupId,
				existingPrefixListID, prefixListName, err)
			plafm.errors = append(plafm.errors, err)
		} else {
			input := ec2.AuthorizeSecurityGroupEgressInput{
				DryRun: aws.Bool(false), GroupId: securityGroup.GroupId, IpPermissions: authorize,
			}
			if _, err := plafm.ec2.AuthorizeSecurityGroupEgress(&input); err != nil {
				log.Printf("Failed to authorize security groups %s egress rule for prefix list %s (%s): %v", *securityGroup.GroupId,
					newPrefixListID, prefixListName, err)
				plafm.errors = append(plafm.errors, err)
			}
		}
	}
}

// updateSSMWithPrefixListIDs updates the specified SSM parameters with the prefix list ids considered final.
func (plafm *PrefixListAddressFamilyManager) updateSSMWithPrefixListIDs(parameters []string, tags TagMap, tier string) {
	// If there are no parameters, there's nothing to do. Short-circuit here so we don't have to keep validating for AWS.
	if len(parameters) == 0 {
		return
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
		plafm.errors = append(plafm.errors, err)
		return
	}

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
				plafm.errors = append(plafm.errors, err)
			}
		} else {
			log.Printf("SSM parameter %s value is up-to-date", *parameter.Name)
		}

		// And check the tags for this resource
		output, err := plafm.ssm.ListTagsForResource(&ssm.ListTagsForResourceInput{
			ResourceId: parameter.Name, ResourceType: aws.String("Parameter")})
		if err != nil {
			log.Printf("Failed to get tags for SSM parameter %s: %v", *parameter.Name, err)
			plafm.errors = append(plafm.errors, err)
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
					plafm.errors = append(plafm.errors, err)
				}
			} else {
				log.Printf("SSM parameter %s tags are up-to-date", *parameter.Name)
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
			plafm.errors = append(plafm.errors, err)
		}
	}
}

// AddMetric saves a metric datum to the saved metrics on this object.
func (plafm *PrefixListAddressFamilyManager) AddMetric(datum *cloudwatch.MetricDatum) {
	plafm.metrics = append(plafm.metrics, datum)
}

// CreateMetric is a utility function for creating a CloudWatch metric datum pre-populated with our dimensions. It also
// sets the timestamp to the current time.
func (plafm *PrefixListAddressFamilyManager) CreateMetric() *cloudwatch.MetricDatum {
	dimensions := []*cloudwatch.Dimension{DimAddressFamily(plafm.addressFamily), DimPrefixListNameBase(plafm.prefixListNameBase)}
	return new(cloudwatch.MetricDatum).SetTimestamp(time.Now().UTC()).SetDimensions(dimensions)
}

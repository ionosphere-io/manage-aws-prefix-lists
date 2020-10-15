package main

import (
	"fmt"
	"math/rand"
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

	managedPrefixLists []*managedPrefixListAndEntries
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
			tags = append(tags, tagSpec.Tags...)
		}
	}

	var entries []*ec2.PrefixListEntry
	for _, entry := range input.Entries {
		entries = append(entries, &ec2.PrefixListEntry{Cidr: entry.Cidr, Description: entry.Description})
	}

	mpl := managedPrefixListAndEntries{
		PrefixList: ec2.ManagedPrefixList{
			AddressFamily:  input.AddressFamily,
			MaxEntries:     input.MaxEntries,
			PrefixListArn:  aws.String(fmt.Sprintf("arn:aws:ec2:us-west-2:123456789012:prefix-list/%s", plID)),
			PrefixListName: input.PrefixListName,
			PrefixListId:   &plID,
			State:          aws.String("create-complete"),
			Tags:           tags,
			Version:        aws.Int64(0),
		},
		Entries: entries,
	}

	m.managedPrefixLists = append(m.managedPrefixLists, &mpl)
	return &ec2.CreateManagedPrefixListOutput{PrefixList: &(mpl.PrefixList)}, nil
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

type SSMMock struct {
	ssmiface.SSMAPI

	parameters map[string]*ssm.Parameter
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
		ARN: &arn, Name: input.Name, Value: input.Value, DataType: &dataType, Version: &version, Type: input.Type,
	}
	m.parameters[name] = &param
	return &ssm.PutParameterOutput{Tier: &tier, Version: &version}, nil
}

type STSMock struct {
	stsiface.STSAPI
}

func (m *STSMock) GetCallerIdentity(_ *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
	output := sts.GetCallerIdentityOutput{Account: aws.String("123456789012"),
		Arn: aws.String("arn:aws-test:iam::123456789012:user/test"), UserId: aws.String("AIDAAAAAAAEXAMPLEUSER")}
	return &output, nil
}

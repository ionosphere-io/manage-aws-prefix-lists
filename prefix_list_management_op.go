package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws/awserr"
)

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

func (opType OperationType) IsError() bool {
	return strings.HasSuffix(opType.String(), "Error")
}

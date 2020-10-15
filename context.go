package main

// This file provides keys for retrieving values out of a Go context.

// EC2ClientKey is a context key to use for retrieving an ec2iface.EC2API value from a context.
var EC2ClientKey EC2ClientKeyType

// SSMClientKey is a context key to use for retrieving an ssmiface.STSAPI value from a context.
var SSMClientKey SSMClientKeyType

// STSClientKey is a context key to use for retrieving an stsiface.STSAPI value from a context.
var STSClientKey STSClientKeyType

// SNSClientKey is a context key to use for retrieving an snsiface.SNSAPI value from a context.
var SNSClientKey SNSClientKeyType

// EC2ClientKeyType is a context key structure identifying an ec2iface.EC2API to use when making API calls (for testing).
type EC2ClientKeyType struct{}

// SSMClientKeyType is a context key structure identifying an ssmiface.SSMAPI to use when making API calls (for testing).
type SSMClientKeyType struct{}

// STSClientKeyType is a context key structure identifying an stsiface.STSAPI to use when making API calls (for testing).
type STSClientKeyType struct{}

// SNSClientKeyType is a context key structure identifying an snsiface.SNSAPI to use when making API calls (for testing).
type SNSClientKeyType struct{}

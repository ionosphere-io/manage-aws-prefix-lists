package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
)

type testingLogger struct {
	testContext *testing.T
}

func (tl *testingLogger) Write(p []byte) (int, error) {
	tl.testContext.Log(string(p))
	return len(p), nil
}

func createLoggerFromTesting(c *testing.T) *log.Logger {
	writer := &testingLogger{testContext: c}
	return log.New(writer, "", 0)
}

type ipRangesHandler struct {
	ipRanges *IPRanges
}

// ServeHTTP serves ip-ranges.json documents when GET requests are performed.
func (ipr *ipRangesHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Add("Server", "IPRanges/0.0")

	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		serialized, err := json.Marshal(ipr.ipRanges)
		if err != nil {
			rw.Header().Add("Content-Type", "text/plain; charset=utf-8")
			serialized = []byte(fmt.Sprintf("Failed to serialize ip-ranges.json: %v", err))
			rw.Header().Add("Content-Length", fmt.Sprintf("%d", len(serialized)))
			rw.WriteHeader(http.StatusInternalServerError)
			if req.Method == "GET" {
				rw.Write(serialized)
			}
		} else {
			rw.Header().Add("Content-Type", "application/json")
			rw.Header().Add("Content-Length", fmt.Sprintf("%d", len(serialized)))
			rw.WriteHeader(http.StatusOK)
			if req.Method != http.MethodHead {
				rw.Write(serialized)
			}
			fmt.Fprintf(os.Stderr, "Wrote ip-ranges.json: %v\n", string(serialized))
		}

		return
	}

	rw.Header().Add("Content-Type", "text/plain; charset=utf-8")
	serialized := []byte(fmt.Sprintf("Invalid request method %s; expected GET or HEAD", req.Method))
	rw.Header().Add("Content-Length", fmt.Sprintf("%d", len(serialized)))
	rw.WriteHeader(http.StatusBadRequest)
	rw.Write(serialized)
	return
}

// IPRangesServer represents a running test ip-ranges.json server.
type IPRangesServer struct {
	Server   *http.Server
	Listener net.Listener
	handler  *ipRangesHandler
}

// StartIPRangesServer creates a new test ip-ranges.json server with the specified initial IP ranges content.
func StartIPRangesServer(c *testing.T, ipRanges *IPRanges) (*IPRangesServer, error) {
	handler := &ipRangesHandler{ipRanges: ipRanges}
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		return nil, err
	}

	server := http.Server{Handler: handler, ErrorLog: createLoggerFromTesting(c)}
	go server.Serve(listener)

	return &IPRangesServer{Server: &server, Listener: listener}, nil
}

// GetURL returns the URL to use for fetching the test ip-ranges.json documents.
func (iprs *IPRangesServer) GetURL() string {
	return fmt.Sprintf("http://%s", iprs.Listener.Addr().String())
}

// Shutdown stops the HTTP server.
func (iprs *IPRangesServer) Shutdown() error {
	return iprs.Server.Shutdown(context.Background())
}

// UpdateIPRanges changes the IP ranges document returned by the HTTP server.
func (iprs *IPRangesServer) UpdateIPRanges(ipRanges *IPRanges) {
	iprs.handler.ipRanges = ipRanges
}

type managedPrefixListAndEntries struct {
	PrefixList ec2.ManagedPrefixList
	Entries    []*ec2.PrefixListEntry
}

type mockEC2TestBasicPrefixList struct {
	ec2iface.EC2API

	managedPrefixLists []*managedPrefixListAndEntries
}

func (m *mockEC2TestBasicPrefixList) CreateManagedPrefixList(input *ec2.CreateManagedPrefixListInput) (*ec2.CreateManagedPrefixListOutput, error) {
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

func (m *mockEC2TestBasicPrefixList) DescribeManagedPrefixListsPages(input *ec2.DescribeManagedPrefixListsInput, iter func(*ec2.DescribeManagedPrefixListsOutput, bool) bool) error {
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

type mockSSMTestBasicPrefixList struct {
	ssmiface.SSMAPI
}

type mockSTSTestBasicPrefixList struct {
	stsiface.STSAPI
}

func (m *mockSTSTestBasicPrefixList) GetCallerIdentity(_ *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
	output := sts.GetCallerIdentityOutput{Account: aws.String("123456789012"),
		Arn: aws.String("arn:aws-test:iam::123456789012:user/test"), UserId: aws.String("AIDAAAAAAAEXAMPLEUSER")}
	return &output, nil
}

func TestBasicPrefixList(c *testing.T) {
	prefixesIPv4 := []IPv4Prefix{
		{IPPrefix: "10.20.0.0/16", Region: "us-west-2", Service: "EC2", NetworkBorderGroup: "us-west-2"},
		{IPPrefix: "10.21.0.0/16", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPPrefix: "192.168.0.0/24", Region: "us-west-1", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-1"},
		{IPPrefix: "192.168.1.0/24", Region: "us-west-1", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-1"},
		{IPPrefix: "192.168.2.0/24", Region: "us-west-1", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-1"},
		{IPPrefix: "192.168.3.0/25", Region: "us-west-1", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-1"},
		{IPPrefix: "192.168.3.128/25", Region: "us-west-1", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-1"},
	}
	prefixesIPv6 := []IPv6Prefix{
		{IPv6Prefix: "fc00:20::/64", Region: "us-west-2", Service: "EC2", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:21::/64", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:0::/64", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:1::/64", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:2:0::/65", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:2:8000::/66", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:2:c000::/66", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
		{IPv6Prefix: "fc00:22:0:3::/64", Region: "us-west-2", Service: "CLOUDFRONT", NetworkBorderGroup: "us-west-2"},
	}
	ipRanges := IPRanges{SyncToken: "1", CreateDate: "2000-01-01-00-00-00", Prefixes: prefixesIPv4, IPv6Prefixes: prefixesIPv6}
	server, err := StartIPRangesServer(c, &ipRanges)
	if err != nil {
		c.Fatalf("Unable to start IP ranges server: %v", err)
		return
	}
	defer server.Shutdown()

	ec2Mock := &mockEC2TestBasicPrefixList{}
	ctx := context.WithValue(context.Background(), EC2ClientKey, ec2Mock)
	ctx = context.WithValue(ctx, SSMClientKey, &mockSSMTestBasicPrefixList{})
	ctx = context.WithValue(ctx, STSClientKey, &mockSTSTestBasicPrefixList{})
	req := ManageAWSPrefixListsRequest{}
	if err = json.Unmarshal([]byte(`{
	"PrefixListNameBase": "cloudfront",
	"Filters": [
		{"Service": "CLOUDFRONT"}
	]
}`), &req); err != nil {
		c.Fatalf("Failed to create request: %v", err)
	}

	req.IPRangesURL = server.GetURL()

	response, error := HandleLambdaRequest(ctx, req)
	if error != nil {
		c.Errorf("Failed to handle request: %v\n", error)
	}
	responseDecoded := make(map[string]interface{})
	error = json.Unmarshal([]byte(response), &responseDecoded)
	if error != nil {
		c.Errorf("Failed to unmarshal response as JSON: %v\n", error)
	}

	// Make sure aggregation happened as expected
	if len(ec2Mock.managedPrefixLists) != 2 {
		c.Errorf("Expected 2 managed prefix lists; got %d", len(ec2Mock.managedPrefixLists))
	}

	for _, mpl := range ec2Mock.managedPrefixLists {
		switch aws.StringValue(mpl.PrefixList.AddressFamily) {
		case "IPv4":
			if len(mpl.Entries) != 2 {
				c.Errorf("Expected 2 CIDRs in IPv4 range: %v", mpl.Entries)
			} else {
				if aws.StringValue(mpl.Entries[1].Cidr) != "192.168.0.0/22" {
					c.Errorf("Expected aggregation to result in 192.168.0.0/22: %v", mpl.Entries[1].Cidr)
				}
			}

		case "IPv6":
			if len(mpl.Entries) != 2 {
				c.Errorf("Expected 2 CIDRs in IPv6 range: %v", mpl.Entries)
			} else {
				if aws.StringValue(mpl.Entries[1].Cidr) != "fc00:22::/62" {
					c.Errorf("Expected aggregation to result in fc00:22::/62: %v", mpl.Entries[1].Cidr)
				}
			}
		}
	}
}

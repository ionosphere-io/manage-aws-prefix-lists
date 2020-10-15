package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/service/ec2"
)

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

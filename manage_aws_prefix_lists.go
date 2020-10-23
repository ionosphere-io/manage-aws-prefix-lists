package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
)

// main program entrypoint. This allows for command-line testing as well as invocation from within Lambda.
func main() {
	if os.Getenv("AWS_LAMBDA_FUNCTION_VERSION") != "" {
		lambda.Start(HandleLambdaRequest)
	} else {
		var request ManageAWSPrefixListsRequest

		flag.Parse()
		args := flag.Args()

		var input io.Reader

		if len(args) == 0 {
			input = os.Stdin
		} else if len(args) > 1 {
			fmt.Fprintf(os.Stderr, "Unknown argument: %s\n", args[1])
			flag.PrintDefaults()
			os.Exit(2)
		} else {
			filename := args[0]
			fileInput, err := os.Open(filename)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to open %s: %v\n", filename, err)
				os.Exit(1)
			}
			defer fileInput.Close()
			input = fileInput
		}

		decoder := json.NewDecoder(input)
		if err := decoder.Decode(&request); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read an ManageAWSPrefixListsRequest from stdin: %v\n", err)
			os.Exit(1)
		}

		result, err := HandleLambdaRequest(context.Background(), request)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Request failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(result)
		os.Exit(0)
	}
}

// HandleLambdaRequest is the main Lambda entrypoint for updating a prefix list from ip-ranges.json.
func HandleLambdaRequest(ctx context.Context, request ManageAWSPrefixListsRequest) (string, error) {
	log.Printf("Incoming request: %v", request)

	plm, err := NewPrefixListManagerFromRequest(ctx, &request)
	if err != nil {
		return "", fmt.Errorf("Failed to create a PrefixListManager app handler: %v", err)
	}

	err = plm.LoadIPRanges()
	if err != nil {
		return "", err
	}

	if err = plm.Process(); err != nil {
		return "", fmt.Errorf("Failed to process ip-ranges.json from %s: %v", request.IPRangesURL, err)
	}

	response := ManageAWSPrefixListsResponse{}

	if len(plm.ipv4.errors) != 0 || len(plm.ipv6.errors) != 0 {
		response.Status = "ERROR"

		for _, err := range plm.ipv4.errors {
			response.Errors = append(response.Errors, err.Error())
		}

		for _, err := range plm.ipv6.errors {
			response.Errors = append(response.Errors, err.Error())
		}
	} else {
		response.Status = "SUCCESS"
	}

	resultBytes, err := json.Marshal(response)
	if err != nil {
		return "", fmt.Errorf("Failed to marshal response: %v", err)
	}

	return string(resultBytes), nil
}

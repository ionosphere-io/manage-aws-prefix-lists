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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/eventbridge"
)

// main program entrypoint. This allows for command-line testing as well as invocation from within Lambda.
func main() {
	if os.Getenv("AWS_LAMBDA_FUNCTION_VERSION") != "" {
		// This branch is invoked in Lambda.
		lambda.Start(HandleLambdaRequest)
	} else {
		// This branch is for command-line testing.
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

		result, err := HandleLambdaRequest(context.Background(), Invoke{ManageRequest: &request})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Request failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(result)
		os.Exit(0)
	}
}

// HandleLambdaRequest is the main Lambda entrypoint for updating a prefix list from ip-ranges.json.
func HandleLambdaRequest(ctx context.Context, invoke Invoke) (string, error) {
	log.Printf("Incoming request: %v", invoke)

	if invoke.IPRangesUpdated != nil {
		return HandleIPRangesUpdated(ctx, invoke.IPRangesUpdated)
	}

	if invoke.ManageRequest != nil {
		return HandleManageRequest(ctx, invoke.ManageRequest)
	}

	return "", fmt.Errorf("Unable to handle incoming request")
}

// HandleIPRangesUpdated handles SNS notifications when ip-ranges.json is updated.
func HandleIPRangesUpdated(ctx context.Context, records *IPRangesUpdatedRequest) (string, error) {
	awsLogLevel := aws.LogDebugWithRequestRetries | aws.LogDebugWithRequestErrors
	awsSession, err := session.NewSession(&aws.Config{LogLevel: &awsLogLevel, MaxRetries: aws.Int(int(MaxRetries))})
	if err != nil {
		log.Printf("Failed to create an AWS session: %v", err)
		return "", err
	}

	// Put an event to EventBridge to trigger the rule(s) to update the prefix lists. This will
	// re-invoke this function with the necessary detail to perform prefix list updates.
	entries := []*eventbridge.PutEventsRequestEntry{{Detail: aws.String("{}"), DetailType: aws.String("IPRanges Update Notification"), Source: aws.String("ManageAWSPrefixLists")}}
	ebClient := eventbridge.New(awsSession)

	result, err := ebClient.PutEvents(&eventbridge.PutEventsInput{Entries: entries})
	if err != nil {
		log.Printf("Failed to invoke EventBridge rules: %v", err)
		return "", err
	}

	if aws.Int64Value(result.FailedEntryCount) != 0 {
		log.Printf("Failed to invoke EventBridge rules: ErrorCode=%d ErrorMessage=%v", result.Entries[0].ErrorCode, result.Entries[0].ErrorMessage)
		return "", fmt.Errorf("Failed to invoke EventBridge rules: ErrorCode=%d ErrorMessage=%v", result.Entries[0].ErrorCode, result.Entries[0].ErrorMessage)
	}

	return `{"Status": "SUCCESS"}`, nil
}

// HandleManageRequest handles the core logic of updating a set of prefix lists from ip-ranges.json.
func HandleManageRequest(ctx context.Context, request *ManageAWSPrefixListsRequest) (string, error) {
	plm, err := NewPrefixListManagerFromRequest(ctx, request)
	if err != nil {
		return "", fmt.Errorf("Failed to create a PrefixListManager app handler: %v", err)
	}

	// Fetch the ranges from the source document.
	err = plm.LoadIPRanges()
	if err != nil {
		return "", err
	}

	// Perform the updates and send any update notifications.
	if err = plm.Process(); err != nil {
		return "", fmt.Errorf("Failed to process ip-ranges.json from %s: %v", request.IPRangesURL, err)
	}

	// Create the output response indicating any errors found.
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

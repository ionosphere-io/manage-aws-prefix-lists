package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/s3"
	errors "github.com/go-errors/errors"
)

const (
	awsProfiles string = "iono:us-east-1 iono-gov:us-gov-west-1"
	filename    string = "manage-aws-prefix-lists.zip"
)

type sessionResult struct {
	profile        string
	errors         []error
	regionVersions map[string]RegionVersion
}

type RegionVersions struct {
	Regions map[string]RegionVersion
}

type RegionVersion struct {
	Bucket    string
	Key       string
	VersionID string `json:"VersionId"`
}

type regionResult struct {
	region        string
	err           error
	regionVersion RegionVersion
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: deploy <zip>\n")
		os.Exit(2)
	}

	inputFilename := os.Args[1]

	zipFile, err := ioutil.ReadFile(inputFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read %s: %v", inputFilename, err)
		os.Exit(1)
	}

	hasher := md5.New()
	sumBinary := make([]byte, 0, 32)
	_, _ = hasher.Write(zipFile)
	sumBinary = hasher.Sum(sumBinary)
	sumHex := make([]byte, hex.EncodedLen(len(sumBinary)))
	hex.Encode(sumHex, sumBinary)

	currentETag := fmt.Sprintf(`"%s"`, sumHex)
	if len(currentETag) != 34 {
		fmt.Fprintf(os.Stderr, "Failed to hash ZIP file correctly: got %d characters instead of 34\n", len(currentETag))
		os.Exit(10)
	}

	sessions := make(map[string]*session.Session)
	for _, profileDefaultRegion := range strings.Split(awsProfiles, " ") {
		parts := strings.SplitN(profileDefaultRegion, ":", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Invalid profile:default-region config: %s\n", profileDefaultRegion)
			os.Exit(1)
		}

		profile := parts[0]
		defaultRegion := parts[1]

		session, err := session.NewSessionWithOptions(session.Options{Profile: profile, Config: aws.Config{Region: &defaultRegion}})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to create AWS session from profile %s: %v\n", profile, err)
			os.Exit(1)
		}

		sessions[profile] = session
	}

	sessionResults := make(chan sessionResult, len(sessions))
	for profile, session := range sessions {
		go runSession(profile, session, zipFile, currentETag, sessionResults)
	}

	errors := 0
	regionVersions := make(map[string]RegionVersion)

	for i := 0; i < len(sessions); i++ {
		result := <-sessionResults
		if len(result.errors) != 0 {
			fmt.Fprintf(os.Stderr, "Processing failed for profile %s:\n", result.profile)
			for _, err := range result.errors {
				fmt.Fprintf(os.Stderr, "    %v\n", err)
			}
			errors += 1
		} else {
			for region, regionVersion := range result.regionVersions {
				regionVersions[region] = regionVersion
			}
		}
	}

	if errors == 0 {
		versions := RegionVersions{Regions: regionVersions}

		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "    ")
		err = encoder.Encode(&versions)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write versions: %v", err)
			os.Exit(1)
		}

		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "%d session(s) had errors\n", errors)
	os.Exit(1)
}

func runSession(profile string, session *session.Session, zipFile []byte, currentETag string, results chan sessionResult) {
	ec2Client := ec2.New(session)
	regions, err := ec2Client.DescribeRegions(&ec2.DescribeRegionsInput{AllRegions: aws.Bool(true)})
	if err != nil {
		results <- sessionResult{profile: profile, errors: []error{errors.Wrap(err, 1)}}
		return
	}

	regionResults := make(chan regionResult, len(regions.Regions))

	for _, region := range regions.Regions {
		go runRegion(profile, aws.StringValue(region.RegionName), zipFile, currentETag, regionResults)
	}

	errorsFound := make([]error, 0)
	regionVersions := make(map[string]RegionVersion)

	for i := 0; i < len(regions.Regions); i++ {
		result := <-regionResults
		if result.err != nil {
			errorsFound = append(errorsFound, errors.Wrap(result.err, 1))
		} else {
			regionVersions[result.region] = result.regionVersion
		}
	}

	results <- sessionResult{profile: profile, errors: errorsFound, regionVersions: regionVersions}
}

func runRegion(profile string, region string, zipFile []byte, currentETag string, results chan regionResult) {
	s, err := session.NewSessionWithOptions(session.Options{Profile: profile, Config: aws.Config{Region: &region}})
	if err != nil {
		results <- regionResult{region: region, err: err}
		return
	}

	bucketName := fmt.Sprintf("ionosphere-public-%s", region)

	s3Client := s3.New(s)
	headObjectResult, err := s3Client.HeadObject(&s3.HeadObjectInput{Bucket: &bucketName, Key: aws.String(filename)})
	if err == nil {
		if aws.StringValue(headObjectResult.ETag) == currentETag {
			// Nothing to be done
			fmt.Fprintf(os.Stderr, "Region %s has the current version\n", region)
			results <- regionResult{region: region, err: nil, regionVersion: RegionVersion{Bucket: bucketName, Key: filename, VersionID: aws.StringValue(headObjectResult.VersionId)}}
			return
		} else {
			fmt.Fprintf(os.Stderr, "Region %s has etag %s, expected %s\n", region, aws.StringValue(headObjectResult.ETag), currentETag)
		}
	}

	body := bytes.NewReader(zipFile)

	// Upload the new object
	fmt.Fprintf(os.Stderr, "Uploading to s3://%s/%s\n", bucketName, filename)
	result, err := s3Client.PutObject(&s3.PutObjectInput{Bucket: &bucketName, Key: aws.String(filename), Body: body, ACL: aws.String("public-read")})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Upload to s3://%s/%s failed: %v\n", bucketName, filename, err)
		results <- regionResult{region: region, err: err}
	} else {
		fmt.Fprintf(os.Stderr, "Upload to s3://%s/%s completed\n", bucketName, filename)
		results <- regionResult{region: region, err: nil, regionVersion: RegionVersion{Bucket: bucketName, Key: filename, VersionID: aws.StringValue(result.VersionId)}}
	}
}

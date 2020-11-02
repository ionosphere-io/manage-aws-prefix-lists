AWS_PROFILE ?= iono
AWS := aws --profile $(AWS_PROFILE)

deploy: versions.json
versions.json: deploy/deploy lambda-linux-amd64/manage-aws-prefix-lists.zip
	deploy/deploy lambda-linux-amd64/manage-aws-prefix-lists.zip > versions.json

deploy/deploy: deploy/deploy.go
	cd deploy; go build -o deploy

lambda-linux-amd64/manage-aws-prefix-lists.zip: lambda-linux-amd64/manage-aws-prefix-lists
	rm -f lambda-linux-amd64/manage-aws-prefix-lists.zip
	cd lambda-linux-amd64 && zip -9 manage-aws-prefix-lists.zip manage-aws-prefix-lists

lambda-linux-amd64/manage-aws-prefix-lists: *.go
	mkdir -p lambda-linux-amd64
	GOARCH=amd64 GOOS=linux go build -o lambda-linux-amd64/manage-aws-prefix-lists

Local Development 
go run *.go -f "dynamodb://ap-south-1/buildConfigs?id=default" -t 1.0.4 -e "" -a "testappname" --output-notes-path "notes.txt"


For prod build

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o crood-1.0.0 .
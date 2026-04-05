module github.com/ocrosby/identity-platform-go/libs/httputil

go 1.26

require (
	github.com/ocrosby/identity-platform-go/libs/errors v0.0.0
	github.com/ocrosby/identity-platform-go/libs/logging v0.0.0
)

replace (
	github.com/ocrosby/identity-platform-go/libs/errors => ../errors
	github.com/ocrosby/identity-platform-go/libs/logging => ../logging
)

#!/bin/bash -e

location=$GOPATH/src/github.wdf.sap.corp/cloudfoundry/goauth_handlers

mkdir -p $(dirname $location)
mv goauth_handlers/ $location

cd $location

go get -t ./...
go test ./...

#!/bin/bash -e

location=$GOPATH/src/github.wdf.sap.corp/cloudfoundry/goauth_handlers

mkdir -p $(dirname $location)
mv goauth_handlers/ $location

cd $location

# setting the timezone is necessary for getting corret token expirity date
export TZ='Asia/Kolkata'

go get -t ./...
go test ./...

#!/bin/bash -e

location=$GOPATH/src/github.infra.hana.ondemand.com/cloudfoundry/goauth_handlers

mkdir -p $(dirname $location)
cp -r goauth_handlers/ $location

cd $location

# setting the timezone is necessary for getting corret token expirity date
export TZ='Asia/Kolkata'

go get -t ./...
go test ./...

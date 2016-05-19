#!/bin/bash -e

location=$GOPATH/src/github.infra.hana.ondemand.com/cloudfoundry/goauth_handlers

mkdir -p $(dirname $location)
cp -r goauth_handlers/ $location

cd $location

go get -t ./...
go test ./...

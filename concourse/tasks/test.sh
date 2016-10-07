#!/bin/bash -e

location=$GOPATH/src/github.com/SAP/goauth-handlers
mkdir -p $location
cp -r goauth-handlers/. $location
cd $location

go get github.com/onsi/ginkgo/ginkgo
go get -t ./...
ginkgo -r

# goauth-handlers

Go HTTP handlers that adds OAuth 2.0 authorization framework to enable a third-party
application to obtain limited access to an HTTP service, either on behalf of a resource
owner by orchestrating an approval interaction between the resource owner and the HTTP
service, or by allowing the third-party application to obtain access on its own behalf.

The goauth-handlers verifies that the current user has the necessary OAuth authorization to continue further.
This library compares the OAuth token, stored in the session of the current user, and verifies that it has not
expired and has the necessary rights. If that is not the case, response with the proper HTTP response code is
sent or forwards the user to a remote OAuth Authorization server as per the Authorization Grant flow.

At this point in time, the goauth-handlers uses a client Cookie to store the user's session and OAuth information
(including token). In order to keep things secure, all session information is encrypted in the cookie so
that the user cannot tamper with the data.

# License
This project is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file.

# User Guide

The library is written in Go so you will need to set that up. Once you have Go, you can use the following command to download the source code and build it.

```go
go get github.com/SAP/goauth-handlers
```

## Tests

`goauth-handlers` project contains unit tests, in order to execute them run the following command in project root directory.

```bash
ginkgo -r
```

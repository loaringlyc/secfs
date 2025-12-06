# A Secure File Sharing System

### Introduction

For comprehensive documentation, see the cs161 Project 2 Spec (https://cs161.org/proj2/).

Write the implementation in `client/client.go` and the integration tests in `client_test/client_test.go`. Unit tests are written in `client/client_unittest.go` (e.g: to test helper functions).

### Go Language

To learn about go language, visit https://tour.golang.org/welcome/1. It is worth referencing frequently when learning for the first time.

Note that we should use `go env -w GOPROXY=https://goproxy.cn,direct` to avoid internet error.

### Test 

To test the implementation, run `go test -v` inside of the `client_test` directory. This will run all tests in both `client/client_unittest.go` and `client_test/client_test.go`.

The test cases are written using Ginkgo framework. Take `client_test.go` for an example. Here are several points to note:
- Function `TestSetupAndExecution()` is the bridge or bootstrap between Ginkgo test framework and go original testing package. 
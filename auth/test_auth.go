// Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
//
// Copyright (c) 2016 by Brocade Communications Systems, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

// This file implements TestAuther which provides ACM-ruleset functionality
// for Unit Tests.  Callers can set up rules in almost identical fashion to
// real ACM rulesets, with the only restriction being that currently groups
// are not supported, so GetPerms() returns an empty map for now.  As an
// example:
//
//      NewTestAuther(
//			NewTestRule(Allow, auth.P_READ, "*"),
//			NewTestRule(Deny, AllOps, "/protocols"),
//			NewTestRule(Deny, AllOps, "/system"),
//			NewTestRule(Allow, AllOps, "*"))
//
// This creates an Auther object that gives read access everywhere (so you
// can actually check the config in tests(!)), blocks access to protocols
// and system commands, then allows catch-all access everywhere else.
// This is reasonably close to 'admin' user type privileges, albeit allowing
// access to all passwords, and should give a good idea of how to use this
// infra.
//
// 3 canned TestAuthers are provided:
//
//  - TestAutherAllowAll()
//  - TestAutherDenyAll()
//  - TestAutherAllowOrDenyAll()

package auth

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os/user"
	"strings"

	"github.com/danos/utils/audit"
	"github.com/danos/utils/pathutil"
)

type testAction bool

const (
	Allow testAction = true
	Deny             = false
)

var AllOps = P_CREATE | P_READ | P_UPDATE | P_DELETE

// For now, we ignore groups - easy enough to add with NewTestRuleWithGrp()
// API or similar, without impacting existing use cases.
type testRule struct {
	action testAction
	perm   int
	path   []string
}

func NewTestRule(action testAction, perm int, absPath string) testRule {
	if len(absPath) == 0 || (absPath != "*" && absPath[0] != '/') {
		// Paths need to be prefixed with '/' on the real router.  We could
		// just assume we should add one, but then it might stop someone
		// from realising their real config was wrong, so we'll panic ...
		// Alternative would be to pass in the testing.T object and call
		// t.Fatalf().
		panic("Invalid path for test rule.")
	}
	ps := pathutil.Makepath(absPath)

	return testRule{action: action, perm: perm, path: ps}
}

const (
	T_REQ_AUTH = 1 << iota
	T_REQ_ACCT_START
	T_REQ_ACCT_STOP
)

type TestAutherRequestType int

type TestAutherRequest struct {
	reqType   TestAutherRequestType
	perm      AuthPerm
	path      string
	pathAttrs pathutil.PathAttrs
}

func NewTestAutherRequest(
	reqType TestAutherRequestType,
	perm AuthPerm,
	path []string,
	pathAttrs *pathutil.PathAttrs,
) TestAutherRequest {
	return TestAutherRequest{reqType, perm, strings.Join(path, " "), *pathAttrs}
}

func NewTestAutherCommandRequest(
	reqType TestAutherRequestType,
	cmd []string,
	pathAttrs *pathutil.PathAttrs,
) TestAutherRequest {
	return NewTestAutherRequest(reqType, P_EXECUTE, cmd, pathAttrs)
}

func TestAutherRequestEquals(a, b TestAutherRequest) bool {
	if a.reqType != b.reqType || a.perm != b.perm || a.path != b.path {
		return false
	}

	if len(a.pathAttrs.Attrs) != len(b.pathAttrs.Attrs) {
		return false
	}

	for i, attr := range a.pathAttrs.Attrs {
		if attr != b.pathAttrs.Attrs[i] {
			return false
		}
	}

	return true
}

type TestAutherRequests struct {
	Reqs []TestAutherRequest
}

func NewTestAutherRequests(req ...TestAutherRequest) TestAutherRequests {
	reqs := TestAutherRequests{}
	reqs.Reqs = append(reqs.Reqs, req...)
	return reqs
}

func (r TestAutherRequests) GetRequestsForPerm(perm AuthPerm) TestAutherRequests {
	ret := NewTestAutherRequests()
	for _, v := range r.Reqs {
		if v.perm == perm {
			ret.Reqs = append(ret.Reqs, v)
		}
	}
	return ret
}

func (r TestAutherRequests) Len() int {
	return len(r.Reqs)
}

func (r TestAutherRequests) Less(i, j int) bool {
	return r.Reqs[i].path < r.Reqs[j].path
}

func (r TestAutherRequests) Swap(i, j int) {
	r.Reqs[i], r.Reqs[j] = r.Reqs[j], r.Reqs[i]
}

func CheckRequests(actual, exp TestAutherRequests) error {
	if len(actual.Reqs) != len(exp.Reqs) {
		return errors.New(fmt.Sprintf("Saw %v auth requests but expected %v\nActual:\n%v\nExpected:\n%v",
			len(actual.Reqs), len(exp.Reqs), actual, exp))
	}

	for i, _ := range exp.Reqs {
		if !TestAutherRequestEquals(actual.Reqs[i], exp.Reqs[i]) {
			return errors.New(fmt.Sprintf("Auth request mismatch at index %v: %v != %v",
				i, actual.Reqs[i], exp.Reqs[i]))
		}
	}

	return nil
}

type TestAuther interface {
	Auther
	GetCmdRequests() TestAutherRequests
	ClearCmdRequests()
	GetCmdAcctRequests() TestAutherRequests
	ClearCmdAcctRequests()
	GetAuditer() *audit.TestAudit
}

type testAuther struct {
	Auth
}

func newAuthForTest() *Auth {
	u, err := user.Current()
	if err != nil {
		panic(err)
	}

	a := NewAuthGlobal(u.Username,
		log.New(ioutil.Discard, "", 0), log.New(ioutil.Discard, "", 0))
	if a == nil {
		panic("Could not instantiate AuthGlobal")
	}

	// Swap in test auditer and enable logging. A test's own auther decides,
	// so the host's ruleset has no say, nor does its lack of one.
	a.auditer = audit.NewTestAudit()
	adb, _ := a.load()
	a.store(&Authdb{Uid: adb.Uid, LogReq: true})

	return NewAuth(a)
}

// See example usage in top of file comment.
func NewTestAuther(rules ...testRule) *testAuther {
	a := &testAuther{*newAuthForTest()}
	a.cmdAccounters = append(a.cmdAccounters, &TestCommandAccounter{})
	a.cmdAuther = &TestCommandAuther{}
	a.dataAuther = &TestDataAuther{rules: rules}
	return a
}

func TestAutherAllowAll() *testAuther {
	return NewTestAuther(NewTestRule(Allow, AllOps, "*"))
}

func TestAutherDenyAll() *testAuther {
	return NewTestAuther(NewTestRule(Deny, AllOps, "*"))
}

func TestAutherAllowOrDenyAll(allow bool) *testAuther {
	if allow == true {
		return TestAutherAllowAll()
	} else {
		return TestAutherDenyAll()
	}
}

// Only needed for testing, so not added to CommandAuther, and thus type
// assertion needed.
func (a *testAuther) AddBlockedCommand(command []string) *testAuther {
	a.cmdAuther.(*TestCommandAuther).AddBlockedCommand(command)
	return a
}

func (a *testAuther) GetAuditer() *audit.TestAudit {
	return a.authGlobal.auditer.(*audit.TestAudit)
}

func (a *testAuther) GetCmdRequests() TestAutherRequests {
	auther := a.cmdAuther.(*TestCommandAuther)
	return NewTestAutherRequests(auther.cmdReqs.Reqs...)
}

func (a *testAuther) ClearCmdRequests() {
	auther := a.cmdAuther.(*TestCommandAuther)
	auther.cmdReqs.Reqs = nil
}

func (a *testAuther) getTestCommandAccounter() *TestCommandAccounter {
	for _, accounter := range a.cmdAccounters {
		if testAccounter, ok := accounter.(*TestCommandAccounter); ok {
			return testAccounter
		}
	}
	panic("No instance of TestCommandAccounter found!")
}

func (a *testAuther) GetCmdAcctRequests() TestAutherRequests {
	accter := a.getTestCommandAccounter()
	return NewTestAutherRequests(accter.cmdAcctReqs.Reqs...)
}

func (a *testAuther) ClearCmdAcctRequests() {
	accter := a.getTestCommandAccounter()
	accter.cmdAcctReqs.Reqs = nil
}

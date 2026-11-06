// Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
//
// Copyright (c) 2015 by Brocade Communications Systems, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/danos/aaa"
	"github.com/danos/utils/audit"
	"github.com/danos/utils/pathutil"
)

func TestMatchPath(t *testing.T) {
	type pathTest struct {
		rulepath  []string
		ruleperm  AuthAction
		reqpath   []string
		reqperm   AuthPerm
		expresult bool
	}
	testTbl := []pathTest{
		{
			rulepath:  []string{"interfaces", "dataplane", "dp0s9"},
			ruleperm:  AUTH_ALLOW,
			reqpath:   []string{"interfaces", "dataplane", "dp0s9"},
			reqperm:   P_DELETE,
			expresult: true,
		},
		{
			rulepath:  []string{"interfaces", "dataplane", "dp0s9"},
			ruleperm:  AUTH_ALLOW,
			reqpath:   []string{"interfaces"},
			reqperm:   P_DELETE,
			expresult: false,
		},
		{
			rulepath:  []string{"interfaces", "dataplane", "dp0s9"},
			ruleperm:  AUTH_ALLOW,
			reqpath:   []string{"interfaces"},
			reqperm:   P_CREATE,
			expresult: true,
		},
		{
			rulepath:  []string{"interfaces", "dataplane", "dp0s9"},
			ruleperm:  AUTH_DENY,
			reqpath:   []string{"interfaces"},
			reqperm:   P_CREATE,
			expresult: false,
		},
		{
			rulepath:  []string{"interfaces", "dataplane", "*"},
			ruleperm:  AUTH_ALLOW,
			reqpath:   []string{"interfaces", "dataplane", "dp0s9"},
			reqperm:   P_UPDATE,
			expresult: true,
		},
		{
			rulepath:  []string{"interfaces", "dataplane", "*"},
			ruleperm:  AUTH_DENY,
			reqpath:   []string{"interfaces", "dataplane", "dp0s9"},
			reqperm:   P_UPDATE,
			expresult: true,
		},
		{
			rulepath:  []string{"interfaces", "dataplane"},
			ruleperm:  AUTH_ALLOW,
			reqpath:   []string{""},
			reqperm:   P_UPDATE,
			expresult: true,
		},
		{
			rulepath:  []string{"interfaces", "dataplane"},
			ruleperm:  AUTH_DENY,
			reqpath:   []string{""},
			reqperm:   P_UPDATE,
			expresult: false,
		},
		{
			rulepath:  []string{"*"},
			ruleperm:  AUTH_DENY,
			reqpath:   []string{"interfaces", "dataplane", "dp0s9"},
			reqperm:   P_DELETE,
			expresult: true,
		},
		{
			rulepath:  []string{"interfaces", "dataplane", "dp0s9"},
			ruleperm:  AUTH_ALLOW,
			reqpath:   []string{"interfaces", "dataplane", "dp0s3"},
			reqperm:   P_CREATE,
			expresult: false,
		},
		{
			rulepath:  []string{},
			ruleperm:  AUTH_ALLOW,
			reqpath:   []string{"interfaces", "dataplane", "dp0s3"},
			reqperm:   P_CREATE,
			expresult: false,
		},
		{
			rulepath:  []string{"interfaces", "*", "dp0s9"},
			ruleperm:  AUTH_ALLOW,
			reqpath:   []string{"interfaces", "dataplane", "dp0s9"},
			reqperm:   P_CREATE,
			expresult: true,
		},
	}
	for _, test := range testTbl {
		match := matchPath(test.rulepath, test.reqpath, test.ruleperm, test.reqperm)
		if match != test.expresult {
			t.Fatalf("Unexpected matchPath result\n"+
				"    Rule: %s\n    RulePerm: %s\n"+
				"    Request: %s\n    ReqPerm: %s\n"+
				"    Result: %t\n    Expected: %t\n",
				test.rulepath, test.ruleperm.String(),
				test.reqpath, test.reqperm.String(),
				match, test.expresult)
		}
	}
}

func genLogReqPathMsg(uid uint32, path string, perm AuthPerm) string {
	return fmt.Sprintf("uid=%d req: {path=[%s], perm=%s}", uid, path, perm.String())
}

func TestLogReqPath(t *testing.T) {
	a := newAuthForTest()
	auditer := a.authGlobal.auditer.(*audit.TestAudit)
	adb, _ := a.load()

	// Generate the path being requested, and corresponding attributes
	path := []string{"set", "foo", "bar"}
	pathAttrs := pathutil.NewPathAttrs()
	pathAttrs.Attrs = append(pathAttrs.Attrs,
		pathutil.PathElementAttrs{Secret: false},
		pathutil.PathElementAttrs{Secret: false},
		pathutil.PathElementAttrs{Secret: false})

	a.LogReqPath(adb.Uid, path, &pathAttrs, P_READ, true)

	// Log another request, this time with a secret element
	pathAttrs.Attrs[2].Secret = true
	a.LogReqPath(adb.Uid, path, &pathAttrs, P_UPDATE, false)

	expUserLogs := audit.UserLogSlice{
		audit.UserLog{
			Type: audit.LOG_TYPE_USER_CFG,
			Msg: genLogReqPathMsg(adb.Uid, "set foo bar", P_READ),
			Result: 1,
		},
		audit.UserLog{
			Type: audit.LOG_TYPE_USER_CFG,
			Msg: genLogReqPathMsg(adb.Uid, "set foo **", P_UPDATE),
			Result: 0,
		},
	}
	audit.AssertUserLogSliceEqual(t, expUserLogs, auditer.GetUserLogs())
}

func TestLogReqPathRedactionFailure(t *testing.T) {
	a := newAuthForTest()
	auditer := a.authGlobal.auditer.(*audit.TestAudit)
	adb, _ := a.load()

	// Don't pass any path attributes
	path := []string{"delete", "bar", "baz"}
	a.LogReqPath(adb.Uid, path, nil, P_READ, true)

	// Log another request, this time with mismatched length of path and attrs
	pathAttrs := pathutil.NewPathAttrs()
	pathAttrs.Attrs = append(pathAttrs.Attrs, pathutil.PathElementAttrs{Secret: true})
	a.LogReqPath(adb.Uid, path, &pathAttrs, P_CREATE, false)

	expUserLogs := audit.UserLogSlice{
		audit.UserLog{
			Type: audit.LOG_TYPE_USER_CFG,
			Msg: genLogReqPathMsg(adb.Uid, "<path redaction failed>", P_READ),
			Result: 1,
		},
		audit.UserLog{
			Type: audit.LOG_TYPE_USER_CFG,
			Msg: genLogReqPathMsg(adb.Uid, "<path redaction failed>", P_CREATE),
			Result: 0,
		},
	}
	audit.AssertUserLogSliceEqual(t, expUserLogs, auditer.GetUserLogs())
}

const (
	rulesetExemptUid = 1000
	rulesetOtherUid  = 2000
	rulesetGroup     = "readers"
)

func authWithRuleset(adb *Authdb) *Auth {
	adb.Uid = rulesetExemptUid
	global := &AuthGlobal{
		Dlog:    log.New(ioutil.Discard, "", 0),
		Elog:    log.New(ioutil.Discard, "", 0),
		auditer: audit.NewTestAudit(),
	}
	global.store(adb)
	global.storeAAA(&aaa.AAA{})
	return NewAuth(global)
}

// Everything a request can ask of a ruleset, answered for one uid.
func answers(a *Auth, uid uint32) map[string]bool {
	path := []string{"system", "login"}
	groups := []string{rulesetGroup}
	return map[string]bool{
		"read":   a.AuthorizeRead(uid, groups, path, nil),
		"create": a.AuthorizeCreate(uid, groups, path, nil),
		"update": a.AuthorizeUpdate(uid, groups, path, nil),
		"delete": a.AuthorizeDelete(uid, groups, path, nil),
		"fn":     a.AuthorizeFn(uid, groups, "Get"),
		"rpc":    a.AuthorizeRPC(uid, groups, "module", "rpc"),
	}
}

func expectAnswers(t *testing.T, what string, got, want map[string]bool) {
	t.Helper()
	for op := range want {
		if got[op] != want[op] {
			t.Errorf("%s: %s reads %t, want %t", what, op, got[op], want[op])
		}
	}
}

func deniedAll() map[string]bool {
	return map[string]bool{"read": false, "create": false, "update": false,
		"delete": false, "fn": false, "rpc": false}
}

// The exempt uid passes the path and function checks. An RPC has no such exemption.
func exemptUnderDenial() map[string]bool {
	return map[string]bool{"read": true, "create": true, "update": true,
		"delete": true, "fn": true, "rpc": false}
}

func writeRuleset(t *testing.T, content string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "configruleset.txt")
	if err := ioutil.WriteFile(name, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return name
}

func expectDeniedAll(t *testing.T, what, filename string) {
	t.Helper()
	logged := &bytes.Buffer{}
	a := authWithRuleset(loadRuleset(filename, log.New(logged, "", 0)))
	expectAnswers(t, what, answers(a, rulesetOtherUid), deniedAll())
	expectAnswers(t, what+", the exempt uid", answers(a, rulesetExemptUid), exemptUnderDenial())
	if got := a.GetPerms([]string{rulesetGroup})["DEFAULT"]; got != "0" {
		t.Errorf("%s: default permissions read %s", what, got)
	}
	if !strings.Contains(logged.String(), "No usable ruleset in "+filename) {
		t.Errorf("%s: logged %q", what, logged.String())
	}
}

func TestAMissingRulesetDeniesAll(t *testing.T) {
	expectDeniedAll(t, "no file", filepath.Join(t.TempDir(), "configruleset.txt"))
}

func TestAnUnreadableRulesetDeniesAll(t *testing.T) {
	expectDeniedAll(t, "a directory", t.TempDir())
}

func TestAnEmptyRulesetDeniesAll(t *testing.T) {
	expectDeniedAll(t, "empty", writeRuleset(t, ""))
	expectDeniedAll(t, "blank", writeRuleset(t, " \n"))
}

func TestAMalformedRulesetDeniesAll(t *testing.T) {
	for what, content := range map[string]string{
		"not JSON":               "enabled: true\n",
		"cut short":              `{"enabled":true,"read-default":2`,
		"an array":               `[]`,
		"a string":               `"enabled"`,
		"a number":               `1`,
		"a wrong type":           `{"enabled":"false"}`,
		"a wrong type in a rule": `{"enabled":true,"read-default":2,"rules":[{"type":1,"rule":{"action":"allow"}}]}`,
		"more after the first":   `{"enabled":false} {"enabled":true}`,
		"text after the first":   `{"enabled":false} text`,
	} {
		expectDeniedAll(t, what, writeRuleset(t, content))
	}
}

// A file that never says it is off keeps the rules on, with what it did not set
// allowing nothing.
func TestARulesetThatDoesNotSayItIsOffDeniesWhatItDoesNotAllow(t *testing.T) {
	for what, content := range map[string]string{
		"null":             `null`,
		"an empty object":  `{}`,
		"another key":      `{"enable":false}`,
		"a null":           `{"enabled":null}`,
		"on and nothing":   `{"enabled":true}`,
		"on and no rule":   `{"enabled":true,"rules":[],"rpc-rules":[]}`,
		"a rule of no use": `{"enabled":true,"rules":[{"type":1,"rule":{"action":2,"groups":["other"],"perm":31,"path":"/"}}]}`,
	} {
		a := authWithRuleset(loadRuleset(writeRuleset(t, content), log.New(ioutil.Discard, "", 0)))
		expectAnswers(t, what, answers(a, rulesetOtherUid), deniedAll())
	}
}

// A rule with nothing in it would stop the daemon at the first request it met.
func TestARuleWithNoBodyIsMalformed(t *testing.T) {
	for what, content := range map[string]string{
		"a null in rules":      `{"enabled":true,"read-default":2,"rules":[null]}`,
		"a null in rpc-rules":  `{"enabled":true,"rpc-default":2,"rpc-rules":[null]}`,
		"no body in rules":     `{"enabled":true,"read-default":2,"rules":[{"type":1}]}`,
		"no body in rpc-rules": `{"enabled":true,"rpc-default":2,"rpc-rules":[{"type":16}]}`,
		"a null body":          `{"enabled":true,"read-default":2,"rules":[{"type":1,"rule":null}]}`,
		"second, after a good": `{"enabled":true,"read-default":2,"rules":[{"type":1,"rule":{"action":2,"groups":["g"],"perm":2,"path":"/"}},null]}`,
		"second in rpc-rules":  `{"enabled":true,"rpc-default":2,"rpc-rules":[{"type":16,"rule":{"action":2,"groups":["g"],"module-name":"*"}},{"type":16}]}`,
	} {
		expectDeniedAll(t, what, writeRuleset(t, content))
	}
}

// What acmd writes, and what a host profile holds.
func TestAGoodRulesetIsEnforcedAsWritten(t *testing.T) {
	const good = `{"enabled":true,"log-requests":false,"create-default":1,"read-default":2,
		"update-default":1,"delete-default":1,"exec-default":1,"rpc-default":1,
		"rules":[
			{"type":1,"rule":{"action":1,"groups":["` + rulesetGroup + `"],"perm":2,"path":"/system/login"}},
			{"type":1,"rule":{"action":2,"groups":["` + rulesetGroup + `"],"perm":1,"path":"/system/login"}},
			{"type":2,"rule":{"action":2,"groups":["` + rulesetGroup + `"],"perm":16,"fn":"Get"}}],
		"rpc-rules":[
			{"type":16,"rule":{"action":2,"groups":["` + rulesetGroup + `"],"module-name":"module","rpc-name":"*"}}]}`
	a := authWithRuleset(loadRuleset(writeRuleset(t, good), log.New(ioutil.Discard, "", 0)))
	expectAnswers(t, "a rule", answers(a, rulesetOtherUid), map[string]bool{
		"read": false, "create": true, "update": false, "delete": false, "fn": true, "rpc": true})
	expectAnswers(t, "the exempt uid", answers(a, rulesetExemptUid), map[string]bool{
		"read": true, "create": true, "update": true, "delete": true, "fn": true, "rpc": true})
	if !a.AuthorizeRead(rulesetOtherUid, []string{rulesetGroup}, []string{"interfaces"}, nil) {
		t.Errorf("a path no rule names reads denied, with read-default allow")
	}
	if a.AuthorizeUpdate(rulesetOtherUid, []string{rulesetGroup}, []string{"interfaces"}, nil) {
		t.Errorf("a path no rule names reads allowed, with update-default deny")
	}
	if a.AuthorizeFn(rulesetOtherUid, []string{rulesetGroup}, "Set") {
		t.Errorf("a function no rule names reads allowed, with exec-default deny")
	}
	if a.AuthorizeRPC(rulesetOtherUid, []string{rulesetGroup}, "other", "rpc") {
		t.Errorf("an RPC no rule names reads allowed, with rpc-default deny")
	}
}

func TestARulesetThatSaysItIsOffIsOff(t *testing.T) {
	a := authWithRuleset(loadRuleset(writeRuleset(t, `{"enabled":false}`), log.New(ioutil.Discard, "", 0)))
	expectAnswers(t, "off", answers(a, rulesetOtherUid), map[string]bool{
		"read": true, "create": true, "update": true, "delete": true, "fn": true, "rpc": true})
}

// A test auther's own rules decide, whatever ruleset the host holds or lacks.
func TestATestAutherTakesNoRulesFromTheHost(t *testing.T) {
	path := []string{"system"}
	for what, a := range map[string]*testAuther{
		"allow all": TestAutherAllowAll(),
		"deny all":  TestAutherDenyAll(),
	} {
		if !a.AuthorizeRPC(rulesetOtherUid, nil, "module", "rpc") {
			t.Errorf("%s: an RPC reads denied", what)
		}
		if !a.AuthorizeFn(rulesetOtherUid, nil, "Get") {
			t.Errorf("%s: a function reads denied", what)
		}
	}
	if !TestAutherAllowAll().AuthorizeRead(rulesetOtherUid, nil, path, nil) {
		t.Errorf("allow all: a read reads denied")
	}
	if TestAutherDenyAll().AuthorizeRead(rulesetOtherUid, nil, path, nil) {
		t.Errorf("deny all: a read reads allowed")
	}
}

// What configd calls. The ruleset's path is fixed, so this runs only where there is none.
func TestNewAuthGlobalWithNoRulesetDeniesAllButTheExemptUser(t *testing.T) {
	if _, err := os.Stat(Authrulefile); err == nil {
		t.Skip(Authrulefile + " exists on this host")
	}
	// Not the user running this: root's uid is what a uid left unset would read.
	u, err := user.Lookup("nobody")
	if err != nil {
		t.Skip(err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	global := NewAuthGlobal(u.Username, log.New(ioutil.Discard, "", 0), log.New(ioutil.Discard, "", 0))
	global.auditer = audit.NewTestAudit()
	a := NewAuth(global)
	expectAnswers(t, "another uid", answers(a, uint32(uid)+1), deniedAll())
	expectAnswers(t, "the exempt user", answers(a, uint32(uid)), exemptUnderDenial())
}

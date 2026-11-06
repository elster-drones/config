// Copyright (c) 2018-2020, AT&T Intellectual Property Inc.
// All rights reserved.
//
// Copyright (c) 2014-2015, 2017 by Brocade Communications Systems, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/danos/aaa"
	"github.com/danos/utils/audit"
	"github.com/danos/utils/guard"
	"github.com/danos/utils/pathutil"
	"github.com/fsnotify/fsnotify" // in vendor dir
)

const Authrulefile = "/opt/vyatta/etc/configruleset.txt"

type AuthPerm int

const (
	P_CREATE = 1 << iota
	P_READ
	P_UPDATE
	P_DELETE
	P_EXECUTE
)

func (p AuthPerm) String() string {
	switch {
	case p&P_CREATE == P_CREATE:
		return "create"
	case p&P_READ == P_READ:
		return "read"
	case p&P_UPDATE == P_UPDATE:
		return "update"
	case p&P_DELETE == P_DELETE:
		return "delete"
	case p&P_EXECUTE == P_EXECUTE:
		return "execute"
	}
	return ""
}

type AuthType int

const (
	AUTH_T_DATA = 1 << iota
	AUTH_T_PROTO
	AUTH_T_SESSION
	AUTH_T_PERMS
	AUTH_T_RPC
)

func (t AuthType) String() string {
	switch t {
	case AUTH_T_DATA:
		return "data"
	case AUTH_T_PROTO:
		return "proto"
	case AUTH_T_SESSION:
		return "session"
	case AUTH_T_PERMS:
		return "perms"
	case AUTH_T_RPC:
		return "rpc"
	}
	return ""
}

type AuthAction int

const (
	AUTH_DENY = 1 << iota
	AUTH_ALLOW
	AUTH_LOG
)

func (a AuthAction) String() string {
	switch {
	case a&AUTH_DENY == AUTH_DENY:
		return "deny"
	case a&AUTH_ALLOW == AUTH_ALLOW:
		return "allow"
	case a&AUTH_LOG == AUTH_LOG:
		return "log"
	}
	return ""
}

type AuthRuleType struct {
	Type AuthType  `json:"type"`
	Rule *AuthRule `json:"rule"`
}

func (r *AuthRuleType) String() string {
	switch r.Type {
	case AUTH_T_DATA:
		return fmt.Sprintf("{type=%s action=%s perm=%s path=%s}",
			r.Type,
			r.Rule.Action,
			r.Rule.Perm,
			r.Rule.Path,
		)
	case AUTH_T_PROTO:
		return fmt.Sprintf("{type=%s action=%s perm=%s fn=%s}",
			r.Type,
			r.Rule.Action,
			r.Rule.Perm,
			r.Rule.Fn,
		)
	case AUTH_T_RPC:
		return fmt.Sprintf("{type=%s action=%s perm=%s module=%s rpc-name=%s}",
			r.Type,
			r.Rule.Action,
			r.Rule.Perm,
			r.Rule.Module,
			r.Rule.Rpc,
		)
	}
	return ""
}

type AuthRule struct {
	Action AuthAction `json:"action"`
	Groups []string   `json:"groups"`
	Perm   AuthPerm   `json:"perm"`
	Path   string     `json:"path,omitempty"`
	Rpc    string     `json:"rpc-name,omitempty"`
	Module string     `json:"module-name,omitempty"`
	Fn     string     `json:"fn,omitempty"`
}

type Authdb struct {
	Uid           uint32          `json:"-"`
	Enabled       bool            `json:"enabled"`
	LogReq        bool            `json:"log-requests"`
	CreateDefault AuthAction      `json:"create-default"`
	ReadDefault   AuthAction      `json:"read-default"`
	UpdateDefault AuthAction      `json:"update-default"`
	DeleteDefault AuthAction      `json:"delete-default"`
	ExecDefault   AuthAction      `json:"exec-default"`
	RpcDefault    AuthAction      `json:"rpc-default"`
	Rules         []*AuthRuleType `json:"rules"`
	RpcRules      []*AuthRuleType `json:"rpc-rules"`
}

func (a *Authdb) authorizeDefault(perm AuthPerm) bool {
	switch perm {
	case P_CREATE:
		if a.CreateDefault == AUTH_ALLOW {
			return true
		}
	case P_READ:
		if a.ReadDefault == AUTH_ALLOW {
			return true
		}
	case P_UPDATE:
		if a.UpdateDefault == AUTH_ALLOW {
			return true
		}
	case P_DELETE:
		if a.DeleteDefault == AUTH_ALLOW {
			return true
		}
	case P_EXECUTE:
		if a.ExecDefault == AUTH_ALLOW {
			return true
		}
	}
	return false
}

func (a *Auth) LogReqPath(uid uint32, path []string, pathAttrs *pathutil.PathAttrs, perm AuthPerm, result bool) {
	if adb, _ := a.load(); adb.LogReq {
		path, _ := pathutil.RedactPath(path, pathAttrs)
		a.authGlobal.auditer.LogUserConfig(fmt.Sprintf(
			"uid=%d req: {path=%s, perm=%s}", uid, path, perm), result)
	}
}

func (a *Auth) LogReqFn(uid uint32, fn string, result bool) {
	if adb, _ := a.load(); adb.LogReq {
		a.authGlobal.auditer.LogUserConfig(fmt.Sprintf(
			"uid=%d req: {fn=%s, perm=%s}", uid, fn, AuthType(P_EXECUTE)), result)
	}
}

// LoadAdb returns nil for a file it cannot use. The rules are on unless the file
// says "enabled": false, and a default it does not set allows nothing.
func LoadAdb(filename string, logger *log.Logger) *Authdb {
	adb := Authdb{Enabled: true}

	data, e := ioutil.ReadFile(filename)
	if e != nil {
		logger.Println(e)
		return nil
	}

	// All of the file must parse: a decoder would stop after its first value.
	e = json.Unmarshal(data, &adb)
	if e != nil {
		logger.Println(e)
		return nil
	}

	for _, rules := range [][]*AuthRuleType{adb.Rules, adb.RpcRules} {
		for _, rulet := range rules {
			if rulet == nil || rulet.Rule == nil {
				logger.Printf("%s: a rule with no body", filename)
				return nil
			}
		}
	}

	return &adb
}

// loadRuleset is what a host starts with: the rules in filename, or, when those
// are missing or malformed, none, so that only the exempt uid gets through.
func loadRuleset(filename string, logger *log.Logger) *Authdb {
	adb := LoadAdb(filename, logger)
	if adb == nil {
		logger.Printf("No usable ruleset in %s: denying all but the exempt uid", filename)
		adb = &Authdb{Enabled: true}
	}
	return adb
}

func (a *Auth) contains(list []string, item string) bool {
	for _, g := range list {
		if g == item {
			return true
		}
	}
	return false
}

type AuthGlobal struct {
	Dlog    *log.Logger
	Elog    *log.Logger
	authdb  atomic.Value
	aaaif   atomic.Value
	auditer audit.Auditer
}

type AuthEnv struct {
	Tty string
}

type Auth struct {
	authGlobal    *AuthGlobal
	cmdAccounters []CommandAccounter
	cmdAuther     CommandAuther
	dataAuther    DataAuther
	env           AuthEnv
}

type TaskAccounter interface {
	AccountStart() error
	AccountStop(*error) error
}

type CommandAccounter interface {
	NewTaskAccounter(uid uint32, groups []string, cmd []string, pathAttrs *pathutil.PathAttrs) TaskAccounter
	AccountCommand(uid uint32, groups []string, cmd []string, pathAttrs *pathutil.PathAttrs)
}

type CommandAuther interface {
	AuthorizeCommand(uid uint32, groups []string, cmd []string, pathAttrs *pathutil.PathAttrs) bool
}

type DataAuther interface {
	AuthorizePath(uid uint32, groups []string, path []string, pathAttrs *pathutil.PathAttrs, perm AuthPerm) bool
	AuthorizeRead(uid uint32, groups []string, path []string, pathAttrs *pathutil.PathAttrs) bool
	AuthorizeCreate(uid uint32, groups []string, path []string, pathAttrs *pathutil.PathAttrs) bool
	AuthorizeUpdate(uid uint32, groups []string, path []string, pathAttrs *pathutil.PathAttrs) bool
	AuthorizeDelete(uid uint32, groups []string, path []string, pathAttrs *pathutil.PathAttrs) bool
	GetPerms(groups []string) map[string]string
}

type Auther interface {
	CommandAccounter
	CommandAuther
	DataAuther

	AuditLog(msg string)
	AuthorizeFn(uid uint32, groups []string, fn string) bool
	AuthorizeRPC(uid uint32, groups []string, module, rpcName string) bool
}

type taskAccounters struct {
	accounters []TaskAccounter
}

func (t taskAccounters) AccountStart() error {
	for _, a := range t.accounters {
		a.AccountStart()
	}
	return nil
}

func (t taskAccounters) AccountStop(err *error) error {
	for _, a := range t.accounters {
		a.AccountStop(err)
	}
	return nil
}

func NewAuthGlobal(username string, dlog, elog *log.Logger) *AuthGlobal {
	auth := &AuthGlobal{
		Dlog:    dlog,
		Elog:    elog,
		auditer: audit.NewAudit(),
	}
	adb := loadRuleset(Authrulefile, elog)
	aaaif, err := aaa.LoadAAA()
	if err != nil {
		elog.Printf("Could not load AAA subsystem: %s", err)
	} else if aaaif == nil {
		aaaif = &aaa.AAA{}
	}
	u, _ := user.Lookup(username)
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	adb.Uid = uint32(uid)
	auth.store(adb)
	auth.storeAAA(aaaif)
	auth.FsListener()
	return auth
}

func NewAuth(global *AuthGlobal) *Auth {
	auth := &Auth{
		authGlobal: global,
	}
	acmAuther := NewAcmAuther(auth)
	auth.cmdAuther = acmAuther
	auth.dataAuther = acmAuther

	/* Commands are sent to the audit logs for *all* users */
	auth.cmdAccounters = []CommandAccounter{NewAuditAccounter(auth)}
	return auth
}

func NewAuthForUser(global *AuthGlobal, uid uint32, groups []string, env *AuthEnv) *Auth {
	auth := NewAuth(global)
	auth.env = *env

	// If user is authorized by an AAA protocol then replace the ACM authers
	proto := global.authzProtocolForUser(uid, groups)
	if proto != nil {
		aaaAuther := NewAaaAuther(auth, proto)
		auth.cmdAuther = aaaAuther
		auth.dataAuther = aaaAuther
	}

	// Look for an additional, suitable, accounting protocol
	if proto := global.accountingProtocolForUser(uid, groups); proto != nil {
		auth.cmdAccounters = append(auth.cmdAccounters, NewAaaAuther(auth, proto))
	}

	return auth
}

func (a *AuthGlobal) authzProtocolForUser(uid uint32, groups []string) *aaa.AAAProtocol {
	_, aaaif := a.load()

	if aaaif != nil {
		for aaaName, proto := range aaaif.Protocols {
			if !proto.Cfg.CmdAuthor {
				continue
			}
			isValidUser, err := guard.CatchPanicBoolError(func() (bool, error) {
				return proto.Plugin.ValidUser(uid, groups)
			})

			if err != nil {
				a.Elog.Printf("Error validating user (%d) via AAA protocol %s: %v", uid, aaaName, err)
				continue
			}
			if isValidUser {
				return proto
			}
		}
	}

	return nil
}

func (a *AuthGlobal) accountingProtocolForUser(uid uint32, groups []string) *aaa.AAAProtocol {
	if _, aaaif := a.load(); aaaif != nil {
		for _, proto := range aaaif.Protocols {
			if !proto.Cfg.CmdAcct {
				continue
			}
			// Currently accounting occurs for *all* users via the first
			// protocol which supports accounting.
			return proto
		}
	}

	return nil
}

func (a *Auth) GetPerms(groups []string) map[string]string {
	return a.dataAuther.GetPerms(groups)
}

func (a *AuthGlobal) load() (*Authdb, *aaa.AAA) {
	adb := a.authdb.Load().(*Authdb)
	aaaif := a.aaaif.Load().(*aaa.AAA)
	return adb, aaaif
}

func (a *Auth) load() (*Authdb, *aaa.AAA) {
	return a.authGlobal.load()
}

func (a *AuthGlobal) store(adb *Authdb) {
	a.authdb.Store(adb)
}

func (a *AuthGlobal) storeAAA(aaaif *aaa.AAA) {
	a.aaaif.Store(aaaif)
}

func (a *Auth) AuthorizeSession(uid uint32, sid string) bool {
	adb, _ := a.load()
	if !adb.Enabled {
		return true
	}
	if uid == adb.Uid {
		return true
	}
	return true
}

func (a *Auth) Log(uid uint32, rule *AuthRule, result bool) {
	if rule.Action&AUTH_LOG == AUTH_LOG {
		a.authGlobal.auditer.LogUserConfig(
			fmt.Sprintf("uid=%d matched rule: %s", uid, rule), result)
	}
}

func (a *Auth) NewTaskAccounter(
	uid uint32, groups []string, cmd []string, pathAttrs *pathutil.PathAttrs,
) TaskAccounter {
	t := taskAccounters{}
	t.accounters = make([]TaskAccounter, 0)
	for _, cmdAcct := range a.cmdAccounters {
		if acct := cmdAcct.NewTaskAccounter(uid, groups, cmd, pathAttrs); acct != nil {
			t.accounters = append(t.accounters, acct)
		}
	}
	return t
}

func (a *Auth) AccountCommand(uid uint32, groups []string, cmd []string, pathAttrs *pathutil.PathAttrs) {
	for _, accounter := range a.cmdAccounters {
		accounter.AccountCommand(uid, groups, cmd, pathAttrs)
	}
}

func (a *Auth) AuthorizeCommand(uid uint32, groups []string, cmd []string, pathAttrs *pathutil.PathAttrs) bool {
	return a.cmdAuther.AuthorizeCommand(uid, groups, cmd, pathAttrs)
}

func (a *Auth) AuthorizePath(uid uint32, groups []string, path []string, pathAttrs *pathutil.PathAttrs, perm AuthPerm) bool {
	return a.dataAuther.AuthorizePath(uid, groups, path, pathAttrs, perm)
}

func (a *Auth) AuthorizeRead(uid uint32, groups []string, path []string, pathAttrs *pathutil.PathAttrs) bool {
	return a.dataAuther.AuthorizeRead(uid, groups, path, pathAttrs)
}

func (a *Auth) AuthorizeCreate(uid uint32, groups []string, path []string, pathAttrs *pathutil.PathAttrs) bool {
	return a.dataAuther.AuthorizeCreate(uid, groups, path, pathAttrs)
}

func (a *Auth) AuthorizeUpdate(uid uint32, groups []string, path []string, pathAttrs *pathutil.PathAttrs) bool {
	return a.dataAuther.AuthorizeUpdate(uid, groups, path, pathAttrs)
}

func (a *Auth) AuthorizeDelete(uid uint32, groups []string, path []string, pathAttrs *pathutil.PathAttrs) bool {
	return a.dataAuther.AuthorizeDelete(uid, groups, path, pathAttrs)
}

func (a *Auth) AuthorizeRPC(uid uint32, group []string, module, rpcName string) bool {
	var result bool
	adb, _ := a.load()
	if !adb.Enabled {
		result = true
		return result
	}
	rpc := module + ":" + rpcName
	rulematch := func(r *AuthRule) bool {
		if r.Module != "*" && r.Module != module {
			return false
		}
		if r.Rpc != "*" && r.Rpc != "" && r.Rpc != rpc {
			return false
		}
		return matchGroup(group, r.Groups)
	}
	for _, rulet := range adb.RpcRules {
		if rulet.Type&AUTH_T_RPC != AUTH_T_RPC {
			continue
		}
		rule := rulet.Rule
		if rulematch(rule) {
			switch {
			case rule.Action&AUTH_DENY == AUTH_DENY:
				result = false
				return result
			case rule.Action&AUTH_ALLOW == AUTH_ALLOW:
				result = true
				return result
			}
		}
	}
	if adb.RpcDefault == AUTH_ALLOW {
		return true
	}
	return false
}

func (a *Auth) AuthorizeFn(uid uint32, groups []string, fn string) bool {
	var result bool
	adb, _ := a.load()
	if !adb.Enabled {
		result = true
		return result
	}
	if uid == adb.Uid {
		return true
	}
	defer func() { a.LogReqFn(uid, fn, result) }()
	for _, rulet := range adb.Rules {
		if rulet.Type != AUTH_T_PROTO {
			continue
		}
		rule := rulet.Rule
		if rule.Fn == fn &&
			matchGroup(groups, rule.Groups) &&
			(rule.Perm&P_EXECUTE == P_EXECUTE) {
			switch {
			case rule.Action&AUTH_DENY == AUTH_DENY:
				result = false
				a.Log(uid, rule, result)
				return result
			case rule.Action&AUTH_ALLOW == AUTH_ALLOW:
				result = true
				a.Log(uid, rule, result)
				return result
			}
		}
	}
	result = adb.authorizeDefault(P_EXECUTE)
	return result
}

func (a *Auth) AuditLog(msg string) {
	adb, _ := a.load()
	if adb.LogReq {
		a.authGlobal.auditer.LogUserConfig(msg, true)
	}
}

func matchEvent(eventName string, path string) bool {
	return strings.Contains(eventName, path)
}

func (a *AuthGlobal) FsListener() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		a.Elog.Println(err)
		return
	}

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				a.Dlog.Println(event)
				if event.Name != Authrulefile &&
					!matchEvent(event.Name, aaa.AAAPluginsCfgDir) {
					break
				}
				a.Dlog.Printf("MATCH: %v", event)
				switch {
				case event.Op&fsnotify.Rename == fsnotify.Rename:
					watcher.Remove(event.Name)
					watcher.Add(event.Name)
					fallthrough
				case event.Op&fsnotify.Create == fsnotify.Create:
					watcher.Add(event.Name)
					fallthrough
				case event.Op&fsnotify.Write == fsnotify.Write:
					if event.Name == Authrulefile {
						adb := LoadAdb(event.Name, a.Elog)
						if adb != nil {
							oldAdb, _ := a.load()
							adb.Uid = oldAdb.Uid
							a.store(adb)
						}
					} else if matchEvent(event.Name, aaa.AAAPluginsCfgDir) {
						aaaif, err := aaa.LoadAAA()
						if err != nil {
							a.Elog.Printf("Could not load AAA subsystem: %s", err)
						} else if aaaif != nil {
							a.storeAAA(aaaif)
						}
					}
				}
			case err := <-watcher.Errors:
				a.Elog.Println(err)
				return
			}
		}
	}()

	err = watcher.Add(filepath.Dir(Authrulefile))
	if err != nil {
		a.Elog.Println(err)
	}

	err = watcher.Add(Authrulefile)
	if err != nil {
		a.Elog.Println(err)
	}

	err = watcher.Add(filepath.Dir(aaa.AAAPluginsCfgDir))
	if err != nil {
		a.Elog.Println(err)
	}
}

func matchGroup(ugrps, rgrps []string) bool {
	for _, rgrp := range rgrps {
		for _, ugrp := range ugrps {
			if ugrp == rgrp {
				return true
			}
		}
	}
	return false
}

func matchPath(rulepath, reqpath []string, act AuthAction, perm AuthPerm) bool {
	/* There is some magic here

	   Parent rules are matched for child nodes that is:
	   If a specific rule for 'services telnet' doesn't exist then we
	   must match the rule for 'services' for that node.

	   However, a rule for 'services telnet` does not match the
	   path 'services' when deleting.

	   This allows the show semantics to do the right thing
	*/
	if len(rulepath) == 0 {
		return false
	}
	for i := 0; i < len(rulepath); i++ {
		if rulepath[i] == "*" {
			if i == len(rulepath)-1 {
				return true
			}
			continue
		}
		// Not allowed to delete a prefix of a rulepath
		if (perm&P_DELETE == P_DELETE) && (i >= len(reqpath)) {
			return false
		}
		if i >= len(reqpath) || (i == 0 && reqpath[i] == "") {
			if act&AUTH_ALLOW == AUTH_ALLOW {
				return true
			} else {
				return false
			}
		}
		if rulepath[i] != reqpath[i] {
			return false
		}
	}
	return true
}

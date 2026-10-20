package core

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const Day = 86400.0
const Helper = "/usr/local/libexec/remote-prune-inspect"

type Auto struct {
	Enabled   float64 `json:"enabled_at"`
	Next      float64 `json:"next_at"`
	Code      string  `json:"code_sha256"`
	Helper    string  `json:"helper_sha256"`
	Suspended string  `json:"suspended"`
}
type Seen struct {
	Identity Identity `json:"identity"`
	Digest   string   `json:"digest"`
	First    float64  `json:"first_seen"`
}
type Pending struct {
	Key      string   `json:"key"`
	Retired  string   `json:"retired"`
	Identity Identity `json:"identity"`
	Phase    string   `json:"phase"`
	At       float64  `json:"at"`
}
type State struct {
	Protocol  int              `json:"protocol"`
	Seen      map[string]Seen  `json:"seen"`
	History   []map[string]any `json:"history"`
	Auto      *Auto            `json:"auto"`
	Pending   *Pending         `json:"pending"`
	LastClock float64          `json:"last_clock"`
}
type Item struct {
	Key     string `json:"key"`
	Commit  string `json:"commit"`
	Version string `json:"version,omitempty"`
	Order   [3]int `json:"-"`
	Reason  string `json:"reason"`
	Snapshot
}
type Preview struct {
	At       float64  `json:"at"`
	Kind     string   `json:"kind"`
	Items    []Item   `json:"items"`
	Eligible []string `json:"eligible"`
	Helper   string   `json:"helper_sha256"`
}
type Engine struct {
	Home        string
	UID         uint32
	Now         func() float64
	Inspect     func() (Inspection, error)
	Fingerprint func() (string, error)
	Root        *os.Root
	RootID      Identity
	Store       *os.Root
	LockFile    *os.File
	State       State
	// Test seams are compiled code only, never CLI/environment overrides.
	Hook      func(string) error
	MountList func() ([]string, error)
}

func NewEngine(home string, uid uint32, bundle string) *Engine {
	return &Engine{Home: home, UID: uid, Now: func() float64 { return float64(time.Now().UnixNano()) / 1e9 },
		Inspect:     func() (Inspection, error) { return InspectInstalled(filepath.Join(bundle, "inspector")) },
		Fingerprint: func() (string, error) { return Fingerprint(bundle) }, MountList: Mounts}
}
func Fingerprint(bundle string) (string, error) {
	base := filepath.Dir(filepath.Dir(bundle))
	names := []string{filepath.Join(bundle, "engine"), filepath.Join(bundle, "inspector"), filepath.Join(base, "dist/extension.js"), filepath.Join(base, "package.json")}
	all := []byte{}
	for _, p := range names {
		h, e := FileHash(p)
		if e != nil {
			return "", e
		}
		all = append(all, []byte(h)...)
	}
	return Hash(all), nil
}
func InspectInstalled(bundled string) (Inspection, error) {
	result := Inspection{}
	if e := secureRootFile(Helper); e != nil {
		return result, fail("helper_unavailable")
	}
	want, e := FileHash(bundled)
	if e != nil {
		return result, e
	}
	before, e := FileHash(Helper)
	if e != nil {
		return result, e
	}
	if before != want {
		return result, fail("helper_version_changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", "-n", Helper)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "GOMAXPROCS=1"}
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		return result, e
	}
	if e = cmd.Start(); e != nil {
		return result, fail("inspection_unavailable")
	}
	data, e := io.ReadAll(io.LimitReader(pipe, 128*1024+1))
	if e != nil || len(data) > 128*1024 {
		cmd.Process.Kill()
		cmd.Wait()
		return result, fail("inspection_limit")
	}
	if e = cmd.Wait(); e != nil {
		return result, fail("inspection_unavailable")
	}
	if e = StrictJSON(data, &result); e != nil {
		return result, fail("inspection_protocol")
	}
	after, e := FileHash(Helper)
	if e != nil {
		return result, e
	}
	if after != before || result.HelperHash != want {
		return result, fail("helper_changed")
	}
	return result, nil
}
func (e *Engine) Open() error {
	for _, p := range []string{e.Home, filepath.Join(e.Home, ".vscode-server")} {
		if x := safeDir(p, e.UID); x != nil {
			return x
		}
	}
	var err error
	e.Root, e.RootID, err = openVerifiedRoot(filepath.Join(e.Home, ".vscode-server"), e.UID)
	if err != nil {
		return err
	}
	dir := filepath.Join(e.Home, ".remote-prune")
	if err = os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		e.Close()
		return err
	}
	if err = safeDir(dir, e.UID); err != nil {
		e.Close()
		return err
	}
	s, _ := os.Stat(dir)
	if s.Mode().Perm()&0077 != 0 {
		e.Close()
		return fail("state_permissions")
	}
	e.Store, _, err = openVerifiedRoot(dir, e.UID)
	if err != nil {
		e.Close()
		return err
	}
	e.LockFile, err = e.Store.OpenFile("lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		e.Close()
		return err
	}
	s, err = e.LockFile.Stat()
	if err != nil {
		e.Close()
		return err
	}
	if !s.Mode().IsRegular() || owner(s) != e.UID || s.Sys().(*syscall.Stat_t).Nlink != 1 {
		e.Close()
		return fail("unsafe_lock")
	}
	if err = syscall.Flock(int(e.LockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		e.Close()
		return fail("another_cleanup_running")
	}
	e.State = State{Protocol: 2, Seen: map[string]Seen{}, History: []map[string]any{}}
	s, err = e.Store.Lstat("state.json")
	if err == nil {
		if owner(s) != e.UID || s.Mode().Perm()&0077 != 0 || s.Sys().(*syscall.Stat_t).Nlink != 1 {
			e.Close()
			return fail("unsafe_state")
		}
		raw, x := readBounded(e.Store, "state.json", MaxBytes)
		if x != nil {
			e.Close()
			return x
		}
		if x = StrictJSON(raw, &e.State); x != nil {
			e.Close()
			return fail("invalid_state")
		}
		if e.State.Protocol != 2 || e.State.Seen == nil || len(e.State.History) > 30 || len(e.State.Seen) > 512 {
			e.Close()
			return fail("state_protocol")
		}
	} else if !os.IsNotExist(err) {
		e.Close()
		return err
	}
	return nil
}
func (e *Engine) Close() {
	if e.LockFile != nil {
		e.LockFile.Close()
		e.LockFile = nil
	}
	if e.Store != nil {
		e.Store.Close()
		e.Store = nil
	}
	if e.Root != nil {
		e.Root.Close()
		e.Root = nil
	}
}
func (e *Engine) hook(phase string) error {
	if e.Hook != nil {
		return e.Hook(phase)
	}
	return nil
}
func (e *Engine) Save() error {
	if x := e.hook("before_record"); x != nil {
		return x
	}
	if len(e.State.History) > 30 {
		e.State.History = e.State.History[len(e.State.History)-30:]
	}
	return atomicJSON(e.Store, "state.json", e.State)
}
func (e *Engine) Record(v map[string]any) error {
	e.State.History = append(e.State.History, v)
	return e.Save()
}
func (e *Engine) clock() (float64, error) {
	now := e.Now()
	if math.IsNaN(now) || math.IsInf(now, 0) || now < e.State.LastClock {
		if e.State.Auto != nil {
			e.State.Auto.Suspended = "clock_reversed"
			_ = e.Save()
		}
		return now, fail("clock_reversed")
	}
	e.State.LastClock = now
	return now, nil
}
func (e *Engine) inspection(required []string) (Inspection, error) {
	v, x := e.Inspect()
	if x != nil {
		return v, x
	}
	if v.Protocol != 2 || v.UID != e.UID || !v.Complete || v.Observed == nil || v.Active == nil || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(v.HelperHash) {
		return v, fail("inspection_incomplete")
	}
	observed := map[string]bool{}
	for _, key := range v.Observed {
		if observed[key] {
			return v, fail("inspection_duplicate")
		}
		observed[key] = true
	}
	for _, key := range append(required, v.Active...) {
		if !observed[key] {
			return v, fail("inspection_missing_target")
		}
	}
	if math.IsNaN(v.Checked) || math.IsInf(v.Checked, 0) || math.Abs(e.Now()-v.Checked) > 30 {
		return v, fail("inspection_stale")
	}
	return v, nil
}
func (e *Engine) snapshot(key string) (Snapshot, error) {
	if x := e.checkRoot(); x != nil {
		return Snapshot{}, x
	}
	m, x := e.MountList()
	if x != nil {
		return Snapshot{}, x
	}
	homeInfo, x := os.Lstat(e.Home)
	if x != nil {
		return Snapshot{}, x
	}
	var privateGroup *uint32
	if homeInfo.Mode().Perm()&0077 == 0 {
		group := homeInfo.Sys().(*syscall.Stat_t).Gid
		privateGroup = &group
	}
	return TreeSnapshot(e.Root, key, filepath.Join(e.Home, ".vscode-server", key), e.UID, m, privateGroup)
}

func (e *Engine) checkRoot() error {
	p := filepath.Join(e.Home, ".vscode-server")
	if x := safeDir(p, e.UID); x != nil {
		return x
	}
	s, x := os.Lstat(p)
	if x != nil {
		return x
	}
	if ident(s) != e.RootID {
		return fail("root_changed")
	}
	return nil
}

var versionPattern = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)

func (e *Engine) installations() ([]Item, error) {
	out := []Item{}
	for _, relative := range []string{"cli/servers", "bin"} {
		absolute := filepath.Join(e.Home, ".vscode-server", relative)
		if _, x := e.Root.Lstat(relative); os.IsNotExist(x) {
			continue
		}
		if x := safeDir(absolute, e.UID); x != nil {
			return nil, x
		}
		if relative == "cli/servers" {
			if x := safeDir(filepath.Dir(absolute), e.UID); x != nil {
				return nil, x
			}
		}
		f, x := e.Root.Open(relative)
		if x != nil {
			return nil, x
		}
		entries, x := f.ReadDir(-1)
		f.Close()
		if x != nil {
			return nil, x
		}
		if len(entries) > 256 {
			return nil, fail("too_many_entries")
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasPrefix(name, ".remote-prune-") {
				return nil, fail("interrupted_quarantine_requires_review")
			}
			if !versionName(relative, name) {
				continue
			}
			item := Item{Key: relative + "/" + name, Commit: name[len(name)-40:]}
			snap, x := e.snapshot(item.Key)
			item.Snapshot = snap
			if x == nil {
				server := item.Key
				if relative == "cli/servers" {
					server += "/server"
				}
				var product struct {
					Commit string `json:"commit"`
				}
				var pack struct {
					Version string `json:"version"`
				}
				var b []byte
				b, x = readBounded(e.Root, server+"/product.json", 2*1024*1024)
				if x == nil {
					x = StrictJSON(b, &product)
				}
				if x == nil {
					b, x = readBounded(e.Root, server+"/package.json", 2*1024*1024)
				}
				if x == nil {
					x = StrictJSON(b, &pack)
				}
				if x == nil {
					match := versionPattern.FindStringSubmatch(pack.Version)
					node, z := e.Root.Lstat(server + "/node")
					if product.Commit != item.Commit || match == nil || z != nil || !node.Mode().IsRegular() {
						x = fail("unrecognized_installation")
					} else {
						item.Version = pack.Version
						for i := 0; i < 3; i++ {
							item.Order[i], z = strconv.Atoi(match[i+1])
							if z != nil {
								x = fail("unrecognized_version")
							}
						}
					}
				}
			}
			if x != nil {
				item.Reason = safeReason(x)
			}
			out = append(out, item)
		}
	}
	return out, nil
}
func (e *Engine) Preview() (Preview, error) {
	report := Preview{Kind: "preview", Items: []Item{}, Eligible: []string{}}
	now, x := e.clock()
	if x != nil {
		return report, x
	}
	report.At = now
	if e.State.Pending != nil {
		return report, fail("interrupted_cleanup_requires_review")
	}
	items, x := e.installations()
	if x != nil {
		return report, x
	}
	keys := []string{}
	for _, i := range items {
		keys = append(keys, i.Key)
	}
	info, x := e.inspection(keys)
	if x != nil {
		return report, x
	}
	active := map[string]bool{}
	for _, k := range info.Active {
		active[k] = true
	}
	newest := -1
	for i, v := range items {
		if v.Reason != "" || active[v.Key] {
			continue
		}
		if newest < 0 || compareVersion(v.Order, items[newest].Order) > 0 {
			newest = i
		}
	}
	freshSeen := map[string]Seen{}
	for i := range items {
		v := &items[i]
		if v.Reason != "" {
			continue
		}
		old, ok := e.State.Seen[v.Key]
		if !ok || old.Identity != v.Identity || old.Digest != v.Digest {
			old = Seen{v.Identity, v.Digest, now}
		}
		freshSeen[v.Key] = old
		switch {
		case active[v.Key]:
			v.Reason = "in_use"
		case i == newest:
			v.Reason = "newest_unused_backup"
		case now-old.First < Day:
			v.Reason = "observed_less_than_24h"
		case now-v.Newest < Day:
			v.Reason = "changed_within_24h"
		default:
			v.Reason = "eligible"
			report.Eligible = append(report.Eligible, v.Key)
		}
	}
	e.State.Seen = freshSeen
	report.Items = items
	report.Helper = info.HelperHash
	return report, e.Save()
}
func compareVersion(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		if a[i] > b[i] {
			return 1
		}
		if a[i] < b[i] {
			return -1
		}
	}
	return 0
}
func (e *Engine) Status() (map[string]any, error) {
	if _, x := e.clock(); x != nil {
		return nil, x
	}
	if e.State.Auto != nil {
		hash, x := e.Fingerprint()
		if x != nil {
			return nil, x
		}
		if hash != e.State.Auto.Code {
			e.State.Auto.Suspended = "extension_changed"
		}
	}
	if x := e.Save(); x != nil {
		return nil, x
	}
	recent := e.State.History
	if len(recent) > 1 {
		recent = recent[len(recent)-1:]
	}
	return map[string]any{"auto": e.State.Auto, "pending": e.State.Pending, "recent": recent}, nil
}
func (e *Engine) Enable() (map[string]any, error) {
	v, x := e.Preview()
	if x != nil {
		return nil, x
	}
	hash, x := e.Fingerprint()
	if x != nil {
		return nil, x
	}
	now := e.Now()
	e.State.Auto = &Auto{Enabled: now, Next: now + Day, Code: hash, Helper: v.Helper}
	if x = e.Record(map[string]any{"kind": "auto_enabled", "at": now}); x != nil {
		return nil, x
	}
	return e.Status()
}
func (e *Engine) Disable() (map[string]any, error) {
	e.State.Auto = nil
	if x := e.Record(map[string]any{"kind": "auto_disabled", "at": e.Now()}); x != nil {
		return nil, x
	}
	return e.Status()
}
func contains(list []string, key string) bool {
	for _, v := range list {
		if key == v {
			return true
		}
	}
	return false
}

func (e *Engine) Cleanup(selected []string, automatic bool) (result map[string]any, err error) {
	now, x := e.clock()
	if x != nil {
		return nil, x
	}
	if automatic {
		if _, x = e.Status(); x != nil {
			return nil, x
		}
		a := e.State.Auto
		if a == nil || a.Suspended != "" || now < a.Next {
			return map[string]any{"kind": "not_due", "at": now, "auto": a}, nil
		}
		a.Next = now + Day
		if x = e.Record(map[string]any{"kind": "auto_attempt", "at": now}); x != nil {
			return nil, x
		}
	}
	defer func() {
		if err != nil {
			reason := safeReason(err)
			if automatic && e.State.Auto != nil && (reason == "helper_changed" || reason == "helper_version_changed") {
				e.State.Auto.Suspended = reason
			}
			_ = e.Record(map[string]any{"kind": "cleanup_refused", "at": e.Now(), "reason": reason})
		}
	}()
	report, x := e.Preview()
	if x != nil {
		return nil, x
	}
	if automatic {
		if report.Helper != e.State.Auto.Helper {
			return nil, fail("helper_changed")
		}
		selected = report.Eligible
	}
	for _, key := range selected {
		if !contains(report.Eligible, key) {
			return nil, fail("selection_no_longer_eligible")
		}
	}
	free, x := diskFree(e.Home)
	if x != nil {
		return nil, x
	}
	kind := "manual_cleanup"
	if automatic {
		kind = "auto_cleanup"
	}
	removed := []string{}
	allocated := int64(0)
	result = map[string]any{"kind": kind, "at": now, "removed": removed, "allocated_bytes": allocated, "free_before": free, "phase": "started"}
	if x = e.Record(clone(result)); x != nil {
		return nil, x
	}
	for _, item := range report.Items {
		if !contains(selected, item.Key) {
			continue
		}
		if x = e.hook("before_candidate_check"); x != nil {
			return nil, x
		}
		snap, x := e.snapshot(item.Key)
		if x != nil {
			return nil, x
		}
		if snap != item.Snapshot {
			return nil, fail("candidate_changed")
		}
		info, x := e.inspection([]string{item.Key})
		if x != nil {
			return nil, x
		}
		if contains(info.Active, item.Key) || info.HelperHash != report.Helper {
			return nil, fail("candidate_became_active_or_helper_changed")
		}
		parentName := filepath.Dir(item.Key)
		parentInfo, x := e.Root.Lstat(parentName)
		if x != nil {
			return nil, x
		}
		parent, x := e.Root.OpenRoot(parentName)
		if x != nil {
			return nil, x
		}
		x = e.removeOne(parent, parentName, ident(parentInfo), item, report.Helper)
		parent.Close()
		if x != nil {
			return nil, x
		}
		removed = append(removed, item.Key)
		allocated += item.Allocated
		delete(e.State.Seen, item.Key)
		result["removed"] = append([]string{}, removed...)
		result["allocated_bytes"] = allocated
		result["phase"] = "progress"
		if x = e.Record(clone(result)); x != nil {
			return nil, x
		}
	}
	free, x = diskFree(e.Home)
	if x != nil {
		return nil, x
	}
	result["free_after"] = free
	result["phase"] = "completed"
	return result, e.Record(clone(result))
}
func clone(v map[string]any) map[string]any {
	out := map[string]any{}
	for k, x := range v {
		out[k] = x
	}
	return out
}
func (e *Engine) removeOne(parent *os.Root, parentName string, parentID Identity, item Item, helperHash string) error {
	name := filepath.Base(item.Key)
	retired := ".remote-prune-" + nonce() + "-" + name
	key := parentName + "/" + retired
	e.State.Pending = &Pending{Key: item.Key, Retired: key, Identity: item.Identity, Phase: "prepared", At: e.Now()}
	if x := e.Save(); x != nil {
		return x
	}
	s, x := parent.Lstat(name)
	if x != nil {
		return x
	}
	ps, x := e.Root.Lstat(parentName)
	if x != nil {
		return x
	}
	f, x := parent.Open(".")
	if x != nil {
		return x
	}
	actual, x := f.Stat()
	f.Close()
	if x != nil {
		return x
	}
	if ident(s) != item.Identity || ident(ps) != parentID || ident(actual) != parentID {
		return fail("candidate_replaced")
	}
	if x = parent.Rename(name, retired); x != nil {
		return x
	}
	if x = syncRoot(parent); x != nil {
		return x
	}
	e.State.Pending.Phase = "quarantined"
	if x = e.Save(); x != nil {
		return x
	}
	if x = e.hook("after_quarantine"); x != nil {
		return x
	}
	info, x := e.inspection([]string{key})
	if x != nil {
		return x
	}
	if contains(info.Active, key) || contains(info.Active, item.Key) {
		if _, x = parent.Lstat(name); !os.IsNotExist(x) {
			return fail("restore_conflict")
		}
		if x = parent.Rename(retired, name); x != nil {
			return x
		}
		if x = syncRoot(parent); x != nil {
			return x
		}
		e.State.Pending = nil
		if x = e.Save(); x != nil {
			return x
		}
		return fail("active_after_quarantine_restored")
	}
	if info.HelperHash != helperHash {
		return fail("helper_changed_after_quarantine")
	}
	snap, x := e.snapshot(key)
	if x != nil {
		return x
	}
	if snap.Identity != item.Identity || snap.Digest != item.Digest {
		return fail("quarantine_changed")
	}
	ps, x = e.Root.Lstat(parentName)
	if x != nil {
		return x
	}
	if ident(ps) != parentID {
		return fail("parent_changed")
	}
	e.State.Pending.Phase = "deleting"
	if x = e.Save(); x != nil {
		return x
	}
	if x = e.hook("before_delete"); x != nil {
		return x
	}
	if x = e.checkRoot(); x != nil {
		return x
	}
	// Go os.Root anchors all recursive deletion to an opened directory. No shell/path rm.
	if x = parent.RemoveAll(retired); x != nil {
		return x
	}
	if x = syncRoot(parent); x != nil {
		return x
	}
	e.State.Pending = nil
	return e.Save()
}

func (e *Engine) Run(command string, input io.Reader) (any, error) {
	switch command {
	case "status":
		return e.Status()
	case "preview":
		return e.Preview()
	case "enable-auto":
		return e.Enable()
	case "disable-auto":
		return e.Disable()
	case "history":
		return map[string]any{"history": e.State.History, "pending": e.State.Pending}, nil
	case "auto":
		return e.Cleanup(nil, true)
	case "cleanup":
		var data struct {
			Selected *[]string `json:"selected"`
		}
		raw, x := io.ReadAll(io.LimitReader(input, 32769))
		if x != nil {
			return nil, x
		}
		if len(raw) > 32768 {
			return nil, fail("selection_too_large")
		}
		if x = StrictJSON(raw, &data); x != nil {
			return nil, fail("invalid_selection")
		}
		if data.Selected == nil {
			return nil, fail("explicit_selection_required")
		}
		return e.Cleanup(*data.Selected, false)
	default:
		return nil, fail("invalid_command")
	}
}
func Failure(e error) { Print(map[string]any{"ok": false, "reason": safeReason(e)}) }

// Keep JSON import used here so gofmt can group serialization with state handling.
var _ = json.Valid

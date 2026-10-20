package core

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fixture struct {
	e            *Engine
	home         string
	now          float64
	active       map[string]bool
	helper, code string
	calls        int
	onInspect    func()
}

func fixtureAt(home string) *fixture {
	f := &fixture{home: home, now: float64(time.Now().Unix()), active: map[string]bool{}, helper: strings.Repeat("a", 64), code: strings.Repeat("b", 64)}
	f.e = NewEngine(home, uint32(os.Getuid()), "")
	f.e.Now = func() float64 { return f.now }
	f.e.Fingerprint = func() (string, error) { return f.code, nil }
	f.e.Inspect = func() (Inspection, error) {
		f.calls++
		if f.onInspect != nil {
			f.onInspect()
		}
		entries, e := os.ReadDir(filepath.Join(home, ".vscode-server/cli/servers"))
		if e != nil {
			return Inspection{}, e
		}
		v := Inspection{Protocol: 2, UID: uint32(os.Getuid()), Complete: true, Observed: []string{}, Active: []string{}, Checked: f.now, HelperHash: f.helper}
		for _, entry := range entries {
			k := "cli/servers/" + entry.Name()
			v.Observed = append(v.Observed, k)
			if f.active[k] {
				v.Active = append(v.Active, k)
			}
		}
		return v, nil
	}
	return f
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := fixtureAt(t.TempDir())
	must(t, os.Chmod(f.home, 0700))
	for i := 1; i <= 3; i++ {
		key := f.key(i)
		p := filepath.Join(f.home, ".vscode-server", key, "server")
		must(t, os.MkdirAll(p, 0755))
		must(t, os.WriteFile(filepath.Join(p, "product.json"), []byte(`{"commit":"`+strings.Repeat(fmt.Sprint(i), 40)+`"}`), 0644))
		must(t, os.WriteFile(filepath.Join(p, "package.json"), []byte(fmt.Sprintf(`{"version":"1.%d.0"}`, i)), 0644))
		must(t, os.WriteFile(filepath.Join(p, "node"), []byte("synthetic\x00\xff"), 0755))
		old := time.Unix(int64(f.now-2*Day), 0)
		must(t, filepath.Walk(filepath.Dir(p), func(p string, s os.FileInfo, e error) error {
			if e != nil {
				return e
			}
			return os.Chtimes(p, old, old)
		}))
	}
	f.active[f.key(2)] = true
	return f
}
func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func (f *fixture) key(i int) string  { return "cli/servers/Stable-" + strings.Repeat(fmt.Sprint(i), 40) }
func (f *fixture) path(i int) string { return filepath.Join(f.home, ".vscode-server", f.key(i)) }
func (f *fixture) open(t *testing.T) { t.Helper(); must(t, f.e.Open()); t.Cleanup(f.e.Close) }
func (f *fixture) mature(t *testing.T) {
	t.Helper()
	f.open(t)
	_, e := f.e.Preview()
	must(t, e)
	f.now += Day + 1
}
func refused(t *testing.T, e error, reason string) {
	t.Helper()
	if e == nil || !strings.Contains(e.Error(), reason) {
		t.Fatalf("expected %s, got %v", reason, e)
	}
}

func TestEligibleOnlyActiveAndNewestPreserved(t *testing.T) {
	f := newFixture(t)
	f.mature(t)
	before, _ := FileHash(filepath.Join(f.path(2), "server/node"))
	r, e := f.e.Cleanup([]string{f.key(1)}, false)
	must(t, e)
	if len(r["removed"].([]string)) != 1 || f.e.State.Pending != nil {
		t.Fatal(r)
	}
	if _, e = os.Stat(f.path(1)); !os.IsNotExist(e) {
		t.Fatal("old still exists")
	}
	after, _ := FileHash(filepath.Join(f.path(2), "server/node"))
	if before != after {
		t.Fatal("active changed")
	}
	if _, e = os.Stat(f.path(3)); e != nil {
		t.Fatal("backup removed")
	}
}
func TestFirstSeenBoundary(t *testing.T) {
	f := newFixture(t)
	f.open(t)
	r, e := f.e.Preview()
	must(t, e)
	if len(r.Eligible) != 0 {
		t.Fatal(r)
	}
	f.now += Day - .01
	r, e = f.e.Preview()
	must(t, e)
	if len(r.Eligible) != 0 {
		t.Fatal(r)
	}
	f.now += .01
	r, e = f.e.Preview()
	must(t, e)
	if len(r.Eligible) != 1 {
		t.Fatal(r)
	}
}
func TestChangedFileResetsAgeEvenWithOldMtime(t *testing.T) {
	f := newFixture(t)
	f.mature(t)
	p := filepath.Join(f.path(1), "server/node")
	must(t, os.WriteFile(p, []byte("changed"), 0755))
	old := time.Unix(int64(f.now-3*Day), 0)
	must(t, os.Chtimes(p, old, old))
	r, e := f.e.Preview()
	must(t, e)
	if len(r.Eligible) != 0 {
		t.Fatal(r)
	}
}
func TestInvalidInstallPreserved(t *testing.T) {
	for _, body := range []string{`{"commit":"wrong"}`, `{"commit":"a","commit":"b"}`, `null`} {
		t.Run(body, func(t *testing.T) {
			f := newFixture(t)
			f.mature(t)
			must(t, os.WriteFile(filepath.Join(f.path(1), "server/product.json"), []byte(body), 0644))
			r, e := f.e.Preview()
			must(t, e)
			if len(r.Eligible) != 0 {
				t.Fatal(r)
			}
		})
	}
}
func TestSymlinkHardlinkSpecialAndMountPreserved(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "mount", "permissions"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			f.mature(t)
			outside := filepath.Join(f.home, "keep")
			must(t, os.WriteFile(outside, []byte("keep"), 0600))
			p := filepath.Join(f.path(1), "unsafe")
			switch kind {
			case "symlink":
				must(t, os.Symlink(outside, p))
			case "hardlink":
				must(t, os.Link(outside, p))
			case "fifo":
				must(t, syscall.Mkfifo(p, 0600))
			case "mount":
				f.e.MountList = func() ([]string, error) { return []string{filepath.Join(f.path(1), "server")}, nil }
			case "permissions":
				must(t, os.Chmod(filepath.Join(f.path(1), "server/node"), 0777))
			}
			r, e := f.e.Preview()
			must(t, e)
			if len(r.Eligible) != 0 {
				t.Fatal(r)
			}
			b, e := os.ReadFile(outside)
			must(t, e)
			if string(b) != "keep" {
				t.Fatal("outside changed")
			}
		})
	}
}
func TestParentSymlinkAndOwnerRefused(t *testing.T) {
	f := newFixture(t)
	parent := filepath.Join(f.home, ".vscode-server/cli/servers")
	must(t, os.Rename(parent, parent+"-other"))
	must(t, os.Symlink(parent+"-other", parent))
	f.open(t)
	_, e := f.e.Preview()
	refused(t, e, "symlink")
	f.e.Close()
	f.e.UID++
	e = f.e.Open()
	refused(t, e, "unsafe_directory")
}
func TestConcurrentChangeBeforeRenamePreserved(t *testing.T) {
	f := newFixture(t)
	f.mature(t)
	f.e.Hook = func(p string) error {
		if p == "before_candidate_check" {
			return os.WriteFile(filepath.Join(f.path(1), "server/node"), []byte("new"), 0755)
		}
		return nil
	}
	_, e := f.e.Cleanup([]string{f.key(1)}, false)
	refused(t, e, "candidate_changed")
	if _, e = os.Stat(f.path(1)); e != nil {
		t.Fatal(e)
	}
}
func TestNewProcessBeforeRenamePreserved(t *testing.T) {
	f := newFixture(t)
	f.mature(t)
	f.calls = 0
	f.onInspect = func() {
		if f.calls == 2 {
			f.active[f.key(1)] = true
		}
	}
	_, e := f.e.Cleanup([]string{f.key(1)}, false)
	refused(t, e, "became_active")
	if _, e = os.Stat(f.path(1)); e != nil {
		t.Fatal(e)
	}
}
func TestNewProcessAfterRenameRestoresOriginal(t *testing.T) {
	f := newFixture(t)
	f.mature(t)
	f.onInspect = func() {
		paths, _ := filepath.Glob(filepath.Join(f.home, ".vscode-server/cli/servers/.remote-prune-*"))
		for _, p := range paths {
			f.active["cli/servers/"+filepath.Base(p)] = true
		}
	}
	_, e := f.e.Cleanup([]string{f.key(1)}, false)
	refused(t, e, "restored")
	if f.e.State.Pending != nil {
		t.Fatal("pending")
	}
	if _, e = os.Stat(f.path(1)); e != nil {
		t.Fatal(e)
	}
}
func TestIncompleteMissingStaleOrWrongProtocolRefused(t *testing.T) {
	for _, kind := range []string{"incomplete", "missing", "stale", "protocol", "helper", "pid-generation"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			f.mature(t)
			original := f.e.Inspect
			f.e.Inspect = func() (Inspection, error) {
				v, e := original()
				switch kind {
				case "incomplete":
					v.Complete = false
				case "missing":
					v.Observed = []string{}
				case "stale":
					v.Checked -= 31
				case "protocol":
					v.Protocol = 99
				case "helper":
					v.HelperHash = "?"
				case "pid-generation":
					return v, fail("process_generation_changed")
				}
				return v, e
			}
			_, e := f.e.Cleanup([]string{f.key(1)}, false)
			if e == nil {
				t.Fatal("accepted incomplete")
			}
			if _, e = os.Stat(f.path(1)); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestRecordFailureBeforeMutation(t *testing.T) {
	f := newFixture(t)
	f.mature(t)
	f.e.Hook = func(phase string) error {
		if phase == "before_record" {
			return errors.New("disk full")
		}
		return nil
	}
	_, e := f.e.Cleanup([]string{f.key(1)}, false)
	if e == nil {
		t.Fatal("record not required")
	}
	if _, e = os.Stat(f.path(1)); e != nil {
		t.Fatal(e)
	}
}
func TestPartialDeletionRemainsForReview(t *testing.T) {
	f := newFixture(t)
	f.mature(t)
	f.e.Hook = func(phase string) error {
		if phase == "before_delete" {
			must(t, f.e.Root.Remove(f.e.State.Pending.Retired+"/server/node"))
			return errors.New("partial deletion")
		}
		return nil
	}
	_, e := f.e.Cleanup([]string{f.key(1)}, false)
	if e == nil {
		t.Fatal("expected failure")
	}
	f.e.Close()
	f.e.Hook = nil
	must(t, f.e.Open())
	_, e = f.e.Preview()
	refused(t, e, "interrupted")
	if f.e.State.Pending.Phase != "deleting" {
		t.Fatal(f.e.State.Pending)
	}
}
func TestSymlinkSwapCannotEscapeDeletionRoot(t *testing.T) {
	f := newFixture(t)
	f.mature(t)
	outside := filepath.Join(f.home, "outside")
	must(t, os.Mkdir(outside, 0700))
	must(t, os.WriteFile(filepath.Join(outside, "keep"), []byte("keep"), 0600))
	f.e.Hook = func(phase string) error {
		if phase == "before_delete" {
			p := f.e.State.Pending.Retired + "/server"
			must(t, f.e.Root.RemoveAll(p))
			return os.Symlink(outside, filepath.Join(f.home, ".vscode-server", p))
		}
		return nil
	}
	_, e := f.e.Cleanup([]string{f.key(1)}, false)
	must(t, e)
	b, e := os.ReadFile(filepath.Join(outside, "keep"))
	must(t, e)
	if string(b) != "keep" {
		t.Fatal("escape")
	}
}
func TestLockIsSharedAcrossProcesses(t *testing.T) {
	f := newFixture(t)
	f.open(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestChildDriver$")
	cmd.Env = append(os.Environ(), "PRUNE_TEST_MODE=lock", "PRUNE_TEST_HOME="+f.home)
	out, e := cmd.CombinedOutput()
	must(t, e)
	if !strings.Contains(string(out), "another_cleanup_running") {
		t.Fatal(string(out))
	}
}
func TestCrashAfterQuarantineNeverAutoResumes(t *testing.T) {
	f := newFixture(t)
	f.mature(t)
	f.e.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestChildDriver$")
	cmd.Env = append(os.Environ(), "PRUNE_TEST_MODE=crash", "PRUNE_TEST_HOME="+f.home, "PRUNE_TEST_NOW="+fmt.Sprint(f.now))
	e := cmd.Run()
	exit, ok := e.(*exec.ExitError)
	if !ok || exit.ExitCode() != 77 {
		t.Fatal(e)
	}
	must(t, f.e.Open())
	_, e = f.e.Preview()
	refused(t, e, "interrupted")
}
func TestChildDriver(t *testing.T) {
	mode := os.Getenv("PRUNE_TEST_MODE")
	if mode == "" {
		return
	}
	f := fixtureAt(os.Getenv("PRUNE_TEST_HOME"))
	f.active[f.key(2)] = true
	if mode == "lock" {
		e := f.e.Open()
		if e == nil {
			f.e.Close()
			t.Fatal("lock acquired")
		}
		fmt.Print(e)
		return
	}
	fmt.Sscan(os.Getenv("PRUNE_TEST_NOW"), &f.now)
	must(t, f.e.Open())
	f.e.Hook = func(p string) error {
		if p == "after_quarantine" {
			os.Exit(77)
		}
		return nil
	}
	_, e := f.e.Cleanup([]string{f.key(1)}, false)
	t.Fatal("did not exit", e)
}
func TestAutomaticDailyBoundaryAndSecondWindow(t *testing.T) {
	f := newFixture(t)
	f.open(t)
	if f.e.State.Auto != nil {
		t.Fatal("enabled by default")
	}
	_, e := f.e.Enable()
	must(t, e)
	f.now += Day - 1
	r, e := f.e.Cleanup(nil, true)
	must(t, e)
	if r["kind"] != "not_due" {
		t.Fatal(r)
	}
	f.now++
	r, e = f.e.Cleanup(nil, true)
	must(t, e)
	if len(r["removed"].([]string)) != 1 {
		t.Fatal(r)
	}
	f.e.Close()
	must(t, f.e.Open())
	r, e = f.e.Cleanup(nil, true)
	must(t, e)
	if r["kind"] != "not_due" {
		t.Fatal(r)
	}
}
func TestFailureRecordsAttemptAndNoImmediateRetry(t *testing.T) {
	f := newFixture(t)
	f.open(t)
	_, e := f.e.Enable()
	must(t, e)
	f.now += Day
	f.e.Inspect = func() (Inspection, error) { return Inspection{}, fail("inspection_unavailable") }
	_, e = f.e.Cleanup(nil, true)
	refused(t, e, "inspection_unavailable")
	if f.e.State.Auto.Next != f.now+Day {
		t.Fatal(f.e.State.Auto)
	}
	r, e := f.e.Cleanup(nil, true)
	must(t, e)
	if r["kind"] != "not_due" {
		t.Fatal(r)
	}
}
func TestCodeHelperClockChangesSuspend(t *testing.T) {
	for _, kind := range []string{"code", "helper", "clock"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			f.open(t)
			_, e := f.e.Enable()
			must(t, e)
			f.now += Day
			switch kind {
			case "code":
				f.code = strings.Repeat("c", 64)
			case "helper":
				f.helper = strings.Repeat("d", 64)
			case "clock":
				f.now -= Day + 1
			}
			_, _ = f.e.Cleanup(nil, true)
			if f.e.State.Auto.Suspended == "" {
				t.Fatal("not suspended")
			}
			if _, e = os.Stat(f.path(1)); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestHistoryBoundAndExplicitSelection(t *testing.T) {
	f := newFixture(t)
	f.mature(t)
	for i := 0; i < 90; i++ {
		must(t, f.e.Record(map[string]any{"kind": "synthetic", "n": i}))
	}
	if len(f.e.State.History) != 30 {
		t.Fatal("unbounded")
	}
	_, e := f.e.Cleanup([]string{"../../outside"}, false)
	refused(t, e, "selection_no_longer")
	_, e = f.e.Run("cleanup", strings.NewReader(`{}`))
	refused(t, e, "explicit_selection")
}
func TestStateTamperingFailsClosed(t *testing.T) {
	f := newFixture(t)
	f.open(t)
	_, e := f.e.Preview()
	must(t, e)
	f.e.Close()
	must(t, os.WriteFile(filepath.Join(f.home, ".remote-prune/state.json"), []byte(`{"protocol":2,"protocol":2}`), 0600))
	e = f.e.Open()
	refused(t, e, "invalid_state")
}
func TestRealOpenFileAndMmapDetected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mapped")
	must(t, os.WriteFile(p, []byte(strings.Repeat("keep", 1024)), 0600))
	cmd := exec.Command(os.Args[0], "-test.run=^TestMappedChild$")
	cmd.Env = append(os.Environ(), "PRUNE_TEST_MAPPED="+p)
	in, e := cmd.StdinPipe()
	must(t, e)
	out, e := cmd.StdoutPipe()
	must(t, e)
	must(t, cmd.Start())
	defer func() { in.Close(); cmd.Wait() }()
	line, e := bufio.NewReader(out).ReadString('\n')
	must(t, e)
	if line != "ready\n" {
		t.Fatal(line)
	}
	active, _ := ScanProcesses(map[string][]string{"test": {p}}, "/proc")
	if !contains(active, "test") {
		t.Fatal(active)
	}
}
func TestMappedChild(t *testing.T) {
	p := os.Getenv("PRUNE_TEST_MAPPED")
	if p == "" {
		return
	}
	f, e := os.Open(p)
	must(t, e)
	defer f.Close()
	b, e := syscall.Mmap(int(f.Fd()), 0, 4096, syscall.PROT_READ, syscall.MAP_PRIVATE)
	must(t, e)
	defer syscall.Munmap(b)
	fmt.Println("ready")
	var input [1]byte
	_, _ = os.Stdin.Read(input[:])
}
func TestBrokenProcAndQuarantinePaths(t *testing.T) {
	proc := t.TempDir()
	must(t, os.Mkdir(filepath.Join(proc, "123"), 0700))
	_, complete := ScanProcesses(map[string][]string{}, proc)
	if complete {
		t.Fatal("incomplete proc accepted")
	}
	f := newFixture(t)
	p := f.path(1)
	newName := ".remote-prune-" + strings.Repeat("a", 32) + "-" + filepath.Base(p)
	must(t, os.Rename(p, filepath.Join(filepath.Dir(p), newName)))
	targets, e := Targets(f.home, uint32(os.Getuid()))
	must(t, e)
	needles := targets["cli/servers/"+newName]
	if !contains(needles, p) {
		t.Fatal(needles)
	}
}
func TestJSONNoDuplicatesAndBoundedState(t *testing.T) {
	for _, raw := range []string{`{"a":1,"a":2}`, `{} {}`, `{"a":NaN}`} {
		var out any
		if StrictJSON([]byte(raw), &out) == nil {
			t.Fatal(raw)
		}
	}
	f := newFixture(t)
	f.open(t)
	e := f.e.Record(map[string]any{"huge": strings.Repeat("x", MaxBytes+1)})
	refused(t, e, "record_too_large")
	var out map[string]any
	must(t, StrictJSON([]byte(`{"a":"한글","b":[1,true,null]}`), &out))
	_, _ = json.Marshal(out)
}

func TestRootReplacementRefusesDeletion(t *testing.T) {
	f := newFixture(t)
	f.mature(t)
	f.e.Hook = func(phase string) error {
		if phase == "before_candidate_check" {
			p := filepath.Join(f.home, ".vscode-server")
			if err := os.Rename(p, p+"-preserved"); err != nil {
				return err
			}
			return os.MkdirAll(filepath.Join(p, "cli/servers"), 0755)
		}
		return nil
	}
	_, err := f.e.Cleanup([]string{f.key(1)}, false)
	refused(t, err, "root_changed")
	if _, err = os.Stat(filepath.Join(f.home, ".vscode-server-preserved", f.key(1))); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveGroupWriteOnlyBehindPrivateHome(t *testing.T) {
	f := newFixture(t)
	must(t, os.Chmod(filepath.Join(f.path(1), "server/product.json"), 0664))
	must(t, os.Chmod(filepath.Join(f.path(1), "server"), 0775))
	f.mature(t)
	v, err := f.e.Preview()
	must(t, err)
	if !contains(v.Eligible, f.key(1)) {
		t.Fatal(v)
	}
	must(t, os.Chmod(f.home, 0750))
	v, err = f.e.Preview()
	must(t, err)
	if contains(v.Eligible, f.key(1)) {
		t.Fatal("group-writable installation in shared home accepted")
	}
}

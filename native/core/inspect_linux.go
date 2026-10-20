package core

import (
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Inspection struct {
	Protocol   int      `json:"protocol"`
	UID        uint32   `json:"uid"`
	Complete   bool     `json:"complete"`
	Observed   []string `json:"observed"`
	Active     []string `json:"active"`
	Checked    float64  `json:"checked_at"`
	HelperHash string   `json:"helper_sha256"`
}

var commitPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var retiredPattern = regexp.MustCompile(`^\.remote-prune-[a-f0-9]{32}-(Stable-)?[a-f0-9]{40}$`)

func versionName(relative, name string) bool {
	if relative == "cli/servers" {
		return strings.HasPrefix(name, "Stable-") && commitPattern.MatchString(strings.TrimPrefix(name, "Stable-"))
	}
	return commitPattern.MatchString(name)
}
func Targets(home string, uid uint32) (map[string][]string, error) {
	root := filepath.Join(home, ".vscode-server")
	for _, p := range []string{home, root} {
		if e := safeDir(p, uid); e != nil {
			return nil, e
		}
	}
	out := map[string][]string{}
	for _, rel := range []string{"cli/servers", "bin"} {
		p := filepath.Join(root, rel)
		if _, e := os.Lstat(p); os.IsNotExist(e) {
			continue
		}
		if e := safeDir(p, uid); e != nil {
			return nil, e
		}
		if rel == "cli/servers" {
			if e := safeDir(filepath.Dir(p), uid); e != nil {
				return nil, e
			}
		}
		entries, e := os.ReadDir(p)
		if e != nil {
			return nil, e
		}
		if len(entries) > 256 {
			return nil, fail("too_many_entries")
		}
		for _, entry := range entries {
			name := entry.Name()
			if !versionName(rel, name) && !retiredPattern.MatchString(name) {
				continue
			}
			full := filepath.Join(p, name)
			if e := safeDir(full, uid); e != nil {
				return nil, e
			}
			commit := name[len(name)-40:]
			key := rel + "/" + name
			out[key] = []string{full, filepath.Join(root, "code-"+commit)}
			if retiredPattern.MatchString(name) {
				old := commit
				if rel == "cli/servers" {
					old = "Stable-" + commit
				}
				out[key] = append(out[key], filepath.Join(p, old))
			}
		}
	}
	return out, nil
}
func limitedFile(p string, limit int64) (string, error) {
	f, e := os.Open(p)
	if e != nil {
		return "", e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return "", e
	}
	if int64(len(b)) > limit {
		return "", fail("proc_limit")
	}
	return string(b), nil
}
func processStart(p string) (string, error) {
	s, e := limitedFile(filepath.Join(p, "stat"), 64*1024)
	if e != nil {
		return "", e
	}
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return "", fail("process_stat_invalid")
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) < 20 {
		return "", fail("process_stat_invalid")
	}
	return fields[19], nil
}
func scanProcess(p string) ([]string, error) {
	before, e := processStart(p)
	if e != nil {
		return nil, e
	}
	cmd, e := limitedFile(filepath.Join(p, "cmdline"), 1024*1024)
	if e != nil {
		return nil, e
	}
	maps, e := limitedFile(filepath.Join(p, "maps"), 8*1024*1024)
	if e != nil {
		return nil, e
	}
	values := []string{cmd, unescape(maps)}
	for _, name := range []string{"exe", "cwd", "root"} {
		v, e := os.Readlink(filepath.Join(p, name))
		if e != nil && !os.IsNotExist(e) {
			return nil, e
		}
		if e == nil {
			values = append(values, v)
		}
	}
	fds, e := os.ReadDir(filepath.Join(p, "fd"))
	if e != nil {
		return nil, e
	}
	if len(fds) > 16384 {
		return nil, fail("proc_fd_limit")
	}
	for _, fd := range fds {
		v, e := os.Readlink(filepath.Join(p, "fd", fd.Name()))
		if e != nil && !os.IsNotExist(e) {
			return nil, e
		}
		if e == nil {
			values = append(values, v)
		}
	}
	after, e := processStart(p)
	if e != nil {
		return nil, e
	}
	if before != after {
		return nil, fail("process_generation_changed")
	}
	return values, nil
}
func ScanProcesses(targets map[string][]string, proc string) ([]string, bool) {
	active := map[string]bool{}
	complete := true
	entries, e := os.ReadDir(proc)
	if e != nil {
		return []string{}, false
	}
	known := map[string]bool{}
	for _, entry := range entries {
		known[entry.Name()] = true
	}
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || pid == os.Getpid() {
			continue
		}
		p := filepath.Join(proc, entry.Name())
		values, e := scanProcess(p)
		if e != nil {
			if _, gone := os.Stat(p); !os.IsNotExist(gone) {
				complete = false
			}
			continue
		}
		for key, needles := range targets {
			for _, needle := range needles {
				for _, v := range values {
					if strings.Contains(v, needle) {
						active[key] = true
					}
				}
			}
		}
	}
	// A process born during the scan has not been inspected. Defer this attempt.
	latest, e := os.ReadDir(proc)
	if e != nil {
		complete = false
	} else {
		for _, entry := range latest {
			if pid, err := strconv.Atoi(entry.Name()); err == nil && pid != os.Getpid() && !known[entry.Name()] {
				complete = false
			}
		}
	}
	out := []string{}
	for k := range active {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, complete
}
func Inspector() (Inspection, error) {
	result := Inspection{Protocol: 2, Complete: false, Observed: []string{}, Active: []string{}}
	if len(os.Args) != 1 || os.Geteuid() != 0 {
		return result, fail("no_argument_sudo_required")
	}
	id, e := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	if e != nil || id == 0 {
		return result, fail("nonroot_caller_required")
	}
	u, e := user.LookupId(strconv.FormatUint(id, 10))
	if e != nil {
		return result, e
	}
	result.UID = uint32(id)
	targets, e := Targets(u.HomeDir, result.UID)
	if e != nil {
		return result, e
	}
	for k := range targets {
		result.Observed = append(result.Observed, k)
	}
	sort.Strings(result.Observed)
	result.Active, result.Complete = ScanProcesses(targets, "/proc")
	exe, e := os.Executable()
	if e != nil {
		return result, e
	}
	result.HelperHash, e = FileHash(exe)
	if e != nil {
		return result, e
	}
	result.Checked = float64(time.Now().UnixNano()) / 1e9
	return result, nil
}

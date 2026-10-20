package core

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const MaxBytes = 5 * 1024 * 1024

type Refused string

func (e Refused) Error() string { return string(e) }
func fail(s string) error       { return Refused(s) }
func Hash(b []byte) string      { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func FileHash(p string) (string, error) {
	f, e := os.Open(p)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func nonce() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}

// Reject duplicate keys, trailing JSON, and excessive nesting before typed decoding.
func StrictJSON(b []byte, dest any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return fail("json_depth")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		if delim, ok := t.(json.Delim); ok {
			if delim == '{' {
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					s, ok := k.(string)
					if !ok || seen[s] {
						return fail("ambiguous_json")
					}
					seen[s] = true
					if e = value(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return fail("invalid_json")
				}
			} else if delim == '[' {
				for d.More() {
					if e = value(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return fail("invalid_json")
				}
			} else {
				return fail("invalid_json")
			}
		}
		return nil
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return fail("trailing_json")
	}
	return json.Unmarshal(b, dest)
}

type Identity struct {
	Dev uint64 `json:"dev"`
	Ino uint64 `json:"ino"`
}

func ident(s os.FileInfo) Identity {
	st := s.Sys().(*syscall.Stat_t)
	return Identity{uint64(st.Dev), st.Ino}
}
func owner(s os.FileInfo) uint32 { return s.Sys().(*syscall.Stat_t).Uid }
func sameStat(a, b os.FileInfo) bool {
	x, y := a.Sys().(*syscall.Stat_t), b.Sys().(*syscall.Stat_t)
	return ident(a) == ident(b) && a.Mode() == b.Mode() && a.Size() == b.Size() && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}
func safeDir(p string, uid uint32) error {
	resolved, e := filepath.EvalSymlinks(p)
	if e != nil {
		return e
	}
	if resolved != p {
		return fail("symlink_path")
	}
	s, e := os.Lstat(p)
	if e != nil {
		return e
	}
	if !s.IsDir() || owner(s) != uid || s.Mode().Perm()&0022 != 0 {
		return fail("unsafe_directory")
	}
	return nil
}

func openVerifiedRoot(p string, uid uint32) (*os.Root, Identity, error) {
	var zero Identity
	if e := safeDir(p, uid); e != nil {
		return nil, zero, e
	}
	before, e := os.Lstat(p)
	if e != nil {
		return nil, zero, e
	}
	r, e := os.OpenRoot(p)
	if e != nil {
		return nil, zero, e
	}
	f, e := r.Open(".")
	if e != nil {
		r.Close()
		return nil, zero, e
	}
	actual, e := f.Stat()
	f.Close()
	after, z := os.Lstat(p)
	if e != nil || z != nil || ident(before) != ident(actual) || ident(before) != ident(after) || after.Mode()&os.ModeSymlink != 0 {
		r.Close()
		return nil, zero, fail("root_changed")
	}
	return r, ident(actual), nil
}
func secureRootFile(p string) error {
	for q := p; ; q = filepath.Dir(q) {
		s, e := os.Lstat(q)
		if e != nil {
			return e
		}
		if s.Mode()&os.ModeSymlink != 0 || owner(s) != 0 || s.Mode().Perm()&0022 != 0 {
			return fail("helper_permissions")
		}
		if q == "/" {
			break
		}
	}
	s, e := os.Stat(p)
	if e != nil {
		return e
	}
	if !s.Mode().IsRegular() {
		return fail("helper_not_file")
	}
	return nil
}
func readBounded(root *os.Root, name string, limit int64) ([]byte, error) {
	s, e := root.Lstat(name)
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() || s.Mode()&os.ModeSymlink != 0 || s.Size() > limit {
		return nil, fail("invalid_file")
	}
	f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !sameStat(s, before) {
		return nil, fail("file_changed")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	after, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if len(b) > int(limit) || !sameStat(before, after) {
		return nil, fail("file_changed")
	}
	return b, nil
}
func syncRoot(r *os.Root) error {
	f, e := r.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func atomicJSON(r *os.Root, name string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if len(b) > MaxBytes {
		return fail("record_too_large")
	}
	tmp := ".write-" + nonce()
	f, e := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer r.Remove(tmp)
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = r.Rename(tmp, name); e != nil {
		return e
	}
	return syncRoot(r)
}

type Snapshot struct {
	Identity  Identity `json:"identity"`
	Digest    string   `json:"digest"`
	Allocated int64    `json:"allocated_bytes"`
	Logical   int64    `json:"logical_bytes"`
	Newest    float64  `json:"newest_mtime"`
}

var octalEscape = regexp.MustCompile(`\\([0-7]{3})`)

func unescape(s string) string {
	return octalEscape.ReplaceAllStringFunc(s, func(v string) string { n, _ := strconv.ParseInt(v[1:], 8, 8); return string(rune(n)) })
}
func Mounts() ([]string, error) {
	b, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil {
		return nil, e
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			return nil, fail("mountinfo_invalid")
		}
		out = append(out, unescape(f[4]))
	}
	return out, nil
}

func TreeSnapshot(base *os.Root, key, absolute string, uid uint32, mounts []string, privateGroup *uint32) (Snapshot, error) {
	result := Snapshot{}
	for _, m := range mounts {
		if m == absolute || strings.HasPrefix(m, absolute+"/") {
			return result, fail("mounted_tree_entry")
		}
	}
	before, e := base.Lstat(key)
	if e != nil {
		return result, e
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return result, fail("unsafe_tree_entry")
	}
	tree, e := base.OpenRoot(key)
	if e != nil {
		return result, e
	}
	defer tree.Close()
	f, e := tree.Open(".")
	if e != nil {
		return result, e
	}
	s, e := f.Stat()
	f.Close()
	if e != nil {
		return result, e
	}
	if ident(s) != ident(before) {
		return result, fail("tree_replaced")
	}
	result.Identity = ident(s)
	h := sha256.New()
	count := 0
	var walk func(string, int) error
	walk = func(name string, depth int) error {
		if depth > 64 {
			return fail("scan_depth_limit")
		}
		s, e := tree.Lstat(name)
		if e != nil {
			return e
		}
		st := s.Sys().(*syscall.Stat_t)
		// Official archives include 0664 files and 0775 directories. Group-write
		// is allowed only behind a private (0700) login home and for its own group.
		groupWrite := s.Mode().Perm()&0020 != 0
		unsafeMode := s.Mode().Perm()&0002 != 0 || (groupWrite && (privateGroup == nil || st.Gid != *privateGroup))
		if owner(s) != uid || unsafeMode || uint64(st.Dev) != result.Identity.Dev || (!s.IsDir() && !s.Mode().IsRegular()) || (s.Mode().IsRegular() && st.Nlink != 1) {
			return fail("unsafe_tree_entry")
		}
		count++
		if count > 20000 {
			return fail("scan_limit")
		}
		result.Allocated += st.Blocks * 512
		mt := float64(s.ModTime().UnixNano()) / 1e9
		if mt > result.Newest {
			result.Newest = mt
		}
		ct := st.Ctim
		if name == "." {
			ct = syscall.Timespec{}
		}
		stamp := []any{name, st.Ino, uint32(st.Mode), st.Uid, st.Gid, s.Size(), st.Mtim, ct}
		raw, _ := json.Marshal(stamp)
		h.Write(raw)
		file, e := tree.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if e != nil {
			return e
		}
		defer file.Close()
		actual, e := file.Stat()
		if e != nil {
			return e
		}
		if !sameStat(s, actual) {
			return fail("tree_changed")
		}
		if s.IsDir() {
			entries, e := file.ReadDir(-1)
			if e != nil {
				return e
			}
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			for _, entry := range entries {
				if e = walk(filepath.Join(name, entry.Name()), depth+1); e != nil {
					return e
				}
			}
		} else {
			result.Logical += s.Size()
			if result.Logical > 2*1024*1024*1024 {
				return fail("scan_limit")
			}
			part := sha256.New()
			if _, e = io.Copy(part, file); e != nil {
				return e
			}
			h.Write(part.Sum(nil))
		}
		after, e := file.Stat()
		if e != nil {
			return e
		}
		if !sameStat(actual, after) {
			return fail("tree_changed")
		}
		return nil
	}
	if e = walk(".", 0); e != nil {
		return result, e
	}
	after, e := base.Lstat(key)
	if e != nil {
		return result, e
	}
	if ident(after) != result.Identity {
		return result, fail("tree_replaced")
	}
	result.Digest = hex.EncodeToString(h.Sum(nil))
	return result, nil
}
func diskFree(home string) (uint64, error) {
	var s syscall.Statfs_t
	e := syscall.Statfs(home, &s)
	return s.Bavail * uint64(s.Bsize), e
}
func safeReason(e error) string {
	if v, ok := e.(Refused); ok {
		return string(v)
	}
	return "system_operation_failed"
}
func Print(v any) {
	b, e := json.Marshal(v)
	if e != nil {
		fmt.Println(`{"ok":false,"reason":"encoding_failed"}`)
		return
	}
	fmt.Println(string(b))
}

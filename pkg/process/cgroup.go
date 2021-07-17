package process

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	multierror "github.com/hashicorp/go-multierror"
)

const (
	procsFile = "cgroup.procs"
)

type Cgroup struct {
	rootPID int
	id      string
	rootDir string
	dirs    map[string]string
}

type CgroupOptions struct {
	Limits  ResourceLimits
	RootPID int
	RootDir string // likely to be /sys/fs/cgroup
}

// NewCgroup creates a new collection of cgroups (cpu, memory, blkio)
// rooted at the argument RootDir. It adds the argument RootPID to
// each of these cgroups and applies the limits specified in the
// argument Limits. If the function returns a nil error, then the
// caller is responsible for calling Cleanup() on the returned Cgroup.
//
// Notes:
// - only cgroups v1 are supported
func NewCgroup(opts CgroupOptions) (*Cgroup, error) {
	if opts.RootPID == 0 {
		return nil, fmt.Errorf("must specify non-zero root PID")
	} else if opts.RootDir == "" {
		return nil, fmt.Errorf("must specify non-empty cgroup root dir")
	}

	id := uuid.New()
	cg := &Cgroup{
		rootPID: opts.RootPID,
		id:      id.String(),
		rootDir: opts.RootDir,
		dirs:    make(map[string]string),
	}

	if err := cg.setup(opts); err != nil {
		if cleanupErr := cg.Cleanup(); cleanupErr != nil {
			err = multierror.Append(err, cleanupErr)
		}
		return nil, err
	}
	return cg, nil
}

// Cleanup removes the root PID from the managed cgroups and cleans up
// any allocated resources. You must call Cleanup() when you are done
// with a Cgroup returned by NewCgroup.
func (c *Cgroup) Cleanup() error {
	var result error
	if err := c.leave(); err != nil {
		result = multierror.Append(result, err)
	}
	if err := c.removeDirs(); err != nil {
		result = multierror.Append(result, err)
	}
	return result
}

// setup performs the initial setup of the cgroup, creating directories
// and applying limits as necessary.
func (c *Cgroup) setup(opts CgroupOptions) error {
	if err := c.createDirs(); err != nil {
		return err
	}

	if err := c.join(); err != nil {
		return err
	}

	if err := c.setLimits(opts.Limits); err != nil {
		return err
	}
	return nil
}

// managed returns a list of the cgroups that are managed by this type
func (c *Cgroup) managed() []string {
	return []string{"memory", "cpu", "blkio"}
}

// setLimits sets the limits described in the argument ResourceLimits
// for the managed cgroups. Note that, if cgroup directories have not
// been created, an error will be returned.
func (c *Cgroup) setLimits(limits ResourceLimits) error {
	setFuncs := map[string]func(string) error{
		"memory": limits.setMemory,
		"cpu":    limits.setCPU,
		"blkio":  limits.setDisk,
	}

	for key, f := range setFuncs {
		dir, ok := c.dirs[key]
		if !ok {
			return fmt.Errorf("cgroup for %v has not been created", key)
		}
		if err := f(dir); err != nil {
			return err
		}
	}
	return nil
}

// join places c.rootPID into the managed cgroups.
func (c *Cgroup) join() error {
	return c.setProcs(c.id)
}

// leave places c.rootPID into the root cgroup.
func (c *Cgroup) leave() error {
	return c.setProcs("")
}

// setProcs adds the root PID to the procs file for each managed cgroup,
// appending the additional component in `suffix` to the path.
func (c *Cgroup) setProcs(suffix string) error {
	var result error
	for _, group := range c.managed() {
		file := filepath.Join(c.rootDir, group, suffix)
		if err := c.setProc(file); err != nil {
			result = multierror.Append(result, err)
		}
	}
	return result
}

// setProc adds the cgroup root PID to the procs file (i.e. cgroup.procs)
// in the argument directory.
func (c *Cgroup) setProc(dir string) error {
	return setCgroupValue(filepath.Join(dir, procsFile), c.rootPID)
}

// removeDirs removes the cgroup directories for the managed cgroups.
// Note that the managed cgroups cannot contain any processes, so you
// should call leave() first.
func (c *Cgroup) removeDirs() error {
	var result error
	for key, dir := range c.dirs {
		if err := os.RemoveAll(dir); err != nil {
			result = multierror.Append(result, err)
		} else {
			delete(c.dirs, key)
		}
	}
	return result
}

// createDirs creates the cgroup directories for the managed cgroups
func (c *Cgroup) createDirs() error {
	for _, dir := range c.managed() {
		cgDir := filepath.Join(c.rootDir, dir, c.id)
		if err := os.MkdirAll(cgDir, 0755); err != nil {
			return err
		}
		c.dirs[dir] = cgDir
	}
	return nil
}

// setCgroupValue writes the argument value to the argument file
func setCgroupValue(file string, value interface{}) error {
	return ioutil.WriteFile(file, []byte(fmt.Sprintf("%v", value)), 0755)
}

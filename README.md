# containers-lite
Lightweight containers implementation for educational purposes. See [DESIGN.md](DESIGN.md)

## tests
Note that tests must be run from within a containerized environment. To
run the tests, simply type `make run` with `docker` and `make` installed.

There are a few test options exposed via the `Makefile`, namely `TEST_DISK`
and `TEST_CGROUP_ROOT`, which refer to the block device to which cgroup disk
read and write limits will be applied, and the root directory under which
cgroups will be created. By default, these values are `sda` and
/sys/fs/cgroup`, respectively. There are no tests depending on the cgroup
configuration, so any values will work here so long as they refer to an
actual block device and cgroup root directory.

# containers-lite
Lightweight containers implementation for educational purposes. See [DESIGN.md](DESIGN.md)


## build and run
Run `make` (or `make client` and `make server`) to build the client and server;
the binaries are output to the `bin` directory. Both the client and server require
quite a few options, and at this time, they must be specified for each invocation
as command line flags. To simplify this, there are TLS materials located in
the `test/tls` directory and a script `environment` to source.

Note that the `environment` file assumes you wish to limit the speed of the
disk `sda` and configure cgroups under `/sys/fs/cgroup`.

To start the server, just `source environment` then run `server`.
```bash
$ source environment
$ server
```

For the client, do the same, but use `client` instead of `server`.
```bash
$ source environment
$ client create -- /bin/bash -c 'for i in $(seq 1 3); do echo test; sleep 1; done;'
ea2cf9b6-daaf-43af-a0cb-24dd81f4da3f
$ client output ea2cf9b6-daaf-43af-a0cb-24dd81f4da3f
test
test
test
```

Use the `--help` flag to see client options. For example, the client can
control the disk write speed by passing `--disk-write <mbps>` to the client.
See `client create --help` for more details.
```bash
$ source environment
$ time client output --stream $(client create --memory 512 --disk-write 8 -- /usr/bin/dd if=/dev/zero of=/tmp/myfile bs=64M count=1 oflag=direct)

real	0m8.616s
user	0m0.051s
sys	0m0.008s
```

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

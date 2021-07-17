# containers-lite design

## Worker library
The worker library will comprise 2 parts: a `Process` type and a process
shim. The shim is necessary for the purpose of isolation and resource
control: since go handles fork and exec in a single call, it is not
feasible to set up cgroups and namespaces between the two syscalls as
is the typical method. In order to work around this, we launch a shim
process in the target namespaces whose responsibility is to set up
the namespaces and add itself to the target cgroups before launching
the actual intended process. This is nothing new and is seen in
(to my knowledge) all golang-based container implementations.

The server process will re-execute itself as the shim by launching
`/proc/self/exe` with `os.Args` set in such a way as to allow us to detect
that this has happened and redirect control to a function other than main.
This essentially creates a multi-call binary and spares us the difficulties
of managing multiple binaries.

### Shim process
In order to keep it simple, the interface between the `Process` type
and the shim layer will use JSON: the shim will be launched with `os.Args[1]`
equal to the serialization of a JSON object containing the run specification,
which is detailed below.

```go
type ProcessSpec struct {
     // The path to the file to launch
     Command    string   `json:"command"`
     // The arguments to pass to the process
     Args       []string `json:"args"`
     // Resource limits to set on cgroup
     Limits     ResourceLimits `json:"limits"`
     // Write stdout to this file
     OutputFile string   `json:"stdout_file"`
     // Write stderr to this file
     ErrorFile  string   `json:"stderr_file"`
}

type ResourceLimits struct {
    // Maximum memory in mebibytes
    MemoryInMiB int `json:"memory_in_mib"`
    // Maximum number of CPU millicores (reservation)
    // 1000 millicores = 1 CPU core
    CPUMillicores int `json:"cpu_millicores"`
    // Maximum disk read speed in megabytes per second
    DiskReadMBPS int `json:"disk_read_mbps"`
    // Maximum disk write speed in megabytes per second
    DiskWriteMBPS int `json:"disk_write_mbps"`
}
```

The shim process will create cgroups for `memory`, `cpu`, and `blkio`,
setting their limits as described in the provided `ResourceLimits`,
and add its own PID as the root before launching the actual process.
After the process returns, the cgroup will be cleaned up by the shim.

### `Process` type
The `Process` type will implement the main functionality described in
the requirements doc. In order to create a new process, the caller
must supply a launch configuration, which is detailed below.

```go
type LaunchConfiguration struct {
     Command       string
     Args          []string
     Limits        ResourceLimits
}
```

The `Process` type will create and manage temporary files to capture
the `stdout` and `stderr` of the process, and then create and launch
the shim process with the appropriate inputs, setting up namespaces
as necessary in order to satisfy the isolation requirements.

The `Process` type will have the following public functions.
```go
func New(config LaunchConfiguration) (*Process, error)
func (p *Process) Cleanup() error
func (p *Process) Stop() error
func (p* Process) Status() ProcessStatus
func (p *Process) Stdout(bool) (io.ReadCloser, error)
func (p *Process) Stderr(bool) (io.ReadCloser, error)

const (
      StateStarted ProcessState = iota
      // StateStopped means stopped by the user
      StateStopped ProcessState = iota
      // StateExited means exited of its own accord
      StateExited  ProcessState = iota
)

type ProcessStatus struct {
     State    ProcessState
     ExitCode int
     ExitErr  error
}
```

Output handling will be by opening the respective file. For streaming
output, there will be a small type implementing `io.ReadCloser` that
blocks while waiting for additional bytes to be written to the file.

### Resource control
Resource control will be provided by cgroups. As mentioned above, the
shim  will create cgroups for `memory`, `cpu`, and `blkio` with
a common name. It will additionally set the necessary values to enforce
the limits specified in the `Limits` section of the `LaunchConfiguration`.
The shim process will add its own PID to each of the cgroups so that the
limits apply to its children. On return, the shim will clean up
the cgroup directories.

To be specific, the following fields will be used to enforce resource
control.
* `/sys/fs/cgroup/memory/<cgid>/memory.limit_in_bytes`: `memory MiB * (1024^2)`
* `/sys/fs/cgroup/cpu/<cgid>/cpu.cfs_period_us`: `1000000`
* `/sys/fs/cgroup/cpu/<cgid>/cpu.cfs_quota_us`: `millicores * 1000`
* `/sys/fs/cgroup/blkid/<cgid>/blkio.throttle.read_bps_device`: `major:minor read limit * (1000^2)`
* `/sys/fs/cgroup/blkid/<cgid>/blkio.throttle.write_bps_device`: `major:minor write limit * (1000^2)`

The block device to limit will be specified on the server side as a
configuration option (command line argument, for now), and the `major:minor`
will be determined by reading `/sys/block/<dev>/dev`.

Note that only cgroups v1 will be supported.

### Isolation
Isolation will be provided by way of namespaces. The shim process will
be launched with `CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET`.

Note that the network namespace will contain only a loopback device. There
will be no network connectivity for processes launched using the `Process`
type. Network connectivity could be provided by creating a bridge in the
root network namespace, ensuring IP forwarding and masquerading are enabled,
and using a veth pair, with one end in the bridge and the other in the
process network namespace. The implementation will be omitted for brevity.

## API
The API will be defined in a ` .proto` file. The following is the proposed
API.
```protobuf
syntax = "proto3";

import "google/protobuf/empty.proto";

message ResourceLimits {
  uint32 memory_in_mib = 1;
  uint32 cpu_millicores = 2;
  uint32 disk_read_mbps = 3;
  uint32 disk_write_mbps = 4;
}

message LaunchConfiguration {
  string command = 1;
  repeated string args = 2;
  ResourceLimits limits = 3;
}

message OutputRequest {
  ProcessHandle id = 1;
  bool stream = 2;
}

message ProcessStatus {
  enum State {
    STARTED = 0;
    STOPPED = 1;
    EXITED = 2;
  }
  State state = 1;
  int32 exit_code = 2;
  string exit_error = 3;
}

message ProcessHandle {
  string value = 1;
}

message ProcessOutput {
  bytes value = 1;
}

service WorkerService {
  // Create the process without launching - returns a handle
  rpc Create(LaunchConfiguration) returns (ProcessHandle) {}
  rpc Stop(ProcessHandle) returns (google.protobuf.Empty) {}
  rpc Status(ProcessHandle) returns (ProcessStatus) {}
  // Output and Error return the stream of bytes written to, respectively,
  // stdout and stderr, by the process. If request.stream is set to true,
  // then the RPC will continue streaming output until the process exits.
  rpc Output(OutputRequest) returns (stream ProcessOutput) {}
  rpc Error(OutputRequest) returns (stream ProcessOutput) {}
}
```

## Security
### Authentication
Authentication will be provided by way of mTLS. The client and server will
accept the path to a CA certificate as an argument in addition to an X.509
keypair. The respective keypairs will be used to secure the connection, and
signatures will be verified with respect to the argument CA certificate.

### Authorization
The authorization scheme will be implemented as a map from common name
to a collection of allowed endpoints. In gRPC, the endpoints are described
by a `FullMethod` string on the server info structure which is presented to
request interceptors. The interceptors will extract the common name from
the client certificate and use this to look up the allowed endpoints; if
the allowed endpoints contain the `FullMethod`, then the request will
be authorized.

The server will accept an argument specifying the common name of the
administrator's certificate; the server will authorize all requests for
all endpoints with the specified common name in the client certificate.

As an example, suppose the server is configured to trust the common
name `client.internal`. The authorizer would be configured with the
the following map.

```go
authorizer := NewInterceptor(InterceptorOptions{
    Permissions: map[string][]string{
        "client.internal": []string{
            "/WorkerService/Create",
            "/WorkerService/Stop",
            "/WorkerService/Status",
            "/WorkerService/Output",
            "/WorkerService/Error",
        },
    },
})
```

The authorizer would have two methods `Unary()` and `Stream()` returning
`grpc.UnaryServerInterceptor` and `grpc.StreamServerInterceptor`, respectively.
Using the `google.golang.org/grpc/peer` package, we can extract the
`google.golang.org/grpc/credentials.TLSInfo` which contains the peer's
certificate; the common name contained therein would be used to look up
the permissions and determine if the `FullMethod` is contained in the
corresponding list.

### TLS Configuration
The assignment asks for a secure TLS configuration. The relevant part
of the `tls.Config` is reproduced below. This configuration achieves
a near-perfect score when tested by ssllabs.com, with some compatibility
tests failing, and session resumption not being supported.

```go
tlsConfig := &tls.Config{
            MinVersion:	              tls.VersionTLS13,
            CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
            PreferServerCipherSuites: true,
}
```

## Server
The server will keep a collection of processes that it is currently
managing, which can be manipulated by the API. This collection will
be kept in memory for the prototype, but a more robust solution would
be to store details of the processes in a database. This would also
require a greater degree of communication between the shim process
and the server process, since the server would need to be able to
regain control of the shim after restarting.

## Client
The client will be a thin wrapper around the generated gRPC client. It
will be implemented using the `github.com/spf13/cobra` library, with one
subcommand for each method in the service defined in the protobuf API.

### CLI UX
The following example outlines the intended CLI experience. Note that there
will be more arguments to the client in order to describe the connection
parameters: host and port, CA certificate path, client certificate and key
paths, and the server certificate common name. The certificate common
name is useful in testing since it allows the target hostname to differ
from the common name presented by the server, but it would be wise to hide
this flag from users in production.

In the longer term, it would make sense to make many of these parameters
part of a configuration file, rather than requiring them to be specified
on the command line.

```
$ client create -- /bin/ls -l /proc/self/ns
ec3f6a6f-23d9-4677-95e8-8a9b348fdb82
$ client start ec3f6a6f-23d9-4677-95e8-8a9b348fdb82
$ client status ec3f6a6f-23d9-4677-95e8-8a9b348fdb82
Status for process ec3f6a6f-23d9-4677-95e8-8a9b348fdb82: EXITED
Exit code: 0; Error message:
$ client output --stream ec3f6a6f-23d9-4677-95e8-8a9b348fdb82
total 0
lrwxrwxrwx    1 root     root             0 Jun 30 14:22 cgroup -> cgroup:[4026531835]
lrwxrwxrwx    1 root     root             0 Jun 30 14:22 ipc -> ipc:[4026531839]
lrwxrwxrwx    1 root     root             0 Jun 30 14:22 mnt -> mnt:[4026532329]
lrwxrwxrwx    1 root     root             0 Jun 30 14:22 net -> net:[4026532332]
lrwxrwxrwx    1 root     root             0 Jun 30 14:22 pid -> pid:[4026532330]
lrwxrwxrwx    1 root     root             0 Jun 30 14:22 pid_for_children -> pid:[4026532330]
lrwxrwxrwx    1 root     root             0 Jun 30 14:22 user -> user:[4026532328]
lrwxrwxrwx    1 root     root             0 Jun 30 14:22 uts -> uts:[4026531838]
$ client error ec3f6a6f-23d9-4677-95e8-8a9b348fdb82
$ client stop ec3f6a6f-23d9-4677-95e8-8a9b348fdb82
Error: process already finished
$ client delete ec3f6a6f-23d9-4677-95e8-8a9b348fdb82
```
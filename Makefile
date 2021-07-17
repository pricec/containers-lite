MKFILE_DIR := $(abspath $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST))))))

TEST_DISK ?= sda
TEST_CGROUP_ROOT ?= /sys/fs/cgroup

PROTO_FILE := pb/api.proto
PROTOBUF_DEF := $(MKFILE_DIR)/$(PROTO_FILE)
PROTOBUF_DEP := $(MKFILE_DIR)/pb/api_grpc.pb.go $(MKFILE_DIR)/pb/api.pb.go

MOD_PATH := github.com/pricec/containers-lite

GO_IMAGE     := golang:1.16.5
PROTOC_IMAGE := takumakei/protoc-gen-go-grpc

DOCKER_FLAGS  := -v $(MKFILE_DIR):/go/$(MOD_PATH) -w /go/$(MOD_PATH) --rm -it
PROTOC_FLAGS  := $(DOCKER_FLAGS)
GO_TEST_FLAGS := $(DOCKER_FLAGS) -e TEST_DISK="$(TEST_DISK)" -e TEST_CGROUP_ROOT="$(TEST_CGROUP_ROOT)" --privileged

GO_TEST := docker run $(GO_TEST_FLAGS) $(GO_IMAGE) go test
PROTOC  := docker run $(PROTOC_FLAGS) $(PROTOC_IMAGE)

.PHONY: test
test: protobuf
	$(GO_TEST) -race -cover $(MOD_PATH)/...

protobuf: $(PROTOBUF_DEP)
$(PROTOBUF_DEP): $(PROTOBUF_DEF)
	$(PROTOC) \
		--go_out=. \
		--go_opt=paths=source_relative \
		--go-grpc_out=. \
		--go-grpc_opt=paths=source_relative \
		$(PROTO_FILE)

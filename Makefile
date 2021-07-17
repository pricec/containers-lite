MKFILE_DIR := $(abspath $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST))))))

TEST_DISK ?= sda
TEST_CGROUP_ROOT ?= /sys/fs/cgroup

MOD_PATH := github.com/pricec/containers-lite

GO_IMAGE     := golang:1.16.5

DOCKER_FLAGS  := -v $(MKFILE_DIR):/go/$(MOD_PATH) -w /go/$(MOD_PATH) --rm -it
GO_TEST_FLAGS := $(DOCKER_FLAGS) -e TEST_DISK="$(TEST_DISK)" -e TEST_CGROUP_ROOT="$(TEST_CGROUP_ROOT)" --privileged

GO_TEST := docker run $(GO_TEST_FLAGS) $(GO_IMAGE) go test

.PHONY: test
test:
	$(GO_TEST) -race -cover $(MOD_PATH)/...

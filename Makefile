# chroot-ng — ptrace-free chroot/bind emulation for rootless Android (AArch64)
#
# Cross-compiled with the aarch64-linux-gnu toolchain and exercised under
# qemu-aarch64.  See docs/DESIGN.md for the architecture and docs/STATUS.md
# for the milestone roadmap.

CROSS   ?= aarch64-linux-gnu-
# CC has a built-in default of `cc`, so ?= won't override it. When CC is still
# the make default, prefer the cross toolchain if present, otherwise keep the
# native compiler (e.g. Termux/NDK clang building on-device). Command-line/env
# CC always wins.
ifeq ($(origin CC),default)
ifneq ($(shell command -v $(CROSS)gcc-13 2>/dev/null),)
CC      := $(CROSS)gcc-13
else ifneq ($(shell command -v $(CROSS)gcc 2>/dev/null),)
CC      := $(CROSS)gcc
endif
endif
OBJCOPY ?= $(CROSS)objcopy
QEMU    ?= qemu-aarch64-static
BUILD   ?= build

# Is the compiler clang (Termux/NDK) rather than gcc? Some flags are gcc-only.
CC_IS_CLANG := $(shell $(CC) --version 2>/dev/null | grep -ci clang)

# Freestanding: no libc, no PIE, our own _start.
CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -ffreestanding -nostdlib -static -fno-pie -no-pie \
           -fno-stack-protector \
           -fno-asynchronous-unwind-tables -fno-builtin \
           -ffunction-sections -fdata-sections \
           -Wall -Wextra -Wno-unused-parameter -Iinclude
# Stop gcc turning our mem* loops into calls to themselves. Clang rejects this
# flag and instead honors -ffreestanding/-fno-builtin for the same effect.
ifeq ($(CC_IS_CLANG),0)
CFLAGS  += -fno-tree-loop-distribute-patterns
endif
LDFLAGS ?=
LDFLAGS += -static -nostdlib -no-pie -Wl,--build-id=none -Wl,-z,noexecstack \
           -Wl,--gc-sections -Wl,-e,_start

CSRC := $(shell find src -name '*.c' 2>/dev/null)
ASRC := $(shell find src -name '*.S' 2>/dev/null)
OBJ  := $(patsubst %,$(BUILD)/%.o,$(CSRC) $(ASRC))
DEP  := $(OBJ:.o=.d)

BIN  := $(BUILD)/chroot-ng

.PHONY: all clean run test probe
all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ)
	@echo "built $@"

$(BUILD)/%.c.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILD)/%.S.o: %.S
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Run the tool itself under the emulator: `make run ARGS="version"`
run: $(BIN)
	$(QEMU) $(BIN) $(ARGS)

test: $(BIN)
	@sh tests/run.sh

clean:
	rm -rf $(BUILD)

-include $(DEP)

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
BUILD   ?= build

# How to run an AArch64 binary here. On an AArch64 host (native Linux or Termux)
# that is "directly", so QEMU stays EMPTY and `$(QEMU) $(BIN)` is just $(BIN);
# elsewhere pick whichever qemu-user build is installed. tests/lib.sh does the
# same detection for the suite, so `make test` needs nothing passed down.
HOST_ARCH := $(shell uname -m)
ifeq ($(filter aarch64 arm64,$(HOST_ARCH)),)
QEMU    ?= $(shell command -v qemu-aarch64-static 2>/dev/null \
             || command -v qemu-aarch64 2>/dev/null || echo qemu-aarch64-static)
else
QEMU    ?=
endif

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
# GCC 13+ defaults to -moutline-atomics, which routes every __atomic builtin
# through a libgcc helper (__aarch64_cas4_acq_rel) that a -nostdlib link has no
# way to resolve. The PID registry uses CAS, so ask for inline atomics — the
# LL/SC form works on every ARMv8. Probed, since not every compiler has it.
CFLAGS  += $(shell $(CC) -mno-outline-atomics -E -x c /dev/null >/dev/null 2>&1 \
             && echo -mno-outline-atomics)
# Link chroot-ng far above the guest ET_EXEC range via an explicit linker script
# (scripts/chroot-ng.ld). A non-PIE guest (notably gcc's cc1) loads at the fixed
# address 0x400000 — where a -no-pie executable also defaults to — so if
# chroot-ng lived there, MAP_FIXED-loading such a guest would overwrite our own
# monitor code. The script sets the location counter to 0x1000000000 (64 GiB) so
# the first segment *starts* there; the -T*/--image-base flags don't relocate a
# -no-pie binary cleanly on lld (they pad a segment up from 0x200000 instead).
LDFLAGS ?=
LDFLAGS += -static -nostdlib -no-pie -Wl,-T,scripts/chroot-ng.ld \
           -Wl,--build-id=none -Wl,-z,noexecstack \
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

# Run the tool itself, natively or under the emulator: `make run ARGS="--version"`
run: $(BIN)
	$(QEMU) $(BIN) $(ARGS)

# Capability probe (a real AArch64 kernel is needed for the seccomp line, so on
# a cross host under qemu that line always reads "inert").
probe: $(BIN)
	$(QEMU) $(BIN) --probe

test: $(BIN)
	@sh tests/run.sh

clean:
	rm -rf $(BUILD)

-include $(DEP)

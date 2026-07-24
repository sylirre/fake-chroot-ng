# chroot-ng — ptrace-free chroot/bind emulation for rootless Android (AArch64)
#
# Cross-compiled with the aarch64-linux-gnu toolchain and exercised under
# qemu-aarch64.  See docs/DESIGN.md for the architecture and docs/STATUS.md
# for the milestone roadmap.

CROSS   ?= aarch64-linux-gnu-
# CC has a built-in default of `cc`, so ?= won't override it. Only set our
# cross-compiler when CC is still the make default; keep command-line/env wins.
ifeq ($(origin CC),default)
CC      := $(CROSS)gcc-13
endif
OBJCOPY ?= $(CROSS)objcopy
QEMU    ?= qemu-aarch64-static
BUILD   ?= build

# Freestanding: no libc, no PIE, our own _start. -fno-tree-loop-distribute-
# patterns stops gcc from turning our mem* loops into calls to themselves.
CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -ffreestanding -nostdlib -static -fno-pie -no-pie \
           -fno-stack-protector -fno-tree-loop-distribute-patterns \
           -fno-asynchronous-unwind-tables -fno-builtin \
           -ffunction-sections -fdata-sections \
           -Wall -Wextra -Wno-unused-parameter -Iinclude
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

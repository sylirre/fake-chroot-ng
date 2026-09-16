/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* PTRACE_SINGLESTEP, in software.
 *
 * Hardware single-step on AArch64 is PSTATE.SS plus MDSCR_EL1.SS, and the only
 * way to arm it from userspace is the kernel's own ptrace — which is exactly
 * what we do not have here. So a step is emulated the way a debugger without
 * hardware support does it: decode the instruction the tracee is about to
 * execute, work out where control goes next, plant a breakpoint there, and let
 * it run to it.
 *
 * The decode has to be exact for anything that can change PC — a missed branch
 * means the breakpoint is never reached and the "stepped" tracee runs away —
 * but it only has to cover *branches*: every other instruction advances by 4.
 * Conditions are evaluated against the frame's own PSTATE, and register-form
 * branches against its registers, so exactly one next PC is planted rather than
 * a breakpoint on each side.
 *
 * The breakpoint uses a distinctive immediate so that a SIGTRAP arriving at
 * that address can be told from one the tracer poked itself (a gdb breakpoint
 * is `brk #0`), and it is removed before any stop is published, so a tracer
 * that reads the text back never sees it.
 */
#include "cng/monitor.h"
#include "cng/ptrace.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#define PT_STEP_BRK 0xD420FFE0u /* brk #0x7ff */

/* The step in flight is per task (cng_pt_step_self): it used to be one
 * process-global record, so two traced threads stepped at once overwrote each
 * other's — the second plant lost the first's original word, the first's
 * breakpoint was then reported as a guest SIGTRAP at an address the tracer
 * had never poked, and the `brk` stayed in the text for good. */

static u64 sext(u64 v, int bits) {
    u64 m = 1ULL << (bits - 1);
    return (v ^ m) - m;
}

/* Evaluate an AArch64 condition code against NZCV. */
static int cond_holds(unsigned cond, u64 pstate) {
    int n = (int)((pstate >> 31) & 1), z = (int)((pstate >> 30) & 1);
    int c = (int)((pstate >> 29) & 1), v = (int)((pstate >> 28) & 1);
    int r;
    switch (cond >> 1) {
    case 0: r = z; break;                    /* EQ / NE */
    case 1: r = c; break;                    /* CS / CC */
    case 2: r = n; break;                    /* MI / PL */
    case 3: r = v; break;                    /* VS / VC */
    case 4: r = c && !z; break;              /* HI / LS */
    case 5: r = (n == v); break;             /* GE / LT */
    case 6: r = (z == 0) && (n == v); break; /* GT / LE */
    default: r = 1; break;                   /* AL / NV */
    }
    if ((cond & 1) && cond != 0xf)
        r = !r;
    return r;
}

/* Register value as a branch reads it: x31 in these encodings is xzr. */
static u64 reg(const struct cng_uregs *r, unsigned n) {
    return n == 31 ? 0 : r->x[n];
}

u64 cng_pt_next_pc(const struct cng_uregs *r) {
    u64 pc = r->pc;
    u32 insn;
    if (cng_user_copyin(&insn, (const void *)pc, sizeof insn) < 0)
        return 0;

    /* B / BL: imm26 << 2 from PC. */
    if ((insn & 0xFC000000u) == 0x14000000u ||
        (insn & 0xFC000000u) == 0x94000000u)
        return pc + sext(insn & 0x03FFFFFFu, 26) * 4;

    /* B.cond (and BC.cond, which differs only in bit 4). */
    if ((insn & 0xFF000000u) == 0x54000000u) {
        if (!cond_holds(insn & 0xf, r->pstate))
            return pc + 4;
        return pc + sext((insn >> 5) & 0x7FFFFu, 19) * 4;
    }

    /* CBZ / CBNZ. */
    if ((insn & 0x7E000000u) == 0x34000000u) {
        u64 v = reg(r, insn & 31);
        if (!(insn & 0x80000000u))
            v = (u32)v; /* 32-bit form tests Wt */
        int taken = (insn & 0x01000000u) ? (v != 0) : (v == 0);
        if (!taken)
            return pc + 4;
        return pc + sext((insn >> 5) & 0x7FFFFu, 19) * 4;
    }

    /* TBZ / TBNZ. */
    if ((insn & 0x7E000000u) == 0x36000000u) {
        unsigned bit = (unsigned)(((insn >> 26) & 0x20) | ((insn >> 19) & 0x1f));
        u64 v = reg(r, insn & 31);
        int set = (int)((v >> bit) & 1);
        int taken = (insn & 0x01000000u) ? set : !set;
        if (!taken)
            return pc + 4;
        return pc + sext((insn >> 5) & 0x3FFFu, 14) * 4;
    }

    /* BR / BLR / RET (unauthenticated forms; the pointer-auth variants are not
     * decoded — a step over one falls back to "cannot step"). */
    if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u ||
        (insn & 0xFFFFFC1Fu) == 0xD63F0000u ||
        (insn & 0xFFFFFC1Fu) == 0xD65F0000u)
        return reg(r, (insn >> 5) & 31);
    if ((insn & 0xFE000000u) == 0xD6000000u && (insn & 0x001F0000u) != 0)
        return 0; /* other branch-register forms (BRAA/ERET/...): undecoded */

    /* Everything else — including SVC, whose stop is reported by the syscall
     * path rather than by a breakpoint — falls through. */
    return pc + 4;
}

/* Two threads stepped through the same instruction want the same word
 * planted. The second finds a `brk` of ours there already, and takes the
 * original from the sibling's record rather than refusing: both records are
 * then live on the address, each thread's own hit is its own, and the word
 * goes back only when the last of them is unplanted (step_unplant). A `brk`
 * of ours that no live sibling accounts for is a stale one and is refused,
 * since the original is not to be had. */
int cng_pt_step_plant(struct cng_uregs *r) {
    struct cng_pt_step *st = cng_pt_step_self(1);
    if (!st)
        return -1;
    cng_pt_step_clear();
    u64 next = cng_pt_next_pc(r);
    if (!next)
        return -1;
    for (int spin = 0;; spin++) {
        u32 word;
        if (cng_user_copyin(&word, (const void *)next, sizeof word) < 0)
            return -1;
        if (word != PT_STEP_BRK) {
            st->orig = word;
            st->addr = next;
            u32 brk = PT_STEP_BRK;
            if (cng_pt_poke_text(next, &brk, 4) < 0)
                return -1;
            __atomic_store_n(&st->live, 1, __ATOMIC_RELEASE);
            return 0;
        }
        u32 orig;
        if (!cng_pt_step_shared(next, &orig)) {
            /* A `brk` of ours that no live record accounts for is either a
             * sibling's in the act of being taken down — its record is
             * already gone and the word is about to follow — or a stale one.
             * The first resolves in a moment; the second never does, and is
             * refused rather than have the original guessed at. */
            if (spin < 1000) {
                CNG_SYS(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
                continue;
            }
            return -1;
        }
        st->orig = orig;
        st->addr = next;
        __atomic_store_n(&st->live, 1, __ATOMIC_RELEASE);
        /* The sibling can have taken the word back between the copy and the
         * publication above; ours is live now, so plant it again if so. */
        if (cng_user_copyin(&word, (const void *)next, sizeof word) < 0)
            return -1;
        if (word != PT_STEP_BRK) {
            u32 brk = PT_STEP_BRK;
            if (cng_pt_poke_text(next, &brk, 4) < 0)
                return -1;
        }
        return 0;
    }
}

/* Take this task's record down and, when no sibling's live record still
 * stands on the address, the word with it. Two tasks unplanting the same
 * address at once each restore the same original, which is harmless. */
static void step_unplant(struct cng_pt_step *st) {
    if (!__atomic_load_n(&st->live, __ATOMIC_ACQUIRE))
        return;
    u64 addr = st->addr;
    u32 orig = st->orig;
    __atomic_store_n(&st->live, 0, __ATOMIC_RELEASE);
    if (!cng_pt_step_shared(addr, 0))
        cng_pt_poke_text(addr, &orig, 4);
    st->addr = 0;
}

void cng_pt_step_clear(void) {
    struct cng_pt_step *st = cng_pt_step_self(0);
    if (st)
        step_unplant(st);
}

int cng_pt_step_hit(u64 pc) {
    struct cng_pt_step *st = cng_pt_step_self(0);
    return st && __atomic_load_n(&st->live, __ATOMIC_ACQUIRE) && pc == st->addr;
}

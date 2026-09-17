/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* include/cng/unistd.h, checked against the build host's own table.
 *
 * The binary takes its syscall numbers from our header alone (see the note
 * there), so nothing else in the tree includes <asm/unistd.h>. This unit
 * includes both, and only where the host has one to offer: every number the two
 * agree on is a silent identical redefinition, and a number they disagree on is
 * a "macro redefined" diagnostic naming it — which the Makefile turns into an
 * error for this one file. A host whose headers stop short of ours says nothing,
 * which is right: that is exactly the host our own table exists for. Compiles
 * to nothing.
 */
#if defined(__has_include)
#if __has_include(<asm/unistd.h>)
#include <asm/unistd.h>
#endif
#endif
#include "cng/unistd.h"

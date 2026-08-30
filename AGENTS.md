# Chroot-NG

Guidelines for AI agents when working with this codebase.

## Overview

Emulator for chroot and `mount --bind` for AArch64 devices, similar to proot but ptrace-free.

Target platforms are regular Linux distributions (Musl, GNU libc) and Android OS (Bionic, restricted by SELinux and seccomp).

## Conventions and rules

General:

* Be thorough in reasoning and concise in output.
* Do not re-read files unless they were changed.
* Do not switch branches, do not look up changes on other branches unless explicitly were asked for this.
* Think about best approach when implementing a requested feature. Ask clarifying questions before making architectural changes and propose solution variants, especially if there are caveats and unintended side effects of requested changes.
* New command line options and environment variables must be added into utility built-in help information.
* Ensure that code comments are up-to-date after made changes.
* Compiler warnings or errors must be resolved.
* Do not give up chasing bugs. You know the code better than anyone.
* Run test suite after finishing changes.
* Never make a failing test pass by weakening it. Investigate the root cause of test failure. If the test indeed faulty, ask the project owner first before making changes.
* If all tests passed and there are no already staged files, commit your changes to current branch.
* Never run `git push`.

Commit messages:

* Each commit must consist of header and description.
* The header must follow this format: `scope: brief description of change`.
* The commit body must be detailed and explain why change was necessary, what was the story behind it. If that's a new feature, explain what it does. If that's a bugfix, explain what was the bug and how it was fixed.
* Wrap each line of the commit body at 72 characters.
* Add `Co-Authored-By` footer with explanation who you are.
* It is forbidden to include `Claude-Session` reference in the commit message.

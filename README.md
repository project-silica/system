# system

Silica's core userspace: what runs between the kernel and everything else.

| Crate | What it is |
| --- | --- |
| `rt` (`silica-rt`) | The native runtime every program links: the start-up record, program entry and exit, the debug console, panics. |
| `proc` (`silica-proc`) | Starting a program: from an ELF image and a memory budget to a running thread in its own address space and CapSpace, holding exactly the capabilities it was granted. |
| `init` | The root task: takes what the kernel hands over and starts the system from the ramdisk. |
| `hello` | The smallest program, started by `init` in the M2 bring-up test. |

A program's whole world is its CapSpace. `silica_rt::slots` says what a new
program finds in it; everything else it was explicitly granted.

Built for the Silica target by `tools/` in the workshop (`./tools/boot.sh
--system`). Depends on the kernel repository's `libsys` and `silica-formats`
by path: the workshop layout is the build layout.

License: MIT OR Apache-2.0.

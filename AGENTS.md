# AGENTS.md

SRv6 (Segment Routing over IPv6) netgraph node implemented as an out-of-tree
FreeBSD kernel module. Builds only on FreeBSD against a kernel source tree;
`SYSDIR` defaults to `/usr/src/sys` (`/usr/src` is a symlink to
`/home/src/freebsd-src` on this host).

## Hard rule

**DO NOT LOAD THE FUCKING KERNEL MODULE.**

Do not run `make load`, `make unload`, `make reload`, `kldload`, `kldunload`,
or `ngctl` against this module unless the user explicitly asks. Build and
inspect only. Loading a broken kernel module can panic or destabilize the host.
Passwordless `sudo` being available is not permission to load it.

## Project goals

- Finish the driver: control plane, data path, and real tests.
- Reference material: `doc/rfc8754.txt` (SRH), `doc/rfc8986.txt` (endpoint
  behaviors), `doc/rfc9602.txt` (SID addressing), `doc/rfc9800.txt`
  (compressed SID), and `doc/ng/*.4` (netgraph APIs).

## Current state / known gaps

- `srv6.c` and `srv6.h` are the real module. Boilerplate `example.c`,
  `example.h`, and `tests/module/test_example.c` have been removed.
- `README.md` documents the netgraph API, hooks, behavior support, and
  limitations.
- The comment at the top of `srv6.c` overstates completeness. Only branches for
  `End`, `End.X`, `End.DX6`, and `End.DX4` exist, and they are incomplete.
  Transit packets are dropped; `srv6_parse_srh()` and `srv6_encapsulate()` are
  defined but never called; encapsulation has no segment list.
- `srv6_cmdlist[]` is populated and `NGM_SRV6_*` handlers are implemented, so
  SIDs and adjacencies can be configured with `ngctl`.
- `srv6_ng_newhook()` accepts any hook name, and `srv6_ng_rcvdata()` runs the
  same pipeline for every hook. `"out"` and `"ctl"` are not wired up.
- `tests/module/test_srv6.c` only loads/unloads. There is no ATF test or
  automated test target.

## Applied fixes

- `srv6_adj_config.hook` already uses `ng_parse_fixedstring_type` with
  `NG_HOOKSIZ` (not `ng_parse_string_type`).
- `srv6_process_packet()` tracks whether a packet was already locally
  processed and skips the transit hop-limit decrement after `SRV6_ACT_CONTINUE`
  to avoid double-decrementing HLIM.
- `srv6_forward_adj()` calls `srv6_adj_account()` to update per-adjacency
  packet/byte counters.
- `SRV6_DEBUG()` macro gates `printf` on `bootverbose` (declared in
  `<sys/systm.h>`, already included by `srv6.c`); every error return path in
  `srv6.c` now calls `SRV6_DEBUG()` so diagnostics print only when the kernel
  is booted with `-v` / `boot_verbose="YES"`.

## Build

```sh
make                    # builds ./srv6.ko
make -C tests           # builds tests/module/test_srv6.ko
```

- Override `SYSDIR=/path/to/sys` if the kernel source is not at `/usr/src/sys`.
- `-Werror` is enabled; mark unused parameters `__unused`.
- Building works unprivileged. Never load or unload the module (see above).
- There is no test runner. Minimum verification is `make` and `make -C tests`.
  Do not attempt runtime validation by loading.
- `srv6.h` includes kernel headers, so it cannot be reused from userland; a
  separate header would be needed for tooling or userland tests.

## Code map

- `srv6.h`: on-wire `srv6_srh`/TLV structs, SID and behavior/flavor enums,
  `srv6_priv` state, hook names, `NGM_SRV6_*` command codes and cookie.
- `srv6.c`: `NETGRAPH_INIT`, `ng_type` methods, module event, and packet path
  `srv6_ng_rcvdata()` -> `srv6_process_packet()` -> `srv6_lookup_sid()` ->
  `srv6_apply_behavior()`.
- For netgraph patterns (`ng_cmdlist`, `NG_RESPOND_MSG`, hook handling), follow
  `/usr/src/sys/netgraph/` (`ng_echo.c`, `ng_iface.c`, `ng_socket.c`). There
  is no in-tree SRv6 node to copy.

## Style

- FreeBSD KNF: hard tabs, 8-column indent, 80 columns, K&R braces. Match
  surrounding code; do not reformat unrelated lines.
- `.clang-format` is currently unusable: `IndentCaseLabels` is duplicated, and
  `UseTab: Never` contradicts the rest of the config. Fix the config before
  running `clang-format`.
- New files use the BSD-2-Clause SPDX header copied from existing sources.
- Keep `KMOD` (`srv6`) in sync with `DECLARE_MODULE`, and add new `.c` files to
  `SRCS` in the root `Makefile`.

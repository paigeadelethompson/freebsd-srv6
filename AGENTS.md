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
- Remove the leftover boilerplate (`example.c`, `example.h`,
  `tests/module/test_example.c`) and replace the boilerplate `README.md` with
  real SRv6 documentation.
- Reference material: `doc/rfc8754.txt` (SRH), `doc/rfc8986.txt` (endpoint
  behaviors), `doc/rfc9602.txt` (SID addressing), `doc/rfc9800.txt`
  (compressed SID), and `doc/ng/*.4` (netgraph APIs).

## Current state / known gaps

- `srv6.c` and `srv6.h` are the real module. `README.md` and `example.*` still
  describe the original generic kmod boilerplate.
- The comment at the top of `srv6.c` overstates completeness. Only branches for
  `End`, `End.X`, `End.DX6`, and `End.DX4` exist, and they are incomplete.
  Transit packets are dropped; `srv6_parse_srh()` and `srv6_encapsulate()` are
  defined but never called; encapsulation has no segment list.
- `srv6_cmdlist[]` is empty and every `NGM_SRV6_*` case in `srv6_ng_rcvmsg()`
  is a TODO, so SIDs/adjacencies cannot be configured with `ngctl` yet.
- `srv6_ng_newhook()` accepts any hook name, and `srv6_ng_rcvdata()` runs the
  same pipeline for every hook. `"out"` and `"ctl"` are not wired up.
- `tests/module/test_srv6.c` only loads/unloads. There is no ATF test or
  automated test target.

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

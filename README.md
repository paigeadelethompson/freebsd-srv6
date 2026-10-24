# SRv6 netgraph node

SRv6 (Segment Routing over IPv6) implemented as an out-of-tree FreeBSD kernel
module. It is a netgraph node type named `srv6` that processes IPv6 packets
carrying a Segment Routing Header (SRH) per [RFC 8754](doc/rfc8754.txt), and
implements the SRv6 endpoint behaviors defined in [RFC 8986](doc/rfc8986.txt)
with [RFC 9602](doc/rfc9602.txt) SID addressing and
[RFC 9800](doc/rfc9800.txt) compressed SID (CSID) flavors.

## Build

```sh
make                    # builds ./srv6.ko
make -C tests           # builds tests/module/test_srv6.ko
```

- Override `SYSDIR=/path/to/sys` if the kernel source is not at `/usr/src/sys`.
- `-Werror` is enabled; mark unused parameters `__unused`.
- Building works unprivileged. **Never load or unload the module** (see
  [Hard rule](#hard-rule)).
- There is no test runner. Minimum verification is `make` and
  `make -C tests`. Do not attempt runtime validation by loading.

## Hard rule

**DO NOT LOAD THE FUCKING KERNEL MODULE.**

Do not run `make load`, `make unload`, `make reload`, `kldload`, `kldunload`,
or `ngctl` against this module unless the user explicitly asks. Build and
inspect only. Loading a broken kernel module can panic or destabilize the host.
Passwordless `sudo` being available is not permission to load it.

## Netgraph API

The node type is registered as `NG_SRV6_NODE_TYPE` (`"srv6"`).

### Hooks

- `"in"` (`NG_SRV6_HOOK_IN`): default ingress hook. IPv6 packets received
  here are parsed and processed through the SRv6 data path.
- `"out"` (`NG_SRV6_HOOK_OUT`): default egress hook. Packets that resolve to
  `SRV6_ACT_FORWARD_OUT` are sent out this hook.
- Additional hooks may be created and named in adjacency entries; they are
  used by `End.X` and `End.DX*` behaviors to forward to a specific next hop.

### Control messages (`ngctl`)

All messages use cookie `NG_SRV6_COOKIE` (`0x53525636`, `"SRV6"`).

| Command | `ngctl` name | Argument | Response | Description |
|---------|--------------|----------|----------|-------------|
| `NGM_SRV6_ADD_SID` | `addsid` | `srv6_sid_config` | — | Add or replace a local SID |
| `NGM_SRV6_DEL_SID` | `delsid` | IPv6 address | — | Remove a local SID |
| `NGM_SRV6_ADD_ADJ` | `addadj` | `srv6_adj_config` | — | Add or replace an L3 adjacency |
| `NGM_SRV6_DEL_ADJ` | `deladj` | `uint32` (index) | — | Remove an adjacency |
| `NGM_SRV6_SET_SRC` | `setsrc` | IPv6 address | — | Set default encapsulation source |
| `NGM_SRV6_GET_STATS` | `getstats` | — | `srv6_stats` | Get node statistics |
| `NGM_SRV6_GET_SID` | `getsid` | IPv6 address | `srv6_sid_info` | Get one local SID |
| `NGM_SRV6_GET_ADJ` | `getadj` | `uint32` (index) | `srv6_adj_info` | Get one adjacency |
| `NGM_SRV6_CLR_STATS` | `clrstats` | — | — | Clear all statistics |

### Data structures

Defined in `srv6.h`:

- `struct srv6_sid_config` — local SID configuration (address, IANA behavior
  codepoint, CSID layout lengths, adjacency index, FIB tables, segment list,
  source address).
- `struct srv6_adj_config` — L3 adjacency (nexthop, index, FIB table, hook
  name).
- `struct srv6_stats` — node counters (`packets_in`, `packets_out`,
  `packets_dropped`, `bytes_in`, `errors`, `sids`, `adjs`).
- `struct srv6_sid_info` / `struct srv6_adj_info` — per-SID/per-adjacency
  counters returned by `GET_SID`/`GET_ADJ`.

### Behavior support

IANA endpoint behavior codepoints (from RFC 8986 Section 10.2 and RFC 9800
Section 12.1) are decoded in `srv6_behavior_decode()`. The base behaviors
implemented are:

- `End` (codepoint 1)
- `End.X` (codepoint 5)
- `End.T` (codepoint 9)
- `End.B6.Encaps` (codepoint 14)
- `End.BM` (codepoint 15)
- `End.DX6` (codepoint 16)
- `End.DX4` (codepoint 17)
- `End.DT6` (codepoint 18)
- `End.DT4` (codepoint 19)
- `End.DT46` (codepoint 20)
- `End.DX2` (codepoint 21)
- `End.DX2V` (codepoint 22)
- `End.DT2U` (codepoint 23)
- `End.DT2M` (codepoint 24)
- `End.B6.Encaps.Red` (codepoint 27)

Flavor bits (`PSP`, `USP`, `USD`, `NEXT-CSID`, `REPLACE-CSID`) are decoded
from the codepoint as described in RFC 8986 and RFC 9800. See
`srv6_behavior_decode()` for the full mapping.

### Known gaps / limitations

- Transit packets are dropped unless a matching local SID is found.
- `srv6_parse_srh()` and `srv6_encapsulate()` are defined but not fully
  integrated into the data path.
- `srv6_cmdlist[]` exists but the `NGM_SRV6_*` handlers are partially
  implemented; SIDs and adjacencies can be added/removed via `ngctl`.
- `srv6_ng_newhook()` accepts any hook name; `"out"` and `"ctl"` are not
  fully wired up to separate pipelines.
- `End.BM`, `End.LBS`, `End.XLBS`, `End.DX2V`, `End.DT2U`, `End.DT2M` return
  `EOPNOTSUPP`.

## Reference material

- `doc/rfc8754.txt` — IPv6 Segment Routing Header (SRH)
- `doc/rfc8986.txt` — SRv6 Network Programming endpoint behaviors
- `doc/rfc9602.txt` — SID addressing architecture
- `doc/rfc9800.txt` — Compressed SID (CSID) flavors
- `doc/ng/*.4` — netgraph API man pages

## Style

- FreeBSD KNF: hard tabs, 8-column indent, 80 columns, K&R braces. Match
  surrounding code; do not reformat unrelated lines.
- `.clang-format` is currently unusable: `IndentCaseLabels` is duplicated, and
  `UseTab: Never` contradicts the rest of the config. Fix the config before
  running `clang-format`.
- New files use the BSD-2-Clause SPDX header copied from existing sources.
- Keep `KMOD` (`srv6`) in sync with `DECLARE_MODULE`, and add new `.c` files to
  `SRCS` in the root `Makefile`.

## License

BSD 2-Clause. See individual source files for their specific license headers.

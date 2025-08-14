README
======
Tiny ICMP Ping (C, Linux/WSL)
-----------------------------
* # TLDR:  
A minimal `ping`-like tool that crafts ICMP Echo requests and receives Echo replies.  
It supports **RAW** and **ICMP DGRAM** sockets, hex dumps, simple RTT stats, and WSL-friendly options.

--------------
feat: implement tiny ICMP ping tool with RAW/DGRAM support, RTT stats, and WSL fixes

- Add ICMP Echo builder + checksum
- Support RAW socket send/recv (parse IP header)
- Support ICMP DGRAM recv with TTL via recvmsg(IP_RECVTTL)
- Implement CLI flags (-c, -i, -W, -t, -s, -v, -A, -M)
- Add auto-fallback from DGRAM to RAW on EPERM/EACCES
- Hex dump for first packet, RTT stats summary
- WSL-specific adjustments: -A to ignore id, ping_group_range note

This MR adds a minimal ICMP ping utility in C with support for RAW and ICMP DGRAM sockets.  
Includes checksum, RTT stats, hex dump, CLI args, auto-fallback, and WSL notes.  
Verified against 1.1.1.1, 8.8.8.8, and localhost on WSL2 with tcpdump confirmation.

---
### Files

ping_like_c/  
 ├── ping.c      // main program (ICMP echo build/send/recv, CLI)  
 ├── ping.h      // small header with types and helpers  
 └── Makefile    // build rules (links with -lm)

---
Build
-----
``make``
### or explicitly:
``cc -O2 -Wall -Wextra -std=c2x -D_POSIX_C_SOURCE=200809L -c ping.c
``  
``
cc -O2 -Wall -Wextra -std=c2x -D_POSIX_C_SOURCE=200809L -o ping ping.o -lm
``
> We link with `-lm` because RTT stats use `sqrt()`.
---
Usage
-----
``./ping [-c count] [-i ms] [-W ms] [-t ttl] [-A] [-v] [-M auto|raw|dgram] [-s size] host``
```
  -c N      number of packets (default 4)  
  -i MS     interval between sends in ms (default 1000)  
  -W MS     per-packet timeout in ms (default 5000)  
  -t N      set IP TTL/hop limit  
  -A        loose match: ignore ICMP identifier (id)  
  -v        verbose: log ICMP seen (replies/errors)  
  -M MODE   socket mode:  
              auto  → try dgram, if denied fall back to raw (default)  
              raw   → raw socket (IP header included in recv path)  
              dgram → datagram ICMP (no IP header in payload)  
  -s SIZE   payload size in bytes (default 56; fills 'A'..'Z' pattern)  
```
**Examples**
# Plain ping with hex dump, raw fallback if needed
``./ping 1.1.1.1``
# 10 packets, 500 ms interval, 7 s timeout
``./ping -c 10 -i 500 -W 7000 8.8.8.8``
# Verbose + DGRAM (works great on WSL after enabling permission)
``./ping -M dgram -v -c 3 cloudflare.com``
# If you see replies but “timeout” lines, add -A (ignore id rewrite)
``./ping -M dgram -A -v -c 3 8.8.8.8``
---
What’s implemented
------------------
* **ICMP Echo builder** with 16-bit 1’s complement checksum.
* **RAW socket** send/recv path (parses IP header + ICMP).
* **ICMP DGRAM socket** recv path (no IP header), with **TTL via `recvmsg` + `IP_RECVTTL`**.
* **Auto-fallback**: `-M auto` (default) tries **DGRAM**, on `EPERM/EACCES` it **falls back to RAW** and prints a short note.
* **Options**: `-c, -i, -W, -t, -s, -v, -A, -M`.
* **Debug**: one-time **hex dump** of the first packet.
* **Stats**: min/avg/max/mdev RTT summary.
---
WSL notes
---------
WSL2 + Hyper-V NAT can behave differently for ICMP:
* With **RAW sockets**, some targets (e.g., `1.1.1.1`) work; others (e.g., `8.8.8.8`) may show no replies arriving.
* **ICMP DGRAM** is often more reliable on WSL, **but** the kernel can rewrite the ICMP **identifier (id)**.  
  Our tool offers `-A` to **ignore id** and match on **sequence** (this made `8.8.8.8` and `localhost` work for you).
* To allow ICMP DGRAM for unprivileged users, enable:  
  ``sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"``
  # persist:
  ``echo 'net.ipv4.ping_group_range=0 2147483647' | sudo tee -a /etc/sysctl.conf
  sudo sysctl -p``
* Alternative: grant the binary capability so you don’t need sudo:  
  ``sudo setcap cap_net_raw+ep ./ping``

**Troubleshooting flow**
1. If RAW mode times out for a host but system `ping` works, try:  
``./ping -M dgram -A -v -c 3 <host>``
2. If you get “Permission denied” in DGRAM:
   * enable `ping_group_range` (above), or
   * run `sudo setcap cap_net_raw+ep ./ping`, or run as root.
3. Use tcpdump to confirm whether replies reach the WSL interface:  
   ``sudo tcpdump -ni any icmp and host 8.8.8.8``
---
Known quirks so far
------------
* **Loopback (`127.0.0.1`)**:  
  On some WSL/kernel combos, RAW shows only your own Echo Requests (type 8).  
  DGRAM receives real Echo Replies, but **id** may be kernel-managed. Use `-A`.
* **TTL in DGRAM**:  
  We fetch TTL via `IP_RECVTTL`; if unsupported, TTL prints as `-1`.
---
Security / permissions
----------------------
* RAW and DGRAM ICMP can require special privileges.  
  We support three ways to run:
  * `sudo ./ping ...`
  * `sudo setcap cap_net_raw+ep ./ping` → then run as normal user
  * widen `ping_group_range` for DGRAM sockets
---
Development trail
-----------------
* Fixed `htons/ntohs` warnings by including proper headers.
* Implemented checksum + ICMP Echo header builder.
* Added hex dump, then RTT measurement & summary stats (`sqrt()` ⇒ `-lm`).
* Added CLI flags `-c, -i, -W, -t, -s, -v, -A`.
* Built **recv path** that checks **type=0, id, seq** (and `-A` to relax id).
* Implemented **DGRAM mode** with **TTL via `recvmsg(IP_RECVTTL)`**.
* Added **auto-fallback** from DGRAM to RAW on `EPERM/EACCES`.
* Verified on WSL:
  * RAW works for 1.1.1.1;
  * DGRAM works for 127.0.0.1 and 8.8.8.8 **with `-A`**;
  * tcpdump used to validate traffic.
---
Example sessions
----------------
```
$ ./ping -M dgram -A -v -c 3 127.0.0.1
... [dbg dgm] ... ttl=64
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.20 ms
...
```
```
$ ./ping -M dgram -A -v -c 3 8.8.8.8
... [dbg dgm] ... ttl=118
64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=25.48 ms
...
```
---




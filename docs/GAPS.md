# Real-world gap analysis (measured)

Date: 2026-11-13. Machine: Apple M-series, Homebrew clang `-O2`,
`build-rel/libwr.a`, OpenSSL 3.5 client library, OpenSSL 4.1 `s_server`.

Everything below was reproduced by running code, not by reading source. The
probe sources are kept with this note so each claim can be re-run.

## Verdict

The core is a good *codec and data-structure* library with a solid test suite.
It is not yet a peer that can complete a call with a browser or with OpenSSL's
own DTLS stack, and it has two memory-safety-adjacent protocol bugs that the
current tests cannot see because the tests are self-consistent. Those are the
items to fix first.

## Blocking gaps (proved by execution)

### 1. DTLS does not interoperate with OpenSSL — no cookie exchange

Probe: `/tmp/p_cookie.c` against `openssl s_server -dtls1_2`.

```
rx 48 bytes type=22 ver=feff
  hs type=3
  HelloVerifyRequest: server_version=0000 cookie_len=23
  -> our client has NO cookie support; it will never answer.
final state=1
```

OpenSSL's first flight is a `HelloVerifyRequest` carrying a 23-byte cookie. The
client ignores handshake type 3 entirely (`handle_handshake` default branch
returns true), so the handshake never advances. A real server is required to
send this; RFC 6347 §4.1.1 makes the cookie exchange mandatory for DTLS 1.2.

Fix: implement the stateless cookie return trip. On `HelloVerifyRequest`,
re-send ClientHello with `cookie` set to the received cookie, and on the server
side validate a cookie that covers client address + a secret. This is also the
amplification fix (a server must not allocate state before the client proves it
can receive at the claimed address).

### 2. DTLS ClientHello has no extensions at all

Probe: `/tmp/p_wire4.c` dumps the real first flight:

```
type=22 ver=fefd epoch=0 len=54
hs type=1 bodylen=42
hello: fe fd <32 random> 00 00 00 02 c0 2b 01 00
```

Parsed: version `fefd`, 32-byte random, session-id len 0, cookie len 0,
cipher-suites len 2 (`c02b`), compression methods len 1 (`00`), **then the
record ends**. There is no extensions block.

Missing and required for WebRTC:

| Extension | Consequence of absence |
|---|---|
| `use_srtp` (0x000e) | No SRTP keys can be derived. Media cannot be protected, so `wr_srtp` is unreachable from `wr_pc`. |
| `supported_groups` (0x000a) | Server picks its own curve; we only implement secp256r1, so a server choosing x25519 deadlocks. |
| `signature_algorithms` (0x000d) | Server cannot choose a certificate signature we can verify. |
| `extended_master_secret` (0x0017) | Session-hash binding is absent; also required by modern stacks. |
| `supported_point_formats` (0x000b) | Some stacks require uncompressed point signalling. |

Fix: emit a real extensions block, and add a matching parser for the
ServerHello extensions. `use_srtp` also needs the SRTP protection-profile list
and the `key derivation` path in `wr_srtp` (which exists) wired to the DTLS
exporter.

### 3. DTLS concatenates multiple application records into one buffer

Probe: `/tmp/p_coalesce.c` sends two records in one UDP datagram:

```
record1=41 record2=41
input(joined) st=0 (ok)
recv len=8 data='AAAABBBB'
EXPECTED: two records delivered separately ('AAAA' then 'BBBB')
GOT     : one span of 8 bytes = two plaintexts concatenated (SCTP would fail CRC)
```

`handle_record` appends every application-data plaintext into a single
`d->recv` buffer and `wr_dtls_recv` returns the whole buffer with one length.
DTLS application data is a *stream* of records, not a datagram: the receiver
must hand each record to the upper layer separately. Concatenated records are
indistinguishable from one large record.

This is the direct cause of gap 4.

### 4. Two back-to-back data-channel messages deliver nothing

Probe: `/tmp/p_pc_burst.c`, real `wr_pc` + ICE + DTLS + SCTP over loopback:

```
ready a=1 b=1
send one -> 0
send two -> 0
send three -> 0
delivered 0 of 3
```

One message works (`/tmp/p_pc_burst.c` with `k<1` delivers `'one'`). Three in a
row deliver nothing. `wr_pc_step` sends the two SCTP packets as two DTLS
records in one UDP datagram; the receiver concatenates them, so the first SCTP
packet's CRC is computed over packet+trailing bytes, fails, and the whole
datagram is dropped. The sender then retransmits on RTO, but every retransmit
has the same shape.

This is the single most damaging bug for real use: a data channel that loses
any message sent while another is in flight.

Fix: make `wr_dtls_recv` return one record per call (or expose an explicit
record iterator), and make the `wr_io` DTLS queue hold a list of records, not
one flat buffer. Then re-run the burst probe; the acceptance test is
`delivered 3 of 3`.

### 5. SCTP accepts DATA on an association that was never established

Probe: `/tmp/p_sctp_auth.c`:

```
state before = 0 (WR_SCTP_ST_CLOSED=0)
input on CLOSED assoc with bogus vtag -> 0 (ok)
recv -> 1  data='INJECTED' stream=0 ppid=54
```

`wr_sctp_input` only checks the verification tag when
`state == WR_SCTP_ST_ESTABLISHED`. In `CLOSED`, `INIT_SENT`, `COOKIE_SENT`,
`COOKIE_ECHOED`, any off-path peer that can guess the 4-tuple can inject
payload, and it is delivered to the application.

Fix: require `state == ESTABLISHED` (or an explicit `start_established` for
tests) before `handle_data` runs, and validate the verification tag on every
chunk in every state where the peer vtag is known.

### 6. SACK gap list is silently truncated at 8 blocks

Probe: `/tmp/p_gaps4.c`, 20 disjoint received TSNs, then read the SACK we emit:

```
pkt 20: 92 bytes | type=3 len=80 cum=999 ngaps=8 arwnd=65535 [bodylen=80 => 8 gap slots]
```

`send_sack` uses `wr_tsn_gap gaps[8]` and passes `WR_ARRAY_LEN(gaps)` as the
maximum, so `wr_tsn_set_gaps` stops at 8 and reports `ngaps=8`. The peer then
believes only 8 runs arrived and retransmits (or stalls on) the other 12.

Fix: either loop until the gap list is exhausted (multiple SACK chunks or a
larger fixed cap with an explicit truncation policy), or reduce the receive
window so 8 gaps can represent every reachable state. Add a test that drives
more than 8 disjoint runs and asserts the emitted gap count equals the true
count.

### 7. SCTP step is O(total sent) and retransmits everything on RTO

Probe: `/tmp/p_scale.c`:

```
queued     step(us) at t+1000ms
  1000      10401.0
  6000      24589.0
 11000      41054.0
 16000      54746.0
 21000      70607.0
 26000      89840.0
```

`wr_sctp_step` scans from `tx_off` to `tx.len` every call, and for every
unacked entry whose `sent_ms` is older than 1 s it retransmits. After the first
RTO expires, all 21k entries are simultaneously "old", so one step emits 21k
packets and takes 70 ms. Real send buffers are full at that point, so most of
those sends fail.

Fix: a proper retransmission queue (RFC 4960 §6.3) with per-message
`retransmit_ts`, a bounded in-flight window tied to `cwnd`/`rwnd`, and
fast-retransmit on the third duplicate SACK. Also track `rwnd` for real:
`send_sack` currently advertises `65535` unconditionally
(`wr_sctp_sack_body(cum, 65535u, ...)`), so the peer never applies back
pressure.

### 8. SCTP has no per-message reassembly

`/tmp/p_throughput.c` sends 200k messages: 128 B arena per message, and
`wr_sctp_send_data` rejects anything over 2020 bytes. There is no
fragmentation: a 4 KiB application write cannot be sent at all, even though the
SDP advertises `a=max-message-size:262144` (`/tmp/p_offer2.c`). A browser offering
a 256 KiB message size will send fragments we cannot emit, and we cannot send
fragments it expects.

Fix: DATA fragmentation with `B`/`E` bits and a per-stream reassembly buffer,
then reconcile `max-message-size` with what is actually implemented.

## Structural gaps (no probe needed, but they block a real product)

### 9. ICE has no STUN server client, so there are no server-reflexive candidates

`grep -rn 'srflx' src/ice` returns only the priority table. `WR_ICE_CAND_SRFLX`
is never populated. `wr_pc_start` adds exactly one host candidate
(`src/pc/pc.c`). Without a STUN binding to a configured server, neither side
learns its public address, so two peers behind NAT cannot connect. TURN
allocation exists (`src/turn/turn.c`) but is not wired into candidate gathering.

### 10. No role-conflict (glare) handling

`grep -rn '487' src` is empty. ICE controlling/controlled is fixed at
construction (`WR_ICE_ROLE_CONTROLLING` on one side). If both sides believe
they are controlling, each sends USE-CANDIDATE and both nominate; RFC 8445
§7.3.1 requires a 487 (Role Conflict) response and a tie-break on the
`ICE-CONTROLLING` attribute. The tie-breaker exists in the state but is never
compared on receipt.

### 11. No RTCP at all in the media path

`src/rtp/rtcp.c` parses and serializes RTCP, but nothing sends it. No
receiver-report, no NACK/PLI emission on loss, no REMB/TWCC feedback, no
jitter buffer, no playout. `wr_pc` has no RTP/RTCP forwarding at all
(`grep -rn 'srtp\\|rtp' src/pc` is empty).

### 12. `wr_pc_step` costs 11-22 ms when idle, because it polls with a 10 ms timeout

Probe: `/tmp/probe_latency.c`:

```
idle wr_pc_step (no DTLS, no traffic): 11.153 ms/step
idle wr_pc_step (DTLS up, no traffic): 22.061 ms/step
```

`pump()` calls `wr_io_wait(pc->io, 10u, &ready)`, so each `wr_pc_step` blocks
for up to 10 ms even when there is nothing to do. The DTLS wrapper adds a
second blocking wait. For a 60 fps media loop this is a 1-2 frame budget
consumed by doing nothing.

Fix: separate "pump non-blocking" from "wait with timeout". The caller should
either pass a deadline or the step should take `timeout_ms`. A poll-based
`wr_io_wait(io, 0, ...)` drain plus an explicit timer would make `step`
sub-microsecond when idle.

### 13. `max-message-size` advertises 262144 while the send path caps at 2020

`wr_sdp_serialize` output is well-formed (verified byte-for-byte:
`/tmp/p_offer2.c` shows `n=337` ending in `\r\n`, no trailing garbage — an
earlier apparent corruption was my own printf reading past `n`, not a library
bug). The real defect is the advertised capability:

```
a=max-message-size:262144      <- SDP, src/pc/pc_jsep.c
data.len > 2020 -> OVERFLOW    <- src/sctp/sctp.c
```

A browser that reads 256 KiB will fragment a large message and expect us to
reassemble it; we neither reassemble nor emit fragments (gap 8). Advertising a
size the code cannot honour is a protocol lie that will surface as a hung data
channel on the first large message.

Fix: advertise the real limit until fragmentation lands, then raise it with the
fragmentation implementation and a test that sends `max-message-size` bytes.

### 14. DTLS record size limit is 2048 bytes

`d->recv` is 2048 and `wr_dtls_send` refuses `app.len > sizeof(recv) - 64`.
With a 1200-byte MTU that is fine for a single SCTP packet, but it is below the
SCTP `max-message-size` we advertise and below what a browser will send in one
record.

## What I would do, in order

1. **DTLS record framing** (gap 3). This alone fixes gap 4, the burst loss.
   Acceptance: `/tmp/p_pc_burst.c` delivers 3 of 3.
2. **HelloVerifyRequest cookie** (gap 1) plus the **extensions block**
   (gap 2). Acceptance: handshake completes against
   `openssl s_server -dtls1_2` with `-msg`, and the ClientHello contains
   `use_srtp`, `supported_groups`, `signature_algorithms`,
   `extended_master_secret`.
3. **SCTP state check** (gap 5) and **SACK gap completeness** (gap 6).
   Acceptance: DATA on a CLOSED association is rejected; 20 disjoint runs emit
   20 gap blocks.
4. **SCTP retransmission queue + real rwnd** (gap 7) and **fragmentation**
   (gap 8). Acceptance: step stays under 10 us at 20k in flight; a 4 KiB write
   round-trips.
5. **ICE STUN gathering** (gap 9) and **role conflict** (gap 10). Acceptance:
   two agents behind a simulated NAT exchange srflx candidates and connect.
6. **Non-blocking step** (gap 12). Acceptance: idle step < 5 us.
7. **Reconcile `max-message-size`** with the real limit (gap 13).

## How I verified each claim

| Gap | Probe | Result |
|---|---|---|
| 1 | `/tmp/p_cookie.c` | server sends HelloVerifyRequest, client ignores it |
| 2 | `/tmp/p_wire4.c` | ClientHello has no extension block |
| 3 | `/tmp/p_coalesce.c` | two records -> `'AAAABBBB'` |
| 4 | `/tmp/p_pc_burst.c` | 3 sends, 0 delivered |
| 5 | `/tmp/p_sctp_auth.c` | DATA accepted on CLOSED association |
| 6 | `/tmp/p_gaps4.c` | 20 runs -> ngaps=8 |
| 7 | `/tmp/p_scale.c` | 70 ms step at 21k in flight |
| 8 | `/tmp/p_throughput.c` | 2020-byte send cap |
| 12 | `/tmp/probe_latency.c` | 11/22 ms idle step |
| 13 | `/tmp/p_offer2.c` | offer is well-formed (337 bytes, ends CRLF); advertised 262144 vs 2020 cap |

None of these are covered by the current test suite: the tests use
`start_established`, send one message at a time, and never speak to a real DTLS
peer. That is why the suite is green while the peer is broken.
# Probes referenced by `docs/GAPS.md`

Each probe is a standalone C file compiled against the release library:

```sh
./scripts/build.sh
clang -O2 -Iinclude docs/probes/<name>.c build-rel/libwr.a \
  -L/opt/homebrew/opt/openssl@3/lib -lcrypto -o /tmp/<name>
/tmp/<name>
```

Probes that need a real DTLS peer also need `openssl s_server`:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout /tmp/wr_key.pem -out /tmp/wr_cert.pem -days 2 -nodes -subj "/CN=test"
```

| Probe | Needs a server | Shows |
|---|---|---|
| `p_cookie.c` | yes (`-dtls1_2 -accept <port>`) | server replies `HelloVerifyRequest`; client ignores it |
| `p_wire4.c` | no (needs a UDP listener) | raw ClientHello bytes; no extension block |
| `p_coalesce.c` | no | two DTLS records in one datagram become `'AAAABBBB'` |
| `p_pc_burst.c` | no | 3 back-to-back data-channel sends deliver 0 |
| `p_sctp_auth.c` | no | DATA accepted on a CLOSED association |
| `p_gaps4.c` | no | 20 disjoint runs emit 8 SACK gap blocks |
| `p_scale.c` | no | SCTP step cost grows linearly with queued TX |
| `p_throughput.c` | no | send cap and 128 B arena cost per message |
| `probe_latency.c` | no | 11/22 ms idle `wr_pc_step` |
| `p_offer2.c` | no | SDP offer bytes and the `max-message-size` mismatch |

For the DTLS server probes, keep `s_server` alive with a FIFO; backgrounding it
with `< /dev/null` makes it exit immediately and the probe reports
`ECONNREFUSED`, which looks like a client bug but is not:

```sh
mkfifo /tmp/fifo
openssl s_server -dtls1_2 -accept 44431 -cert /tmp/wr_cert.pem \
  -key /tmp/wr_key.pem -state -naccept 1 < /tmp/fifo > /tmp/s.log 2>&1 &
exec 9>/tmp/fifo          # hold the write end open in this shell
/tmp/p_cookie 44431
```
#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/net.h"

#include <string.h>

static uint64_t g_fired;

static void bump(void *ctx, uint64_t now_ms)
{
    (void)now_ms;
    (*(uint64_t *)ctx)++;
    g_fired++;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_fuzz_stream fs;
    wr_fuzz_stream_init(&fs, data, size);
    size_t cap = 1u + wr_fuzz_stream_below(&fs, 16u);
    wr_timer *t = wr_timer_create(cap);
    if (!t) {
        return 0;
    }
    g_fired = 0u;
    uint64_t counter = 0;
    uint64_t ids[16];
    uint64_t at[16];
    memset(ids, 0, sizeof(ids));
    memset(at, 0, sizeof(at));
    size_t n = 0;

    uint64_t now = 0u;
    for (int i = 0; i < 96; ++i) {
        uint32_t op = wr_fuzz_stream_below(&fs, 4u);
        if (op == 0u && n < cap) {
            uint64_t when = now + wr_fuzz_stream_below(&fs, 64u);
            uint64_t id = 0;
            if (wr_timer_schedule(t, when, bump, &counter, &id) == WR_OK) {
                ids[n] = id;
                at[n] = when;
                n++;
            }
        } else if (op == 1u && n > 0u) {
            size_t k = wr_fuzz_stream_below(&fs, (uint32_t)n);
            if (wr_timer_cancel(t, ids[k])) {
                ids[k] = ids[n - 1u];
                at[k] = at[n - 1u];
                n--;
            }
        } else if (op == 2u) {
            now += wr_fuzz_stream_below(&fs, 32u);
            uint64_t due_before = g_fired;
            uint32_t fired = wr_timer_fire(t, now);
            if (fired != g_fired - due_before) {
                __builtin_trap();
            }
            /* Remove fired entries from the tracking set. */
            size_t w = 0;
            for (size_t k = 0; k < n; ++k) {
                if (at[k] > now) {
                    ids[w] = ids[k];
                    at[w] = at[k];
                    w++;
                }
            }
            n = w;
        } else {
            uint64_t next = wr_timer_next_deadline(t, now);
            bool any = false;
            uint64_t best = 0;
            for (size_t k = 0; k < n; ++k) {
                if (!any || at[k] < best) {
                    best = at[k];
                    any = true;
                }
            }
            if (!any) {
                if (next != 0u) {
                    __builtin_trap();
                }
            } else if (best <= now) {
                if (next != now) {
                    __builtin_trap();
                }
            } else if (next != best) {
                __builtin_trap();
            }
        }
    }
    wr_timer_destroy(t);
    return 0;
}
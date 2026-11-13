#ifndef WR_MAP_H
#define WR_MAP_H

#include "wr/arena.h"
#include "wr/hash.h"

/*
 * Open-addressing hash maps backed by an arena. Arrays of hash/key/value are
 * kept separate so a probe touches one cache line for the hash and another
 * for the payload, and a full scan can stream the value array.
 *
 * No tombstones: erase uses backward-shift deletion, so probe chains stay
 * dense and iteration never visits holes. Load factor is capped at 0.7.
 */

typedef struct {
    uint64_t *hash; /* 0 = empty */
    uint64_t *key;
    uint32_t *val;
    uint32_t cap;
    uint32_t mask;
    uint32_t len;
    uint32_t _pad;
    wr_arena *a;
} wr_u64_map;

bool wr_u64_map_init(wr_u64_map *m, wr_arena *a, uint32_t hint);
void wr_u64_map_destroy(wr_u64_map *m);
uint32_t *wr_u64_map_find(const wr_u64_map *m, uint64_t key);
uint32_t *wr_u64_map_find_hash(const wr_u64_map *m, uint64_t h, uint64_t key);
bool wr_u64_map_put(wr_u64_map *m, uint64_t key, uint32_t val);
bool wr_u64_map_put_hash(wr_u64_map *m, uint64_t h, uint64_t key,
                         uint32_t val);
bool wr_u64_map_erase(wr_u64_map *m, uint64_t key);
uint32_t wr_u64_map_len(const wr_u64_map *m);

/*
 * Compact string map. Keys are copied into an arena buffer; values are u32
 * (typically an index into the caller's SoA array). `find` returns a stable
 * pointer to the value, or NULL.
 */
typedef struct {
    uint64_t *slot_hash; /* 0 = empty */
    uint32_t *slot_id;   /* slot -> key id */
    uint32_t slot_cap;
    uint32_t slot_mask;
    uint32_t *off; /* key id -> offset in buf */
    uint32_t *len; /* key id -> length */
    uint32_t *val; /* key id -> caller value */
    uint32_t count;
    uint32_t cap;
    char *buf;
    size_t used;
    size_t buf_cap;
    wr_arena *a;
} wr_str_map;

bool wr_str_map_init(wr_str_map *m, wr_arena *a, uint32_t hint);
void wr_str_map_destroy(wr_str_map *m);
bool wr_str_map_put(wr_str_map *m, wr_span_c key, uint32_t val);
uint32_t *wr_str_map_find(wr_str_map *m, wr_span_c key);
const char *wr_str_map_key(const wr_str_map *m, uint32_t id);
uint32_t wr_str_map_len(const wr_str_map *m);

#endif /* WR_MAP_H */
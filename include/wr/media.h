#ifndef WR_MEDIA_H
#define WR_MEDIA_H

#include "wr/arena.h"
#include "wr/base.h"

/*
 * Media payloads (RFC 6184 H.264, RFC 7741 VP8, RFC 7587 Opus). This layer
 * is independent of FFmpeg: it turns an encoder access unit into RTP packets
 * and back. `src/media/codec.c` wraps libavcodec when WR_MEDIA=ON.
 */

typedef enum {
    WR_MEDIA_H264 = 0,
    WR_MEDIA_VP8,
    WR_MEDIA_OPUS,
} wr_media_codec;

/*
 * A decoded frame. For video, `data` is the luma plane and `data_u`/`data_v`
 * the chroma planes of a YUV420p frame; `linesize` is the stride of `data`
 * (the chroma stride is linesize / 2). For audio, `nb_samples` frames of
 * `channels` floats are at `data`.
 */
typedef struct {
    uint8_t *data;  /* Y plane (video) or planar samples (audio) */
    uint8_t *data_u; /* U plane, or NULL for audio and non-YUV video */
    uint8_t *data_v; /* V plane, or NULL */
    size_t linesize; /* stride of the Y plane in bytes */
    size_t len;
    int width;
    int height;
    int sample_rate;
    int channels;
    int nb_samples;
    uint64_t pts_ms; /* presentation time in milliseconds, when known */
} wr_media_frame;

typedef struct {
    uint16_t mtu;       /* max RTP payload bytes, header excluded */
    uint8_t pt;         /* RTP payload type */
    uint16_t seq;       /* first sequence number */
    uint32_t ts;        /* RTP timestamp */
    uint32_t ssrc;
    bool marker;        /* set on the last packet of the access unit */
} wr_rtp_pay_cfg;

typedef struct {
    uint8_t *ptr;
    size_t cap;
    size_t len;
} wr_rtp_out;

/* ------------------------------------------------------------------------- */
/* H.264 (RFC 6184)                                                          */
/* ------------------------------------------------------------------------- */

wr_status wr_h264_packetize(wr_span_c annex_b, const wr_rtp_pay_cfg *cfg,
                            wr_rtp_out *out, uint32_t max, uint32_t *count);

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    uint8_t ref_idc;
    uint8_t type;
    bool active;
} wr_h264_depay;

void wr_h264_depay_init(wr_h264_depay *d, uint8_t *buf, size_t cap);
/* Returns WR_OK and *out on a complete NAL, WR_ERR_AGAIN while a FU-A is
 * still being reassembled, or an error. */
wr_status wr_h264_depay_input(wr_h264_depay *d, wr_span_c payload,
                              wr_span_c *out);

/* ------------------------------------------------------------------------- */
/* VP8 (RFC 7741)                                                            */
/* ------------------------------------------------------------------------- */

wr_status wr_vp8_packetize(wr_span_c frame, const wr_rtp_pay_cfg *cfg,
                           wr_rtp_out *out, uint32_t max, uint32_t *count);

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
} wr_vp8_depay;

void wr_vp8_depay_init(wr_vp8_depay *d, uint8_t *buf, size_t cap);
wr_status wr_vp8_depay_input(wr_vp8_depay *d, wr_span_c payload, bool marker,
                             wr_span_c *out);

/* ------------------------------------------------------------------------- */
/* Opus (RFC 7587)                                                           */
/* ------------------------------------------------------------------------- */

wr_status wr_opus_packetize(wr_span_c frame, const wr_rtp_pay_cfg *cfg,
                            wr_rtp_out *out, uint32_t max, uint32_t *count);

#endif /* WR_MEDIA_H */
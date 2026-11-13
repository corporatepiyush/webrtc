#ifndef WR_MEDIA_CODEC_H
#define WR_MEDIA_CODEC_H

#include "wr/arena.h"
#include "wr/base.h"
#include "wr/media.h"

/*
 * FFmpeg-backed codec wrapper. Enabled with -DWR_MEDIA=ON; the RTP payload
 * layer in wr/media.h does not depend on FFmpeg.
 */

typedef struct {
    wr_media_codec codec;
    uint16_t width;
    uint16_t height;
    uint16_t fps;
    uint32_t bitrate;
    uint16_t gop;
    uint32_t sample_rate; /* audio */
    uint16_t channels;    /* audio */
} wr_media_enc_config;

typedef struct {
    wr_span_c data; /* points into the encoder packet; consume before next call */
} wr_media_packet;

typedef struct wr_media_enc wr_media_enc;
typedef struct wr_media_dec wr_media_dec;

wr_media_enc *wr_media_enc_create(wr_arena *a, const wr_media_enc_config *cfg);
void wr_media_enc_destroy(wr_media_enc *e);
wr_status wr_media_enc_push(wr_media_enc *e, wr_span_c raw_yuv, uint64_t pts_ms,
                            wr_media_packet *out, uint32_t max, uint32_t *count);
wr_status wr_media_enc_push_audio(wr_media_enc *e, const float *planar,
                                  int samples_per_channel, wr_media_packet *out,
                                  uint32_t max, uint32_t *count);
wr_status wr_media_enc_flush(wr_media_enc *e, wr_media_packet *out,
                             uint32_t max, uint32_t *count);

wr_media_dec *wr_media_dec_create(wr_arena *a, wr_media_codec codec);
void wr_media_dec_destroy(wr_media_dec *d);
wr_status wr_media_dec_push(wr_media_dec *d, wr_span_c bitstream,
                            wr_media_frame *out, bool *got_frame);

#endif /* WR_MEDIA_CODEC_H */
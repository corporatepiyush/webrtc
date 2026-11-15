#include "wr/media_codec.h"

#include <libavcodec/avcodec.h>
#include <libavutil/error.h>
#include <libavutil/frame.h>
#include <libavutil/imgutils.h>
#include <libavutil/opt.h>

#include <string.h>

struct wr_media_enc {
    AVCodecContext *ctx;
    AVFrame *frame;
    AVPacket *pkt;
    wr_media_codec codec;
    uint16_t width;
    uint16_t height;
    uint64_t pts;
    wr_arena *a;
};

struct wr_media_dec {
    AVCodecContext *ctx;
    AVFrame *frame;
    AVPacket *pkt;
    wr_media_codec codec;
    wr_arena *a;
};

static enum AVMediaType codec_type(wr_media_codec c)
{
    return c == WR_MEDIA_OPUS ? AVMEDIA_TYPE_AUDIO : AVMEDIA_TYPE_VIDEO;
}

static enum AVCodecID codec_id(wr_media_codec c)
{
    switch (c) {
    case WR_MEDIA_H264: return AV_CODEC_ID_H264;
    case WR_MEDIA_VP8:  return AV_CODEC_ID_VP8;
    case WR_MEDIA_OPUS: return AV_CODEC_ID_OPUS;
    }
    return AV_CODEC_ID_NONE;
}

static void drain_packets(wr_media_enc *e, wr_media_packet *out, uint32_t max,
                          uint32_t *count)
{
    while (*count < max) {
        if (avcodec_receive_packet(e->ctx, e->pkt) != 0) {
            break;
        }
        size_t len = (size_t)e->pkt->size;
        uint8_t *copy = (uint8_t *)wr_arena_alloc(e->a, len + 1u);
        if (!copy) {
            av_packet_unref(e->pkt);
            break;
        }
        if (len) {
            memcpy(copy, e->pkt->data, len);
        }
        out[*count].data.ptr = copy;
        out[*count].data.len = len;
        (*count)++;
        av_packet_unref(e->pkt);
    }
}

wr_media_enc *wr_media_enc_create(wr_arena *a, const wr_media_enc_config *cfg)
{
    if (!a || !cfg || cfg->bitrate > (uint32_t)INT32_MAX) {
        return NULL;
    }
    if (codec_type(cfg->codec) == AVMEDIA_TYPE_VIDEO &&
        (cfg->width == 0u || cfg->height == 0u ||
         (cfg->width & 1u) != 0u || (cfg->height & 1u) != 0u)) {
        return NULL;
    }
    const AVCodec *codec;
    if (cfg->codec == WR_MEDIA_OPUS) {
        codec = avcodec_find_encoder_by_name("libopus");
        if (!codec) {
            codec = avcodec_find_encoder(AV_CODEC_ID_OPUS);
        }
    } else {
        codec = avcodec_find_encoder(codec_id(cfg->codec));
    }
    if (!codec) {
        return NULL;
    }
    wr_media_enc *e = (wr_media_enc *)wr_arena_calloc(a, 1, sizeof(*e));
    if (!e) {
        return NULL;
    }
    e->a = a;
    e->codec = cfg->codec;
    e->width = cfg->width;
    e->height = cfg->height;
    e->ctx = avcodec_alloc_context3(codec);
    e->frame = av_frame_alloc();
    e->pkt = av_packet_alloc();
    if (!e->ctx || !e->frame || !e->pkt) {
        wr_media_enc_destroy(e);
        return NULL;
    }

    e->ctx->width = cfg->width;
    e->ctx->height = cfg->height;
    e->ctx->time_base = (AVRational){ 1, 90000 };
    e->ctx->framerate = (AVRational){ cfg->fps ? cfg->fps : 30, 1 };
    e->ctx->gop_size = cfg->gop ? cfg->gop : (cfg->fps ? cfg->fps : 30);
    e->ctx->max_b_frames = 0;
    e->ctx->bit_rate = (int64_t)cfg->bitrate * 1000;
    if (codec_type(cfg->codec) == AVMEDIA_TYPE_VIDEO) {
        e->ctx->pix_fmt = AV_PIX_FMT_YUV420P;
    } else {
        e->ctx->sample_rate = cfg->sample_rate ? cfg->sample_rate : 48000;
        av_channel_layout_default(&e->ctx->ch_layout,
                                  cfg->channels ? cfg->channels : 2);
        e->ctx->sample_fmt = AV_SAMPLE_FMT_S16;
        e->ctx->frame_size = 960;
        e->ctx->time_base = (AVRational){ 1, e->ctx->sample_rate };
    }
    if (avcodec_open2(e->ctx, codec, NULL) < 0) {
        wr_media_enc_destroy(e);
        return NULL;
    }

    if (codec_type(cfg->codec) == AVMEDIA_TYPE_VIDEO) {
        e->frame->format = e->ctx->pix_fmt;
        e->frame->width = e->ctx->width;
        e->frame->height = e->ctx->height;
        if (av_frame_get_buffer(e->frame, 32) < 0) {
            wr_media_enc_destroy(e);
            return NULL;
        }
    } else {
        e->frame->format = e->ctx->sample_fmt;
        e->frame->nb_samples = e->ctx->frame_size;
        e->frame->ch_layout = e->ctx->ch_layout;
        int frc = av_frame_get_buffer(e->frame, 0);
        if (frc < 0) {
            wr_media_enc_destroy(e);
            return NULL;
        }
    }
    return e;
}

void wr_media_enc_destroy(wr_media_enc *e)
{
    if (!e) {
        return;
    }
    if (e->ctx) {
        avcodec_free_context(&e->ctx);
    }
    if (e->frame) {
        av_frame_free(&e->frame);
    }
    if (e->pkt) {
        av_packet_free(&e->pkt);
    }
    memset(e, 0, sizeof(*e));
}

wr_status wr_media_enc_push(wr_media_enc *e, wr_span_c raw_yuv, uint64_t pts_ms,
                            wr_media_packet *out, uint32_t max, uint32_t *count)
{
    if (!e || !out || !count || !raw_yuv.ptr) {
        return WR_ERR_INVAL;
    }
    *count = 0u;
    if (codec_type(e->codec) != AVMEDIA_TYPE_VIDEO) {
        return WR_ERR_UNSUPPORTED;
    }
    size_t need = (size_t)e->width * (size_t)e->height * 3u / 2u;
    if (raw_yuv.len < need) {
        return WR_ERR_INVAL;
    }

    /* Honour the caller's timestamp: the encoder time base is 1/90000 for
     * video, so convert milliseconds rather than using a synthetic counter
     * that discards the caller's clock. */
    e->frame->pts = (int64_t)((pts_ms * (uint64_t)e->ctx->time_base.den) /
                              (uint64_t)e->ctx->time_base.num / 1000u);
    e->pts++;
    /* av_frame_get_buffer allocated the planes; make them writable, then
     * copy the packed YUV420p input into them. */
    if (av_frame_make_writable(e->frame) < 0) {
        return WR_ERR_NOMEM;
    }
    const uint8_t *src = raw_yuv.ptr;
    for (int y = 0; y < e->height; ++y) {
        memcpy(e->frame->data[0] + (size_t)y * e->frame->linesize[0], src,
               e->width);
        src += e->width;
    }
    for (int y = 0; y < e->height / 2; ++y) {
        memcpy(e->frame->data[1] + (size_t)y * e->frame->linesize[1], src,
               e->width / 2);
        src += e->width / 2;
        memcpy(e->frame->data[2] + (size_t)y * e->frame->linesize[2], src,
               e->width / 2);
        src += e->width / 2;
    }

    if (avcodec_send_frame(e->ctx, e->frame) < 0) {
        return WR_ERR_CRYPTO;
    }
    drain_packets(e, out, max, count);
    return WR_OK;
}

wr_status wr_media_enc_push_audio(wr_media_enc *e, const float *planar,
                                  int samples_per_channel, wr_media_packet *out,
                                  uint32_t max, uint32_t *count)
{
    if (!e || !out || !count || !planar) {
        return WR_ERR_INVAL;
    }
    *count = 0u;
    if (codec_type(e->codec) != AVMEDIA_TYPE_AUDIO) {
        return WR_ERR_UNSUPPORTED;
    }
    if (samples_per_channel != e->ctx->frame_size) {
        return WR_ERR_INVAL;
    }
    int mw = av_frame_make_writable(e->frame);
    if (mw < 0) {
        return WR_ERR_NOMEM;
    }
    int nch = e->ctx->ch_layout.nb_channels;
    int16_t *dst = (int16_t *)(void *)e->frame->data[0];
    for (int i = 0; i < samples_per_channel; ++i) {
        for (int ch = 0; ch < nch; ++ch) {
            float v = planar[(size_t)ch * (size_t)samples_per_channel + (size_t)i];
            if (v > 1.0f) v = 1.0f;
            if (v < -1.0f) v = -1.0f;
            dst[(size_t)i * (size_t)nch + (size_t)ch] = (int16_t)(v * 32767.0f);
        }
    }
    e->frame->pts = e->pts++;
    if (avcodec_send_frame(e->ctx, e->frame) < 0) {
        return WR_ERR_CRYPTO;
    }
    drain_packets(e, out, max, count);
    return WR_OK;
}

wr_status wr_media_enc_flush(wr_media_enc *e, wr_media_packet *out,
                             uint32_t max, uint32_t *count)
{
    if (!e || !out || !count) {
        return WR_ERR_INVAL;
    }
    *count = 0u;
    if (avcodec_send_frame(e->ctx, NULL) < 0) {
        return WR_ERR_STATE;
    }
    drain_packets(e, out, max, count);
    return WR_OK;
}

wr_media_dec *wr_media_dec_create(wr_arena *a, wr_media_codec codec)
{
    const AVCodec *c = avcodec_find_decoder(codec_id(codec));
    if (!a || !c) {
        return NULL;
    }
    wr_media_dec *d = (wr_media_dec *)wr_arena_calloc(a, 1, sizeof(*d));
    if (!d) {
        return NULL;
    }
    d->a = a;
    d->codec = codec;
    d->ctx = avcodec_alloc_context3(c);
    d->frame = av_frame_alloc();
    d->pkt = av_packet_alloc();
    if (d->ctx && codec == WR_MEDIA_OPUS) {
        d->ctx->sample_rate = 48000;
        av_channel_layout_default(&d->ctx->ch_layout, 2);
        d->ctx->request_sample_fmt = AV_SAMPLE_FMT_FLTP;
    }
    if (!d->ctx || !d->frame || !d->pkt || avcodec_open2(d->ctx, c, NULL) < 0) {
        wr_media_dec_destroy(d);
        return NULL;
    }
    return d;
}

void wr_media_dec_destroy(wr_media_dec *d)
{
    if (!d) {
        return;
    }
    if (d->ctx) {
        avcodec_free_context(&d->ctx);
    }
    if (d->frame) {
        av_frame_free(&d->frame);
    }
    if (d->pkt) {
        av_packet_free(&d->pkt);
    }
    memset(d, 0, sizeof(*d));
}

wr_status wr_media_dec_push(wr_media_dec *d, wr_span_c bitstream,
                            wr_media_frame *out, bool *got_frame)
{
    if (!d || !out || !got_frame || !bitstream.ptr) {
        return WR_ERR_INVAL;
    }
    *got_frame = false;
    if (bitstream.len > (size_t)INT32_MAX) {
        return WR_ERR_OVERFLOW;
    }
    if (av_new_packet(d->pkt, (int)bitstream.len) < 0) {
        return WR_ERR_NOMEM;
    }
    memcpy(d->pkt->data, bitstream.ptr, bitstream.len);
    d->pkt->pts = (int64_t)bitstream.len; /* decode only; pts unused here */
    if (avcodec_send_packet(d->ctx, d->pkt) < 0) {
        av_packet_unref(d->pkt);
        return WR_ERR_TRUNCATED;
    }
    av_packet_unref(d->pkt);

    if (avcodec_receive_frame(d->ctx, d->frame) == 0) {
        memset(out, 0, sizeof(*out));
        out->width = d->frame->width;
        out->height = d->frame->height;
        out->data = d->frame->data[0];
        out->data_u = d->frame->data[1];
        out->data_v = d->frame->data[2];
        out->linesize = (size_t)d->frame->linesize[0];
        out->len = (size_t)d->frame->height * (size_t)d->frame->linesize[0];
        if (d->frame->pts != AV_NOPTS_VALUE && d->frame->time_base.den != 0u) {
            out->pts_ms = (uint64_t)((int64_t)d->frame->pts *
                                     (int64_t)d->frame->time_base.num * 1000 /
                                     (int64_t)d->frame->time_base.den);
        }
        out->sample_rate = d->frame->sample_rate;
        out->channels = d->frame->ch_layout.nb_channels;
        out->nb_samples = d->frame->nb_samples;
        *got_frame = true;
    }
    return WR_OK;
}
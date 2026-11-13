#include "fuzz.h"

#include "wr/media.h"
#include "wr/rtp.h"

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 13u) {
        return 0;
    }
    wr_rtp_hdr h;
    if (!wr_rtp_parse(wr_span_c_make(data, size), &h)) {
        return 0;
    }
    wr_span_c payload = wr_span_c_sub(wr_span_c_make(data, size), h.payload_off,
                                      h.payload_len);
    if (payload.len == 0u) {
        return 0;
    }

    uint8_t h264buf[2048];
    wr_h264_depay hd;
    wr_h264_depay_init(&hd, h264buf, sizeof(h264buf));
    wr_span_c out;
    (void)wr_h264_depay_input(&hd, payload, &out);

    uint8_t vp8buf[2048];
    wr_vp8_depay vd;
    wr_vp8_depay_init(&vd, vp8buf, sizeof(vp8buf));
    (void)wr_vp8_depay_input(&vd, payload, h.marker != 0u, &out);

    /* Packetize the payload as H.264 Annex B. Many inputs are not Annex B;
     * that must be rejected, never crash. */
    wr_rtp_pay_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mtu = (uint16_t)(payload.len < 4u ? 4u : (payload.len > 512u ? 512u : payload.len));
    cfg.pt = h.pt;
    cfg.seq = h.seq;
    cfg.ts = h.timestamp;
    cfg.ssrc = h.ssrc;
    cfg.marker = true;
    uint8_t bufs[16][576];
    wr_rtp_out outp[16];
    for (int i = 0; i < 16; ++i) {
        outp[i].ptr = bufs[i];
        outp[i].cap = sizeof(bufs[i]);
    }
    uint32_t n = 0;
    (void)wr_h264_packetize(payload, &cfg, outp, 16, &n);

    (void)wr_opus_packetize(payload, &cfg, &outp[0], 1u, &n);
    return 0;
}
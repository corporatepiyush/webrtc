#ifndef WR_SDP_INTERNAL_H
#define WR_SDP_INTERNAL_H

#include "wr/sdp.h"

/* Shared tokenizer/address helpers used by the parser and the JSEP
 * convenience parsers. */
bool sdp_tok_next(wr_span_c *rest, wr_span_c *tok);
bool sdp_parse_hex(uint8_t c, uint8_t *out);
bool sdp_parse_addr(wr_span_c s, wr_endpoint *out);

#endif /* WR_SDP_INTERNAL_H */

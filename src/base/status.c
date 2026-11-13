#include "wr/base.h"

const char *wr_status_module(wr_status st)
{
    switch (st >> 16) {
    case WR_MOD_BASE: return "base";
    case WR_MOD_NET:  return "net";
    case WR_MOD_SDP:  return "sdp";
    case WR_MOD_STUN: return "stun";
    case WR_MOD_ICE:  return "ice";
    case WR_MOD_DTLS: return "dtls";
    case WR_MOD_SRTP: return "srtp";
    case WR_MOD_RTP:  return "rtp";
    case WR_MOD_SCTP: return "sctp";
    case WR_MOD_DCEP: return "dcep";
    case WR_MOD_PC:   return "pc";
    default:          return "unknown";
    }
}

const char *wr_status_str(wr_status st)
{
    switch (st) {
    case WR_OK:         return "ok";
    case WR_ERR_INVAL:  return "invalid argument";
    case WR_ERR_NOMEM:  return "out of memory";
    case WR_ERR_TRUNCATED: return "truncated input";
    case WR_ERR_OVERFLOW: return "overflow";
    case WR_ERR_NOT_FOUND: return "not found";
    case WR_ERR_EXISTS: return "already exists";
    case WR_ERR_STATE:  return "invalid state transition";
    case WR_ERR_AUTH:   return "authentication failed";
    case WR_ERR_TIMEOUT: return "timed out";
    case WR_ERR_IO:     return "i/o error";
    case WR_ERR_LIMIT:  return "limit reached";
    case WR_ERR_CRYPTO: return "crypto error";
    case WR_ERR_CLOSED: return "closed";
    case WR_ERR_AGAIN:  return "try again";
    case WR_ERR_UNSUPPORTED: return "unsupported";
    default:
        if ((st >> 16) == WR_MOD_BASE) return "unknown base error";
        return "module error";
    }
}
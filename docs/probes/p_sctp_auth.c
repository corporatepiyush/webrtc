#include <stdio.h>
#include <string.h>
#include "wr/arena.h"
#include "wr/net.h"
#include "wr/rng.h"
#include "wr/sctp.h"

int main(void){
    wr_arena *a=wr_arena_create(256*1024);
    wr_rng *rng=wr_rng_create(); wr_rng_seed(rng,77);
    wr_endpoint self; wr_endpoint_loopback(&self,0);
    wr_io *io=wr_io_udp_create(&self,true);
    wr_io_local_addr(io,&self);

    /* Association that was never started: state CLOSED. */
    wr_sctp_assoc *as=wr_sctp_create(a,self.port,self.port,rng);
    printf("state before = %d (WR_SCTP_ST_CLOSED=%d)\n", wr_sctp_get_state(as), WR_SCTP_ST_CLOSED);

    /* Build a CRC-valid DATA chunk for TSN 1 on stream 0, as any off-path peer could. */
    char body[256], chunk[512], raw[512];
    size_t blen=0, clen=0, rawlen=0;
    wr_sctp_data_body(1u, 0u, 0u, 54u, wr_span_c_from_str("INJECTED"), body, sizeof body, &blen);
    wr_sctp_chunk_serialize(WR_SCTP_DATA, 0x03u, wr_span_c_make(body,blen), chunk, sizeof chunk, &clen);
    wr_sctp_packet p; memset(&p,0,sizeof p);
    p.src_port=self.port; p.dst_port=self.port; p.vtag=0xdeadbeefu;   /* bogus vtag */
    wr_sctp_serialize(&p, wr_span_c_make(chunk,clen), raw, sizeof raw, &rawlen);

    wr_status st = wr_sctp_input(as, 1000, NULL, wr_span_c_make(raw,rawlen));
    printf("input on CLOSED assoc with bogus vtag -> %d (%s)\n", st, wr_status_str(st));

    wr_sctp_delivery d;
    bool got = wr_sctp_recv(as,&d);
    printf("recv -> %d", got);
    if(got) printf("  data='%.*s' stream=%u ppid=%u", (int)d.data.len, d.data.ptr, d.stream, d.ppid);
    printf("\n");
    return 0;
}

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "wr/arena.h"
#include "wr/net.h"
#include "wr/rng.h"
#include "wr/sctp.h"

static double now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e9+t.tv_nsec;}

int main(void){
    wr_arena *a=wr_arena_create(64u<<20);
    wr_rng *rng=wr_rng_create(); wr_rng_seed(rng,9);
    wr_endpoint self; wr_endpoint_loopback(&self,0);
    wr_io *io=wr_io_udp_create(&self,true);
    wr_io_local_addr(io,&self);
    wr_sctp_assoc *as=wr_sctp_create(a,self.port,self.port,rng);
    wr_sctp_attach_io(as,io,&self);
    wr_sctp_start_established(as,0x2000,0x1000,0x1000);

    /* Send as fast as possible, then measure how long the arena took. */
    size_t before = wr_arena_used(a);
    double t0=now_ns();
    int n=0;
    for(;n<200000;n++){
        if(wr_sctp_send_data(as,0,54,wr_span_c_from_str("x"),1000+(uint64_t)n)!=WR_OK) break;
    }
    double t1=now_ns();
    printf("sent %d messages in %.1f ms; arena %zu -> %zu bytes (%.0f B/msg)\n",
           n,(t1-t0)/1e6,before,wr_arena_used(a), n? (double)(wr_arena_used(a)-before)/n:0.0);

    /* Drain with an RTO-only retransmit path: how long to ack 10k? */
    wr_sctp_delivery d;
    printf("ready queue deliveries pending: ?\n");
    (void)d;
    return 0;
}

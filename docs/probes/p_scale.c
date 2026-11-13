#include <stdio.h>
#include <time.h>
#include "wr/arena.h"
#include "wr/net.h"
#include "wr/rng.h"
#include "wr/sctp.h"
static double now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e9+t.tv_nsec;}
int main(void){
    wr_arena *a=wr_arena_create(256u<<20);
    wr_rng *rng=wr_rng_create(); wr_rng_seed(rng,9);
    wr_endpoint loop; wr_endpoint_loopback(&loop,0);
    wr_io *io=wr_io_udp_create(&loop,true); wr_endpoint self; wr_io_local_addr(io,&self);
    wr_sctp_assoc *as=wr_sctp_create(a,self.port,self.port,rng);
    wr_sctp_attach_io(as,io,&self);
    wr_sctp_start_established(as,0x2000,0x1000,1000);
    printf("%8s %12s %12s\n","queued","send(us)","step(us) at t+1000ms");
    for(int target=1000; target<=50000; target+=1000*5){
        while(0){}
        static int sent=0;
        for(; sent<target; sent++){
            if(wr_sctp_send_data(as,0,54,wr_span_c_from_str("x"),1000+(uint64_t)sent)!=WR_OK){printf("send failed at %d\n",sent);return 1;}
        }
        double t0=now_ns();
        wr_sctp_step(as, 1000+(uint64_t)target+1000);   /* force RTO path over all entries */
        double t1=now_ns();
        printf("%8d %12.1f %12.1f\n", target, 0.0, (t1-t0)/1e3);
        /* Drain what the step just queued so we don't fill the socket buffer. */
        uint8_t b[2048]; int drained=0;
        for(int k=0;k<200;k++){bool r=false;if(wr_io_wait(io,0,&r)!=WR_OK||!r)break;
            wr_endpoint f;wr_span d;if(wr_io_recv(io,&f,wr_span_make(b,sizeof b),&d)!=WR_OK)break;drained++;}
        (void)drained;
    }
    printf("arena used=%zu bytes\n", wr_arena_used(a));
    return 0;
}

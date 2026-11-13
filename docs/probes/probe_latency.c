#include <stdio.h>
#include <time.h>
#include "wr/arena.h"
#include "wr/net.h"
#include "wr/pc.h"
#include "wr/rng.h"

static double now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e9+t.tv_nsec;}

int main(void){
    wr_arena *a1=wr_arena_create(1<<20), *a2=wr_arena_create(1<<20);
    wr_rng *r1=wr_rng_create(), *r2=wr_rng_create();
    wr_rng_seed(r1,5); wr_rng_seed(r2,6);
    wr_endpoint loop; wr_endpoint_loopback(&loop,0);
    wr_io *i1=wr_io_udp_create(&loop,true), *i2=wr_io_udp_create(&loop,true);
    wr_endpoint e1,e2; wr_io_local_addr(i1,&e1); wr_io_local_addr(i2,&e2);
    wr_pc *p1=wr_pc_create(a1,r1,i1,&e1,&e2,WR_ICE_ROLE_CONTROLLING);
    wr_pc *p2=wr_pc_create(a2,r2,i2,&e2,&e1,WR_ICE_ROLE_CONTROLLED);
    wr_pc_set_credentials(p1,wr_span_c_from_str("uA"),wr_span_c_from_str("pA"),wr_span_c_from_str("uB"),wr_span_c_from_str("pB"));
    wr_pc_set_credentials(p2,wr_span_c_from_str("uB"),wr_span_c_from_str("pB"),wr_span_c_from_str("uA"),wr_span_c_from_str("pA"));
    uint64_t now=1000; wr_pc_start(p1,now); wr_pc_start(p2,now);
    for(int i=0;i<400;i++){now+=5;wr_pc_step(p1,now);wr_pc_step(p2,now);if(wr_pc_ready(p1)&&wr_pc_ready(p2))break;}
    printf("ready=%d %d\n", wr_pc_ready(p1), wr_pc_ready(p2));

    /* idle step latency: 200 steps with no traffic */
    double t0=now_ns();
    for(int i=0;i<200;i++){now+=5;wr_pc_step(p1,now);}
    double t1=now_ns();
    printf("idle wr_pc_step (no DTLS, no traffic): %.3f ms/step\n",(t1-t0)/200.0/1e6);

    /* now enable DTLS and measure again on a fresh pair */
    wr_arena *b1=wr_arena_create(2<<20), *b2=wr_arena_create(2<<20);
    wr_rng *s1=wr_rng_create(), *s2=wr_rng_create(); wr_rng_seed(s1,11); wr_rng_seed(s2,12);
    wr_endpoint l2; wr_endpoint_loopback(&l2,0);
    wr_io *j1=wr_io_udp_create(&l2,true), *j2=wr_io_udp_create(&l2,true);
    wr_endpoint f1,f2; wr_io_local_addr(j1,&f1); wr_io_local_addr(j2,&f2);
    wr_pc *q1=wr_pc_create(b1,s1,j1,&f1,&f2,WR_ICE_ROLE_CONTROLLING);
    wr_pc *q2=wr_pc_create(b2,s2,j2,&f2,&f1,WR_ICE_ROLE_CONTROLLED);
    wr_pc_set_credentials(q1,wr_span_c_from_str("uA"),wr_span_c_from_str("pA"),wr_span_c_from_str("uB"),wr_span_c_from_str("pB"));
    wr_pc_set_credentials(q2,wr_span_c_from_str("uB"),wr_span_c_from_str("pB"),wr_span_c_from_str("uA"),wr_span_c_from_str("pA"));
    wr_pc_enable_dtls(q1); wr_pc_enable_dtls(q2);
    const uint8_t *fa,*fb; size_t la,lb;
    wr_pc_local_fingerprint(q1,&fa,&la); wr_pc_local_fingerprint(q2,&fb,&lb);
    wr_pc_set_peer_fingerprint(q1,fb,lb); wr_pc_set_peer_fingerprint(q2,fa,la);
    uint64_t n2=1000; wr_pc_start(q1,n2); wr_pc_start(q2,n2);
    for(int i=0;i<1000;i++){n2+=5;wr_pc_step(q1,n2);wr_pc_step(q2,n2);if(wr_pc_ready(q1)&&wr_pc_ready(q2))break;}
    printf("dtls ready=%d %d\n", wr_pc_ready(q1), wr_pc_ready(q2));
    t0=now_ns();
    for(int i=0;i<200;i++){n2+=5;wr_pc_step(q1,n2);wr_pc_step(q2,n2);}
    t1=now_ns();
    printf("idle wr_pc_step (DTLS up, no traffic): %.3f ms/step\n",(t1-t0)/200.0/1e6);
    return 0;
}

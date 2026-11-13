#include <stdio.h>
#include <string.h>
#include "wr/arena.h"
#include "wr/dtls.h"
#include "wr/net.h"
#include "wr/rng.h"

static int capture(wr_io *io, uint8_t *buf, size_t cap, size_t *n){
    for(int i=0;i<50;i++){bool r=false;if(wr_io_wait(io,1,&r)!=WR_OK||!r)continue;
        wr_endpoint s;wr_span d;if(wr_io_recv(io,&s,wr_span_make(buf,cap),&d)!=WR_OK)continue;
        if(d.len>cap)return -1;memcpy(buf,d.ptr,d.len);*n=d.len;return 0;}
    return 1;
}
int main(void){
    wr_arena *a=wr_arena_create(4<<20);
    wr_rng *r1=wr_rng_create(),*r2=wr_rng_create();wr_rng_seed(r1,3);wr_rng_seed(r2,4);
    wr_endpoint l1,l2;wr_endpoint_loopback(&l1,0);wr_endpoint_loopback(&l2,0);
    wr_io *i1=wr_io_udp_create(&l1,true),*i2=wr_io_udp_create(&l2,true);
    wr_endpoint e1,e2;wr_io_local_addr(i1,&e1);wr_io_local_addr(i2,&e2);
    wr_dtls *c=wr_dtls_create(a,r1,WR_DTLS_ROLE_CLIENT,i1,&e2);
    wr_dtls *s=wr_dtls_create(a,r2,WR_DTLS_ROLE_SERVER,i2,&e1);
    size_t fl;const uint8_t *f;
    f=wr_dtls_fingerprint(c,&fl);wr_dtls_set_peer_fingerprint(s,f,fl);
    f=wr_dtls_fingerprint(s,&fl);wr_dtls_set_peer_fingerprint(c,f,fl);
    uint64_t now=1000;wr_dtls_start(c,now);
    for(int i=0;i<300&&!(wr_dtls_ready(c)&&wr_dtls_ready(s));i++){
        now+=5;wr_dtls_step(c,now);wr_dtls_step(s,now);
        uint8_t b[2048];size_t n;
        if(capture(i2,b,sizeof b,&n)==0)wr_dtls_input(s,wr_span_c_make(b,n));
        if(capture(i1,b,sizeof b,&n)==0)wr_dtls_input(c,wr_span_c_make(b,n));
    }
    printf("handshake ready c=%d s=%d\n",wr_dtls_ready(c),wr_dtls_ready(s));

    /* Two app-data records, each its own DTLS record, delivered in ONE datagram. */
    uint8_t d1[512], d2[512]; size_t n1=0, n2=0;
    wr_dtls_send(c, wr_span_c_from_str("AAAA"));
    if(capture(i2,d1,sizeof d1,&n1)!=0){printf("capture1 failed\n");return 1;}
    wr_dtls_send(c, wr_span_c_from_str("BBBB"));
    if(capture(i2,d2,sizeof d2,&n2)!=0){printf("capture2 failed\n");return 1;}
    printf("record1=%zu record2=%zu\n", n1, n2);

    uint8_t joined[1024]; memcpy(joined,d1,n1); memcpy(joined+n1,d2,n2);
    wr_status st = wr_dtls_input(s, wr_span_c_make(joined, n1+n2));
    printf("input(joined) st=%d (%s)\n", st, wr_status_str(st));
    wr_span_c out;
    if(wr_dtls_recv(s,&out)){
        printf("recv len=%zu data='%.*s'\n", out.len, (int)out.len, out.ptr);
        printf("EXPECTED: two records delivered separately ('AAAA' then 'BBBB')\n");
        printf("GOT     : one span of %zu bytes = %s\n", out.len,
               (out.len==8)?"two plaintexts concatenated (SCTP would fail CRC)":"ok");
    } else printf("recv returned nothing\n");
    return 0;
}

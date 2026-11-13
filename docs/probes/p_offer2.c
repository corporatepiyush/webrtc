#include <stdio.h>
#include <string.h>
#include "wr/arena.h"
#include "wr/net.h"
#include "wr/pc.h"
#include "wr/rng.h"
int main(void){
    wr_arena *a=wr_arena_create(1<<20);
    wr_rng *rng=wr_rng_create(); wr_rng_seed(rng,1);
    wr_endpoint loop; wr_endpoint_loopback(&loop,0);
    wr_io *io=wr_io_udp_create(&loop,true);
    wr_endpoint lo,ro; wr_io_local_addr(io,&lo); ro=lo;
    wr_pc *pc=wr_pc_create(a,rng,io,&lo,&ro,WR_ICE_ROLE_CONTROLLING);
    wr_pc_set_credentials(pc,wr_span_c_from_str("uA"),wr_span_c_from_str("pA"),wr_span_c_from_str("uB"),wr_span_c_from_str("pB"));
    static char buf[4096]; memset(buf,0xCC,sizeof buf);
    size_t n=0;
    wr_status st=wr_pc_create_offer(pc,buf,sizeof buf,&n);
    printf("st=%d n=%zu\n",st,n);
    printf("--- bytes %zu..%zu ---\n", n?n-8:0, n+8);
    for(size_t i=(n>8?n-8:0); i<n+8 && i<sizeof buf; i++) printf("%02x ", (unsigned char)buf[i]);
    printf("\n");
    printf("last 40 bytes as text: [");
    for(size_t i=(n>40?n-40:0); i<n; i++){ unsigned char c=(unsigned char)buf[i]; putchar((c>=32&&c<127)?c:'.'); }
    printf("]\n");
    return 0;
}

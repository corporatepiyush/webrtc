#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include "wr/arena.h"
#include "wr/dtls.h"
#include "wr/net.h"
#include "wr/rng.h"
int main(int argc,char**argv){
    int port=atoi(argv[1]);
    setvbuf(stdout,NULL,_IONBF,0);
    wr_arena *ar=wr_arena_create(4<<20);
    wr_rng *rng=wr_rng_create(); wr_rng_seed(rng,22);
    wr_endpoint bind; wr_endpoint_loopback(&bind,0);
    wr_io *io=wr_io_udp_create(&bind,true);
    char ep[64]; snprintf(ep,sizeof ep,"127.0.0.1:%d",port);
    wr_endpoint peer; wr_endpoint_parse(wr_span_c_from_str(ep),(uint16_t)port,&peer);
    wr_dtls *d=wr_dtls_create(ar,rng,WR_DTLS_ROLE_CLIENT,io,&peer);
    wr_dtls_start(d,1000);
    for(int i=0;i<20;i++){
        uint8_t buf[2048];
        for(int k=0;k<4;k++){
            bool ready=false;
            if(wr_io_wait(io,k==0?5:0,&ready)!=WR_OK||!ready)break;
            wr_endpoint from; wr_span data;
            if(wr_io_recv(io,&from,wr_span_make(buf,sizeof buf),&data)!=WR_OK)break;
            printf("rx %zu bytes type=%u ver=%02x%02x\n",data.len,data.ptr[0],data.ptr[1],data.ptr[2]);
            if(data.len>13){
                printf("  hs type=%u\n", data.ptr[13]);
                if(data.ptr[13]==3){
                    printf("  HelloVerifyRequest: server_version=%02x%02x cookie_len=%u\n",
                        data.ptr[14],data.ptr[15], data.len>16?data.ptr[16]:0);
                    printf("  -> our client has NO cookie support; it will never answer.\n");
                }
            }
            wr_dtls_input(d,NULL,wr_span_upcast(data));
        }
    }
    printf("final state=%d\n",wr_dtls_state(d));
    return 0;
}

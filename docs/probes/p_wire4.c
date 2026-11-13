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
    int rx=socket(AF_INET,SOCK_DGRAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_port=htons(port); a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(rx,(struct sockaddr*)&a,sizeof a)!=0){perror("bind");return 1;}
    setvbuf(stdout,NULL,_IONBF,0);

    wr_arena *ar=wr_arena_create(4<<20);
    wr_rng *rng=wr_rng_create(); wr_rng_seed(rng,22);
    wr_endpoint bind; wr_endpoint_loopback(&bind,0);
    wr_io *io=wr_io_udp_create(&bind,true);
    char ep[64]; snprintf(ep,sizeof ep,"127.0.0.1:%d",port);
    wr_endpoint peer; wr_endpoint_parse(wr_span_c_from_str(ep),(uint16_t)port,&peer);
    printf("peer port=%u\n",peer.port);

    wr_dtls *d=wr_dtls_create(ar,rng,WR_DTLS_ROLE_CLIENT,io,&peer);
    wr_status st=wr_dtls_start(d,1000);
    printf("start st=%d state=%d\n", st, wr_dtls_state(d));

    uint8_t buf[2048];
    struct sockaddr_in from; socklen_t fl=sizeof from;
    errno=0;
    ssize_t n=recvfrom(rx,buf,sizeof buf,0,(struct sockaddr*)&from,&fl);
    printf("recvfrom n=%zd errno=%d\n", n, errno);
    if(n>13){
        printf("type=%u ver=%02x%02x epoch=%u len=%u\n",buf[0],buf[1],buf[2],(buf[3]<<8)|buf[4],(buf[11]<<8)|buf[12]);
        printf("hs type=%u bodylen=%u\n", buf[13], ((unsigned)buf[14]<<16)|((unsigned)buf[15]<<8)|buf[16]);
        printf("hello:"); for(int i=25;i<n;i++)printf(" %02x",buf[i]); printf("\n");
    }
    return 0;
}

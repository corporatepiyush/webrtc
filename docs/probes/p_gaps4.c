#include <stdio.h>
#include <string.h>
#include "wr/arena.h"
#include "wr/net.h"
#include "wr/rng.h"
#include "wr/sctp.h"
int main(void){
    wr_arena *a=wr_arena_create(8<<20);
    wr_rng *rng=wr_rng_create(); wr_rng_seed(rng,4);
    wr_endpoint loop; wr_endpoint_loopback(&loop,0);
    wr_io *ia=wr_io_udp_create(&loop,true);
    wr_endpoint ea; wr_io_local_addr(ia,&ea);
    wr_sctp_assoc *as=wr_sctp_create(a,ea.port,ea.port,rng);
    wr_sctp_attach_io(as,ia,&ea);
    wr_sctp_start_established(as,0x2000,0x1000,1000);

    for(uint32_t i=0;i<20;i++){
        uint32_t tsn=1001u+i*2u;
        char body[64],chunk[128],raw[256];size_t bl=0,cl=0,rl=0;
        wr_sctp_data_body(tsn,0,0,54,wr_span_c_from_str("y"),body,sizeof body,&bl);
        wr_sctp_chunk_serialize(WR_SCTP_DATA,0x03u,wr_span_c_make(body,bl),chunk,sizeof chunk,&cl);
        wr_sctp_packet p;memset(&p,0,sizeof p);
        p.src_port=ea.port;p.dst_port=ea.port;p.vtag=0x2000;
        wr_sctp_serialize(&p,wr_span_c_make(chunk,cl),raw,sizeof raw,&rl);
        wr_sctp_input(as,1000,NULL,wr_span_c_make(raw,rl));
    }
    uint8_t buf[2048]; int pkts=0;
    for(int k=0;k<40;k++){
        bool ready=false;
        if(wr_io_wait(ia,1,&ready)!=WR_OK||!ready)break;
        wr_endpoint f; wr_span d;
        if(wr_io_recv(ia,&f,wr_span_make(buf,sizeof buf),&d)!=WR_OK)break;
        pkts++;
        printf("pkt %d: %zu bytes", pkts, d.len);
        for(size_t off=12;off+4<=d.len;){
            uint8_t ty=buf[off];uint16_t ln=(uint16_t)((buf[off+2]<<8)|buf[off+3]);
            printf(" | type=%u len=%u",ty,ln);
            if(ty==3 && ln>=16){
                uint32_t cum=((uint32_t)buf[off+4]<<24)|((uint32_t)buf[off+5]<<16)|((uint32_t)buf[off+6]<<8)|buf[off+7];
                uint16_t ng=(uint16_t)((buf[off+12]<<8)|buf[off+13]);
                printf(" cum=%u ngaps=%u arwnd=%u",cum,ng,(unsigned)((buf[off+8]<<24)|(buf[off+9]<<16)|(buf[off+10]<<8)|buf[off+11]));
                printf(" [bodylen=%u => %u gap slots]",ln,(ln-12)/8);
            }
            if(ln<4)break; off+=ln;
        }
        printf("\n");
    }
    printf("total packets=%d\n",pkts);
    return 0;
}

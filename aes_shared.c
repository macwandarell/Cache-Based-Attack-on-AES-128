#include "aes_shared.h"

#define FIXED_ADDR ((void*)0x500000000000ULL)
#define SHM_NAME "/aes_ttable_shm"
#define TTABLE_SIZE (256*4*sizeof(uint32_t))

static uint32_t (*T0)[256]=NULL;
static uint32_t (*T1)[256]=NULL;
static uint32_t (*T2)[256]=NULL;
static uint32_t (*T3)[256]=NULL;

//S-box
static const uint8_t Sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };


//GF(2^8)
static inline uint8_t xtime(uint8_t x){
    return (uint8_t)(x<<1)^((x&0x80?0x1b:0x00));
}

//t-table initialization
__attribute__((constructor))
static void init_ttables(void){
    int shm_fd=shm_open(SHM_NAME,O_CREAT|O_RDWR,0666);
    if(shm_fd==-1){perror("shm_open failed");exit(EXIT_FAILURE);}
    if(ftruncate(shm_fd,TTABLE_SIZE)==-1){perror("ftruncate failed");close(shm_fd);exit(EXIT_FAILURE);}

    void *ptr=mmap(FIXED_ADDR,TTABLE_SIZE,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_FIXED,shm_fd,0);
    if(ptr==MAP_FAILED){perror("mmap failed");close(shm_fd);exit(EXIT_FAILURE);}
    close(shm_fd);

    uint32_t *base=(uint32_t *)ptr;
    T0=(uint32_t(*)[256])(base+0*256);
    T1=(uint32_t(*)[256])(base+1*256);
    T2=(uint32_t(*)[256])(base+2*256);
    T3=(uint32_t(*)[256])(base+3*256);

    for(int i=0;i<256;i++){
        uint8_t s=Sbox[i];
        uint8_t s2=xtime(s);
        uint8_t s3=s2^s;
        uint32_t t0=((uint32_t)s2<<24)|((uint32_t)s<<16)|((uint32_t)s<<8)|(uint32_t)s3;
        (*T0)[i]=t0;
        (*T1)[i]=(t0>>8)|(t0<<24);
        (*T2)[i]=(t0>>16)|(t0<<16);
        (*T3)[i]=(t0>>24)|(t0<<8);
    }
}

//Table address
uint32_t *get_ttable_address(void){
    return (uint32_t *)FIXED_ADDR;
}

//round-1 t-table
static void round_ttable_core(const uint8_t *state,uint8_t *out){
    uint32_t c0=(*T0)[state[0]]^(*T1)[state[5]]^(*T2)[state[10]]^(*T3)[state[15]];
    uint32_t c1=(*T0)[state[4]]^(*T1)[state[9]]^(*T2)[state[14]]^(*T3)[state[3]];
    uint32_t c2=(*T0)[state[8]]^(*T1)[state[13]]^(*T2)[state[2]]^(*T3)[state[7]];
    uint32_t c3=(*T0)[state[12]]^(*T1)[state[1]]^(*T2)[state[6]]^(*T3)[state[11]];
    out[0]=(uint8_t)(c0>>24);
    out[1]=(uint8_t)(c0>>16);
    out[2]=(uint8_t)(c0>>8);
    out[3]=(uint8_t)c0;
    out[4]=(uint8_t)(c1>>24);
    out[5]=(uint8_t)(c1>>16);
    out[6]=(uint8_t)(c1>>8);
    out[7]=(uint8_t)c1;
    out[8]=(uint8_t)(c2>>24);
    out[9]=(uint8_t)(c2>>16);
    out[10]=(uint8_t)(c2>>8);
    out[11]=(uint8_t)c2;
    out[12]=(uint8_t)(c3>>24);
    out[13]=(uint8_t)(c3>>16);
    out[14]=(uint8_t)(c3>>8);
    out[15]=(uint8_t)c3;
}

//round-1 key expansion

static void expand_round_key_1(const uint8_t *key,uint8_t *round_key_1){
    uint8_t w0[4];
    uint8_t w1[4];
    uint8_t w2[4];
    uint8_t w3[4];
    uint8_t t[4];

    for(int i=0;i<4;i++){
        w0[i]=key[i];
        w1[i]=key[i+4];
        w2[i]=key[i+8];
        w3[i]=key[i+12];
    }

    t[0]=w3[1];
    t[1]=w3[2];
    t[2]=w3[3];
    t[3]=w3[0];
    for(int i=0;i<4;i++){
        t[i]=Sbox[t[i]];
    }
    t[0]^=0x01;
    uint8_t w4[4];
    uint8_t w5[4];
    uint8_t w6[4];
    uint8_t w7[4];

    for(int i=0;i<4;i++){
        w4[i]=w0[i]^t[i];
        w5[i]=w1[i]^w4[i];
        w6[i]=w2[i]^w5[i];
        w7[i]=w3[i]^w6[i];
    }

    for(int i=0;i<4;i++){
        round_key_1[i]=w4[i];
        round_key_1[i+4]=w5[i];
        round_key_1[i+8]=w6[i];
        round_key_1[i+12]=w7[i];
    }
}

//round-2 key expansion (derived from round_key_1, same schedule step applied again)

static void expand_round_key_2(const uint8_t *round_key_1,uint8_t *round_key_2){
    uint8_t w0[4];
    uint8_t w1[4];
    uint8_t w2[4];
    uint8_t w3[4];
    uint8_t t[4];

    for(int i=0;i<4;i++){
        w0[i]=round_key_1[i];
        w1[i]=round_key_1[i+4];
        w2[i]=round_key_1[i+8];
        w3[i]=round_key_1[i+12];
    }

    t[0]=w3[1];
    t[1]=w3[2];
    t[2]=w3[3];
    t[3]=w3[0];
    for(int i=0;i<4;i++){
        t[i]=Sbox[t[i]];
    }
    t[0]^=0x02;
    uint8_t w4[4];
    uint8_t w5[4];
    uint8_t w6[4];
    uint8_t w7[4];

    for(int i=0;i<4;i++){
        w4[i]=w0[i]^t[i];
        w5[i]=w1[i]^w4[i];
        w6[i]=w2[i]^w5[i];
        w7[i]=w3[i]^w6[i];
    }

    for(int i=0;i<4;i++){
        round_key_2[i]=w4[i];
        round_key_2[i+4]=w5[i];
        round_key_2[i+8]=w6[i];
        round_key_2[i+12]=w7[i];
    }
}

//internal flush

static void flush_ttables_internal(void){
    uintptr_t base=(uintptr_t)FIXED_ADDR;
    for(size_t offset=0;offset<TTABLE_SIZE;offset+=64){
        _mm_clflush((void*)(base+offset));
    }
    _mm_mfence();
}


//round-1

void aes_round1(const uint8_t *plaintext,const uint8_t *key,uint8_t *out){
    uint8_t state[16];
    for(int i=0;i<16;i++){
        state[i]=plaintext[i]^key[i];
    }
    round_ttable_core(state,out);
}

//round-2
void aes_round2(const uint8_t *plaintext,const uint8_t *key,uint8_t *out){
    uint8_t state0[16];
    uint8_t state1_prekey[16];
    uint8_t round_key_1[16];
    uint8_t state1[16];
    for(int i=0;i<16;i++){
        state0[i]=plaintext[i]^key[i];
    }
    round_ttable_core(state0,state1_prekey);
    expand_round_key_1(key,round_key_1);
    for(int i=0;i<16;i++){
        state1[i]=state1_prekey[i]^round_key_1[i];
    }
    flush_ttables_internal();
    round_ttable_core(state1,out);
}

//delay mode
#ifndef AES_SLEEP_DELAY_CYCLES
#define AES_SLEEP_DELAY_CYCLES 20000ULL
#endif

static inline void aes_phase_delay(void){
    #ifdef AES_SLEEP_MODE
        unsigned int aux;
        uint64_t start=__rdtscp(&aux);
        while(__rdtscp(&aux)-start<AES_SLEEP_DELAY_CYCLES){
            _mm_pause();
        }
    #endif
}

int aes_sleep_mode_enabled(void){
    #ifdef AES_SLEEP_MODE
        return 1;
    #else
        return 0;
    #endif
}

//windowed-round-2

void aes_round2_windowed(const uint8_t *plaintext,const uint8_t *key,uint8_t *out, uint64_t *tsc_r1_start, uint64_t *tsc_r1_end,uint64_t *tsc_r2_start,uint64_t *tsc_r2_end){
    uint8_t state0[16];
    uint8_t state1_prekey[16];
    uint8_t round_key_1[16];
    uint8_t state1[16];
    unsigned int aux;
    uint64_t t_r1_start;
    uint64_t t_r1_end;
    uint64_t t_r2_start;
    uint64_t t_r2_end;
    for(int i=0;i<16;i++){
        state0[i]=plaintext[i]^key[i];
    }

    t_r1_start=__rdtscp(&aux);
    round_ttable_core(state0,state1_prekey);
    t_r1_end=__rdtscp(&aux);
    expand_round_key_1(key,round_key_1);
    for(int i=0;i<16;i++){
        state1[i]=state1_prekey[i]^round_key_1[i];
    }
    aes_phase_delay();

    t_r2_start=__rdtscp(&aux);
    round_ttable_core(state1,out);
    t_r2_end=__rdtscp(&aux);
    if(tsc_r1_start!=NULL){*tsc_r1_start=t_r1_start;}
    if(tsc_r1_end!=NULL){*tsc_r1_end=t_r1_end;}
    if(tsc_r2_start!=NULL){*tsc_r2_start=t_r2_start;}
    if(tsc_r2_end!=NULL){*tsc_r2_end=t_r2_end;}
}

//windowed-round-3
//
//Same structure as aes_round2_windowed, chained one round further.
//Round 3 exists only to demonstrate that execution continues past
//round 2 -- its output/timing is not used to recover any key bits.
//No internal flush is issued between round 2 and round 3: the
//attacker is responsible for any eviction in that gap, exactly as
//it already is between round 1 and round 2.
//
//We deliberately do not read back a round-3 "end" timestamp: the
//caller only needs round3_start (the round-2/round-3 boundary) to
//build the next windowed gap, mirroring how round1_end is the only
//boundary timestamp phase 2 needs out of round 1.

void aes_round3_windowed(const uint8_t *plaintext,const uint8_t *key,uint8_t *out, uint64_t *tsc_r1_start, uint64_t *tsc_r1_end,uint64_t *tsc_r2_start,uint64_t *tsc_r2_end,uint64_t *tsc_r3_start){
    uint8_t state0[16];
    uint8_t state1_prekey[16];
    uint8_t round_key_1[16];
    uint8_t state1[16];
    uint8_t state2_prekey[16];
    uint8_t round_key_2[16];
    uint8_t state2[16];
    unsigned int aux;
    uint64_t t_r1_start;
    uint64_t t_r1_end;
    uint64_t t_r2_start;
    uint64_t t_r2_end;
    uint64_t t_r3_start;

    for(int i=0;i<16;i++){
        state0[i]=plaintext[i]^key[i];
    }

    t_r1_start=__rdtscp(&aux);
    round_ttable_core(state0,state1_prekey);
    t_r1_end=__rdtscp(&aux);
    expand_round_key_1(key,round_key_1);
    for(int i=0;i<16;i++){
        state1[i]=state1_prekey[i]^round_key_1[i];
    }
    aes_phase_delay();

    t_r2_start=__rdtscp(&aux);
    round_ttable_core(state1,state2_prekey);
    t_r2_end=__rdtscp(&aux);
    expand_round_key_2(round_key_1,round_key_2);
    for(int i=0;i<16;i++){
        state2[i]=state2_prekey[i]^round_key_2[i];
    }
    aes_phase_delay();

    t_r3_start=__rdtscp(&aux);
    round_ttable_core(state2,out);

    if(tsc_r1_start!=NULL){*tsc_r1_start=t_r1_start;}
    if(tsc_r1_end!=NULL){*tsc_r1_end=t_r1_end;}
    if(tsc_r2_start!=NULL){*tsc_r2_start=t_r2_start;}
    if(tsc_r2_end!=NULL){*tsc_r2_end=t_r2_end;}
    if(tsc_r3_start!=NULL){*tsc_r3_start=t_r3_start;}
}

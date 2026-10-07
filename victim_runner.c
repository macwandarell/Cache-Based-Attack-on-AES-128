#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <immintrin.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "control_shared.h"

#define FIXED_ADDR ((void*)0x500000000000ULL)
#define TTABLE_SIZE 4096
#define VICTIM_KEY0 0x00

typedef uint32_t *(*get_ttable_address_fn)(void);
typedef void (*aes_round1_fn)(const uint8_t*,const uint8_t*,uint8_t*);
typedef void (*aes_round2_fn)(const uint8_t*,const uint8_t*,uint8_t*);
typedef void (*aes_round2_windowed_fn)(const uint8_t*,const uint8_t*,uint8_t*,uint64_t*,uint64_t*,uint64_t*,uint64_t*);
typedef int (*aes_sleep_mode_enabled_fn)(void);

//error
static void die(const char *message){
    perror(message);
    exit(EXIT_FAILURE);
}

//cpu affinity
static void set_cpu(int cpu){
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu,&set);
    if(sched_setaffinity(0,sizeof(set),&set)==-1){die("sched_setaffinity");}
}

//pipe write
static void write_exact(int fd,const void *buffer,size_t length){
    const uint8_t *ptr=(const uint8_t *)buffer;
    while(length!=0){
        ssize_t written=write(fd,ptr,length);
        if(written<0){
            if(errno==EINTR)continue;
            die("write");
        }
        if(written==0)exit(EXIT_FAILURE);
        ptr+=(size_t)written;
        length-=(size_t)written;
    }
}

//control block creation
static control_block_t *create_control_block(void){
    int fd=shm_open(CONTROL_SHM_NAME,O_CREAT|O_RDWR,0666);
    if(fd==-1)die("shm_open control");
    if(ftruncate(fd,sizeof(control_block_t))==-1){close(fd);die("ftruncate control");}

    void *ptr=mmap(NULL,sizeof(control_block_t),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    close(fd);
    if(ptr==MAP_FAILED)die("mmap control");

    memset(ptr,0,sizeof(control_block_t));
    return (control_block_t *)ptr;
}

//flush all t-table lines
static void flush_ttables(void *ttable){
    uintptr_t base=(uintptr_t)ttable;
    for(size_t offset=0;offset<TTABLE_SIZE;offset+=64){
        _mm_clflush((void*)(base+offset));
    }
    _mm_mfence();
}

//main
int main(int argc,char **argv){
    const char *library_path=argc>=3?argv[2]:"./libaes.so";
    int cpu=argc>=4?atoi(argv[3]):4;

    set_cpu(cpu);

    //load library
    void *handle=dlopen(library_path,RTLD_NOW);
    if(handle==NULL){
        fprintf(stderr,"[-] dlopen(%s): %s\n",library_path,dlerror());
        return EXIT_FAILURE;
    }

    dlerror();
    get_ttable_address_fn get_ttable_address=(get_ttable_address_fn)dlsym(handle,"get_ttable_address");
    const char *error=dlerror();
    if(error!=NULL||get_ttable_address==NULL){
        fprintf(stderr,"[-] get_ttable_address: %s\n",error?error:"unknown");
        return EXIT_FAILURE;
    }

    dlerror();
    aes_round1_fn aes_round1=(aes_round1_fn)dlsym(handle,"aes_round1");
    error=dlerror();
    if(error!=NULL||aes_round1==NULL){
        fprintf(stderr,"[-] aes_round1: %s\n",error?error:"unknown");
        return EXIT_FAILURE;
    }

    dlerror();
    aes_round2_fn aes_round2=(aes_round2_fn)dlsym(handle,"aes_round2");
    error=dlerror();
    if(error!=NULL||aes_round2==NULL){
        fprintf(stderr,"[-] aes_round2: %s\n",error?error:"unknown");
        return EXIT_FAILURE;
    }

    dlerror();
    aes_round2_windowed_fn aes_round2_windowed=(aes_round2_windowed_fn)dlsym(handle,"aes_round2_windowed");
    error=dlerror();
    if(error!=NULL||aes_round2_windowed==NULL){
        fprintf(stderr,"[-] aes_round2_windowed: %s\n",error?error:"unknown");
        return EXIT_FAILURE;
    }

    dlerror();
    aes_sleep_mode_enabled_fn aes_sleep_mode_enabled=(aes_sleep_mode_enabled_fn)dlsym(handle,"aes_sleep_mode_enabled");
    error=dlerror();
    if(error!=NULL||aes_sleep_mode_enabled==NULL){
        fprintf(stderr,"[-] aes_sleep_mode_enabled: %s\n",error?error:"unknown");
        return EXIT_FAILURE;
    }

    void *ttable=(void *)get_ttable_address();
    if(ttable!=FIXED_ADDR){
        fprintf(stderr,"[-] Unexpected T-table address: %p\n",ttable);
        return EXIT_FAILURE;
    }

    //flush initial table state
    flush_ttables(ttable);

    //control block
    control_block_t *control=create_control_block();
    control->sleep_mode_active=(uint8_t)aes_sleep_mode_enabled();

    fprintf(stderr,"[*] Loaded %s (AES_SLEEP_MODE %s)\n",library_path,control->sleep_mode_active?"ENABLED":"disabled");

    //fixed secret key
    //this remains victim-side lab configuration.
    //the attacker does not obtain it from the AES API.
    uint8_t key[16]={
        VICTIM_KEY0,
        0x13,0x24,0xf3,
        0xd8,0x5a,0x16,0x07,
        0x0c,0xc3,0xaf,0x4b,
        0x8a,0x3d,0xd5,0x69
    };

    //ground truth is only for experimental verification.
    //it is not consulted by the recovery calculations.
    for(int i=0;i<16;i++){
        control->real_key[i]=key[i];
    }
    _mm_mfence();

    //ready
    {
        char ready='R';
        write_exact(STDOUT_FILENO,&ready,1);
    }

    //persistent request loop
    //the victim executes the selected operation naturally.
    //there are no attacker-controlled pauses at round boundaries.
    uint32_t seen_request=0;
    uint8_t output[16];

    for(;;){
        while(control->request_seq==seen_request){
            _mm_pause();
        }

        seen_request=control->request_seq;
        _mm_mfence();

        if(control->quit)break;

        uint8_t plaintext[16];
        for(int i=0;i<16;i++){
            plaintext[i]=control->plaintext[i];
        }

        uint8_t mode=control->mode;

        //round 1 only
        if(mode==CONTROL_MODE_ROUND1){
            aes_round1(plaintext,key,output);
            for(int i=0;i<16;i++){
                control->last_round1_output[i]=output[i];
            }
        }

        //two-round aes
        else if(mode==CONTROL_MODE_ROUND2){
            aes_round2(plaintext,key,output);
            for(int i=0;i<16;i++){
                control->last_round2_output[i]=output[i];
            }
        }

        //two-round aes, windowed
        //no internal flush.
        //phase 1 reads the four timestamps for calibration.
        //phase 2 and phase 3 do not read them.
        else if(mode==CONTROL_MODE_ROUND2_NOFLUSH){
            uint64_t tsc_r1_start=0;
            uint64_t tsc_r1_end=0;
            uint64_t tsc_r2_start=0;
            uint64_t tsc_r2_end=0;

            aes_round2_windowed(plaintext,key,output,&tsc_r1_start,&tsc_r1_end,&tsc_r2_start,&tsc_r2_end);

            for(int i=0;i<16;i++){
                control->last_round2_output[i]=output[i];
            }

            control->round1_start_tsc=tsc_r1_start;
            control->round1_end_tsc=tsc_r1_end;
            control->round2_start_tsc=tsc_r2_start;
            control->round2_end_tsc=tsc_r2_end;
        }

        else{
            fprintf(stderr,"[-] Invalid victim mode: %u\n",(unsigned int)mode);
            break;
        }

        _mm_mfence();
        control->response_seq=seen_request;
        _mm_mfence();
    }

    //cleanup
    munmap(control,sizeof(control_block_t));
    dlclose(handle);
    return EXIT_SUCCESS;
}
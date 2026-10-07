#ifndef CONTROL_SHARED_H
#define CONTROL_SHARED_H
#include <stdint.h>
#define CONTROL_SHM_NAME "/aes_control_shm"
#define CONTROL_MODE_ROUND1 1
#define CONTROL_MODE_ROUND2 2
#define CONTROL_MODE_ROUND2_NOFLUSH 3

typedef struct{
    volatile uint32_t request_seq;
    volatile uint32_t response_seq;
    volatile uint8_t mode;
    volatile uint8_t plaintext[16];
    volatile uint8_t real_key[16];
    volatile uint8_t last_round1_output[16];
    volatile uint8_t last_round2_output[16];
    volatile uint64_t round1_start_tsc;
    volatile uint64_t round1_end_tsc;
    volatile uint64_t round2_start_tsc;
    volatile uint64_t round2_end_tsc;
    volatile uint8_t sleep_mode_active;
    volatile uint8_t quit;
    uint8_t padding[32];
} control_block_t;

#endif
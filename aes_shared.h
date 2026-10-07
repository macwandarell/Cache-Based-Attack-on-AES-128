#ifndef AES_SHARED_H
#define AES_SHARED_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <immintrin.h>
uint32_t *get_ttable_address(void);
void aes_round1(const uint8_t *plaintext,const uint8_t *key,uint8_t *out);
void aes_round2(const uint8_t *plaintext,const uint8_t *key,uint8_t *out);
int aes_sleep_mode_enabled(void);
void aes_round2_windowed(const uint8_t *plaintext,const uint8_t *key,uint8_t *out, uint64_t *tsc_r1_start, uint64_t *tsc_r1_end,uint64_t *tsc_r2_start,uint64_t *tsc_r2_end);

#endif
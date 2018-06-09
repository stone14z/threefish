/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "argon2.h"

#define MAX_COST 0x3fff
#define MAX_MEM 0x1fffff
#define MAX_COMPLEXITY 0x3ffffff

#define MAX_THREADS 0x03
#define MAX_DELAY_SECS 0x0f

#define HASHLEN 64
#define SALTLEN 16
#define PWD "password"


int main(void) {
    uint8_t hash1[HASHLEN];
    uint8_t salt[SALTLEN];
    FILE* fd_ = NULL; 

    unsigned int  t_cost;            // 1-pass computation
    unsigned int  m_cost;      // 64 mebibytes memory usage
    unsigned int  parallelism;       // number of threads and lanes
    unsigned long complexity;       
    uint8_t *pwd = (uint8_t *)strdup(PWD);
    uint32_t pwdlen = strlen((char *)pwd);
    unsigned int  max_loops = 11;
    struct timespec t_delay;
    struct timespec t_rem;

    fd_ = fopen("/dev/urandom", "r");

    while (max_loops--) {

       do {

          fread( &t_cost, 4, 1, fd_);
          t_cost |= 1;
          t_cost &= MAX_COST;

          fread( &m_cost, 4, 1, fd_);
          m_cost |= 1;
          m_cost &= MAX_MEM;

          complexity = (unsigned long)t_cost * (unsigned long)m_cost;

       } while (complexity > MAX_COMPLEXITY);

	    fread( &parallelism, 1, 1, fd_);
	    parallelism &= MAX_THREADS;
       if (!parallelism) parallelism++;

	    fread( &t_delay.tv_sec, 4, 1, fd_);
	    t_delay.tv_sec &= MAX_DELAY_SECS;

	    fread( &t_delay.tv_nsec, 8, 1, fd_);
	    t_delay.tv_nsec |= 1;

	    printf( "cost %d mem %dK threads %d delay %ld sec\n", t_cost, m_cost, parallelism, (t_delay.tv_sec));

	    memset( salt, 0x3c, SALTLEN );

	    // high-level API
	    argon2id_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash1, HASHLEN);

	    nanosleep(&t_delay, &t_rem);

    }

    fclose(fd_);

    return 0;
}

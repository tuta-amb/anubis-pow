/*
 * anubis-solve.c - native multithreaded solver for Anubis "fast" proof-of-work
 *
 * Verified against Anubis v1.28.2 (TecharoHQ/anubis):
 *   - web/js/worker/sha256.ts: hash = SHA-256(randomData + nonce), nonce is a
 *     decimal string starting at 0, each worker steps by thread count.
 *   - lib/challenge/proofofwork/proofofwork.go Validate(): the response must
 *     equal the hex digest and have `difficulty` leading zero hex nibbles.
 *
 * Usage: anubis-solve <randomData> <difficulty> [threads]
 * Prints on stdout, one line: <nonce> <hexdigest>
 * Exit 0 on success, 1 on usage error.
 *
 * Build: cc -O3 -pthread -o anubis-solve anubis-solve.c
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

/* ---- compact SHA-256 (public domain style, FIPS 180-4) ---- */

typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    size_t buflen;
} sha256_ctx;

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(sha256_ctx *c, const uint8_t *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[i*4] << 24 | (uint32_t)p[i*4+1] << 16 |
               (uint32_t)p[i*4+2] << 8 | (uint32_t)p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i-15],7) ^ ROTR(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROTR(w[i-2],17) ^ ROTR(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3],
             e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

static void sha256_init(sha256_ctx *c) {
    static const uint32_t H0[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    memcpy(c->h, H0, sizeof H0);
    c->len = 0;
    c->buflen = 0;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t n) {
    const uint8_t *p = data;
    c->len += n;
    if (c->buflen) {
        size_t take = 64 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        n -= take;
        if (c->buflen == 64) {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
    while (n >= 64) {
        sha256_block(c, p);
        p += 64;
        n -= 64;
    }
    if (n) {
        memcpy(c->buf, p, n);
        c->buflen = n;
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buflen != 56)
        sha256_update(c, &zero, 1);
    uint8_t lenbuf[8];
    for (int i = 0; i < 8; i++)
        lenbuf[7 - i] = (uint8_t)(bits >> (i * 8));
    sha256_update(c, lenbuf, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}

/* ---- PoW worker ---- */

static char g_data[256];          /* randomData, hex from the challenge page */
static size_t g_datalen;
static int g_difficulty;
static int g_threads;
static volatile int g_found = 0;
static uint64_t g_found_nonce;
static uint8_t g_found_hash[32];

/* leading-zero check matching both the JS worker and the Go validator:
 * difficulty counts leading zero hex nibbles of the digest. */
static int has_difficulty(const uint8_t h[32], int difficulty) {
    int full = difficulty / 2;
    for (int i = 0; i < full; i++)
        if (h[i] != 0)
            return 0;
    if (difficulty & 1)
        if (h[full] >> 4 != 0)
            return 0;
    return 1;
}

static void *worker(void *arg) {
    uint64_t start = (uint64_t)(uintptr_t)arg;
    char input[320];
    memcpy(input, g_data, g_datalen);
    uint8_t hash[32];

    for (uint64_t nonce = start; !g_found; nonce += (uint64_t)g_threads) {
        int nlen = snprintf(input + g_datalen, sizeof input - g_datalen,
                            "%llu", (unsigned long long)nonce);
        sha256_ctx c;
        sha256_init(&c);
        sha256_update(&c, input, g_datalen + (size_t)nlen);
        sha256_final(&c, hash);
        if (has_difficulty(hash, g_difficulty)) {
            if (!g_found) {
                g_found = 1;
                g_found_nonce = nonce;
                memcpy(g_found_hash, hash, 32);
            }
            break;
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <randomData> <difficulty> [threads]\n", argv[0]);
        return 1;
    }
    g_datalen = strlen(argv[1]);
    if (g_datalen == 0 || g_datalen >= sizeof g_data) {
        fprintf(stderr, "randomData length %zu out of range\n", g_datalen);
        return 1;
    }
    memcpy(g_data, argv[1], g_datalen);
    g_difficulty = atoi(argv[2]);
    if (g_difficulty < 0 || g_difficulty > 62) {
        fprintf(stderr, "difficulty %d out of range\n", g_difficulty);
        return 1;
    }
    g_threads = argc > 3 ? atoi(argv[3]) : 0;
    if (g_threads <= 0) {
        long n = sysconf(_SC_NPROCESSORS_ONLN);
        g_threads = n > 0 ? (int)n : 1;
    }

    pthread_t *t = malloc(sizeof *t * (size_t)g_threads);
    for (uintptr_t i = 0; i < (uintptr_t)g_threads; i++)
        pthread_create(&t[i], NULL, worker, (void *)i);
    for (int i = 0; i < g_threads; i++)
        pthread_join(t[i], NULL);
    free(t);

    if (!g_found) {
        fprintf(stderr, "no solution found (impossible unless interrupted)\n");
        return 1;
    }

    printf("%llu ", (unsigned long long)g_found_nonce);
    for (int i = 0; i < 32; i++)
        printf("%02x", g_found_hash[i]);
    printf("\n");
    return 0;
}

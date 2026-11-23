/*
 * pow-solve.c - native multithreaded solver for Anubis and go-away
 * proof-of-work challenges.
 *
 * Verified against Anubis v1.28.2 (TecharoHQ/anubis) and go-away master
 * (git.gammaspectra.live/git/go-away) sources:
 *
 *   fast        Anubis "fast"/"slow" (lib/challenge/proofofwork/proofofwork.go,
 *               web/js/worker/sha256.ts): SHA-256(randomData + decimal nonce),
 *               nonce from 0; digest needs `difficulty` leading zero hex
 *               nibbles.
 *
 *   wasm-sha256 Anubis wasm sha256 (wasm/pow/sha256/src/lib.rs): challenge is
 *               hex; nonce is a u32 appended to the raw challenge bytes,
 *               little-endian when the last challenge byte >= 128, otherwise
 *               big-endian; digest needs `difficulty` leading zero BITS.
 *
 *   goaway      go-away js-pow-sha256 (embed/challenge/js-pow-sha256/runtime/
 *               runtime.go, static/load.mjs): challenge and target are hex;
 *               nonce is an 8-byte little-endian counter appended to the
 *               challenge bytes; SHA-256(challenge || nonce) must be < target
 *               (equivalently: `difficulty` leading zero bits).
 *
 * Usage:
 *   pow-solve fast        <randomData> <difficulty> [threads]
 *       -> "<nonce> <hexdigest>"
 *   pow-solve wasm-sha256 <randomDataHex> <difficultyBits> [threads]
 *       -> "<nonce> <hexdigest>"
 *   pow-solve goaway      <challengeHex> <targetHex> [threads]
 *       -> "<hex(challenge || nonce8)>"  (the __goaway_token value)
 *
 * Build: cc -O3 -pthread -o pow-solve pow-solve.c
 * Static: cc -O3 -pthread -static -o pow-solve pow-solve.c
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

/* ---- compact SHA-256 (FIPS 180-4) ---- */

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

static void sha256_once(const uint8_t *data, size_t n, uint8_t out[32]) {
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, n);
    sha256_final(&c, out);
}

/* ---- shared helpers ---- */

static int hexval(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* returns decoded length, or -1 on bad hex */
static long hex_decode(const char *s, uint8_t *out, long outmax) {
    size_t n = strlen(s);
    if (n % 2 != 0 || (long)(n / 2) > outmax) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval(s[i*2]), lo = hexval(s[i*2+1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return (long)(n / 2);
}

static void print_hex(const uint8_t *p, long n) {
    for (long i = 0; i < n; i++)
        printf("%02x", p[i]);
}

/* leading zero nibbles (Anubis fast/slow rule) */
static int has_difficulty_nibbles(const uint8_t h[32], int difficulty) {
    int full = difficulty / 2;
    for (int i = 0; i < full; i++)
        if (h[i] != 0)
            return 0;
    if (difficulty & 1)
        if (h[full] >> 4 != 0)
            return 0;
    return 1;
}

/* leading zero bits (Anubis wasm rule and go-away rule) */
static int has_difficulty_bits(const uint8_t *h, long n, int difficulty) {
    int remaining = difficulty;
    for (long i = 0; i < n && remaining > 0; i++) {
        uint8_t b = h[i];
        if (remaining >= 8) {
            if (b != 0) return 0;
            remaining -= 8;
        } else {
            uint8_t mask = (uint8_t)(0xFF << (8 - remaining));
            if ((b & mask) != 0) return 0;
            remaining = 0;
        }
    }
    return 1;
}

/* ---- shared worker state ---- */

static int g_threads;
static volatile int g_found = 0;

/* fast/slow + wasm inputs */
static uint8_t g_data[512];
static long g_datalen;
static int g_difficulty;

static int default_threads(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
}

static int resolve_threads(char **argv, int idx) {
    int t = atoi(argv[idx]);
    if (t <= 0) t = default_threads();
    return t;
}

static int run_threads(void *(*fn)(void *)) {
    pthread_t *t = malloc(sizeof *t * (size_t)g_threads);
    if (!t) { fprintf(stderr, "out of memory\n"); return 1; }
    for (uintptr_t i = 0; i < (uintptr_t)g_threads; i++)
        pthread_create(&t[i], NULL, fn, (void *)i);
    for (int i = 0; i < g_threads; i++)
        pthread_join(t[i], NULL);
    free(t);
    if (!g_found) {
        fprintf(stderr, "no solution found (impossible unless interrupted)\n");
        return 1;
    }
    return 0;
}

/* ---- mode: fast (also "slow"; identical server-side) ---- */

static uint64_t g_fast_nonce;
static uint8_t g_fast_hash[32];

static void *fast_worker(void *arg) {
    uint64_t start = (uint64_t)(uintptr_t)arg;
    uint8_t input[512 + 24];
    memcpy(input, g_data, (size_t)g_datalen);
    uint8_t hash[32];

    for (uint64_t nonce = start; !g_found; nonce += (uint64_t)g_threads) {
        int nlen = snprintf((char *)input + g_datalen, sizeof input - (size_t)g_datalen,
                            "%llu", (unsigned long long)nonce);
        sha256_once(input, (size_t)g_datalen + (size_t)nlen, hash);
        if (has_difficulty_nibbles(hash, g_difficulty)) {
            if (!g_found) {
                g_found = 1;
                g_fast_nonce = nonce;
                memcpy(g_fast_hash, hash, 32);
            }
            break;
        }
    }
    return NULL;
}

static int mode_fast(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: pow-solve fast <randomData> <difficulty> [threads]\n");
        return 1;
    }
    size_t n = strlen(argv[1]);
    if (n == 0 || n > sizeof g_data) {
        fprintf(stderr, "randomData length %zu out of range\n", n);
        return 1;
    }
    memcpy(g_data, argv[1], n);
    g_datalen = (long)n;
    g_difficulty = atoi(argv[2]);
    if (g_difficulty < 0 || g_difficulty > 62) {
        fprintf(stderr, "difficulty %d out of range\n", g_difficulty);
        return 1;
    }
    g_threads = argc > 3 ? resolve_threads(argv, 3) : default_threads();

    if (run_threads(fast_worker)) return 1;

    printf("%llu ", (unsigned long long)g_fast_nonce);
    print_hex(g_fast_hash, 32);
    printf("\n");
    return 0;
}

/* ---- mode: wasm-sha256 ---- */

static uint32_t g_wasm_nonce;
static uint8_t g_wasm_hash[32];
static int g_wasm_le; /* nonce byte order: LE when last challenge byte >= 128 */

static void *wasm_worker(void *arg) {
    uint32_t start = (uint32_t)(uintptr_t)arg;
    uint8_t input[512 + 4];
    memcpy(input, g_data, (size_t)g_datalen);
    uint8_t hash[32];
    uint32_t step = (uint32_t)g_threads;

    for (uint32_t nonce = start; !g_found; nonce += step) {
        if (g_wasm_le) {
            input[g_datalen+0] = (uint8_t)(nonce);
            input[g_datalen+1] = (uint8_t)(nonce >> 8);
            input[g_datalen+2] = (uint8_t)(nonce >> 16);
            input[g_datalen+3] = (uint8_t)(nonce >> 24);
        } else {
            input[g_datalen+0] = (uint8_t)(nonce >> 24);
            input[g_datalen+1] = (uint8_t)(nonce >> 16);
            input[g_datalen+2] = (uint8_t)(nonce >> 8);
            input[g_datalen+3] = (uint8_t)(nonce);
        }
        sha256_once(input, (size_t)g_datalen + 4, hash);
        if (has_difficulty_bits(hash, 32, g_difficulty)) {
            if (!g_found) {
                g_found = 1;
                g_wasm_nonce = nonce;
                memcpy(g_wasm_hash, hash, 32);
            }
            break;
        }
        if (UINT32_MAX - nonce < (uint32_t)step) {
            /* wrapped around the whole u32 space */
            if (!g_found) break;
        }
    }
    return NULL;
}

static int mode_wasm_sha256(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: pow-solve wasm-sha256 <randomDataHex> <difficultyBits> [threads]\n");
        return 1;
    }
    long n = hex_decode(argv[1], g_data, sizeof g_data);
    if (n <= 0) {
        fprintf(stderr, "randomData is not valid hex\n");
        return 1;
    }
    g_datalen = n;
    g_difficulty = atoi(argv[2]);
    if (g_difficulty < 0 || g_difficulty > 255) {
        fprintf(stderr, "difficulty %d out of range\n", g_difficulty);
        return 1;
    }
    g_wasm_le = g_data[g_datalen - 1] >= 128;
    g_threads = argc > 3 ? resolve_threads(argv, 3) : default_threads();

    if (run_threads(wasm_worker)) return 1;

    printf("%u ", g_wasm_nonce);
    print_hex(g_wasm_hash, 32);
    printf("\n");
    return 0;
}

/* ---- mode: goaway ---- */

static uint8_t g_target[32];
static uint8_t g_goaway_result[64]; /* challenge || nonce */
static long g_goaway_result_len;

static void *goaway_worker(void *arg) {
    uint64_t start = (uint64_t)(uintptr_t)arg;
    uint8_t input[64];
    memcpy(input, g_data, (size_t)g_datalen);
    uint8_t *nonceb = input + g_datalen;
    uint8_t hash[32];
    uint64_t step = (uint64_t)g_threads;

    for (uint64_t ctr = start; !g_found; ctr += step) {
        for (int i = 0; i < 8; i++)
            nonceb[i] = (uint8_t)(ctr >> (8 * i));
        sha256_once(input, (size_t)g_datalen + 8, hash);
        /* hash < target, bytewise big-endian compare (load.mjs lessThan) */
        int ok = 0;
        for (int i = 0; i < 32; i++) {
            if (hash[i] < g_target[i]) { ok = 1; break; }
            if (hash[i] > g_target[i]) { break; }
        }
        if (ok) {
            if (!g_found) {
                g_found = 1;
                memcpy(g_goaway_result, input, (size_t)g_datalen + 8);
                g_goaway_result_len = g_datalen + 8;
            }
            break;
        }
        if (UINT64_MAX - ctr < step) {
            if (!g_found) break;
        }
    }
    return NULL;
}

static int mode_goaway(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: pow-solve goaway <challengeHex> <targetHex> [threads]\n");
        return 1;
    }
    long n = hex_decode(argv[1], g_data, 56);
    if (n <= 0) {
        fprintf(stderr, "challenge is not valid hex\n");
        return 1;
    }
    g_datalen = n;
    if (hex_decode(argv[2], g_target, 32) != 32) {
        fprintf(stderr, "target is not 32 bytes of hex\n");
        return 1;
    }
    g_threads = argc > 3 ? resolve_threads(argv, 3) : default_threads();

    if (run_threads(goaway_worker)) return 1;

    print_hex(g_goaway_result, g_goaway_result_len);
    printf("\n");
    return 0;
}

/* ---- main ---- */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s fast <randomData> <difficulty> [threads]\n"
            "  %s wasm-sha256 <randomDataHex> <difficultyBits> [threads]\n"
            "  %s goaway <challengeHex> <targetHex> [threads]\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }
    /* "slow" is the same wire protocol as "fast" */
    if (strcmp(argv[1], "fast") == 0 || strcmp(argv[1], "slow") == 0)
        return mode_fast(argc - 1, argv + 1);
    if (strcmp(argv[1], "wasm-sha256") == 0 || strcmp(argv[1], "sha256") == 0)
        return mode_wasm_sha256(argc - 1, argv + 1);
    if (strcmp(argv[1], "goaway") == 0)
        return mode_goaway(argc - 1, argv + 1);
    fprintf(stderr, "unknown mode '%s'\n", argv[1]);
    return 1;
}

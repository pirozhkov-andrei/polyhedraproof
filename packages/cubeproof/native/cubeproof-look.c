/*
 * cubeproof-look: the native helper of lookahead-v1 (specification §9.3).
 *
 *   cubeproof-look REQUEST_FILE     one cubeproof-look-request-1 document in, one
 *                                   cubeproof-look-result-1 document (J + LF) on stdout
 *   cubeproof-look --version        "cubeproof-look 1 lookahead-v1"
 *
 * The algorithm is the one of the Python reference (cubeproof.split.lookahead); its module
 * docstring is the normative description, including the probe accounting. With the same
 * probe_limit and no wall budget the result bytes are identical to the reference's.
 *
 * Exit codes: 0 valid result on stdout; 2 bad usage or request; 3 formula unreadable, hash
 * mismatch or not canonical DIMACS; 4 resource (allocation) or size limit. A single
 * diagnostic line goes to stderr on failure; stdout carries only the result document.
 *
 * Build: python3 build.py (warnings are errors: -Wall -Wextra -Wpedantic -Werror).
 */
#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define VERSION_LINE "cubeproof-look 1 lookahead-v1"
#define REQUEST_FORMAT "cubeproof-look-request-1"
#define RESULT_FORMAT "cubeproof-look-result-1"
#define ALGORITHM "lookahead-v1"
#define K_MAX 20
#define SAMPLE_CHILDREN 16
/* Scores stay below 2^62 for V + 2 <= 2^28 (16 children, product of two V + 1 gains). */
#define MAX_VARIABLES 268435454u
#define MAX_FORMULA_BYTES ((uint64_t)1 << 31)
#define MAX_REQUEST_BYTES ((size_t)1 << 26)
#define PATH_CAP 4096

enum { EXIT_BAD_REQUEST = 2, EXIT_BAD_FORMULA = 3, EXIT_RESOURCE = 4 };

static _Noreturn void die(int code, const char *message) {
    fprintf(stderr, "cubeproof-look: %.200s\n", message);
    exit(code);
}

static void *xalloc(size_t count, size_t size) {
    void *memory;
    if (size != 0 && count > SIZE_MAX / size) die(EXIT_RESOURCE, "allocation too large");
    memory = calloc(count == 0 ? 1 : count, size == 0 ? 1 : size);
    if (memory == NULL) die(EXIT_RESOURCE, "out of memory");
    return memory;
}

static void *xgrow(void *memory, size_t count, size_t size) {
    void *grown;
    if (size != 0 && count > SIZE_MAX / size) die(EXIT_RESOURCE, "allocation too large");
    grown = realloc(memory, count * size);
    if (grown == NULL) die(EXIT_RESOURCE, "out of memory");
    return grown;
}

static uint64_t now_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) die(EXIT_RESOURCE, "no monotonic clock");
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

/* ---- SHA-256 ------------------------------------------------------------------------- */

typedef struct {
    uint32_t h[8];
    uint8_t block[64];
    uint64_t length;
    size_t fill;
} Sha;

static const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

static uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32u - n)); }

static void sha_compress(Sha *s, const uint8_t *chunk) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    unsigned i;
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)chunk[4 * i] << 24) | ((uint32_t)chunk[4 * i + 1] << 16) |
               ((uint32_t)chunk[4 * i + 2] << 8) | (uint32_t)chunk[4 * i + 3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) +
                      K256[i] + w[i];
        uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g, g = f, f = e, e = d + t1, d = c, c = b, b = a, a = t1 + t2;
    }
    s->h[0] += a, s->h[1] += b, s->h[2] += c, s->h[3] += d;
    s->h[4] += e, s->h[5] += f, s->h[6] += g, s->h[7] += h;
}

static void sha_init(Sha *s) {
    static const uint32_t init[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                     0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    memcpy(s->h, init, sizeof init);
    s->length = 0;
    s->fill = 0;
}

static void sha_update(Sha *s, const void *data, size_t n) {
    const uint8_t *p = (const uint8_t *)data;
    s->length += n;
    while (n > 0) {
        size_t take = 64 - s->fill;
        if (take > n) take = n;
        memcpy(s->block + s->fill, p, take);
        s->fill += take;
        p += take;
        n -= take;
        if (s->fill == 64) {
            sha_compress(s, s->block);
            s->fill = 0;
        }
    }
}

static void sha_final(Sha *s, uint8_t out[32]) {
    uint64_t bits = s->length * 8u;
    uint8_t pad = 0x80;
    unsigned i;
    sha_update(s, &pad, 1);
    pad = 0;
    while (s->fill != 56) sha_update(s, &pad, 1);
    for (i = 0; i < 8; i++) {
        uint8_t byte = (uint8_t)(bits >> (56 - 8 * i));
        sha_update(s, &byte, 1);
    }
    for (i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(s->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(s->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(s->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)s->h[i];
    }
}

static void to_hex(const uint8_t digest[32], char out[65]) {
    static const char digits[] = "0123456789abcdef";
    unsigned i;
    for (i = 0; i < 32; i++) {
        out[2 * i] = digits[digest[i] >> 4];
        out[2 * i + 1] = digits[digest[i] & 15];
    }
    out[64] = '\0';
}

/* ---- request ------------------------------------------------------------------------- */

typedef struct {
    char path[PATH_CAP + 1];
    char hash[65];
    int32_t *cube;
    size_t ncube;
    int k;
    int has_pool;
    int32_t *pool;
    size_t npool;
    int64_t probe_limit;
    int64_t wall_ms; /* 0: no wall budget */
} Request;

typedef struct {
    const char *p;
    const char *end;
} Cursor;

static _Noreturn void bad_request(const char *message) { die(EXIT_BAD_REQUEST, message); }

static void skip_ws(Cursor *c) {
    while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r'))
        c->p++;
}

static void expect(Cursor *c, char ch) {
    skip_ws(c);
    if (c->p >= c->end || *c->p != ch) bad_request("malformed request document");
    c->p++;
}

static int peek(Cursor *c, char ch) {
    skip_ws(c);
    return c->p < c->end && *c->p == ch;
}

static size_t put_utf8(char *out, uint32_t cp) {
    if (cp < 0x80) {
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    out[0] = (char)(0xE0 | (cp >> 12));
    out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[2] = (char)(0x80 | (cp & 0x3F));
    return 3;
}

static size_t parse_string(Cursor *c, char *out, size_t cap) {
    size_t n = 0;
    expect(c, '"');
    for (;;) {
        unsigned char ch;
        if (c->p >= c->end) bad_request("unterminated string");
        ch = (unsigned char)*c->p++;
        if (ch == '"') break;
        if (ch < 0x20) bad_request("control character in a string");
        if (ch == '\\') {
            if (c->p >= c->end) bad_request("unterminated string");
            ch = (unsigned char)*c->p++;
            switch (ch) {
                case '"': case '\\': case '/': break;
                case 'b': ch = '\b'; break;
                case 'f': ch = '\f'; break;
                case 'n': ch = '\n'; break;
                case 'r': ch = '\r'; break;
                case 't': ch = '\t'; break;
                case 'u': {
                    uint32_t cp = 0;
                    int i;
                    char encoded[4];
                    size_t len;
                    if (c->end - c->p < 4) bad_request("bad unicode escape");
                    for (i = 0; i < 4; i++) {
                        char d = *c->p++;
                        cp <<= 4;
                        if (d >= '0' && d <= '9') cp |= (uint32_t)(d - '0');
                        else if (d >= 'a' && d <= 'f') cp |= (uint32_t)(d - 'a' + 10);
                        else if (d >= 'A' && d <= 'F') cp |= (uint32_t)(d - 'A' + 10);
                        else bad_request("bad unicode escape");
                    }
                    if (cp >= 0xD800 && cp <= 0xDFFF) bad_request("surrogate escape");
                    len = put_utf8(encoded, cp);
                    if (n + len >= cap) bad_request("string too long");
                    memcpy(out + n, encoded, len);
                    n += len;
                    continue;
                }
                default: bad_request("bad escape");
            }
        }
        if (n + 1 >= cap) bad_request("string too long");
        out[n++] = (char)ch;
    }
    out[n] = '\0';
    return n;
}

static int64_t parse_int(Cursor *c) {
    int negative = 0;
    int digits = 0;
    int64_t value = 0;
    skip_ws(c);
    if (c->p < c->end && *c->p == '-') {
        negative = 1;
        c->p++;
    }
    if (c->p >= c->end || *c->p < '0' || *c->p > '9') bad_request("expected an integer");
    if (*c->p == '0' && c->p + 1 < c->end && c->p[1] >= '0' && c->p[1] <= '9')
        bad_request("leading zero");
    while (c->p < c->end && *c->p >= '0' && *c->p <= '9') {
        if (++digits > 18) bad_request("integer out of range");
        value = value * 10 + (*c->p - '0');
        c->p++;
    }
    if (c->p < c->end && (*c->p == '.' || *c->p == 'e' || *c->p == 'E'))
        bad_request("a number that is not an integer");
    return negative ? -value : value;
}

static int32_t *parse_int_array(Cursor *c, size_t *count) {
    int32_t *values = NULL;
    size_t n = 0, cap = 0;
    expect(c, '[');
    if (!peek(c, ']')) {
        for (;;) {
            int64_t v = parse_int(c);
            if (v < INT32_MIN || v > INT32_MAX) bad_request("literal out of range");
            if (n == cap) {
                cap = cap == 0 ? 16 : cap * 2;
                values = (int32_t *)xgrow(values, cap, sizeof *values);
            }
            values[n++] = (int32_t)v;
            if (peek(c, ',')) {
                c->p++;
                continue;
            }
            break;
        }
    }
    expect(c, ']');
    *count = n;
    return values;
}

static int parse_null(Cursor *c) {
    skip_ws(c);
    if (c->end - c->p >= 4 && memcmp(c->p, "null", 4) == 0) {
        c->p += 4;
        return 1;
    }
    return 0;
}

enum { F_FORMAT = 1, F_PATH = 2, F_HASH = 4, F_CUBE = 8, F_K = 16, F_POOL = 32, F_PROBES = 64,
       F_WALL = 128, F_ALL = 255 };

static void parse_request(const char *data, size_t length, Request *r) {
    Cursor cursor = {data, data + length};
    Cursor *c = &cursor;
    unsigned seen = 0;
    char key[64];
    char format[64];
    size_t n;
    memset(r, 0, sizeof *r);
    expect(c, '{');
    for (;;) {
        unsigned flag;
        int64_t value;
        parse_string(c, key, sizeof key);
        expect(c, ':');
        if (strcmp(key, "format") == 0) flag = F_FORMAT;
        else if (strcmp(key, "formula_path") == 0) flag = F_PATH;
        else if (strcmp(key, "formula_sha256") == 0) flag = F_HASH;
        else if (strcmp(key, "cube") == 0) flag = F_CUBE;
        else if (strcmp(key, "k") == 0) flag = F_K;
        else if (strcmp(key, "pool") == 0) flag = F_POOL;
        else if (strcmp(key, "probe_limit") == 0) flag = F_PROBES;
        else if (strcmp(key, "wall_ms") == 0) flag = F_WALL;
        else bad_request("unknown request field");
        if (seen & flag) bad_request("duplicate request field");
        seen |= flag;
        switch (flag) {
            case F_FORMAT:
                parse_string(c, format, sizeof format);
                if (strcmp(format, REQUEST_FORMAT) != 0) bad_request("unknown request format");
                break;
            case F_PATH:
                n = parse_string(c, r->path, sizeof r->path);
                if (n == 0 || r->path[0] != '/' || strlen(r->path) != n)
                    bad_request("formula_path must be an absolute path");
                break;
            case F_HASH:
                n = parse_string(c, r->hash, sizeof r->hash);
                if (n != 64) bad_request("formula_sha256 must be 64 lowercase hex digits");
                for (n = 0; n < 64; n++) {
                    char d = r->hash[n];
                    if (!((d >= '0' && d <= '9') || (d >= 'a' && d <= 'f')))
                        bad_request("formula_sha256 must be 64 lowercase hex digits");
                }
                break;
            case F_CUBE: r->cube = parse_int_array(c, &r->ncube); break;
            case F_K:
                value = parse_int(c);
                if (value < 1 || value > K_MAX) bad_request("k must be in 1..20");
                r->k = (int)value;
                break;
            case F_POOL:
                if (parse_null(c)) r->has_pool = 0;
                else {
                    r->has_pool = 1;
                    r->pool = parse_int_array(c, &r->npool);
                }
                break;
            case F_PROBES:
                value = parse_int(c);
                if (value < 1) bad_request("probe_limit must be positive");
                r->probe_limit = value;
                break;
            default: /* F_WALL */
                if (parse_null(c)) r->wall_ms = 0;
                else {
                    value = parse_int(c);
                    if (value < 1) bad_request("wall_ms must be positive or null");
                    r->wall_ms = value;
                }
                break;
        }
        if (peek(c, ',')) {
            c->p++;
            continue;
        }
        break;
    }
    expect(c, '}');
    skip_ws(c);
    if (c->p != c->end) bad_request("trailing bytes after the request");
    if (seen != F_ALL) bad_request("a request field is missing");
}

/* ---- formula and propagation engine ------------------------------------------------------ */

typedef struct {
    uint32_t variables;
    uint32_t nclauses;       /* indexed clauses: no tautologies, no empty clause */
    int empty;               /* the formula contains the empty clause */
    uint64_t *cstart;        /* nclauses + 1 offsets into clits */
    int32_t *clits;          /* distinct literals */
    uint64_t *ostart;        /* 2 * (V + 1) + 2 offsets into occ */
    uint32_t *occ;           /* clause positions per literal slot */
    uint32_t *units;         /* positions of one-literal clauses */
    size_t nunits;
    int32_t *ntrue;
    int32_t *nfalse;
    uint8_t *value;          /* 0 unassigned, 1 true, 2 false */
    int32_t *trail;
    size_t ntrail;
    uint32_t *queue;
    size_t qlen;
    size_t root_mark;
    int root_conflict;
} Engine;

static size_t slot(int32_t literal) {
    return literal > 0 ? 2u * (size_t)literal : 2u * (size_t)(-(int64_t)literal) + 1u;
}

static int32_t clause_length(const Engine *e, uint32_t c) {
    return (int32_t)(e->cstart[c + 1] - e->cstart[c]);
}

static int eng_set(Engine *e, int32_t literal) {
    size_t i;
    int conflict = 0;
    int32_t variable = literal > 0 ? literal : -literal;
    size_t s = slot(literal), t = slot(-literal);
    e->value[variable] = literal > 0 ? 1 : 2;
    e->trail[e->ntrail++] = literal;
    for (i = (size_t)e->ostart[s]; i < (size_t)e->ostart[s + 1]; i++) e->ntrue[e->occ[i]]++;
    for (i = (size_t)e->ostart[t]; i < (size_t)e->ostart[t + 1]; i++) {
        uint32_t c = e->occ[i];
        e->nfalse[c]++;
        if (e->ntrue[c] == 0) {
            int32_t left = clause_length(e, c) - e->nfalse[c];
            if (left == 0) conflict = 1;
            else if (left == 1) e->queue[e->qlen++] = c;
        }
    }
    return conflict;
}

static int eng_propagate(Engine *e) {
    size_t head = 0;
    int conflict = 0;
    while (head < e->qlen && !conflict) {
        uint32_t c = e->queue[head++];
        uint64_t i;
        if (e->ntrue[c] != 0 || clause_length(e, c) - e->nfalse[c] != 1) continue;
        for (i = e->cstart[c]; i < e->cstart[c + 1]; i++) {
            int32_t literal = e->clits[i];
            int32_t variable = literal > 0 ? literal : -literal;
            if (e->value[variable] == 0) {
                conflict = eng_set(e, literal);
                break;
            }
        }
    }
    e->qlen = 0;
    return conflict;
}

static int eng_assume(Engine *e, int32_t literal) {
    int32_t variable = literal > 0 ? literal : -literal;
    uint8_t current = e->value[variable];
    if (current != 0) return (current == 1) != (literal > 0);
    if (eng_set(e, literal)) {
        e->qlen = 0;
        return 1;
    }
    return eng_propagate(e);
}

static void eng_replay(Engine *e, const int32_t *literals, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) (void)eng_set(e, literals[i]);
    e->qlen = 0;
}

static void eng_undo(Engine *e, size_t mark) {
    while (e->ntrail > mark) {
        int32_t literal = e->trail[--e->ntrail];
        int32_t variable = literal > 0 ? literal : -literal;
        size_t s = slot(literal), t = slot(-literal), i;
        e->value[variable] = 0;
        for (i = (size_t)e->ostart[s]; i < (size_t)e->ostart[s + 1]; i++) e->ntrue[e->occ[i]]--;
        for (i = (size_t)e->ostart[t]; i < (size_t)e->ostart[t + 1]; i++) e->nfalse[e->occ[i]]--;
    }
}

/* The whole file, at most `limit` bytes; `code` is the exit code of a file that cannot be read. */
static unsigned char *read_file(const char *path, uint64_t limit, int code, size_t *length) {
    FILE *stream = fopen(path, "rb");
    unsigned char *data = NULL;
    size_t n = 0, cap = 0;
    if (stream == NULL) die(code, "cannot open a file");
    for (;;) {
        size_t got;
        if (cap - n < 65536) {
            cap = cap == 0 ? 1 << 16 : cap * 2;
            data = (unsigned char *)xgrow(data, cap, 1);
        }
        got = fread(data + n, 1, cap - n, stream);
        n += got;
        if ((uint64_t)n > limit) die(EXIT_RESOURCE, "a file is larger than its limit");
        if (got == 0) break;
    }
    if (ferror(stream)) die(code, "cannot read a file");
    fclose(stream);
    *length = n;
    return data;
}

static _Noreturn void bad_formula(void) {
    die(EXIT_BAD_FORMULA, "the formula is not canonical DIMACS");
}

static uint64_t parse_count(const unsigned char *data, size_t length, size_t *pos) {
    uint64_t value = 0;
    size_t digits = 0;
    while (*pos < length && data[*pos] >= '0' && data[*pos] <= '9') {
        if (++digits > 10) bad_formula();
        value = value * 10 + (uint64_t)(data[*pos] - '0');
        (*pos)++;
    }
    if (digits == 0) bad_formula();
    return value;
}

static void load_formula(const unsigned char *data, size_t length, Engine *e) {
    size_t pos = 0;
    uint64_t variables, clauses, clause;
    size_t nlits = 0, caplits = 0;
    uint32_t *mark;
    int8_t *msign;
    uint32_t tag = 0;
    size_t i;
    uint64_t *count;
    memset(e, 0, sizeof *e);
    if (length < 9 || memcmp(data, "p cnf ", 6) != 0) bad_formula();
    pos = 6;
    variables = parse_count(data, length, &pos);
    if (pos >= length || data[pos++] != ' ') bad_formula();
    clauses = parse_count(data, length, &pos);
    if (pos >= length || data[pos++] != '\n') bad_formula();
    if (variables > MAX_VARIABLES) die(EXIT_RESOURCE, "too many variables for the helper");
    if (clauses > UINT32_MAX - 1 || clauses * 3 > length) bad_formula();
    e->variables = (uint32_t)variables;
    e->cstart = (uint64_t *)xalloc((size_t)clauses + 1, sizeof *e->cstart);
    e->units = (uint32_t *)xalloc((size_t)clauses, sizeof *e->units);
    mark = (uint32_t *)xalloc((size_t)variables + 1, sizeof *mark);
    msign = (int8_t *)xalloc((size_t)variables + 1, sizeof *msign);
    for (clause = 0; clause < clauses; clause++) {
        size_t start = nlits;
        int taut = 0;
        ++tag;
        if (pos < length && data[pos] == ' ') { /* the empty clause: " 0\n" */
            if (length - pos < 3 || data[pos + 1] != '0' || data[pos + 2] != '\n') bad_formula();
            pos += 3;
        } else {
            for (;;) {
                int negative = 0;
                uint64_t magnitude = 0;
                size_t digits = 0;
                if (pos < length && data[pos] == '-') {
                    negative = 1;
                    pos++;
                }
                while (pos < length && data[pos] >= '0' && data[pos] <= '9') {
                    if (++digits > 10) bad_formula();
                    magnitude = magnitude * 10 + (uint64_t)(data[pos] - '0');
                    pos++;
                }
                if (digits == 0) bad_formula();
                if (magnitude == 0) { /* the clause terminator "0\n" */
                    if (negative || pos >= length || data[pos++] != '\n') bad_formula();
                    break;
                }
                if (magnitude > variables || pos >= length || data[pos++] != ' ') bad_formula();
                if (mark[magnitude] == tag) {
                    if ((msign[magnitude] > 0) != !negative) taut = 1;
                    continue;
                }
                mark[magnitude] = tag;
                msign[magnitude] = negative ? -1 : 1;
                if (nlits == caplits) {
                    caplits = caplits == 0 ? 1024 : caplits * 2;
                    e->clits = (int32_t *)xgrow(e->clits, caplits, sizeof *e->clits);
                }
                e->clits[nlits++] = negative ? -(int32_t)magnitude : (int32_t)magnitude;
            }
        }
        if (taut) {
            nlits = start;
        } else if (nlits == start) {
            e->empty = 1;
        } else {
            if (nlits - start == 1) e->units[e->nunits++] = e->nclauses;
            e->cstart[e->nclauses] = start;
            e->nclauses++;
            e->cstart[e->nclauses] = nlits;
        }
    }
    if (pos != length) bad_formula();
    free(mark);
    free(msign);
    /* occurrence lists by literal slot */
    e->ostart = (uint64_t *)xalloc(2 * ((size_t)variables + 1) + 3, sizeof *e->ostart);
    count = e->ostart;
    for (i = 0; i < nlits; i++) count[slot(e->clits[i]) + 1]++;
    for (i = 0; i < 2 * ((size_t)variables + 1) + 2; i++) count[i + 1] += count[i];
    e->occ = (uint32_t *)xalloc(nlits, sizeof *e->occ);
    {
        uint64_t *fill = (uint64_t *)xalloc(2 * ((size_t)variables + 1) + 2, sizeof *fill);
        uint32_t c;
        for (c = 0; c < e->nclauses; c++) {
            uint64_t j;
            for (j = e->cstart[c]; j < e->cstart[c + 1]; j++) {
                size_t s = slot(e->clits[j]);
                e->occ[e->ostart[s] + fill[s]++] = c;
            }
        }
        free(fill);
    }
    e->ntrue = (int32_t *)xalloc(e->nclauses, sizeof *e->ntrue);
    e->nfalse = (int32_t *)xalloc(e->nclauses, sizeof *e->nfalse);
    e->value = (uint8_t *)xalloc((size_t)variables + 1, sizeof *e->value);
    e->trail = (int32_t *)xalloc((size_t)variables + 1, sizeof *e->trail);
    e->queue = (uint32_t *)xalloc((size_t)e->nclauses + 1, sizeof *e->queue);
    /* the root state: the unit clauses of F propagated once */
    if (e->empty) {
        e->root_conflict = 1;
    } else {
        for (i = 0; i < e->nunits; i++) e->queue[e->qlen++] = e->units[i];
        e->root_conflict = eng_propagate(e);
    }
    e->root_mark = e->ntrail;
}

static void free_engine(Engine *e) {
    free(e->cstart);
    free(e->clits);
    free(e->ostart);
    free(e->occ);
    free(e->units);
    free(e->ntrue);
    free(e->nfalse);
    free(e->value);
    free(e->trail);
    free(e->queue);
}

/* ---- the algorithm ---------------------------------------------------------------------- */

typedef struct {
    uint8_t digest[32];
    uint32_t index;
} Keyed;

static int keyed_less(const Keyed *a, const Keyed *b) {
    int c = memcmp(a->digest, b->digest, 32);
    return c < 0 || (c == 0 && a->index < b->index);
}

/* The sampled child indices of 2^width sign vectors; returns how many (at most 16). */
static size_t sample_children(const char *node, unsigned round, unsigned width, uint32_t *out) {
    size_t count = 0;
    uint64_t total = (uint64_t)1 << width;
    uint64_t i;
    char prefix[128];
    size_t plen;
    Keyed best[SAMPLE_CHILDREN];
    if (total <= SAMPLE_CHILDREN) {
        for (i = 0; i < total; i++) out[i] = (uint32_t)i;
        return (size_t)total;
    }
    /* node_id NUL round NUL, the round in decimal ASCII (snprintf cannot write the NULs) */
    memcpy(prefix, node, 64);
    prefix[64] = '\0';
    plen = 65 + (size_t)snprintf(prefix + 65, sizeof prefix - 65, "%u", round);
    prefix[plen] = '\0';
    plen++;
    for (i = 0; i < total; i++) {
        Keyed key;
        char tail[16];
        size_t tlen = (size_t)snprintf(tail, sizeof tail, "%" PRIu64, i);
        Sha sha;
        size_t at;
        sha_init(&sha);
        sha_update(&sha, prefix, plen);
        sha_update(&sha, tail, tlen);
        sha_final(&sha, key.digest);
        key.index = (uint32_t)i;
        if (count == SAMPLE_CHILDREN && !keyed_less(&key, &best[count - 1])) continue;
        at = count < SAMPLE_CHILDREN ? count++ : count - 1;
        while (at > 0 && keyed_less(&key, &best[at - 1])) {
            best[at] = best[at - 1];
            at--;
        }
        best[at] = key;
    }
    for (i = 0; i < count; i++) out[i] = best[i].index;
    return count;
}

typedef struct {
    int conflict;
    int32_t *closure;
    size_t nclosure;
    uint8_t *bits; /* assigned variables as a bitset */
} Child;

static int bit(const uint8_t *bits, uint32_t variable) {
    return (bits[variable >> 3] >> (variable & 7)) & 1;
}

static uint8_t *snapshot_bits(const Engine *e) {
    uint32_t v;
    uint8_t *bits = (uint8_t *)xalloc(((size_t)e->variables >> 3) + 1, 1);
    for (v = 1; v <= e->variables; v++)
        if (e->value[v] != 0) bits[v >> 3] |= (uint8_t)(1u << (v & 7));
    return bits;
}

static void free_children(Child *children, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        free(children[i].closure);
        free(children[i].bits);
    }
}

typedef enum { ST_CHOSEN, ST_NO_ELIGIBLE, ST_BUDGET, ST_FAILED } Status;
typedef enum { STOP_K, STOP_CANDIDATES, STOP_PROBE_LIMIT, STOP_WALL_MS, STOP_PARENT_CONFLICT,
               STOP_NONE } Stop;

static const char *const STATUS_NAMES[] = {"chosen", "no_eligible", "budget", "failed"};
static const char *const STOP_NAMES[] = {"k", "candidates", "probe_limit", "wall_ms",
                                         "parent_conflict"};

typedef struct {
    Status status;
    Stop stop;
    int32_t variables[K_MAX];
    int64_t scores[K_MAX];
    int nchosen;
    uint64_t candidates;
    uint64_t parent_assigned;
    uint64_t probes;
} Outcome;

static void lookahead(Engine *e, const Request *r, const char *node, uint64_t started,
                      Outcome *out) {
    uint64_t limit = (uint64_t)r->probe_limit;
    uint64_t wall_ns = r->wall_ms == 0 ? 0 : (uint64_t)r->wall_ms * 1000000u;
    uint64_t used = 0;
    int has_wall = r->wall_ms != 0;
    uint32_t variables = e->variables;
    size_t i, parent_mark;
    int conflict;
    int32_t *candidates;
    size_t ncandidates = 0;
    uint8_t *chosen_flag;
    uint8_t *parent_bits;
    Stop stop = STOP_NONE;
    memset(out, 0, sizeof *out);

#define OVER_WALL() (has_wall && now_ns() - started >= wall_ns)

    if (OVER_WALL()) {
        out->status = ST_BUDGET;
        out->stop = STOP_WALL_MS;
        return;
    }
    used = 1;
    conflict = e->root_conflict;
    if (!conflict) {
        for (i = 0; i < r->ncube; i++) {
            if (eng_assume(e, r->cube[i])) {
                conflict = 1;
                break;
            }
        }
    }
    if (conflict) {
        eng_undo(e, e->root_mark);
        out->status = ST_FAILED;
        out->stop = STOP_PARENT_CONFLICT;
        out->probes = used;
        return;
    }
    parent_mark = e->ntrail;
    out->parent_assigned = parent_mark;
    candidates = (int32_t *)xalloc((size_t)variables + 1, sizeof *candidates);
    if (r->has_pool) {
        for (i = 0; i < r->npool; i++)
            if (!e->value[r->pool[i]]) candidates[ncandidates++] = r->pool[i];
    } else {
        uint32_t v;
        for (v = 1; v <= variables; v++)
            if (!e->value[v]) candidates[ncandidates++] = (int32_t)v;
    }
    out->candidates = ncandidates;
    chosen_flag = (uint8_t *)xalloc((size_t)variables + 1, 1);
    parent_bits = snapshot_bits(e);

    while (out->nchosen < r->k) {
        unsigned round = (unsigned)out->nchosen + 1;
        Child children[SAMPLE_CHILDREN];
        uint32_t sampled[SAMPLE_CHILDREN];
        size_t nchildren = 0, nsampled, c, a;
        const Child *loaded = NULL;
        int32_t best_variable = 0;
        int64_t best_score = -1;
        size_t remaining = 0;
        memset(children, 0, sizeof children);
        for (a = 0; a < ncandidates; a++)
            if (!chosen_flag[candidates[a]]) remaining++;
        if (remaining == 0) {
            stop = STOP_CANDIDATES;
            break;
        }
        if (out->nchosen == 0) {
            children[0].bits = parent_bits;
            nchildren = 1;
        } else {
            nsampled = sample_children(node, round, (unsigned)out->nchosen, sampled);
            for (c = 0; c < nsampled; c++) {
                int clash = 0;
                int j;
                if (used >= limit) {
                    stop = STOP_PROBE_LIMIT;
                    break;
                }
                if (OVER_WALL()) {
                    stop = STOP_WALL_MS;
                    break;
                }
                used++;
                eng_undo(e, parent_mark);
                for (j = 0; j < out->nchosen; j++) {
                    int32_t w = out->variables[j];
                    if (eng_assume(e, ((sampled[c] >> j) & 1u) ? w : -w)) {
                        clash = 1;
                        break;
                    }
                }
                children[nchildren].conflict = clash;
                if (!clash) {
                    size_t n = e->ntrail - parent_mark;
                    children[nchildren].nclosure = n;
                    children[nchildren].closure = (int32_t *)xalloc(n, sizeof(int32_t));
                    if (n > 0) memcpy(children[nchildren].closure, e->trail + parent_mark,
                                      n * sizeof(int32_t));
                    children[nchildren].bits = snapshot_bits(e);
                }
                nchildren++;
            }
        }
        eng_undo(e, parent_mark);
        if (stop != STOP_NONE) {
            if (out->nchosen != 0) free_children(children, nchildren);
            break;
        }
        for (a = 0; a < ncandidates && stop == STOP_NONE; a++) {
            int32_t v = candidates[a];
            uint64_t live = 0;
            int64_t score = 0;
            int complete = 1;
            if (chosen_flag[v]) continue;
            for (c = 0; c < nchildren; c++)
                if (!children[c].conflict && !bit(children[c].bits, (uint32_t)v)) live++;
            if (limit - used < 2 * live) {
                stop = STOP_PROBE_LIMIT;
                break;
            }
            for (c = 0; c < nchildren && complete; c++) {
                int64_t gains[2] = {0, 0};
                int side;
                if (children[c].conflict || bit(children[c].bits, (uint32_t)v)) continue;
                if (loaded != &children[c]) {
                    eng_undo(e, parent_mark);
                    eng_replay(e, children[c].closure, children[c].nclosure);
                    loaded = &children[c];
                }
                for (side = 0; side < 2; side++) {
                    int32_t literal = side == 0 ? v : -v;
                    size_t mark;
                    int clash;
                    if (OVER_WALL()) {
                        stop = STOP_WALL_MS;
                        complete = 0;
                        break;
                    }
                    used++;
                    mark = e->ntrail;
                    clash = eng_assume(e, literal);
                    gains[side] = clash ? (int64_t)variables + 1 : (int64_t)(e->ntrail - mark) - 1;
                    eng_undo(e, mark);
                }
                if (!complete) break;
                score += (gains[0] + 1) * (gains[1] + 1);
            }
            if (!complete) break;
            if (score > best_score) {
                best_variable = v;
                best_score = score;
            }
        }
        eng_undo(e, parent_mark);
        if (out->nchosen != 0) free_children(children, nchildren);
        if (best_variable != 0) {
            out->variables[out->nchosen] = best_variable;
            out->scores[out->nchosen] = best_score;
            out->nchosen++;
            chosen_flag[best_variable] = 1;
        }
        if (stop != STOP_NONE) break;
    }
    eng_undo(e, e->root_mark);
    if (stop == STOP_NONE) stop = STOP_K;
    out->stop = stop;
    out->probes = used;
    if (out->nchosen > 0) out->status = ST_CHOSEN;
    else out->status = stop == STOP_CANDIDATES ? ST_NO_ELIGIBLE : ST_BUDGET;
    free(candidates);
    free(chosen_flag);
    free(parent_bits);
#undef OVER_WALL
}

/* ---- validation of the request against the formula, output, main ------------------------- */

static void check_request(const Request *r, uint32_t variables) {
    size_t i;
    int64_t previous = 0;
    for (i = 0; i < r->ncube; i++) {
        int64_t magnitude = r->cube[i] < 0 ? -(int64_t)r->cube[i] : r->cube[i];
        if (r->cube[i] == 0 || magnitude <= previous || magnitude > (int64_t)variables)
            bad_request("the cube is not canonical or out of range");
        previous = magnitude;
    }
    previous = 0;
    if (r->has_pool) {
        for (i = 0; i < r->npool; i++) {
            if (r->pool[i] <= previous || (int64_t)r->pool[i] > (int64_t)variables)
                bad_request("the pool is not sorted, distinct and in range");
            previous = r->pool[i];
        }
    }
}

static void node_identity(const Request *r, char out[65]) {
    Sha sha;
    uint8_t digest[32];
    size_t i;
    sha_init(&sha);
    sha_update(&sha, "node", 4);
    sha_update(&sha, "\0", 1);
    sha_update(&sha, r->hash, 64);
    sha_update(&sha, "\0", 1);
    for (i = 0; i < r->ncube; i++) {
        char text[16];
        size_t n = (size_t)snprintf(text, sizeof text, "%s%" PRId32, i == 0 ? "" : " ", r->cube[i]);
        sha_update(&sha, text, n);
    }
    sha_final(&sha, digest);
    to_hex(digest, out);
}

static void emit(const Outcome *o, const char *node) {
    char buffer[4096];
    size_t n = 0;
    int i;
#define PUT(...)                                                                     \
    do {                                                                              \
        int w = snprintf(buffer + n, sizeof buffer - n, __VA_ARGS__);                 \
        if (w < 0 || (size_t)w >= sizeof buffer - n) die(EXIT_RESOURCE, "result too large"); \
        n += (size_t)w;                                                               \
    } while (0)
    PUT("{\"format\":\"%s\",\"info\":{\"algorithm\":\"%s\",\"candidates\":%" PRIu64
        ",\"parent_assigned\":%" PRIu64 ",\"probes\":%" PRIu64 ",\"rounds\":%d,\"scores\":[",
        RESULT_FORMAT, ALGORITHM, o->candidates, o->parent_assigned, o->probes, o->nchosen);
    for (i = 0; i < o->nchosen; i++) PUT("%s%" PRId64, i == 0 ? "" : ",", o->scores[i]);
    PUT("],\"stop\":\"%s\"},\"node_id\":\"%s\",\"status\":\"%s\",\"variables\":[",
        STOP_NAMES[o->stop], node, STATUS_NAMES[o->status]);
    for (i = 0; i < o->nchosen; i++) PUT("%s%" PRId32, i == 0 ? "" : ",", o->variables[i]);
    PUT("]}\n");
#undef PUT
    if (fwrite(buffer, 1, n, stdout) != n || fflush(stdout) != 0)
        die(EXIT_RESOURCE, "cannot write the result");
}

int main(int argc, char **argv) {
    uint64_t started = now_ns();
    Request request;
    Engine engine;
    Outcome outcome;
    char node[65], actual[65];
    unsigned char *request_data, *formula;
    size_t request_length, formula_length;
    Sha sha;
    uint8_t digest[32];

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts(VERSION_LINE);
        return 0;
    }
    if (argc != 2) die(EXIT_BAD_REQUEST, "usage: cubeproof-look REQUEST_FILE | --version");
    request_data = read_file(argv[1], MAX_REQUEST_BYTES, EXIT_BAD_REQUEST, &request_length);
    parse_request((const char *)request_data, request_length, &request);
    free(request_data);

    formula = read_file(request.path, MAX_FORMULA_BYTES, EXIT_BAD_FORMULA, &formula_length);
    sha_init(&sha);
    sha_update(&sha, formula, formula_length);
    sha_final(&sha, digest);
    to_hex(digest, actual);
    if (strcmp(actual, request.hash) != 0) die(EXIT_BAD_FORMULA, "the formula hash differs");
    load_formula(formula, formula_length, &engine);
    free(formula);
    check_request(&request, engine.variables);
    node_identity(&request, node);
    lookahead(&engine, &request, node, started, &outcome);
    emit(&outcome, node);
    free_engine(&engine);
    free(request.cube);
    free(request.pool);
    return 0;
}

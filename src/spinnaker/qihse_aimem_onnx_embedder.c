/*
 * qihse_aimem_onnx_embedder.c — real-model ONNX embedder for AI memory.
 *
 * A BERT WordPiece tokenizer plus an onnxruntime session, packaged as a
 * qihse_ai_memory_embedder_t provider. Tokenization mirrors HF
 * BasicTokenizer(do_lower_case=true) + WordPiece for the ASCII/CJK subset:
 * whitespace splitting, ASCII lowercasing, ASCII punctuation splitting, CJK
 * codepoints as single characters, and greedy longest-match WordPiece with
 * "##" continuations. Text that falls outside that subset (accent folding,
 * full NFD normalization) is passed through as opaque codepoints rather than
 * dropped; WordPiece maps unknown pieces to [UNK].
 *
 * Link with -lonnxruntime. Everything allocates per call or at install time;
 * OrtSession Run is thread-safe, so the embed callback needs no lock.
 */

#include "qihse_aimem_onnx_embedder.h"
#include "qihse_ai_memory.h"

#include <onnxruntime/onnxruntime_c_api.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define ONNX_EMBEDDER_MAX_SEQ 256u
#define ONNX_EMBEDDER_MAX_PIECES_PER_WORD 100u
#define ONNX_EMBEDDER_VOCAB_SLOTS (1u << 17) /* > 2x a 30522-entry vocab */

/* ── vocabulary ─────────────────────────────────────────────────────────── */

typedef struct {
    char** tokens; /* length = vocab_count */
    uint32_t* ids; /* parallel to slots; slot -> vocab index, UINT32_MAX empty */
    uint32_t vocab_count;
    int64_t id_cls, id_sep, id_unk, id_pad;
} vocab_t;

static uint64_t fnv1a(const char* s, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static int32_t vocab_lookup(const vocab_t* v, const char* tok, size_t n) {
    if (n == 0 || v->ids == NULL) return -1;
    uint32_t mask = ONNX_EMBEDDER_VOCAB_SLOTS - 1u;
    uint32_t slot = (uint32_t)(fnv1a(tok, n) & mask);
    for (;;) {
        uint32_t idx = v->ids[slot];
        if (idx == UINT32_MAX) return -1;
        const char* cand = v->tokens[idx];
        if (strlen(cand) == n && memcmp(cand, tok, n) == 0) return (int32_t)idx;
        slot = (slot + 1u) & mask;
    }
}

static bool vocab_load(vocab_t* v, const char* path) {
    memset(v, 0, sizeof *v);
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    v->ids = malloc(ONNX_EMBEDDER_VOCAB_SLOTS * sizeof(uint32_t));
    if (!v->ids) { fclose(f); return false; }
    for (uint32_t i = 0; i < ONNX_EMBEDDER_VOCAB_SLOTS; i++) v->ids[i] = UINT32_MAX;

    size_t cap = 40968;
    v->tokens = malloc(cap * sizeof(char*));
    if (!v->tokens) { free(v->ids); v->ids = NULL; fclose(f); return false; }

    char line[512];
    while (fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        if (n == 0 || n >= sizeof line - 1) { /* blank or overlong: keep the line count honest */
            if (n == 0) { v->vocab_count++; continue; }
            goto fail;
        }
        if ((uint32_t)v->vocab_count >= cap) goto fail;
        char* tok = malloc(n + 1);
        if (!tok) goto fail;
        memcpy(tok, line, n + 1);
        uint32_t mask = ONNX_EMBEDDER_VOCAB_SLOTS - 1u;
        uint32_t slot = (uint32_t)(fnv1a(tok, n) & mask);
        while (v->ids[slot] != UINT32_MAX) slot = (slot + 1u) & mask;
        v->ids[slot] = v->vocab_count;
        v->tokens[v->vocab_count] = tok;
        v->vocab_count++;
    }
    fclose(f);
    f = NULL;

    int32_t cls = vocab_lookup(v, "[CLS]", 5);
    int32_t sep = vocab_lookup(v, "[SEP]", 5);
    int32_t unk = vocab_lookup(v, "[UNK]", 5);
    int32_t pad = vocab_lookup(v, "[PAD]", 5);
    if (cls < 0 || sep < 0 || unk < 0 || pad < 0) goto fail;
    v->id_cls = cls; v->id_sep = sep; v->id_unk = unk; v->id_pad = pad;
    return true;

fail:
    if (f) fclose(f);
    for (uint32_t i = 0; i < v->vocab_count; i++) free(v->tokens[i]);
    free(v->tokens); free(v->ids);
    memset(v, 0, sizeof *v);
    return false;
}

static void vocab_free(vocab_t* v) {
    for (uint32_t i = 0; i < v->vocab_count; i++) free(v->tokens[i]);
    free(v->tokens);
    free(v->ids);
    memset(v, 0, sizeof *v);
}

/* ── tokenizer ──────────────────────────────────────────────────────────── */

/* Decode one UTF-8 codepoint; advances *s. Invalid bytes decode as themselves. */
static uint32_t utf8_next(const char** s) {
    const unsigned char* p = (const unsigned char*)*s;
    uint32_t c = *p++;
    if ((c & 0x80u) == 0) { *s = (const char*)p; return c; }
    int extra = (c & 0xE0u) == 0xC0u ? 1 : (c & 0xF0u) == 0xE0u ? 2 : (c & 0xF8u) == 0xF0u ? 3 : 0;
    if (extra == 0) { *s = (const char*)p; return c; } /* stray continuation: pass through */
    uint32_t cp = c & (uint32_t)(0x3Fu >> extra);
    for (int i = 0; i < extra; i++) {
        if ((*p & 0xC0u) != 0x80u) { *s = (const char*)p; return c; }
        cp = (cp << 6) | (uint32_t)(*p++ & 0x3Fu);
    }
    *s = (const char*)p;
    return cp;
}

static size_t utf8_encode(uint32_t cp, char* out) {
    if (cp < 0x80u) { out[0] = (char)cp; return 1; }
    if (cp < 0x800u) {
        out[0] = (char)(0xC0u | (cp >> 6)); out[1] = (char)(0x80u | (cp & 0x3Fu)); return 2;
    }
    if (cp < 0x10000u) {
        out[0] = (char)(0xE0u | (cp >> 12)); out[1] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        out[2] = (char)(0x80u | (cp & 0x3Fu)); return 3;
    }
    out[0] = (char)(0xF0u | (cp >> 18)); out[1] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
    out[2] = (char)(0x80u | ((cp >> 6) & 0x3Fu)); out[3] = (char)(0x80u | (cp & 0x3Fu)); return 4;
}

static bool is_cjk(uint32_t cp) {
    return (cp >= 0x4E00u && cp <= 0x9FFFu) || (cp >= 0x3040u && cp <= 0x30FFu) ||
           (cp >= 0xAC00u && cp <= 0xD7AFu) || (cp >= 0xF900u && cp <= 0xFAFFu);
}

static bool is_hf_punct_ascii(uint32_t cp) {
    if (cp >= 0x21u && cp <= 0x2Fu) return true;  /* ! " # $ % & ' ( ) * + , - . / */
    if (cp >= 0x3Au && cp <= 0x40u) return true;  /* : ; < = > ? @ */
    if (cp >= 0x5Bu && cp <= 0x60u) return true;  /* [ \ ] ^ _ ` */
    if (cp >= 0x7Bu && cp <= 0x7Eu) return true;  /* { | } ~ */
    return false;
}

/* Basic tokenization: whitespace split, ASCII lowercase, ASCII punctuation
 * split, CJK per-character. Writes word pointers into the (caller-owned)
 * byte copy of `text`. Returns the word count, or 0 on allocation failure. */
#define MAX_BASIC_WORDS 8192u
static uint32_t basic_tokenize(char* text, char** words, uint32_t words_cap) {
    uint32_t n = 0;
    char word_buf[256];
    size_t wlen = 0;
    const char* p = text;

    if (words_cap == 0 || words_cap > MAX_BASIC_WORDS) return 0;
    while (*p) {
        uint32_t cp = utf8_next(&p);
        if (cp == ' ' || cp == '\t' || cp == '\n' || cp == '\r' || cp == '\v' || cp == '\f' ||
            cp == 0x3000u /* ideographic space */) {
            if (wlen > 0 && n < words_cap) { word_buf[wlen] = '\0'; words[n] = strdup(word_buf); if (!words[n]) return 0; n++; wlen = 0; }
            continue;
        }
        if (cp < 0x80u) cp = (uint32_t)tolower((int)cp);
        char enc[4];
        size_t enc_len = utf8_encode(cp, enc);
        if (is_hf_punct_ascii(cp) || is_cjk(cp)) {
            if (wlen > 0 && n < words_cap) { word_buf[wlen] = '\0'; words[n] = strdup(word_buf); if (!words[n]) return 0; n++; wlen = 0; }
            if (n < words_cap) {
                words[n] = malloc(enc_len + 1);
                if (!words[n]) return 0;
                memcpy(words[n], enc, enc_len); words[n][enc_len] = '\0';
                n++;
            }
            continue;
        }
        if (wlen + enc_len >= sizeof word_buf) { if (n < words_cap) { word_buf[wlen] = '\0'; words[n] = strdup(word_buf); if (!words[n]) return 0; n++; } wlen = 0; }
        memcpy(word_buf + wlen, enc, enc_len);
        wlen += enc_len;
    }
    if (wlen > 0 && n < words_cap) { word_buf[wlen] = '\0'; words[n] = strdup(word_buf); if (!words[n]) return 0; n++; }
    return n;
}

/* Greedy longest-match WordPiece for one word. Appends ids to out. */
static void wordpiece(const vocab_t* v, const char* word, int64_t* out, uint32_t* count) {
    size_t len = strlen(word);
    uint32_t pieces = 0;
    size_t start = 0;
    while (start < len) {
        size_t end = len;
        int32_t found = -1;
        size_t found_len = 0;
        while (start < end) {
            char cand[286]; /* "##" + word length bounded by 256-byte words */
            size_t n = 0;
            if (start > 0) { cand[0] = '#'; cand[1] = '#'; n = 2; }
            size_t seg = end - start;
            if (n + seg >= sizeof cand) { end--; continue; }
            memcpy(cand + n, word + start, seg);
            n += seg;
            int32_t id = vocab_lookup(v, cand, n);
            if (id >= 0) { found = id; found_len = seg; break; }
            end--;
        }
        if (found < 0 || *count >= ONNX_EMBEDDER_MAX_SEQ) {
            out[(*count)++] = v->id_unk;
            return; /* whole word becomes [UNK], matching HF behavior */
        }
        out[(*count)++] = (int64_t)found;
        pieces++;
        start += found_len;
        if (pieces >= ONNX_EMBEDDER_MAX_PIECES_PER_WORD) {
            /* Overlong word: rewind this word's pieces to a single [UNK]. */
            uint32_t first_of_word = *count - pieces;
            *count = first_of_word;
            out[(*count)++] = v->id_unk;
            return;
        }
    }
}

/* Full pipeline: [CLS] pieces… [SEP], capped at ONNX_EMBEDDER_MAX_SEQ. */
static bool tokenize_ids(const vocab_t* v, const char* text, int64_t* ids, uint32_t* out_len) {
    char* copy = strdup(text ? text : "");
    if (!copy) return false;
    char** words = malloc(MAX_BASIC_WORDS * sizeof(char*));
    if (!words) { free(copy); return false; }
    uint32_t nwords = basic_tokenize(copy, words, MAX_BASIC_WORDS);
    uint32_t count = 0;
    ids[count++] = v->id_cls;
    bool ok = true;
    for (uint32_t i = 0; i < nwords && ok; i++) {
        wordpiece(v, words[i], ids, &count);
        if (count >= ONNX_EMBEDDER_MAX_SEQ - 1u) { count = ONNX_EMBEDDER_MAX_SEQ - 1u; break; }
    }
    ids[count++] = v->id_sep;
    for (uint32_t i = 0; i < nwords; i++) free(words[i]);
    free(words);
    free(copy);
    if (count > ONNX_EMBEDDER_MAX_SEQ) count = ONNX_EMBEDDER_MAX_SEQ;
    *out_len = count;
    return ok;
}

/* ── onnxruntime session ────────────────────────────────────────────────── */

typedef struct {
    const OrtApi* ort;
    OrtEnv* env;
    OrtSessionOptions* opts;
    OrtSession* session;
    OrtMemoryInfo* meminfo;
    vocab_t vocab;
    size_t dim;
    char name[64];
    char model_path[1024];
} onnx_embedder_t;

static onnx_embedder_t g_onnx;
static bool g_onnx_installed = false;
static _Thread_local uint64_t g_onnx_thread_deadline_ns;

void qihse_aimem_onnx_embedder_set_thread_deadline(uint64_t monotonic_ns) {
    g_onnx_thread_deadline_ns = monotonic_ns;
}

static uint64_t onnx_mono_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return UINT64_MAX;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

typedef struct {
    const OrtApi* ort;
    OrtRunOptions* options;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    bool stopped;
    uint64_t deadline;
} onnx_run_timer_t;

static void* onnx_run_terminate_at_deadline(void* opaque) {
    onnx_run_timer_t* timer = opaque;
    struct timespec when = {(time_t)(timer->deadline / UINT64_C(1000000000)),
                            (long)(timer->deadline % UINT64_C(1000000000))};
    pthread_mutex_lock(&timer->lock);
    while (!timer->stopped) {
        int rc = pthread_cond_timedwait(&timer->cond, &timer->lock, &when);
        if (rc == ETIMEDOUT) break;
        if (rc != 0) break;
    }
    if (!timer->stopped) {
        OrtStatus* status = timer->ort->RunOptionsSetTerminate(timer->options);
        if (status) {
            fprintf(stderr, "[qihse-aimem-onnx] could not terminate expired Run: %s\n",
                    timer->ort->GetErrorMessage(status));
            timer->ort->ReleaseStatus(status);
        }
    }
    pthread_mutex_unlock(&timer->lock);
    return NULL;
}

#define ORT_TRY(call)                                                     \
    do {                                                                  \
        OrtStatus* st_ = (call);                                          \
        if (st_ != NULL) {                                                \
            const char* msg_ = g_onnx.ort->GetErrorMessage(st_);          \
            fprintf(stderr, "[qihse-aimem-onnx] %s: %s\n", #call, msg_ ? msg_ : "?"); \
            g_onnx.ort->ReleaseStatus(st_);                               \
            goto fail;                                                    \
        }                                                                 \
    } while (0)

/* One full forward pass; out must have room for g_onnx.dim floats.
 * Tokenizes, runs the session, mask-mean-pools, L2-normalizes. */
static bool onnx_embed(const char* text, float* out, size_t dim, void* ctx) {
    (void)ctx;
    if (!g_onnx_installed || dim != g_onnx.dim || !text || !out) return false;
    const OrtApi* ort = g_onnx.ort;
    uint64_t deadline = g_onnx_thread_deadline_ns;
    if (deadline && onnx_mono_ns() >= deadline) return false;

    int64_t ids[ONNX_EMBEDDER_MAX_SEQ];
    uint32_t seq = 0;
    if (!tokenize_ids(&g_onnx.vocab, text, ids, &seq) || seq < 2u) return false;

    int64_t* mask = malloc((size_t)seq * sizeof(int64_t));
    int64_t* type_ids = malloc((size_t)seq * sizeof(int64_t));
    bool ok = false;
    OrtValue* in_ids = NULL;
    OrtValue* in_mask = NULL;
    OrtValue* in_type = NULL;
    OrtValue* out_tensor = NULL;
    OrtTensorTypeAndShapeInfo* info = NULL;
    OrtTypeInfo* type_info = NULL;
    float* data = NULL;
    OrtRunOptions* run_options = NULL;
    onnx_run_timer_t timer = {0};
    pthread_t timer_thread;
    bool timer_mutex = false, timer_cond = false, timer_started = false;
    if (!mask || !type_ids || (deadline && onnx_mono_ns() >= deadline)) goto done;
    for (uint32_t i = 0; i < seq; i++) { mask[i] = 1; type_ids[i] = 0; }

    int64_t shape[2] = {1, (int64_t)seq};
    ORT_TRY(ort->CreateTensorWithDataAsOrtValue(
        g_onnx.meminfo, ids, (size_t)seq * sizeof(int64_t), shape, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64, &in_ids));
    ORT_TRY(ort->CreateTensorWithDataAsOrtValue(
        g_onnx.meminfo, mask, (size_t)seq * sizeof(int64_t), shape, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64, &in_mask));
    ORT_TRY(ort->CreateTensorWithDataAsOrtValue(
        g_onnx.meminfo, type_ids, (size_t)seq * sizeof(int64_t), shape, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64, &in_type));

    const char* input_names[3] = {"input_ids", "attention_mask", "token_type_ids"};
    const char* output_names[1] = {"last_hidden_state"};
    const OrtValue* inputs[3] = {in_ids, in_mask, in_type};
    if (deadline) {
        if (onnx_mono_ns() >= deadline) goto done;
        ORT_TRY(ort->CreateRunOptions(&run_options));
        timer.ort = ort;
        timer.options = run_options;
        timer.deadline = deadline;
        if (pthread_mutex_init(&timer.lock, NULL) != 0) goto done;
        timer_mutex = true;
        pthread_condattr_t attr;
        if (pthread_condattr_init(&attr) != 0) goto done;
        int attr_ok = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
        if (attr_ok == 0 && pthread_cond_init(&timer.cond, &attr) == 0)
            timer_cond = true;
        pthread_condattr_destroy(&attr);
        if (!timer_cond || pthread_create(&timer_thread, NULL,
                                          onnx_run_terminate_at_deadline, &timer) != 0)
            goto done;
        timer_started = true;
    }
    ORT_TRY(ort->Run(g_onnx.session, run_options, input_names, inputs, 3,
                     output_names, 1, &out_tensor));
    if (deadline && onnx_mono_ns() >= deadline) goto done;

    ORT_TRY(ort->GetTypeInfo(out_tensor, &type_info));
    ORT_TRY(ort->CastTypeInfoToTensorInfo(type_info, (const OrtTensorTypeAndShapeInfo**)&info));
    size_t element_count = 0;
    ORT_TRY(ort->GetTensorShapeElementCount(info, &element_count));
    if (element_count != (size_t)seq * g_onnx.dim) {
        fprintf(stderr, "[qihse-aimem-onnx] output shape mismatch: %zu != %ux%zu\n",
                element_count, seq, g_onnx.dim);
        goto done;
    }
    ORT_TRY(ort->GetTensorMutableData(out_tensor, (void**)&data));
    if (!data) goto done;

    /* attention-masked mean pooling over the seq positions, then L2 norm */
    double acc[1024];
    memset(acc, 0, g_onnx.dim * sizeof(double));
    for (uint32_t i = 0; i < seq; i++) {
        const float* row = data + (size_t)i * g_onnx.dim;
        for (size_t d = 0; d < g_onnx.dim; d++) acc[d] += (double)row[d];
    }
    double norm = 0.0;
    for (size_t d = 0; d < g_onnx.dim; d++) {
        out[d] = (float)(acc[d] / (double)seq);
        norm += (double)out[d] * (double)out[d];
    }
    norm = sqrt(norm);
    if (norm <= 0.0) goto done;
    for (size_t d = 0; d < g_onnx.dim; d++) out[d] = (float)((double)out[d] / norm);
    ok = true;

done:
    if (timer_started) {
        pthread_mutex_lock(&timer.lock);
        timer.stopped = true;
        pthread_cond_signal(&timer.cond);
        pthread_mutex_unlock(&timer.lock);
        pthread_join(timer_thread, NULL);
    }
    if (timer_cond) pthread_cond_destroy(&timer.cond);
    if (timer_mutex) pthread_mutex_destroy(&timer.lock);
    if (run_options) ort->ReleaseRunOptions(run_options);
    if (deadline && onnx_mono_ns() >= deadline) ok = false;
    if (!ok) memset(out, 0, dim * sizeof *out);
    if (type_info) ort->ReleaseTypeInfo(type_info);
    if (out_tensor) ort->ReleaseValue(out_tensor);
    if (in_ids) ort->ReleaseValue(in_ids);
    if (in_mask) ort->ReleaseValue(in_mask);
    if (in_type) ort->ReleaseValue(in_type);
    free(mask);
    free(type_ids);
    return ok;

fail:
    ok = false;
    goto done;
}

static void onnx_teardown(void) {
    if (g_onnx.session) g_onnx.ort->ReleaseSession(g_onnx.session);
    if (g_onnx.opts) g_onnx.ort->ReleaseSessionOptions(g_onnx.opts);
    if (g_onnx.meminfo) g_onnx.ort->ReleaseMemoryInfo(g_onnx.meminfo);
    if (g_onnx.env) g_onnx.ort->ReleaseEnv(g_onnx.env);
    vocab_free(&g_onnx.vocab);
    memset(&g_onnx, 0, sizeof g_onnx);
    g_onnx_installed = false;
}

static bool onnx_embedder_provider(const char* text, float* out, size_t dim, void* ctx);

static bool hash_artifact(EVP_MD_CTX* ctx, const char* path, const char* tag) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat before, after;
    bool ok = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
              before.st_size > 0 && before.st_size <= (off_t)(1024u * 1024u * 1024u);
    uint64_t size = ok ? (uint64_t)before.st_size : 0u;
    uint8_t length[8];
    for (size_t i = 0; i < sizeof length; i++) length[i] = (uint8_t)(size >> (8u * i));
    ok = ok && EVP_DigestUpdate(ctx, tag, strlen(tag)) == 1 &&
         EVP_DigestUpdate(ctx, length, sizeof length) == 1;
    uint8_t bytes[64u * 1024u];
    uint64_t remaining = size;
    while (ok && remaining) {
        size_t want = remaining < sizeof bytes ? (size_t)remaining : sizeof bytes;
        ssize_t got = read(fd, bytes, want);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { ok = false; break; }
        ok = EVP_DigestUpdate(ctx, bytes, (size_t)got) == 1;
        remaining -= (size_t)got;
    }
    uint8_t extra;
    if (ok && (read(fd, &extra, 1u) != 0 || fstat(fd, &after) != 0 ||
               after.st_dev != before.st_dev || after.st_ino != before.st_ino ||
               after.st_size != before.st_size ||
               after.st_mtim.tv_sec != before.st_mtim.tv_sec ||
               after.st_mtim.tv_nsec != before.st_mtim.tv_nsec ||
               after.st_ctim.tv_sec != before.st_ctim.tv_sec ||
               after.st_ctim.tv_nsec != before.st_ctim.tv_nsec)) ok = false;
    if (close(fd) != 0) ok = false;
    return ok;
}

static bool onnx_model_fingerprint(const char* model_path, const char* vocab_path,
                                    uint8_t out[32]) {
    static const char domain[] = "qihse:aimem:onnx-wordpiece:ascii-cjk:v1:seq256:mean-l2";
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    unsigned int len = 0u;
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
              EVP_DigestUpdate(ctx, domain, sizeof domain - 1u) == 1 &&
              hash_artifact(ctx, model_path, "model.onnx") &&
              hash_artifact(ctx, vocab_path, "vocab.txt") &&
              EVP_DigestFinal_ex(ctx, out, &len) == 1 && len == 32u;
    EVP_MD_CTX_free(ctx);
    if (!ok) memset(out, 0, 32u);
    return ok;
}

bool qihse_aimem_onnx_embedder_install(const char* model_dir) {
    if (!model_dir || !*model_dir) return false;
    if (g_onnx_installed) {
        (void)qihse_ai_memory_set_embedder(NULL);
        onnx_teardown();
    }
    memset(&g_onnx, 0, sizeof g_onnx);

    const OrtApi* ort = OrtGetApiBase()->GetApi(ORT_API_VERSION);
    if (!ort) {
        fprintf(stderr, "[qihse-aimem-onnx] onnxruntime API %d unavailable\n", ORT_API_VERSION);
        goto fail;
    }
    g_onnx.ort = ort;

    const char* base = strrchr(model_dir, '/');
    base = base ? base + 1 : model_dir;
    if (snprintf(g_onnx.name, sizeof g_onnx.name, "onnx:%s", base) >= (int)sizeof g_onnx.name) {
        fprintf(stderr, "[qihse-aimem-onnx] model dir name too long\n");
        goto fail;
    }
    if (snprintf(g_onnx.model_path, sizeof g_onnx.model_path, "%s/model.onnx", model_dir) >= (int)sizeof g_onnx.model_path) {
        fprintf(stderr, "[qihse-aimem-onnx] model path too long\n");
        goto fail;
    }
    char vocab_path[1024];
    if (snprintf(vocab_path, sizeof vocab_path, "%s/vocab.txt", model_dir) >= (int)sizeof vocab_path) goto fail;
    uint8_t before_digest[32];
    if (!onnx_model_fingerprint(g_onnx.model_path, vocab_path, before_digest)) goto fail;
    if (!vocab_load(&g_onnx.vocab, vocab_path)) {
        fprintf(stderr, "[qihse-aimem-onnx] cannot load %s\n", vocab_path);
        goto fail;
    }

    ORT_TRY(ort->CreateEnv(ORT_LOGGING_LEVEL_WARNING, "qihse-aimem-onnx", &g_onnx.env));
    ORT_TRY(ort->CreateSessionOptions(&g_onnx.opts));
    ORT_TRY(ort->SetIntraOpNumThreads(g_onnx.opts, 2));
    ORT_TRY(ort->SetSessionGraphOptimizationLevel(g_onnx.opts, ORT_ENABLE_ALL));
    ORT_TRY(ort->CreateSession(g_onnx.env, g_onnx.model_path, g_onnx.opts, &g_onnx.session));
    ORT_TRY(ort->CreateCpuMemoryInfo(OrtArenaAllocator, OrtMemTypeDefault, &g_onnx.meminfo));

    /* Warm-up run derives and validates the embedding dimension. */
    float probe[1024];
    size_t probe_dim = 0;
    {
        /* tokenize_ids needs the vocab only; run one embed to learn dim. To
         * learn dim before knowing it, use the max and detect from output. */
        const char probe_text[] = "dimension probe";
        int64_t ids[ONNX_EMBEDDER_MAX_SEQ];
        uint32_t seq = 0;
        if (!tokenize_ids(&g_onnx.vocab, probe_text, ids, &seq) || seq < 2u) goto fail;
        int64_t* mask = malloc((size_t)seq * sizeof(int64_t));
        int64_t* type_ids = malloc((size_t)seq * sizeof(int64_t));
        if (!mask || !type_ids) { free(mask); free(type_ids); goto fail; }
        for (uint32_t i = 0; i < seq; i++) { mask[i] = 1; type_ids[i] = 0; }
        int64_t shape[2] = {1, (int64_t)seq};
        OrtValue* in_ids = NULL; OrtValue* in_mask = NULL; OrtValue* in_type = NULL; OrtValue* out_v = NULL;
        ORT_TRY(ort->CreateTensorWithDataAsOrtValue(g_onnx.meminfo, ids, (size_t)seq * sizeof(int64_t), shape, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64, &in_ids));
        ORT_TRY(ort->CreateTensorWithDataAsOrtValue(g_onnx.meminfo, mask, (size_t)seq * sizeof(int64_t), shape, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64, &in_mask));
        ORT_TRY(ort->CreateTensorWithDataAsOrtValue(g_onnx.meminfo, type_ids, (size_t)seq * sizeof(int64_t), shape, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64, &in_type));
        const char* input_names[3] = {"input_ids", "attention_mask", "token_type_ids"};
        const char* output_names[1] = {"last_hidden_state"};
        const OrtValue* inputs[3] = {in_ids, in_mask, in_type};
        ORT_TRY(ort->Run(g_onnx.session, NULL, input_names, inputs, 3, output_names, 1, &out_v));
        OrtTypeInfo* type_info = NULL;
        const OrtTensorTypeAndShapeInfo* info = NULL;
        ORT_TRY(ort->GetTypeInfo(out_v, &type_info));
        ORT_TRY(ort->CastTypeInfoToTensorInfo(type_info, &info));
        size_t rank = 0;
        ORT_TRY(ort->GetDimensionsCount(info, &rank));
        if (rank != 3) {
            fprintf(stderr, "[qihse-aimem-onnx] expected rank-3 output\n");
            ort->ReleaseTypeInfo(type_info);
            goto fail_free;
        }
        int64_t dims[3] = {0, 0, 0};
        ORT_TRY(ort->GetDimensions(info, dims, 3));
        probe_dim = (size_t)dims[2];
        ort->ReleaseTypeInfo(type_info);
        if (probe_dim == 0 || probe_dim > 1024u || dims[0] != 1 || dims[1] != (int64_t)seq) {
            fprintf(stderr, "[qihse-aimem-onnx] unexpected output shape %lldx%lldx%lld\n",
                    (long long)dims[0], (long long)dims[1], (long long)dims[2]);
            goto fail_free;
        }
        float* data = NULL;
        ORT_TRY(ort->GetTensorMutableData(out_v, (void**)&data));
        memcpy(probe, data, probe_dim * sizeof(float));
    fail_free:
        if (out_v) ort->ReleaseValue(out_v);
        if (in_ids) ort->ReleaseValue(in_ids);
        if (in_mask) ort->ReleaseValue(in_mask);
        if (in_type) ort->ReleaseValue(in_type);
        free(mask); free(type_ids);
        if (probe_dim == 0) goto fail;
    }
    if (probe_dim > QIHSE_AIMEM_MAX_DIM) {
        fprintf(stderr, "[qihse-aimem-onnx] model dim %zu exceeds QIHSE_AIMEM_MAX_DIM %d\n",
                probe_dim, (int)QIHSE_AIMEM_MAX_DIM);
        goto fail;
    }
    g_onnx.dim = probe_dim;

    qihse_ai_memory_embedder_t provider;
    provider.name = g_onnx.name;
    provider.dim = g_onnx.dim;
    provider.embed = onnx_embedder_provider;
    provider.ctx = NULL;
    uint8_t model_digest[32];
    if (!onnx_model_fingerprint(g_onnx.model_path, vocab_path, model_digest) ||
        memcmp(before_digest, model_digest, sizeof model_digest) != 0 ||
        !qihse_ai_memory_set_embedder(&provider) ||
        !qihse_ai_memory_set_embedder_fingerprint(model_digest)) goto fail;
    g_onnx_installed = true;
    fprintf(stderr, "[qihse-aimem-onnx] installed %s (dim %zu, vocab %u, warm-up ok)\n",
            g_onnx.name, g_onnx.dim, g_onnx.vocab.vocab_count);
    return true;

fail:
    onnx_teardown();
    (void)qihse_ai_memory_set_embedder(NULL);
    return false;
}

const char* qihse_aimem_onnx_embedder_name(void) {
    return g_onnx_installed ? g_onnx.name : "";
}

bool qihse_aimem_onnx_embedder_active(void) {
    return g_onnx_installed && g_onnx.session != NULL && g_onnx.ort != NULL &&
           strcmp(g_onnx.name, qihse_ai_memory_embedder_name()) == 0;
}

static bool onnx_embedder_provider(const char* text, float* out, size_t dim, void* ctx) {
    return onnx_embed(text, out, dim, ctx);
}

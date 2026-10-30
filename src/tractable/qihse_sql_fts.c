#include "qihse_sql_fts.h"
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_INPUT 4096
#define MAX_TOKEN 256
#define MAX_OUTPUT 4096

typedef struct sb_stemmer stemmer_t;
typedef struct { char lexeme[MAX_TOKEN + 1]; unsigned pos; } entry_t;

static int is_word(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}
static char lower(unsigned char c) { return c >= 'A' && c <= 'Z' ? (char)(c + 32) : (char)c; }
static int compare(const void *a, const void *b) {
    const entry_t *x = a, *y = b;
    int cmp = strcmp(x->lexeme, y->lexeme);
    return cmp ? cmp : (x->pos > y->pos) - (x->pos < y->pos);
}
static int stopword(const char *s) {
    static const char *const words[] = {
        "a", "about", "above", "after", "again", "against", "all", "am", "an", "and",
        "any", "are", "aren", "as", "at", "be", "because", "been", "before", "being",
        "below", "between", "both", "but", "by", "can", "cannot", "could", "couldn",
        "did", "didn", "do", "does", "doesn", "doing", "don", "down", "during", "each",
        "few", "for", "from", "further", "had", "hadn", "has", "hasn", "have", "haven",
        "having", "he", "her", "here", "hers", "herself", "him", "himself", "his", "how",
        "i", "if", "in", "into", "is", "isn", "it", "its", "itself", "let", "me", "more",
        "most", "mustn", "my", "myself", "no", "nor", "not", "of", "off", "on", "once",
        "only", "or", "other", "ought", "our", "ours", "ourselves", "out", "over", "own",
        "same", "shan", "she", "should", "shouldn", "so", "some", "such", "than", "that",
        "the", "their", "theirs", "them", "themselves", "then", "there", "these", "they",
        "this", "those", "through", "to", "too", "under", "until", "up", "very", "was",
        "wasn", "we", "were", "weren", "what", "when", "where", "which", "while", "who",
        "whom", "why", "will", "with", "won", "would", "wouldn", "you", "your", "yours",
        "yourself", "yourselves"
    };
    for (size_t i = 0; i < sizeof(words) / sizeof(*words); ++i)
        if (!strcmp(s, words[i])) return 1;
    return 0;
}
/* Keep complete emails as one lexeme, not PostgreSQL's email component lexemes. */
static const char *email_end(const char *p) {
    const char *q = p;
    while (is_word((unsigned char)*q) || *q == '_' || *q == '.' ||
           *q == '+' || *q == '-') ++q;
    if (q == p || *q != '@' || !is_word((unsigned char)q[-1])) return NULL;
    const char *domain = ++q;
    int dot = 0;
    while (is_word((unsigned char)*q) || *q == '.' || *q == '-') {
        if (*q == '.') dot = 1;
        ++q;
    }
    return dot && q > domain && is_word((unsigned char)q[-1]) ? q : NULL;
}
static int append(char *out, size_t *used, const char *s, size_t n) {
    if (n > MAX_OUTPUT - *used) return 0;
    memcpy(out + *used, s, n);
    *used += n;
    out[*used] = 0;
    return 1;
}

bool qihse_sql_to_tsvector_english(const char *text, char **canonical_out) {
    if (!canonical_out) return false;
    *canonical_out = NULL;
    if (!text) return false;
    size_t input_len = strnlen(text, MAX_INPUT + 1);
    if (input_len > MAX_INPUT) return false;
    for (size_t i = 0; i < input_len; ++i)
        if ((unsigned char)text[i] > 127) return false;

    void *lib = dlopen("libstemmer.so.0d", RTLD_NOW | RTLD_LOCAL);
    if (!lib) return false;
    stemmer_t *(*create)(const char *, const char *) = dlsym(lib, "sb_stemmer_new");
    const unsigned char *(*stem)(stemmer_t *, const unsigned char *, int) =
        dlsym(lib, "sb_stemmer_stem");
    int (*stem_length)(stemmer_t *) = dlsym(lib, "sb_stemmer_length");
    void (*destroy)(stemmer_t *) = dlsym(lib, "sb_stemmer_delete");
    if (!create || !stem || !stem_length || !destroy) { dlclose(lib); return false; }
    stemmer_t *analyzer = create("english", "UTF_8");
    if (!analyzer) { dlclose(lib); return false; }
    entry_t *entries = calloc(MAX_INPUT / 2 + 1, sizeof(*entries));
    if (!entries) { destroy(analyzer); dlclose(lib); return false; }
    size_t count = 0;
    unsigned position = 0;
    int ok = 1;
    const char *p = text;
    while (*p && ok) {
        if (!is_word((unsigned char)*p)) { ++p; continue; }
        const char *start = p, *end = email_end(p);
        int email = end != NULL;
        if (email) p = end;
        else {
            while (is_word((unsigned char)*p) || *p == '\'') ++p;
            end = p;
            while (end > start && end[-1] == '\'') --end;
        }
        size_t n = (size_t)(end - start);
        if (!n || n > MAX_TOKEN || ++position > 16383) { ok = 0; break; }
        char token[MAX_TOKEN + 1];
        for (size_t i = 0; i < n; ++i) token[i] = lower((unsigned char)start[i]);
        token[n] = 0;
        if (!email && stopword(token)) continue;
        if (!email) {
            const unsigned char *result = stem(analyzer, (const unsigned char *)token, (int)n);
            int len = stem_length(analyzer);
            if (!result || len <= 0 || len > MAX_TOKEN) { ok = 0; break; }
            memcpy(token, result, (size_t)len);
            token[len] = 0;
        }
        if (count >= MAX_INPUT / 2 + 1) { ok = 0; break; }
        strcpy(entries[count].lexeme, token);
        entries[count++].pos = position;
    }
    destroy(analyzer);
    dlclose(lib);
    char *out = ok ? calloc(MAX_OUTPUT + 1, 1) : NULL;
    if (!out) ok = 0;
    if (ok) {
        qsort(entries, count, sizeof(*entries), compare);
        size_t used = 0;
        for (size_t i = 0; i < count && ok; ++i) {
            int first = !i || strcmp(entries[i - 1].lexeme, entries[i].lexeme);
            if (first) {
                if (i) ok = append(out, &used, " ", 1);
                if (ok) ok = append(out, &used, "'", 1);
                for (const char *c = entries[i].lexeme; *c && ok; ++c) {
                    if (*c == '\'' || *c == '\\') ok = append(out, &used, "\\", 1);
                    if (ok) ok = append(out, &used, c, 1);
                }
                if (ok) ok = append(out, &used, "'", 1);
            } else ok = append(out, &used, ",", 1);
            char pos[16];
            int size = snprintf(pos, sizeof(pos), ":%u", entries[i].pos);
            if (size <= 0 || !ok) ok = 0;
            else ok = append(out, &used, pos + !first, (size_t)size - !first);
        }
    }
    free(entries);
    if (!ok) { free(out); return false; }
    *canonical_out = out;
    return true;
}

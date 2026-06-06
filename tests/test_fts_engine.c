#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qihse_fts.h"

int main(void) {
    printf("Testing Full-Text Search (Trigram/BM25)...\n");

    qihse_fts_index_t* index = qihse_fts_create();
    if (!index) {
        printf("Failed to create FTS index.\n");
        return 1;
    }

    const char* doc1 = "The quick brown fox jumps over the lazy dog";
    const char* doc2 = "A fast brown fox leaped over a sleeping dog";
    const char* doc3 = "The lazy dog was very sleepy today";

    qihse_fts_add_document(index, 101, doc1, strlen(doc1));
    qihse_fts_add_document(index, 102, doc2, strlen(doc2));
    qihse_fts_add_document(index, 103, doc3, strlen(doc3));

    qihse_fts_result_t results[10];
    
    // 1. Exact Word Search
    printf("\nQuery: 'quick'\n");
    int num = qihse_fts_search(index, "quick", results, 10);
    bool pass1 = (num == 1 && results[0].doc_id == 101);
    printf("Hits: %d. Top hit doc_id: %llu (Expected: 101). %s\n", 
            num, num > 0 ? (unsigned long long)results[0].doc_id : 0, pass1 ? "PASS" : "FAIL");

    // 2. Partial/Fuzzy Search
    // 'sleep' trigrams: sle, lee, eep. It will match 'sleeping' (doc2) and 'sleepy' (doc3)
    // But 'sleepy' has fewer words in the document, so BM25 might score doc3 higher due to length normalization.
    printf("\nQuery: 'sleep'\n");
    num = qihse_fts_search(index, "sleep", results, 10);
    bool pass2 = (num == 2);
    printf("Hits: %d (Expected: 2). %s\n", num, pass2 ? "PASS" : "FAIL");
    for (int i = 0; i < num; i++) {
        printf("  - doc_id: %llu, score: %.4f\n", (unsigned long long)results[i].doc_id, results[i].bm25_score);
    }

    // 3. Short Word Search
    printf("\nQuery: 'a'\n");
    num = qihse_fts_search(index, "a", results, 10);
    bool pass3 = false;
    if (num > 0 && results[0].doc_id == 102) {
        pass3 = true;
    }
    printf("Hits: %d. Top hit doc_id: %llu (Expected: 102). %s\n", 
            num, num > 0 ? (unsigned long long)results[0].doc_id : 0, pass3 ? "PASS" : "FAIL");

    qihse_fts_destroy(index);

    if (pass1 && pass2 && pass3) {
        printf("\nALL PASS\n");
        return 0;
    }
    return 1;
}

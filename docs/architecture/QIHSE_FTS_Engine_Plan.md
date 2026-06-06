# QIHSE Full-Text Search Engine Plan

## 1. Overview
The QIHSE FTS Engine provides sub-millisecond document retrieval using BM25 scoring over a reverse index. To enable robust fuzzy matching and partial-word substring searches without complex suffix trees, the engine uses a Trigram-based tokenizer.

## 2. Core Components

### 2.1 Trinary Trie Dictionary
The core dictionary maps extracted tokens to their posting lists. The `qihse_trinary_trie_t` provides fast, memory-efficient string lookups that are well-suited for high cardinality token sets like trigrams.

### 2.2 Trigram Tokenizer
Instead of pure word boundaries, the tokenizer extracts contiguous 3-character sequences (trigrams) from the alphanumeric words. For example, the word `hello` is tokenized into `hel`, `ell`, and `llo`. This allows queries for `ell` to correctly match `hello`. Words shorter than 3 characters are indexed as-is.

### 2.3 Positional Posting Lists
Posting lists track not just the document ID and term frequency (`tf`), but also the exact byte positions of the token in the original document. This enables future phrase queries and exact-word reconstruction by verifying that sequential trigrams are positionally adjacent.

### 2.4 BM25 Scoring
The search evaluation aggregates scores across matching tokens using the Okapi BM25 formula. BM25 balances the Term Frequency (TF) against the Inverse Document Frequency (IDF), with length normalization to avoid biasing toward excessively long documents.

## 3. Implementation Plan

1. **Modify `qihse_fts_add_document`**:
   - Refactor the token extraction loop.
   - For every extracted word, if the length >= 3, extract overlapping 3-character sliding windows and insert each as a separate token.
   - For words shorter than 3 characters, insert the whole word as a single token.

2. **Modify `qihse_fts_search`**:
   - Apply the exact same trigram tokenizer to the query string.
   - Look up the posting lists for each generated trigram.
   - Aggregate BM25 scores. Since the query `hello` will break into `hel`, `ell`, and `llo`, a document containing `hello` will get a high aggregated BM25 score because it hits all three trigrams.

3. **Testing**:
   - Create `tests/test_fts_engine.c`.
   - Index documents and test full word queries, partial word queries, and case insensitivity.

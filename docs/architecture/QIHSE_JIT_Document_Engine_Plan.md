# QIHSE JIT Document Engine Plan

## 1. Overview
The QIHSE JIT Document Engine adds native JSON/BSON document capabilities on top of the underlying memory arenas and KV store. Rather than just breaking JSON down into primitive KVs, we serialize it into a compact, schema-less BSON-like payload. Queries over this data will leverage the existing bytecode compiler (`qihse_bytecode_compiler.c`) to evaluate documents natively with zero callbacks to Python or higher-level languages.

## 2. Core Components

### 2.1 BSON-like Serialization
Instead of storing text JSON, `qihse_doc_store_insert_json` should parse the JSON string and serialize it into a tightly packed binary format. This format makes it fast to iterate over fields and push them onto the VM stack during filtering.

### 2.2 Dynamic Indexing
We want to be able to tag specific paths in a document (e.g., `user.age`) for indexing. An inverted index maps these values to `doc_id` lists. When a query targets an indexed field, we fetch the candidate `doc_id` list first, and then apply the JIT filter to just those candidates, rather than performing a full table scan.

### 2.3 JIT Query Evaluation (`qihse_doc_store_query`)
A new API will take a SQL `WHERE` expression:
1. Compile the query string via `qihse_bc_compile()` into a compact VM bytecode array.
2. Initialize a `qihse_bytecode_context_t` array containing the current document's fields.
3. Feed the bytecode and context into `qihse_bytecode_eval()`.
4. Return an array of all `doc_id` values that pass the filter.

## 3. Implementation Plan

1. **Extend `qihse_document.h`**:
   - Add `qihse_doc_store_query` signature.
   - Add a struct for `qihse_document_result_t`.

2. **Modify `qihse_document_store.c`**:
   - Improve the JSON ingestion to store a serialized context or keep it in a structured hash table inside the arena.
   - Implement the inverted indexing system using the `qihse_radix_node_t` trie.
   - Implement `qihse_doc_store_query` to invoke the `qihse_bc_compile()` function and iterate over all documents, populating the `qihse_bytecode_context_t` on the fly and evaluating the bytecode.

3. **Testing**:
   - Create `tests/test_document_store.c`.
   - Insert multiple documents, run queries (e.g., `age > 25 AND score >= 80`), and assert correct `doc_id` responses.

/*
 * qihse_aimem_onnx_embedder.h — real-model ONNX embedder for AI memory.
 *
 * Installs an onnxruntime-backed embedding provider (a BERT WordPiece model
 * such as bge-small-en-v1.5 exported to ONNX) into qihse_ai_memory via
 * qihse_ai_memory_set_embedder(). After a successful install, AIMEM SEMANTIC
 * and HYBRID recall rank by meaning instead of the built-in lexical hash.
 *
 * The model directory must contain:
 *   model.onnx  — inputs input_ids/attention_mask/token_type_ids (int64,
 *                 dynamic seq), output last_hidden_state [1, seq, dim]
 *   vocab.txt   — BERT WordPiece vocabulary, one token per line
 *
 * Fail-closed: install returns false on ANY error (missing file, bad vocab,
 * session failure, dim above QIHSE_AIMEM_MAX_DIM) and the caller must refuse
 * to serve rather than silently degrade semantic recall to the lexical hash.
 */

#ifndef QIHSE_AIMEM_ONNX_EMBEDDER_H
#define QIHSE_AIMEM_ONNX_EMBEDDER_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Load the model under `model_dir` and install it as the active AI-memory
 * embedder. The provider name is descriptive; the SHA-256 fingerprint binds
 * vectors to model artifacts and preprocessing. Returns false on any failure. */
bool qihse_aimem_onnx_embedder_install(const char* model_dir);

/* The installed provider name, or "" when the ONNX embedder is not active. */
const char* qihse_aimem_onnx_embedder_name(void);

/* True only while a fully installed ONNX provider is active. */
bool qihse_aimem_onnx_embedder_active(void);

/* Optional absolute CLOCK_MONOTONIC deadline for the calling thread's next
 * embeddings. Set 0 to clear. ONNX Run is cooperatively terminated through
 * its per-call RunOptions when this deadline passes. The caller must still
 * enforce its own deadline across KV, ranking and materialization. */
void qihse_aimem_onnx_embedder_set_thread_deadline(uint64_t monotonic_ns);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_AIMEM_ONNX_EMBEDDER_H */

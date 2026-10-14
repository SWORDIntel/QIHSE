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

#ifdef __cplusplus
extern "C" {
#endif

/* Load the model under `model_dir` and install it as the active AI-memory
 * embedder. The provider name is "onnx:<basename(model_dir)>", so vectors
 * stay bound to the model that produced them. Returns false on any failure. */
bool qihse_aimem_onnx_embedder_install(const char* model_dir);

/* The installed provider name, or "" when the ONNX embedder is not active. */
const char* qihse_aimem_onnx_embedder_name(void);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_AIMEM_ONNX_EMBEDDER_H */

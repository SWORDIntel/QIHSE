#!/usr/bin/env python3
"""Export a BERT-family embedding model to ONNX for the QIHSE AIMEM embedder.

Produces the artifact layout expected by qihse-redis-server's
--embedder-onnx option:

    <out-dir>/model.onnx       input_ids / attention_mask / token_type_ids
                               (int64, dynamic seq) -> last_hidden_state
    <out-dir>/model.onnx.data  external weights
    <out-dir>/vocab.txt        WordPiece vocabulary

The embedding used by AIMEM is attention-mask mean pooling over
last_hidden_state followed by L2 normalization (the bge recipe). Defaults to
BAAI/bge-small-en-v1.5 (384-dim); any BERT-family causal LM-free encoder with
the same three inputs works.

Usage:
    python3 export_bge_onnx.py                 # ./models/bge-small-en-v1.5
    python3 export_bge_onnx.py --out ./models/mymodel --model org/model
"""

from __future__ import annotations

import argparse
import glob
import os
import shutil
from pathlib import Path

import torch
from transformers import AutoModel, AutoTokenizer


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="BAAI/bge-small-en-v1.5",
                        help="HF model id (default: BAAI/bge-small-en-v1.5)")
    parser.add_argument("--out", default=None,
                        help="output dir (default: ./models/<model-basename>)")
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--opset", type=int, default=17)
    return parser.parse_args()


def find_vocab(model_id: str) -> str:
    """Locate vocab.txt inside the local HF cache for model_id."""
    plain = os.path.expanduser(f"~/.cache/huggingface/hub/models--{model_id.replace('/', '--')}")
    hits = glob.glob(os.path.join(plain, "snapshots", "*", "vocab.txt"))
    if hits:
        return hits[0]
    raise SystemExit(
        f"vocab.txt not found in the HF cache for {model_id}; "
        "run once with network access so transformers caches the tokenizer"
    )


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out) if args.out else Path("models") / args.model.split("/")[-1]
    out_dir.mkdir(parents=True, exist_ok=True)

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModel.from_pretrained(args.model)
    model.eval()

    class _Pool(torch.nn.Module):
        def __init__(self, inner):
            super().__init__()
            self.inner = inner

        def forward(self, input_ids, attention_mask, token_type_ids):
            out = self.inner(input_ids=input_ids, attention_mask=attention_mask,
                             token_type_ids=token_type_ids)
            return out.last_hidden_state

    dummy = tokenizer("export probe sentence", return_tensors="pt",
                      truncation=True, max_length=args.max_length)
    with torch.no_grad():
        torch.onnx.export(
            _Pool(model),
            (dummy["input_ids"], dummy["attention_mask"], dummy["token_type_ids"]),
            str(out_dir / "model.onnx"),
            input_names=["input_ids", "attention_mask", "token_type_ids"],
            output_names=["last_hidden_state"],
            dynamic_axes={
                "input_ids": {0: "batch", 1: "seq"},
                "attention_mask": {0: "batch", 1: "seq"},
                "token_type_ids": {0: "batch", 1: "seq"},
                "last_hidden_state": {0: "batch", 1: "seq"},
            },
            opset_version=args.opset,
        )
    shutil.copy(find_vocab(args.model), out_dir / "vocab.txt")

    print(f"staged {out_dir}:")
    for f in sorted(out_dir.iterdir()):
        print(f"  {f.name}  {f.stat().st_size // 1024} KB")
    print("\nserve with (QIHSE checkout):")
    print("  export QIHSE_OPERATOR_PASSWORD='<operator 12+ chars>'")
    print("  export QIHSE_AIMEM_SERVICE_PASSWORD='<distinct service 12+ chars>'")
    print("  export QIHSE_AIMEM_SERVICE_USER_ID=65000 QIHSE_AIMEM_SERVICE_TENANT_ID=1")
    print("  ./qihse-redis-server \\")
    print("      --port 6401 --bind 127.0.0.1 --require-auth \\")
    print(f"      --embedder-onnx {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

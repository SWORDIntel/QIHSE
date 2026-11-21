#!/usr/bin/env python3
"""Compare equal-sized random-phase and paired sine/cosine feature maps.

Synthetic mathematical experiment only: this does not call QIHSE, measure
throughput, or establish production retrieval recall. Requires NumPy. The
default writes JSON to stdout; --output optionally saves the same report.
"""

import argparse
import json
import math
from pathlib import Path

import numpy as np


def positive_integer(value):
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def run_experiment(features, trials, seed, gamma):
    rng = np.random.default_rng(seed)
    omega = rng.standard_normal((trials, features)) * math.sqrt(2.0 * gamma)
    bias = rng.uniform(0.0, 2.0 * np.pi, (trials, features))
    results = []
    for delta in (0.0, 0.25, 1.0, 3.0):
        x, y, shift = 1.2, 1.2 + delta, 8.0
        exact = math.exp(-gamma * delta * delta)
        random_phase = 2.0 * np.mean(
            np.cos(omega * x + bias) * np.cos(omega * y + bias), axis=1
        )
        paired = np.mean(np.cos(omega[:, : features // 2] * (x - y)), axis=1)
        shifted_random = 2.0 * np.mean(
            np.cos(omega * (x + shift) + bias)
            * np.cos(omega * (y + shift) + bias),
            axis=1,
        )
        shifted_paired = np.mean(
            np.cos(omega[:, : features // 2] * ((x + shift) - (y + shift))),
            axis=1,
        )
        results.append(
            {
                "delta": delta,
                "kernel_truth": exact,
                "random_phase_rmse": float(np.sqrt(np.mean((random_phase - exact) ** 2))),
                "paired_rmse": float(np.sqrt(np.mean((paired - exact) ** 2))),
                "random_phase_translation_max_change": float(
                    np.max(np.abs(shifted_random - random_phase))
                ),
                "paired_translation_max_change": float(
                    np.max(np.abs(shifted_paired - paired))
                ),
            }
        )
    return {
        "scope": "Synthetic formula comparison; no QIHSE execution, throughput, or retrieval claim",
        "numpy_version": np.__version__,
        "seed": seed,
        "real_output_dimensions": features,
        "independent_trials": trials,
        "input_dimensions": 1,
        "gamma": gamma,
        "results": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=positive_integer, default=128,
                        help="equal real feature-vector size for both maps; must be even")
    parser.add_argument("--trials", type=positive_integer, default=4096)
    parser.add_argument("--seed", type=int, default=20261114)
    parser.add_argument("--gamma", type=float, default=0.5,
                        help="RBF kernel parameter in exp(-gamma * distance_squared)")
    parser.add_argument("--output", type=Path,
                        help="optional JSON destination; stdout is always emitted")
    args = parser.parse_args()
    if args.features % 2:
        parser.error("--features must be even for paired sine/cosine features")
    if args.seed < 0:
        parser.error("--seed must be nonnegative")
    if not math.isfinite(args.gamma) or args.gamma <= 0:
        parser.error("--gamma must be finite and positive")
    report = run_experiment(args.features, args.trials, args.seed, args.gamma)
    rendered = json.dumps(report, indent=2, allow_nan=False) + "\n"
    if args.output is not None:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()

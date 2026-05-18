#!/usr/bin/env python3
"""Analyze qmag auto-policy candidates from randomized sweep summaries.

The expected input is the lightweight list format emitted by sweep summaries,
for example results/sweep100/summary.json. A qmag "positive" means qmag was the
recorded winner for that case. Candidate policies predict whether an auto-policy
should choose qmag and are scored against that winner label.

When --results-dir is provided, per-case result JSON files are merged into the
summary cases so policies can use the actual qmag effective candidate pool
recorded by the benchmark runner.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable, Iterable


Case = dict[str, Any]
Predicate = Callable[[Case], bool]
DEFAULT_C_DENOMINATOR = 64


@dataclass(frozen=True)
class Metric:
    name: str
    label: str
    getter: Callable[[Case], float | None]
    fmt: str = "{:.6g}"


@dataclass(frozen=True)
class Condition:
    metric: Metric
    op: str
    threshold: float

    def match(self, case: Case) -> bool:
        value = self.metric.getter(case)
        if value is None or math.isnan(value):
            return False
        if self.op == "<=":
            return value <= self.threshold
        if self.op == ">=":
            return value >= self.threshold
        raise ValueError(f"unsupported operator: {self.op}")

    def describe(self) -> str:
        return f"{self.metric.name}{self.op}{self.metric.fmt.format(self.threshold)}"


@dataclass(frozen=True)
class Policy:
    name: str
    conditions: tuple[Condition, ...]
    joiner: str = "and"

    def match(self, case: Case) -> bool:
        if not self.conditions:
            return self.name == "always_qmag"
        if self.joiner == "and":
            return all(condition.match(case) for condition in self.conditions)
        if self.joiner == "or":
            return any(condition.match(case) for condition in self.conditions)
        raise ValueError(f"unsupported joiner: {self.joiner}")

    def describe(self) -> str:
        if not self.conditions:
            return self.name
        sep = f" {self.joiner} "
        return sep.join(condition.describe() for condition in self.conditions)


@dataclass(frozen=True)
class Score:
    policy: Policy
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    selected: int
    actual_positive: int
    mean_selected_speedup: float | None

    @property
    def errors(self) -> int:
        return self.false_positive + self.false_negative

    @property
    def accuracy(self) -> float:
        total = self.true_positive + self.false_positive + self.true_negative + self.false_negative
        return (self.true_positive + self.true_negative) / total if total else 0.0

    @property
    def precision(self) -> float:
        denom = self.true_positive + self.false_positive
        return self.true_positive / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positive + self.false_negative
        return self.true_positive / denom if denom else 0.0

    @property
    def f1(self) -> float:
        denom = self.precision + self.recall
        return 2.0 * self.precision * self.recall / denom if denom else 0.0


@dataclass(frozen=True)
class CThreshold:
    metric: str
    source_threshold: float
    fraction: Fraction
    c_expression: str


QMAG_WINNER = "qmag"


def numeric(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def number(case: Case, key: str) -> float | None:
    return numeric(case.get(key))


def ratio(numerator: float | None, denominator: float | None) -> float | None:
    if numerator is None or denominator in (None, 0.0):
        return None
    return numerator / denominator


def query_active_ratio(case: Case) -> float | None:
    explicit = number(case, "query_active_ratio")
    if explicit is not None:
        return explicit
    return ratio(number(case, "query_active"), number(case, "dims"))


def base_active_ratio(case: Case) -> float | None:
    explicit = number(case, "base_active_ratio")
    if explicit is not None:
        return explicit
    return ratio(number(case, "base_active"), number(case, "dims"))


def active_product_ratio(case: Case) -> float | None:
    query = query_active_ratio(case)
    base = base_active_ratio(case)
    if query is None or base is None:
        return None
    return query * base


def active_mean_ratio(case: Case) -> float | None:
    query = query_active_ratio(case)
    base = base_active_ratio(case)
    if query is None or base is None:
        return None
    return (query + base) / 2.0


def rerank_ratio(case: Case) -> float | None:
    actual = number(case, "actual_qmag_effective_pool_live_rows_ratio")
    if actual is not None:
        return actual
    explicit = number(case, "rerank_ratio")
    if explicit is not None:
        return explicit
    for key in ("effective_candidate_pool", "candidate_pool", "reranked_rows", "rerank_rows"):
        value = number(case, key)
        rows = number(case, "rows")
        derived = ratio(value, rows)
        if derived is not None:
            return derived
    return ratio(number(case, "top_k"), number(case, "rows"))


def top_k_live_rows_ratio(case: Case) -> float | None:
    actual = number(case, "actual_top_k_live_rows_ratio")
    if actual is not None:
        return actual
    return ratio(number(case, "top_k"), number(case, "rows"))


def active_ratio(case: Case) -> float | None:
    actual = number(case, "actual_active_ratio")
    if actual is not None:
        return actual
    return query_active_ratio(case)


def speedup_vs_best(case: Case) -> float | None:
    explicit = number(case, "qmag_speedup_vs_best_non_qmag")
    if explicit is not None:
        return explicit
    qmag = number(case, "qmag_mean_us")
    f32 = number(case, "float32_mean_us")
    qtri = number(case, "qtri_mean_us")
    candidates = [value for value in (f32, qtri) if value is not None]
    if qmag in (None, 0.0) or not candidates:
        return None
    return min(candidates) / qmag


def load_cases(path: Path) -> list[Case]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if isinstance(value, dict) and isinstance(value.get("cases"), list):
        value = value["cases"]
    if not isinstance(value, list):
        raise ValueError(f"{path} must contain a JSON list or an object with a cases list")
    cases = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"case {index} must be a JSON object")
        cases.append(item)
    if not cases:
        raise ValueError(f"{path} contains no cases")
    return cases


def find_qmag_mode(result: Case) -> Case | None:
    modes = result.get("modes")
    if not isinstance(modes, list):
        return None
    for mode in modes:
        if isinstance(mode, dict) and str(mode.get("mode", "")) == QMAG_WINNER:
            return mode
    return None


def nested_number(container: Any, key: str) -> float | None:
    if not isinstance(container, dict):
        return None
    return numeric(container.get(key))


def active_query_ratio(result: Case) -> float | None:
    explicit = number(result, "active_ratio")
    if explicit is not None:
        return explicit
    active_query_dims = result.get("active_query_dims")
    if not isinstance(active_query_dims, dict):
        return None
    active = nested_number(active_query_dims, "mean")
    total_dims = nested_number(active_query_dims, "total_dims")
    if total_dims is None:
        total_dims = number(result, "dimensions")
    return ratio(active, total_dims)


def extract_actual_qmag_metrics(result: Case) -> dict[str, Any]:
    qmag = find_qmag_mode(result)
    if qmag is None:
        return {}
    effective_pool = nested_number(qmag, "effective_candidate_pool")
    if effective_pool is None:
        effective_pool = nested_number(qmag, "candidate_pool")
    if effective_pool is None:
        effective_pool = nested_number(qmag, "reranked_rows")
    live_rows = nested_number(qmag, "live_rows")
    if live_rows is None:
        live_rows = number(result, "live_rows")
    if live_rows is None:
        live_rows = number(result, "rows")
    top_k = nested_number(qmag, "top_k")
    if top_k is None:
        top_k = number(result, "top_k")
    actual = {
        "actual_qmag_effective_pool": effective_pool,
        "actual_qmag_live_rows": live_rows,
        "actual_top_k": top_k,
        "actual_active_ratio": active_query_ratio(result),
        "actual_qmag_effective_pool_live_rows_ratio": ratio(effective_pool, live_rows),
        "actual_top_k_live_rows_ratio": ratio(top_k, live_rows),
    }
    return {key: value for key, value in actual.items() if value is not None}


def load_actual_qmag_metrics(results_dir: Path) -> dict[str, dict[str, Any]]:
    metrics_by_name: dict[str, dict[str, Any]] = {}
    for path in sorted(results_dir.glob("*.json")):
        if path.name == "summary.json":
            continue
        with path.open("r", encoding="utf-8") as handle:
            result = json.load(handle)
        if not isinstance(result, dict):
            continue
        metrics = extract_actual_qmag_metrics(result)
        if not metrics:
            continue
        name = str(result.get("workload") or path.stem)
        metrics["actual_qmag_result_file"] = str(path)
        metrics_by_name[name] = metrics
    return metrics_by_name


def enrich_cases_with_actual_qmag(cases: list[Case], results_dir: Path) -> tuple[list[Case], int]:
    metrics_by_name = load_actual_qmag_metrics(results_dir)
    enriched: list[Case] = []
    matched = 0
    for case in cases:
        copy = dict(case)
        name = str(case.get("name", ""))
        metrics = metrics_by_name.get(name)
        if metrics is not None:
            copy.update(metrics)
            matched += 1
        enriched.append(copy)
    return enriched, matched


def qmag_won(case: Case) -> bool:
    return str(case.get("winner", "")) == QMAG_WINNER


def mismatch_count(case: Case) -> int:
    mismatches = case.get("mismatches", {})
    if isinstance(mismatches, dict):
        value = mismatches.get("qmag", 0)
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0
    if isinstance(mismatches, list):
        return len(mismatches)
    return 0


def format_value(value: float | None) -> str:
    if value is None or math.isnan(value):
        return "n/a"
    if abs(value) >= 100:
        return f"{value:.0f}"
    return f"{value:.4g}"


def fraction_value(value: Fraction) -> float:
    return value.numerator / value.denominator


def format_fraction(value: Fraction) -> str:
    if value.denominator == 1:
        return str(value.numerator)
    return f"{value.numerator}/{value.denominator}"


def ceil_fraction(value: float, denominator: int = DEFAULT_C_DENOMINATOR) -> Fraction:
    numerator = math.ceil((value * denominator) - 1e-12)
    return Fraction(numerator, denominator)


def c_ratio_expression(metric: str, threshold: Fraction) -> str:
    numerator = threshold.numerator
    denominator = threshold.denominator
    rhs = "dims" if metric in ("active_ratio", "query_active_ratio") else "live_rows"
    lhs = {
        "active_ratio": "active_query_dims",
        "query_active_ratio": "active_query_dims",
        "rerank_ratio": "effective_qmag_pool",
        "top_k_live_rows_ratio": "top_k",
    }.get(metric, metric)
    if numerator == 1:
        return f"{lhs} * {denominator} <= {rhs}"
    return f"{lhs} * {denominator} <= {rhs} * {numerator}"


def group_rows(cases: list[Case], metric: Metric) -> list[dict[str, Any]]:
    groups: dict[float, list[Case]] = defaultdict(list)
    missing = 0
    for case in cases:
        value = metric.getter(case)
        if value is None or math.isnan(value):
            missing += 1
            continue
        groups[value].append(case)
    rows = []
    for value, items in sorted(groups.items()):
        wins = sum(1 for item in items if qmag_won(item))
        speedups = [speedup_vs_best(item) for item in items]
        speedups = [item for item in speedups if item is not None]
        rows.append(
            {
                "metric": metric.name,
                "value": value,
                "cases": len(items),
                "qmag_wins": wins,
                "qmag_losses": len(items) - wins,
                "win_rate": wins / len(items),
                "mean_speedup_vs_best_non_qmag": sum(speedups) / len(speedups) if speedups else None,
            }
        )
    if missing:
        rows.append(
            {
                "metric": metric.name,
                "value": None,
                "cases": missing,
                "qmag_wins": 0,
                "qmag_losses": missing,
                "win_rate": 0.0,
                "mean_speedup_vs_best_non_qmag": None,
            }
        )
    return rows


def score_policy(cases: list[Case], policy: Policy) -> Score:
    tp = fp = tn = fn = selected = actual_positive = 0
    selected_speedups: list[float] = []
    for case in cases:
        actual = qmag_won(case)
        predicted = policy.match(case)
        if actual:
            actual_positive += 1
        if predicted:
            selected += 1
            value = speedup_vs_best(case)
            if value is not None:
                selected_speedups.append(value)
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1
    mean_speedup = sum(selected_speedups) / len(selected_speedups) if selected_speedups else None
    return Score(policy, tp, fp, tn, fn, selected, actual_positive, mean_speedup)


def unique_thresholds(cases: list[Case], metric: Metric) -> list[float]:
    values = set()
    for case in cases:
        value = metric.getter(case)
        if value is not None and not math.isnan(value):
            values.add(value)
    return sorted(values)


def generate_policies(cases: list[Case], metrics: list[Metric], max_terms: int) -> list[Policy]:
    policies = [Policy("always_qmag", ()), Policy("never_qmag", ())]
    single_conditions: list[Condition] = []
    for metric in metrics:
        for threshold in unique_thresholds(cases, metric):
            single_conditions.append(Condition(metric, "<=", threshold))
            single_conditions.append(Condition(metric, ">=", threshold))
    policies.extend(Policy(condition.describe(), (condition,)) for condition in single_conditions)
    if max_terms >= 2:
        for left_index, left in enumerate(single_conditions):
            for right in single_conditions[left_index + 1 :]:
                if left.metric.name == right.metric.name:
                    continue
                policies.append(Policy(f"{left.describe()} and {right.describe()}", (left, right), "and"))
    return policies


def rank_scores(scores: list[Score]) -> list[Score]:
    return sorted(
        scores,
        key=lambda score: (
            score.errors,
            -score.f1,
            -score.accuracy,
            score.false_positive,
            score.false_negative,
            len(score.policy.conditions),
            score.policy.describe(),
        ),
    )


def find_best_threshold_score(scores: list[Score], pool_metric: str) -> Score | None:
    active_metrics = {"active_ratio", "query_active_ratio"}
    for score in scores:
        conditions = score.policy.conditions
        if len(conditions) != 2 or score.policy.joiner != "and":
            continue
        metric_names = {condition.metric.name for condition in conditions}
        ops = {condition.op for condition in conditions}
        if ops == {"<="} and pool_metric in metric_names and metric_names.intersection(active_metrics):
            return score
    return None


def rationalized_policy(score: Score | None) -> tuple[Policy | None, list[CThreshold]]:
    if score is None:
        return None, []
    conditions: list[Condition] = []
    thresholds: list[CThreshold] = []
    for condition in score.policy.conditions:
        if condition.op != "<=":
            return None, []
        fraction = ceil_fraction(condition.threshold)
        conditions.append(Condition(condition.metric, "<=", fraction_value(fraction)))
        thresholds.append(
            CThreshold(
                metric=condition.metric.name,
                source_threshold=condition.threshold,
                fraction=fraction,
                c_expression=c_ratio_expression(condition.metric.name, fraction),
            )
        )
    name = "c_threshold_" + "_and_".join(threshold.metric for threshold in thresholds)
    return Policy(name, tuple(conditions), "and"), thresholds


def c_threshold_recommendations(cases: list[Case], scores: list[Score]) -> list[dict[str, Any]]:
    recommendations = []
    for label, pool_metric in (
        ("default_actual_pool_policy", "rerank_ratio"),
        ("default_top_k_proxy_policy", "top_k_live_rows_ratio"),
    ):
        source_score = find_best_threshold_score(scores, pool_metric)
        c_policy, thresholds = rationalized_policy(source_score)
        if source_score is None or c_policy is None:
            continue
        c_score = score_policy(cases, c_policy)
        recommendations.append(
            {
                "label": label,
                "source_policy": source_score.policy.describe(),
                "c_policy": " and ".join(
                    f"{threshold.metric}<={format_fraction(threshold.fraction)}"
                    for threshold in thresholds
                ),
                "thresholds": thresholds,
                "score": c_score,
            }
        )
    return recommendations


def print_patterns(cases: list[Case], metrics: list[Metric]) -> None:
    print("\nqmag win/loss patterns")
    for metric in metrics:
        print(f"\n[{metric.label}]")
        print("value\tcases\twins\tlosses\twin_rate\tmean_qmag_speedup_vs_best")
        for row in group_rows(cases, metric):
            value = row["value"]
            value_text = "missing" if value is None else metric.fmt.format(value)
            print(
                f"{value_text}\t{row['cases']}\t{row['qmag_wins']}\t{row['qmag_losses']}\t"
                f"{row['win_rate']:.3f}\t{format_value(row['mean_speedup_vs_best_non_qmag'])}"
            )


def print_policy_scores(scores: list[Score], limit: int) -> None:
    print("\nrecommended candidate policies")
    print("rank\tpolicy\terrors\tfp\tfn\ttp\ttn\tselected\tprecision\trecall\tf1\taccuracy\tmean_selected_speedup")
    for rank, score in enumerate(scores[:limit], start=1):
        print(
            f"{rank}\t{score.policy.describe()}\t{score.errors}\t{score.false_positive}\t{score.false_negative}\t"
            f"{score.true_positive}\t{score.true_negative}\t{score.selected}\t{score.precision:.3f}\t"
            f"{score.recall:.3f}\t{score.f1:.3f}\t{score.accuracy:.3f}\t"
            f"{format_value(score.mean_selected_speedup)}"
        )


def print_c_threshold_recommendations(recommendations: list[dict[str, Any]]) -> None:
    if not recommendations:
        return
    print("\nrecommended C thresholds if used as the default qmag auto-policy")
    print("label\tsource_policy\tc_policy\texpected_selected\tfp\tfn\tprecision\trecall\tmean_selected_speedup")
    for item in recommendations:
        score = item["score"]
        print(
            f"{item['label']}\t{item['source_policy']}\t{item['c_policy']}\t"
            f"{score.selected}\t{score.false_positive}\t{score.false_negative}\t"
            f"{score.precision:.3f}\t{score.recall:.3f}\t{format_value(score.mean_selected_speedup)}"
        )
    print("C integer predicates")
    for item in recommendations:
        expressions = "; ".join(threshold.c_expression for threshold in item["thresholds"])
        print(f"{item['label']}\t{expressions}")


def build_metrics() -> list[Metric]:
    return [
        Metric("active_ratio", "actual active ratio when available, fallback query active ratio", active_ratio),
        Metric("query_active_ratio", "query active ratio", query_active_ratio),
        Metric("base_active_ratio", "base active ratio", base_active_ratio),
        Metric("active_product_ratio", "query_active_ratio * base_active_ratio", active_product_ratio),
        Metric("active_mean_ratio", "mean(query_active_ratio, base_active_ratio)", active_mean_ratio),
        Metric("rerank_ratio", "actual qmag effective_pool/live_rows when available, fallback summary rerank/top_k/rows", rerank_ratio),
        Metric("top_k_live_rows_ratio", "actual top_k/live_rows when available, fallback top_k/rows", top_k_live_rows_ratio),
        Metric("rows", "rows", lambda case: number(case, "rows"), "{:.0f}"),
        Metric("dims", "dims", lambda case: number(case, "dims"), "{:.0f}"),
        Metric("top_k", "top_k", lambda case: number(case, "top_k"), "{:.0f}"),
    ]


def json_report(
    cases: list[Case],
    metrics: list[Metric],
    scores: list[Score],
    limit: int,
    actual_qmag_result_cases: int,
    c_recommendations: list[dict[str, Any]],
) -> dict[str, Any]:
    winners: dict[str, int] = defaultdict(int)
    for case in cases:
        winners[str(case.get("winner", "<missing>"))] += 1
    return {
        "cases": len(cases),
        "actual_qmag_result_cases": actual_qmag_result_cases,
        "winners": dict(sorted(winners.items())),
        "qmag_mismatch_cases": sum(1 for case in cases if mismatch_count(case) != 0),
        "patterns": {metric.name: group_rows(cases, metric) for metric in metrics},
        "candidate_policies": [
            {
                "rank": index + 1,
                "policy": score.policy.describe(),
                "errors": score.errors,
                "false_positives": score.false_positive,
                "false_negatives": score.false_negative,
                "true_positives": score.true_positive,
                "true_negatives": score.true_negative,
                "selected": score.selected,
                "actual_qmag_wins": score.actual_positive,
                "precision": score.precision,
                "recall": score.recall,
                "f1": score.f1,
                "accuracy": score.accuracy,
                "mean_selected_speedup_vs_best_non_qmag": score.mean_selected_speedup,
            }
            for index, score in enumerate(scores[:limit])
        ],
        "recommended_c_thresholds": [
            {
                "label": item["label"],
                "source_policy": item["source_policy"],
                "c_policy": item["c_policy"],
                "thresholds": [
                    {
                        "metric": threshold.metric,
                        "source_threshold": threshold.source_threshold,
                        "fraction": format_fraction(threshold.fraction),
                        "decimal": fraction_value(threshold.fraction),
                        "c_expression": threshold.c_expression,
                    }
                    for threshold in item["thresholds"]
                ],
                "expected_selected_cases": item["score"].selected,
                "false_positives": item["score"].false_positive,
                "false_negatives": item["score"].false_negative,
                "precision": item["score"].precision,
                "recall": item["score"].recall,
                "mean_selected_speedup_vs_best_non_qmag": item["score"].mean_selected_speedup,
            }
            for item in c_recommendations
        ],
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", nargs="?", default="results/sweep100/summary.json", help="sweep summary JSON")
    parser.add_argument("--top", type=int, default=12, help="number of ranked candidate policies to print")
    parser.add_argument("--max-policy-terms", type=int, choices=(1, 2), default=2, help="maximum threshold terms per candidate policy")
    parser.add_argument(
        "--results-dir",
        type=Path,
        help="directory containing per-case result JSON files with actual qmag effective_candidate_pool values",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON instead of text")
    args = parser.parse_args(argv)

    try:
        cases = load_cases(Path(args.summary))
        actual_qmag_result_cases = 0
        if args.results_dir is not None:
            cases, actual_qmag_result_cases = enrich_cases_with_actual_qmag(cases, args.results_dir)
        metrics = build_metrics()
        policies = generate_policies(cases, metrics, args.max_policy_terms)
        scores = rank_scores([score_policy(cases, policy) for policy in policies])
        c_recommendations = c_threshold_recommendations(cases, scores)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"qmag policy analyzer failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(
            json.dumps(
                json_report(cases, metrics, scores, args.top, actual_qmag_result_cases, c_recommendations),
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    winners: dict[str, int] = defaultdict(int)
    for case in cases:
        winners[str(case.get("winner", "<missing>"))] += 1
    print(f"cases={len(cases)} winners=" + ", ".join(f"{key}:{value}" for key, value in sorted(winners.items())))
    print(f"actual_qmag_result_cases={actual_qmag_result_cases}")
    print(f"qmag_mismatch_cases={sum(1 for case in cases if mismatch_count(case) != 0)}")
    print_patterns(cases, metrics)
    print_policy_scores(scores, args.top)
    print_c_threshold_recommendations(c_recommendations)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

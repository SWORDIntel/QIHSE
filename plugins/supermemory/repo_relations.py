#!/usr/bin/env python3
"""Dynamic repository relationship & dependency graph engine for QIHSE AIMEM.

Automatically and dynamically detects related repositories and projects
(e.g., QIHSE <-> KEYSTONE <-> KP15-SUITE/VEXEL/DEXWARD, or hax <-> INFRA bridges)
at runtime through build manifests, symlinks, documentation references,
and shared system architectures.

Maintains a fast dynamic cache in ~/.cache/qihse-aimem/repo_relations.json
with configurable TTL, ensuring fast prompt hooks (< 1ms) while adapting
dynamically to project relationships without requiring reinstall.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Dynamic cache location & default TTL (30 minutes)
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "qihse-aimem"
CACHE_FILE = CACHE_DIR / "repo_relations.json"
DEFAULT_TTL_SEC = 1800

# Canonical core system clusters (baseline affinities)
BASELINE_CLUSTERS: List[Set[str]] = [
    {
        "qihse", "keystone", "kp15-suite", "kp14", "vexel", "dexward",
        "methra", "radare3", "isanity", "angryier", "qihse-docs", "qihse-fan-stack",
    },
    {
        "hax", "headless-linux-bridge", "headless-winrm-bridge", "infra",
        "supermemory-qihse-bridge",
    },
]

# Patterns for manifests to inspect
MANIFEST_NAMES = {
    "Cargo.toml", "go.mod", "meson.build", "CMakeLists.txt",
    "Makefile", "package.json", ".gitmodules",
}

DOC_NAMES = {
    "README.md", "ROADMAP.md", "AGENTS.md", "ARCHITECTURE.md",
    "CLAUDE.md", "PLAN.md", "AI_WORKBENCH_GUIDE.md",
}


# Directories and words to strictly ignore as repositories
IGNORE_DIRS = {
    "bin", "data", "desktop", "documents", "downloads", "go", "info", "output",
    "plugins", "public", "templates", "tmp", "tools", "work", "scripts", "sounds",
    "raid", "misc", "sound", "toasts", "new-folder", "pycache", "__pycache__",
    "backups", "android", "intel", "orchestration", "templates", "bridge", "suite",
    "home", "target", "build", "external", "src", "docs",
}

# Files that identify a directory as a genuine project / repo
PROJECT_MARKERS = {
    ".git", "Cargo.toml", "go.mod", "meson.build", "CMakeLists.txt",
    "package.json", "setup.py", "pyproject.toml", "Makefile",
}


def is_valid_project_dir(p: Path) -> bool:
    """Check if a path represents a legitimate code repository or project."""
    name = canonical_repo_name(p.name)
    if name in IGNORE_DIRS or len(name) < 3:
        return False
    if p.is_symlink():
        return True
    if not p.is_dir():
        return False
    # Check for project markers
    for marker in PROJECT_MARKERS:
        if (p / marker).exists():
            return True
    return False


def canonical_repo_name(name_or_path: str | Path) -> str:
    """Normalize repository or path name to lowercase alphanumeric-hyphen identifier."""
    name = Path(name_or_path).name.strip().lower()
    name = re.sub(r"[_\s]+", "-", name)
    name = re.sub(r"[^a-z0-9.-]+", "-", name)
    return name.strip("-.")[:128]


def get_current_repo(cwd: Optional[str | Path] = None) -> Tuple[str, Path]:
    """Detect current repository root and canonical name from cwd or git.
    
    Correctly recognizes suite subprojects (e.g. KP15-SUITE/suite/VEXEL), suite
    containers, and parent workspaces as tightly coupled entities.
    """
    start_dir = Path(cwd).resolve() if cwd else Path.cwd().resolve()
    home = Path.home().resolve()
    docs = (home / "Documents").resolve()

    # If start_dir is under Documents/ or home/, determine project root
    for root_container in (docs, home):
        try:
            rel = start_dir.relative_to(root_container)
            if len(rel.parts) >= 1 and rel.parts[0] not in IGNORE_DIRS:
                # Check for suite subproject: e.g. KP15-SUITE/suite/VEXEL
                if len(rel.parts) >= 3 and rel.parts[1].lower() == "suite" and rel.parts[2] not in IGNORE_DIRS:
                    sub_dir = root_container / rel.parts[0] / rel.parts[1] / rel.parts[2]
                    return canonical_repo_name(rel.parts[2]), sub_dir
                proj_dir = root_container / rel.parts[0]
                return canonical_repo_name(proj_dir.name), proj_dir
        except ValueError:
            pass

    # 1. Try git rev-parse --show-toplevel (unless it points to home or docs)
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=start_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=1,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            top = Path(proc.stdout.strip()).resolve()
            if top not in (home, docs) and canonical_repo_name(top.name) not in IGNORE_DIRS:
                return canonical_repo_name(top.name), top
    except Exception:
        pass

    # 2. Fallback to start_dir
    return canonical_repo_name(start_dir.name), start_dir


def _find_candidate_sibling_dirs(root_dir: Path) -> List[Path]:
    """Find sibling project directories and symlinks in the workspace parent."""
    home = Path.home().resolve()
    docs = (home / "Documents").resolve()
    parent = root_dir.parent

    # If parent is docs, search docs; if parent is something else, search parent and docs
    parents_to_search = [parent]
    if docs.exists() and docs not in parents_to_search:
        parents_to_search.append(docs)

    candidates: List[Path] = []
    seen: Set[Path] = set()

    for p_dir in parents_to_search:
        try:
            for entry in p_dir.iterdir():
                if entry.name.startswith(".") or entry in seen:
                    continue
                if entry.resolve() in (home, docs):
                    continue
                if is_valid_project_dir(entry):
                    seen.add(entry)
                    candidates.append(entry)
        except Exception:
            pass
    return candidates


def _scan_repo_relations(repo_dir: Path, known_repo_names: Set[str]) -> Tuple[Set[str], List[str]]:
    """Scan a repository for explicit dependencies, symlinks, and doc references."""
    related: Set[str] = set()
    evidence: List[str] = []

    # 1. Check symlink targets
    try:
        if repo_dir.is_symlink():
            target_str = os.readlink(repo_dir)
            target_path = Path(target_str)
            for part in target_path.parts:
                norm_part = canonical_repo_name(part)
                if norm_part in known_repo_names and norm_part not in IGNORE_DIRS and norm_part != canonical_repo_name(repo_dir.name):
                    related.add(norm_part)
                    evidence.append(f"symlink_target:{norm_part}")
    except Exception:
        pass

    # Check symlinks within repo_dir (first level)
    try:
        if repo_dir.is_dir():
            for item in repo_dir.iterdir():
                if item.is_symlink():
                    try:
                        target = os.readlink(item)
                        for part in Path(target).parts:
                            norm_part = canonical_repo_name(part)
                            if norm_part in known_repo_names and norm_part not in IGNORE_DIRS and norm_part != canonical_repo_name(repo_dir.name):
                                related.add(norm_part)
                                evidence.append(f"inner_symlink:{item.name}->{norm_part}")
                    except Exception:
                        pass
    except Exception:
        pass

    # Check suite/ directory (e.g. KP15-SUITE/suite/*) - tight coupling with all members
    try:
        suite_dir = repo_dir / "suite"
        if suite_dir.is_dir():
            for sub in suite_dir.iterdir():
                sub_name = canonical_repo_name(sub.name)
                if sub_name not in IGNORE_DIRS:
                    related.add(sub_name)
                    evidence.append(f"suite_member:{sub.name}")
                if sub.is_symlink():
                    try:
                        target_str = os.readlink(sub)
                        for part in Path(target_str).parts:
                            norm_part = canonical_repo_name(part)
                            if norm_part in known_repo_names and norm_part not in IGNORE_DIRS and norm_part != canonical_repo_name(repo_dir.name):
                                related.add(norm_part)
                                evidence.append(f"suite_symlink:{sub.name}->{norm_part}")
                    except Exception:
                        pass
    except Exception:
        pass

    # If repo_dir itself is located inside a suite/ folder (e.g. .../KP15-SUITE/suite/VEXEL)
    try:
        if repo_dir.parent.name.lower() == "suite" and repo_dir.parent.parent.is_dir():
            parent_repo_name = canonical_repo_name(repo_dir.parent.parent.name)
            if parent_repo_name not in IGNORE_DIRS:
                related.add(parent_repo_name)
                evidence.append(f"parent_suite:{parent_repo_name}")
            for sibling in repo_dir.parent.iterdir():
                sib_name = canonical_repo_name(sibling.name)
                if sib_name not in IGNORE_DIRS and sib_name != canonical_repo_name(repo_dir.name):
                    related.add(sib_name)
                    evidence.append(f"suite_sibling:{sibling.name}")
    except Exception:
        pass

    # 2. Check build manifests for path dependencies or mentions
    for manifest_name in MANIFEST_NAMES:
        mpath = repo_dir / manifest_name
        if not mpath.exists():
            continue
        try:
            content = mpath.read_text(encoding="utf-8", errors="ignore")[:65536]
            for kn in known_repo_names:
                if kn == canonical_repo_name(repo_dir.name) or kn in IGNORE_DIRS or len(kn) < 3:
                    continue
                # Search for path or explicit dependency mentions
                pattern = rf"(?<![a-zA-Z0-9_-]){re.escape(kn)}(?![a-zA-Z0-9_-])|(\.\./{re.escape(kn)})"
                if re.search(pattern, content, re.IGNORECASE):
                    related.add(kn)
                    evidence.append(f"manifest:{manifest_name}->{kn}")
        except Exception:
            pass

    # 3. Check top-level documentation
    for doc_name in DOC_NAMES:
        dpath = repo_dir / doc_name
        if not dpath.exists():
            continue
        try:
            content = dpath.read_text(encoding="utf-8", errors="ignore")[:32768]
            for kn in known_repo_names:
                if kn == canonical_repo_name(repo_dir.name) or kn in IGNORE_DIRS or len(kn) < 4:
                    continue
                # Word-boundary check for known repo
                pattern = rf"(?<![a-zA-Z0-9_-]){re.escape(kn)}(?![a-zA-Z0-9_-])"
                if re.search(pattern, content, re.IGNORECASE):
                    related.add(kn)
                    evidence.append(f"doc:{doc_name}->{kn}")
        except Exception:
            pass

    return related, evidence


def discover_dependency_graph(current_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Dynamically discover repository relationships across active project workspaces."""
    _, repo_root = get_current_repo(current_dir)
    sibling_dirs = _find_candidate_sibling_dirs(repo_root)

    # Collect all known candidate repo names
    known_dirs: Dict[str, Path] = {}
    for d in [repo_root] + sibling_dirs:
        norm = canonical_repo_name(d.name)
        known_dirs[norm] = d

    known_names = set(known_dirs.keys())
    # Add baseline keywords to known names
    for cluster in BASELINE_CLUSTERS:
        known_names.update(cluster)

    graph: Dict[str, Set[str]] = {name: set() for name in known_names}
    evidence_map: Dict[str, List[str]] = {name: [] for name in known_names}

    # Scan directories on disk for direct relations
    for name, p in known_dirs.items():
        if not p.exists() or name in IGNORE_DIRS:
            continue
        rel, ev = _scan_repo_relations(p, known_names)
        for r in rel:
            if r not in IGNORE_DIRS and r != name:
                graph[name].add(r)
                if r in graph:
                    graph[r].add(name)
        evidence_map[name].extend(ev)

    # Seed explicit core system clusters
    for cluster in BASELINE_CLUSTERS:
        for a in cluster:
            for b in cluster:
                if a != b:
                    graph[a].add(b)

    # Prepare serialized cache payload with direct related sets (1-hop strong neighbours)
    result: Dict[str, Any] = {
        "version": 1,
        "updated_at": int(time.time()),
        "root_checked": str(repo_root),
        "repos": {},
    }

    for name in known_names:
        if name in IGNORE_DIRS:
            continue
        related_set = sorted(graph.get(name, set()) | {name})
        result["repos"][name] = {
            "related": related_set,
            "evidence": evidence_map.get(name, []),
        }

    return result


def load_cached_relations(force_refresh: bool = False, max_age_sec: int = DEFAULT_TTL_SEC) -> Dict[str, Any]:
    """Load cached relations or dynamically discover if missing, stale, or forced."""
    now = int(time.time())
    if not force_refresh and CACHE_FILE.exists():
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            if data.get("version") == 1 and (now - data.get("updated_at", 0)) < max_age_sec:
                return data
        except Exception:
            pass

    # Dynamically build dependency map
    try:
        data = discover_dependency_graph()
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        # Atomic write
        tmp_file = CACHE_FILE.with_suffix(f".tmp.{os.getpid()}")
        tmp_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp_file.replace(CACHE_FILE)
        return data
    except Exception as e:
        # Fallback to in-memory baseline
        fallback = {"version": 1, "updated_at": now, "repos": {}}
        for cluster in BASELINE_CLUSTERS:
            for item in cluster:
                fallback["repos"][item] = {"related": sorted(cluster), "evidence": ["baseline_cluster"]}
        return fallback


def get_related_repos(repo_name_or_path: Optional[str | Path] = None, force_refresh: bool = False) -> Set[str]:
    """Get the set of related repositories for a given repo name or path.
    
    Dynamically loads or refreshes repository relations without requiring installation.
    """
    if repo_name_or_path is None:
        target_name, _ = get_current_repo()
    else:
        target_name = canonical_repo_name(repo_name_or_path)

    data = load_cached_relations(force_refresh=force_refresh)
    repos = data.get("repos", {})

    # If the requested repo is not yet in the cache, trigger dynamic discovery once
    if target_name not in repos and not force_refresh:
        data = load_cached_relations(force_refresh=True)
        repos = data.get("repos", {})

    entry = repos.get(target_name)
    if entry and "related" in entry:
        return set(entry["related"])

    # Fallback to searching baseline clusters
    for cluster in BASELINE_CLUSTERS:
        if target_name in cluster:
            return set(cluster)

    return {target_name}


def parse_memory_hit(raw_hit: Any) -> Dict[str, Any]:
    """Normalize a raw QIHSE RESP hit (list of 7 fields or dict) into a structured record."""
    if isinstance(raw_hit, list) and len(raw_hit) == 7:
        raw_text = raw_hit[6]
        hit: Dict[str, Any] = {
            "id": raw_hit[0],
            "created_ms": int(raw_hit[1]),
            "kind": int(raw_hit[2]),
            "classification": int(raw_hit[3]),
            "sci": int(raw_hit[4]),
            "score": float(raw_hit[5]),
            "text": str(raw_text),
        }
    elif isinstance(raw_hit, dict):
        hit = dict(raw_hit)
        raw_text = hit.get("text", "")
    else:
        raise ValueError(f"Unsupported memory hit format: {type(raw_hit)}")

    if isinstance(raw_text, str) and raw_text.startswith("{") and raw_text.endswith("}"):
        try:
            doc = json.loads(raw_text)
            if isinstance(doc, dict) and "text" in doc and isinstance(doc["text"], str):
                hit["text"] = doc["text"]
                metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
                repo = (
                    metadata.get("repo")
                    or metadata.get("repository")
                    or doc.get("repo")
                    or doc.get("repository")
                )
                scope = metadata.get("scope") or doc.get("scope")
                if metadata:
                    hit["metadata"] = metadata
                if repo:
                    hit["repo"] = canonical_repo_name(repo)
                if scope:
                    hit["scope"] = scope
        except (json.JSONDecodeError, ValueError):
            pass

    return hit


def rank_and_filter_memories(
    hits: List[Dict[str, Any]],
    current_repo: Optional[str] = None,
    related_repos: Optional[Set[str]] = None,
    min_score: float = 0.005,
) -> List[Dict[str, Any]]:
    """Rank and filter memory hits considering current repo and its dynamic relations.
    
    - Memories explicitly referencing the current repo get boosted (1.4x).
    - Memories referencing related repos are included and boosted (1.2x).
    - General/global memories (conventions, tools, arch) are preserved (1.0x).
    - Memories referencing strictly unrelated repos are deprioritized or filtered.
    """
    if current_repo is None:
        current_repo, _ = get_current_repo()
    if related_repos is None:
        related_repos = get_related_repos(current_repo)

    scored: List[Tuple[float, Dict[str, Any]]] = []

    for raw in hits:
        h = parse_memory_hit(raw)
        base_score = float(h.get("score", 0.0))
        if base_score < min_score:
            continue
        text = h.get("text", "")
        low_text = text.lower()

        # Check for matching current repo
        is_current = current_repo in low_text
        # Check for matching related repos
        matched_related = [r for r in related_repos if r in low_text]

        multiplier = 1.0
        if is_current:
            multiplier = 1.4
        elif matched_related:
            multiplier = 1.2

        adjusted_score = base_score * multiplier
        h_copy = dict(h)
        h_copy["adjusted_score"] = adjusted_score
        h_copy["matched_scope"] = current_repo if is_current else (matched_related[0] if matched_related else "global")
        scored.append((adjusted_score, h_copy))

    # Sort descending by adjusted score
    scored.sort(key=lambda x: x[0], reverse=True)
    return [item[1] for item in scored]


def judge_and_filter_scope(
    hits: List[Dict[str, Any]],
    current_repo: Optional[str] = None,
    related_repos: Optional[Set[str]] = None,
    requested_scope: str = "auto",
    min_score: float = 0.005,
    limit: int = 5,
    query: str = "",
) -> Dict[str, Any]:
    """Judge memory relevance automatically and filter with dynamic scope.
    
    Default behavior is GLOBAL: searches all system and project memories.
    However, if irrelevant foreign memories (from disjoint repositories/domains)
    pollute the top results and would crowd out pertinent context, the engine
    automatically switches to REPO-ONLY (current repo + its tightly coupled cluster),
    suppresses the foreign noise, and sets a notification explaining the switch.
    """
    if current_repo is None:
        current_repo, _ = get_current_repo()
    if related_repos is None:
        related_repos = get_related_repos(current_repo)

    norm_scope = (requested_scope or "auto").strip().lower()

    # Pre-filter hits meeting minimum score
    valid_hits = []
    for raw in hits:
        h = parse_memory_hit(raw)
        if float(h.get("score", 0.0)) >= min_score:
            valid_hits.append(h)
    if not valid_hits:
        return {
            "hits": [],
            "effective_scope": norm_scope,
            "scope_switched": False,
            "notification": "",
            "current_repo": current_repo,
            "related_repos": sorted(list(related_repos)),
        }

    # If user explicitly requested repo or global, respect it directly
    if norm_scope == "repo":
        repo_ranked = rank_and_filter_memories(valid_hits, current_repo, related_repos, min_score=min_score)
        # In repo-only, filter out foreign unrelated entries
        filtered = [
            h for h in repo_ranked
            if h.get("matched_scope") in (current_repo, "global") or h.get("matched_scope") in related_repos
        ]
        return {
            "hits": filtered[:limit],
            "effective_scope": "repo",
            "scope_switched": False,
            "notification": "",
            "current_repo": current_repo,
            "related_repos": sorted(list(related_repos)),
        }
    elif norm_scope == "global":
        global_ranked = rank_and_filter_memories(valid_hits, current_repo, related_repos, min_score=min_score)
        return {
            "hits": global_ranked[:limit],
            "effective_scope": "global",
            "scope_switched": False,
            "notification": "",
            "current_repo": current_repo,
            "related_repos": sorted(list(related_repos)),
        }

    # "auto" mode: GLOBAL BY DEFAULT, with automated self-judging irrelevance detection
    query_low = query.lower() if isinstance(query, str) else ""
    ranked_global = rank_and_filter_memories(valid_hits, current_repo, related_repos, min_score=min_score)

    # Inspect top candidates (up to 2 * limit)
    candidate_sample = ranked_global[: min(len(ranked_global), max(limit * 2, 8))]

    # Classify candidate affinity
    foreign_unrelated_count = 0
    relevant_cluster_count = 0
    top_is_foreign = False

    # A repository or domain name is considered foreign if it is a known project outside current cluster
    # and the user's query did NOT explicitly mention it.
    all_known_repos = set(load_cached_relations().get("repos", {}).keys())
    disjoint_repos = all_known_repos - related_repos - {current_repo}

    # Build disjoint keywords (both full name and prominent segments)
    disjoint_keywords: Set[str] = set()
    for fr in disjoint_repos:
        if len(fr) >= 4 and fr not in IGNORE_DIRS and fr not in related_repos and fr != current_repo:
            disjoint_keywords.add(fr)
            for part in fr.split("-"):
                if len(part) >= 5 and part not in IGNORE_DIRS and part not in related_repos and part != current_repo:
                    disjoint_keywords.add(part)

    for idx, h in enumerate(candidate_sample):
        text = str(h.get("text", "")).lower()
        metadata = h.get("metadata") or {}
        repo_tag = str(h.get("repo") or metadata.get("repo") or "").lower()

        # Check explicit [repo: xyz] tag in header or metadata
        tag_match = re.search(r"\[repo:\s*([a-zA-Z0-9_\-]+)\]", text)
        explicit_tag = canonical_repo_name(tag_match.group(1)) if tag_match else repo_tag

        is_foreign = False
        if explicit_tag and explicit_tag not in related_repos and explicit_tag != current_repo:
            if explicit_tag not in query_low:
                is_foreign = True
        else:
            for kw in disjoint_keywords:
                if re.search(rf"\b{re.escape(kw)}\b", text):
                    if kw not in query_low:
                        is_foreign = True
                        break

        if is_foreign:
            foreign_unrelated_count += 1
            if idx == 0:
                top_is_foreign = True
        else:
            scope = h.get("matched_scope", "global")
            if scope == current_repo or scope in related_repos:
                relevant_cluster_count += 1

    # Heuristic for detecting irrelevant memory pollution:
    # 1. Foreign unrelated memories make up > 35% of candidate sample
    # 2. Or the #1 top memory is foreign while relevant cluster memories exist in the pool
    should_switch_to_repo = False
    if len(candidate_sample) >= 3:
        foreign_ratio = foreign_unrelated_count / len(candidate_sample)
        if foreign_ratio > 0.35 and relevant_cluster_count > 0:
            should_switch_to_repo = True
        elif top_is_foreign and relevant_cluster_count > 0:
            should_switch_to_repo = True

    if should_switch_to_repo:
        # Filter down strictly to current repo, related cluster, or universal memories
        repo_scoped = [
            h for h in ranked_global
            if not any(re.search(rf"\b{re.escape(kw)}\b", str(h.get("text", "")).lower()) for kw in disjoint_keywords if kw not in query_low)
        ]
        # If filtering removed everything, fall back to ranked_global
        final_hits = repo_scoped if repo_scoped else ranked_global
        notification = (
            f"Notice: Auto-switched from global to repository scope ({current_repo} cluster) "
            f"to suppress irrelevant cross-domain results."
        )
        return {
            "hits": final_hits[:limit],
            "effective_scope": "repo",
            "scope_switched": True,
            "notification": notification,
            "current_repo": current_repo,
            "related_repos": sorted(list(related_repos)),
        }
    else:
        # Retain clean global scope
        return {
            "hits": ranked_global[:limit],
            "effective_scope": "global",
            "scope_switched": False,
            "notification": "",
            "current_repo": current_repo,
            "related_repos": sorted(list(related_repos)),
        }


if __name__ == "__main__":
    import sys
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg in ("--scan", "-s", "--refresh"):
        res = load_cached_relations(force_refresh=True)
        print(f"Dynamically refreshed repository relations at {time.ctime(res['updated_at'])}.")
        for r, info in sorted(res.get("repos", {}).items()):
            rel = info.get("related", [])
            if len(rel) > 1:
                print(f"  {r} -> {', '.join(rel)}")
    else:
        repo, root = get_current_repo()
        rel = get_related_repos(repo)
        print(f"Current repository: {repo} ({root})")
        print(f"Dynamically related repositories ({len(rel)}): {', '.join(sorted(rel))}")

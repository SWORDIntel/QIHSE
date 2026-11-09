#!/usr/bin/env python3
"""Validate automatic compact-format choice through the authenticated CLI.

Graphs and state are synthetic and confined to temporary directories. Snapshot
sizes come from authenticated ``stats``; directory listings only check retention.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))
from codegraph_p0_baseline import comparable, graph_fixture
from test_codegraph_native import git

PROJECT = Path(__file__).resolve().parents[1]
FORMATS = ("zstd-v1", "packed-v2", "packed-v3", "packed-v4")
SELECTOR_FIXTURE = r"""
#define _GNU_SOURCE
#include "qihse_codegraph_storage.h"
#include "qihse_codegraph_chunked.h"
#include "qihse_codegraph_dictionary.h"
#include "qihse_audit.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#define PASSWORD "CodegraphAutoSelection1!"
static long bytes(const char *path) {
    struct stat st;assert(!stat(path,&st));assert(st.st_size>=0);return(long)st.st_size;
}
#ifndef CONTROLLED_LENGTHS
static bool save_kind(qihse_kv_store_t *store,const char *path,qihse_user_t *user,unsigned kind) {
    if(kind==0)return cg_storage_save(store,path,user);
    if(kind==1)return cg_storage_save_packed(store,path,user);
    if(kind==2)return cg_storage_save_dictionary(store,path,user);
    return cg_storage_save_chunked(store,path,user);
}
#endif
/* Isolated size-selector unit: dummy candidates are never decoded. Actual
 * codecs and authenticated CLI behavior are tested separately below. */
#ifdef CONTROLLED_LENGTHS
static size_t lengths[3],calls[3];static char raw_checksum[65];
static bool controlled(FILE *input,FILE *output,qihse_user_t *user,size_t kind) {
    assert(user && qihse_auth_user_is_active(user));calls[kind]++;
    cg_snapshot_checksum checksum;assert(cg_snapshot_checksum_stream_user(input,user,CG_CHECKSUM_XXH3_128,&checksum));
    if(*raw_checksum)assert(!strcmp(raw_checksum,checksum.hex));else memcpy(raw_checksum,checksum.hex,sizeof(raw_checksum));
    unsigned char zero[4096]={0};size_t remaining=lengths[kind];
    while(remaining){size_t n=remaining>sizeof(zero)?sizeof(zero):remaining;if(fwrite(zero,1,n,output)!=n)return false;remaining-=n;}
    return !fflush(output);
}
bool cg_packed_encode_snapshot(FILE *in,FILE *out,qihse_user_t *u,size_t b,size_t r){(void)b;(void)r;return controlled(in,out,u,0);}
bool cg_dictionary_encode_snapshot(FILE *in,FILE *out,qihse_user_t *u,size_t b,size_t r){(void)b;(void)r;return controlled(in,out,u,1);}
bool cg_chunked_encode_snapshot(FILE *in,FILE *out,qihse_user_t *u,size_t b,size_t r){(void)b;(void)r;return controlled(in,out,u,2);}
#endif
int main(int argc,char **argv) {
    assert(argc==2);assert(!setenv("QIHSE_DATA_DIR",argv[1],1));assert(!setenv("QIHSE_FIPS_MODE","disabled",1));
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator(PASSWORD));qihse_user_t *user=qihse_auth_authenticate_id(0,PASSWORD);assert(user);
    qihse_kv_store_t *store=qihse_kv_store_create_user(user);assert(store);
    for(unsigned i=0;i<64;i++) {
        char key[36],value[500];snprintf(key,sizeof(key),"n:%032x",i);
        snprintf(value,sizeof(value),"{\"id\":\"%032x\",\"file\":\"src/shared/module.c\",\"kind\":\"function\",\"unknown\":{\"name\":\"namespace::symbol_%u\",\"exact_number\":1.2300e+04}}",i,i);
        assert(qihse_kv_set_user(store,key,value,0,0,user));
    }
    char path[4096],automatic[4096];snprintf(automatic,sizeof(automatic),"%s/automatic.kv",argv[1]);
#ifdef CONTROLLED_LENGTHS
    snprintf(path,sizeof(path),"%s/zstd.kv",argv[1]);assert(cg_storage_save(store,path,user));long base=bytes(path);assert(base>3);
    for(unsigned winner=0;winner<4;winner++) {
        memset(calls,0,sizeof(calls));*raw_checksum=0;
        for(unsigned i=0;i<3;i++)lengths[i]=(size_t)(base-(winner && i>=winner-1?winner:0));
        cg_storage_format selected;assert(cg_storage_save_auto_format(store,automatic,user,&selected));
        assert((unsigned)selected==winner && bytes(automatic)==base-winner);
        for(unsigned i=0;i<3;i++)assert(calls[i]==1);
    }
    qihse_kv_store_destroy(store);
    FILE *raw=tmpfile();assert(raw);char *value=malloc(16384);assert(value);memset(value,'q',16384);
    for(unsigned i=0;i<4200;i++) {
        char key[36];int length=snprintf(key,sizeof(key),"n:%032x",i);assert(length==34);
        assert(fprintf(raw,"34 16384 0 0 0 0 %u\n",i+1)>0);assert(fwrite(key,1,34,raw)==34);
        assert(fwrite(value,1,16384,raw)==16384 && fputc('\n',raw)!=EOF);
    }
    free(value);assert(!fflush(raw));long raw_bytes=ftell(raw);assert(raw_bytes>64L*1024*1024);rewind(raw);
    store=qihse_kv_open_snapshot_user(raw,user,128u<<20,5000);assert(store);fclose(raw);
    snprintf(path,sizeof(path),"%s/large-zstd.kv",argv[1]);assert(cg_storage_save(store,path,user));base=bytes(path);assert(base>1);
    memset(calls,0,sizeof(calls));*raw_checksum=0;lengths[0]=lengths[1]=lengths[2]=(size_t)base-1;
    cg_storage_format selected;assert(cg_storage_save_auto_format(store,automatic,user,&selected));
    assert(selected==CG_STORAGE_CHUNKED && bytes(automatic)==base-1);
    assert(calls[0]==0 && calls[1]==0 && calls[2]==1);
    printf("{\"controlled_ties\":4,\"large_raw_bytes\":%ld,\"large_v2_v3_skipped\":true,\"large_v4_eligible\":true}\n",raw_bytes);
#else
    long candidates[4]={0};unsigned winner=0;
    for(unsigned i=0;i<4;i++) {snprintf(path,sizeof(path),"%s/candidate-%u.kv",argv[1],i);assert(save_kind(store,path,user,i));candidates[i]=bytes(path);if(candidates[i]<candidates[winner])winner=i;}
    cg_storage_format selected;assert(cg_storage_save_auto_format(store,automatic,user,&selected));
    assert((unsigned)selected==winner && bytes(automatic)==candidates[winner]);
    char chosen[4096];snprintf(chosen,sizeof(chosen),"%s/candidate-%u.kv",argv[1],winner);
    cg_snapshot_checksum expected,actual;assert(cg_snapshot_checksum_file_user(chosen,user,CG_CHECKSUM_XXH3_128,&expected));
    assert(cg_snapshot_checksum_file_user(automatic,user,CG_CHECKSUM_XXH3_128,&actual));assert(!strcmp(expected.hex,actual.hex));
    cg_storage_info_t info;qihse_kv_store_t *opened=cg_storage_open_checksum_info(automatic,user,1u<<20,1000,&expected,&info);assert(opened && info.valid);
    char *value=qihse_kv_get_user(opened,"n:00000000000000000000000000000000",user);assert(value && strstr(value,"exact_number"));free(value);qihse_kv_store_destroy(opened);
    printf("{\"same_export_exact_minimum\":true,\"selected\":%u,\"sizes\":[%ld,%ld,%ld,%ld]}\n",winner,candidates[0],candidates[1],candidates[2],candidates[3]);
#endif
    qihse_kv_store_destroy(store);qihse_audit_shutdown();return 0;
}
"""


def selector_contract(root: Path) -> dict:
    root.mkdir()
    source = root / "selector.c"
    source.write_text(SELECTOR_FIXTURE)
    flags = subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "openssl", "libzstd"], text=True
    ).split()
    library = PROJECT / "tools/codegraph_xxh3/build/libqihse_xxh3.a"
    assert library.is_file(), "Build the CodeGraph XXH3 module before running this test"
    reports = {}
    for mode in ("real", "controlled"):
        executable = root / mode
        command = [
            *shlex.split(os.environ.get("CC", "cc")),
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-ffunction-sections",
            "-fdata-sections",
            "-I" + str(PROJECT / "include"),
            "-I" + str(PROJECT / "core"),
            "-I" + str(PROJECT / "tools"),
            str(source),
            str(PROJECT / "tools/qihse_codegraph_storage.c"),
            str(PROJECT / "tools/qihse_codegraph_checksum.c"),
        ]
        if mode == "controlled":
            command.append("-DCONTROLLED_LENGTHS")
        else:
            command.extend(
                str(PROJECT / "tools" / name)
                for name in ("qihse_codegraph_packed.c", "qihse_codegraph_dictionary.c")
            )
        command.extend(
            [
                str(library),
                "-o",
                str(executable),
                "-L" + str(PROJECT),
                "-lqihse",
                *flags,
                "-lpthread",
                "-lm",
                "-ldl",
                "-Wl,--gc-sections",
            ]
        )
        compiled = subprocess.run(command, capture_output=True, text=True, check=False)
        assert compiled.returncode == 0, (mode, compiled.stdout, compiled.stderr)
        state = root / (mode + "-state")
        state.mkdir(mode=0o700)
        env = dict(
            os.environ,
            LD_LIBRARY_PATH=str(PROJECT)
            + os.pathsep
            + os.environ.get("LD_LIBRARY_PATH", ""),
        )
        process = subprocess.run(
            [str(executable), str(state)],
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        assert process.returncode == 0, (
            mode,
            process.returncode,
            process.stdout,
            process.stderr,
        )
        reports[mode] = json.loads(process.stdout)
    return reports


def check_case(binary: Path, root: Path, nodes: int, edges: int) -> dict:
    repo = root / "repo"
    repo.mkdir(parents=True)
    git(repo, "init", "-q")
    source = root / "source.jsonl"
    graph_fixture(repo, source, nodes, edges)
    common = {
        **os.environ,
        "LD_LIBRARY_PATH": str(binary.parent)
        + os.pathsep
        + os.environ.get("LD_LIBRARY_PATH", ""),
    }
    environments = {
        name: {**common, "XDG_STATE_HOME": str(root / (name + "-state"))}
        for name in (*FORMATS, "default", "auto")
    }

    def invoke(name: str, *arguments: str, expect: int = 0) -> dict:
        result = subprocess.run(
            [str(binary), *arguments, "--repo", str(repo)],
            env=environments[name],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == expect, (
            name,
            arguments,
            result.returncode,
            result.stdout,
            result.stderr,
        )
        return json.loads(result.stdout)

    def generations(name: str) -> set[str]:
        state = Path(environments[name]["XDG_STATE_HOME"]) / "qihse/codegraph"
        directory = state / hashlib.sha256(os.fsencode(repo)).hexdigest()
        return {path.name for path in directory.glob("graph-*.kv")}

    imported = {}
    sizes = {}
    receipts = {}

    def query_facts(name: str, result: dict) -> dict:
        # The physical snapshot checksum changes with the encoding. Validate
        # it against that format's authenticated receipt before comparing the
        # complete graph result; only this already-checked physical value is
        # excluded from cross-format semantic equality.
        assert (
            result["snapshot_hash_algorithm"]
            == receipts[name]["snapshot_hash_algorithm"]
        ), (name, result)
        assert result["snapshot_hash"] == receipts[name]["snapshot_hash"], (
            name,
            result,
            receipts[name],
        )
        return {
            key: value
            for key, value in comparable(result).items()
            if key != "snapshot_hash"
        }

    for name in environments:
        arguments = [] if name == "default" else ["--storage-format", name]
        imported[name] = invoke(name, "import", "--input", str(source), *arguments)
        assert imported[name]["status"] == "published", imported[name]
        stats = invoke(name, "stats")
        assert stats["coverage"] == "authorized_current_generation", stats
        assert stats["snapshot_hash_algorithm"] == "xxh3-128", stats
        assert len(stats["snapshot_hash"]) == 32, stats
        assert all(c in "0123456789abcdef" for c in stats["snapshot_hash"]), stats
        assert imported[name]["snapshot_hash_algorithm"] == "xxh3-128", imported[name]
        assert imported[name]["snapshot_hash"] == stats["snapshot_hash"], (
            imported[name],
            stats,
        )
        receipts[name] = stats
        sizes[name] = stats["encoded_bytes"]
        assert sizes[name] > 0, stats

    # Separate imports carry independently created authenticated KV metadata.
    # Their byte sizes need not match exactly even for identical graph facts.
    # selector_contract compares all four encoders over the same export; here
    # verify the public format choice and graph behavior across real imports.
    for name in ("default", "auto"):
        selected = imported[name]["storage_format"].removeprefix("qihse-codegraph-")
        assert selected in FORMATS, imported[name]
        assert (
            invoke(name, "stats")["storage_format"] == imported[name]["storage_format"]
        )

    # An unchanged import must reject a manifest that labels actual v3 bytes as
    # v2, just as loading/stats does. It must not publish or mutate that manifest.
    directory = (
        Path(environments["packed-v3"]["XDG_STATE_HOME"])
        / "qihse/codegraph"
        / hashlib.sha256(os.fsencode(repo)).hexdigest()
    )
    manifest_path = directory / "current.json"
    original_manifest = manifest_path.read_bytes()
    mismatched = json.loads(original_manifest)
    mismatched["storage_format"] = "qihse-codegraph-packed-v2"
    manifest_path.write_text(json.dumps(mismatched))
    before_denial = manifest_path.read_bytes()
    rejected = invoke("packed-v3", "import", "--input", str(source), expect=1)
    assert "existing snapshot" in rejected["error"], rejected
    assert manifest_path.read_bytes() == before_denial
    manifest_path.write_bytes(original_manifest)

    cases = (
        ("query", "--symbol", "common", "--match", "exact", "--limit", "256"),
        (
            "context",
            "--symbol",
            "caller",
            "--depth",
            "1",
            "--limit",
            "256",
            "--max-tokens",
            "16000",
        ),
        (
            "impact",
            "--symbol",
            "target",
            "--depth",
            "1",
            "--limit",
            "256",
            "--max-tokens",
            "16000",
        ),
        ("query", "--symbol", "not_present", "--match", "exact"),
    )
    references = []
    for command in cases:
        expected_exit = 2 if "not_present" in command else 0
        reference = query_facts(
            "zstd-v1", invoke("zstd-v1", *command, expect=expected_exit)
        )
        references.append(reference)
        for name in (*FORMATS[1:], "default", "auto"):
            assert (
                query_facts(name, invoke(name, *command, expect=expected_exit))
                == reference
            ), (
                name,
                command,
            )

    # Importing identical content must not create another generation. Both
    # automatic selectors exercise the same reuse and retention contract.
    for name in ("default", "auto"):
        before = generations(name)
        directory = (
            Path(environments[name]["XDG_STATE_HOME"])
            / "qihse/codegraph"
            / hashlib.sha256(os.fsencode(repo)).hexdigest()
        )
        obsolete = directory / ("graph-" + "f" * 64 + "-ABC123.kv")
        obsolete.write_bytes(b"synthetic obsolete generation")
        abandoned = directory / ".runtime-abandoned"
        abandoned.mkdir(mode=0o700)
        lease = abandoned / ".lease"
        lease.touch(mode=0o600)
        arguments = [] if name == "default" else ["--storage-format", "auto"]
        repeated = invoke(name, "import", "--input", str(source), *arguments)
        assert repeated["status"] == "unchanged", repeated
        assert repeated["snapshot"] == imported[name]["snapshot"], repeated
        assert generations(name) == before and len(before) == 1, (name, before)
        assert repeated["removed_snapshots"] == 1 and repeated["removed_runtimes"] == 1
        assert not obsolete.exists() and not abandoned.exists()
        obsolete.write_bytes(b"synthetic obsolete generation")
        selected = repeated["storage_format"].removeprefix("qihse-codegraph-")
        same_format = invoke(name, "migrate", "--storage-format", selected)
        assert same_format["status"] == "unchanged", same_format
        assert same_format["removed_snapshots"] == 1 and not obsolete.exists()

    # Automatic migration must keep a valid representation or strictly reduce
    # its size. Reserialization order can change between processes, so another
    # migration may make a further reduction; it must never grow the snapshot.
    migration_results = {}
    for name in FORMATS:
        before = sizes[name]
        result = invoke(name, "migrate", "--storage-format", "auto")
        receipts[name] = invoke(name, "stats")
        after = receipts[name]["encoded_bytes"]
        assert result["status"] in ("migrated", "unchanged"), (name, result)
        if result["status"] == "unchanged":
            assert after == before, (name, before, after)
            assert result["snapshot"] == imported[name]["snapshot"], result
        else:
            assert after < before, (name, before, after)
            assert result["snapshot"] != imported[name]["snapshot"], result
        assert len(generations(name)) <= 2, (name, generations(name))
        # Omitting the option must have the same optimization/no-enlargement
        # behavior, including for an already selected packed snapshot.
        again = invoke(name, "migrate")
        receipts[name] = invoke(name, "stats")
        final_size = receipts[name]["encoded_bytes"]
        assert again["status"] in ("migrated", "unchanged"), again
        if again["status"] == "unchanged":
            assert again["snapshot"] == result["snapshot"], (result, again)
            assert final_size == after, (after, final_size)
        else:
            assert again["snapshot"] != result["snapshot"], (result, again)
            assert final_size < after, (after, final_size)
        assert len(generations(name)) <= 2, (name, generations(name))
        assert query_facts(name, invoke(name, *cases[1])) == references[1]
        migration_results[name] = {
            "before": before,
            "after": after,
            "final": final_size,
            "status": result["status"],
        }
    return {
        "nodes": nodes,
        "edges": edges,
        "encoded_bytes": sizes,
        "migrations": migration_results,
        "query_parity": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="qihse-codegraph-auto-") as temporary:
        root = Path(temporary)
        selection = selector_contract(root / "selector")
        reports = [
            check_case(binary, root / name, nodes, edges)
            for name, nodes, edges in (("tiny", 8, 4), ("medium", 800, 2400))
        ]
        print(
            json.dumps(
                {
                    "automatic_storage": "passed",
                    "cases": reports,
                    "selector_contract": selection,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()

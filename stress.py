import os
import sys
import multiprocessing
import subprocess
import time

tests = [
    "./tests/test_qihse_e2e",
    "./tests/test_document_store",
    "./tests/test_column_store",
    "./tests/test_fts_engine",
    "./tests/test_timeseries",
    "./tests/qihse_trinary_codec_test",
    "./tests/test_bytecode",
    "./tests/test_lsm_tree"
]

def run_test(test):
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = "."
    while True:
        subprocess.run([test], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    processes = []
    # Launch each test in multiple processes
    for test in tests:
        if os.path.exists(test):
            for _ in range(4): # 4 processes per test
                p = multiprocessing.Process(target=run_test, args=(test,))
                p.start()
                processes.append(p)
    
    print(f"Launched {len(processes)} infinite-loop processes to bleed the CPU...")
    try:
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        for p in processes:
            p.terminate()

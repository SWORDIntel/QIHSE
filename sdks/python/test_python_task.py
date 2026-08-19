"""
End-to-End Test for QIHSE Python Task Queue SDK
"""

import sys
import os
import time
import subprocess
import socket

# Add sdk path
sys.path.insert(0, os.path.dirname(__file__))

from qihse_task import task, TaskClient, TaskError, TaskTimeoutError, set_default_client

def add_numbers(x, y):
    return x + y

def multiply(a, b, factor=1):
    return a * b * factor

@task(queue="calc_q", priority="HIGH")
def remote_multiply(a, b, factor=1):
    return a * b * factor

def main():
    print("=== Testing QIHSE Python Task Queue SDK (Celery Equivalent) ===")

    # Start a test RESP server using a temporary C test binary or port
    # Let's compile and run a background RESP server helper if needed
    # Or run the RESP cluster node
    test_port = 57421
    qihse_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

    server_bin = os.path.join(qihse_root, "tests/test_task_resp")
    # First build test-task-resp if needed
    subprocess.run(["make", "-C", qihse_root, "test-task-resp"], check=True, stdout=subprocess.PIPE)

    # Let's create a dedicated single-server harness for python tests
    harness_src = """
#define _GNU_SOURCE
#include "qihse_resp_wire.h"
#include "qihse_kv_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

static volatile int g_running = 1;
void sig_handler(int sig) { (void)sig; g_running = 0; }

int main(int argc, char** argv) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    uint16_t port = argc > 1 ? atoi(argv[1]) : 57421;

    qihse_kv_store_t* kv = qihse_kv_store_create();
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = kv;
    cfg.port = port;
    cfg.auth_required = false;
    cfg.enable_task_queue = true;
    cfg.enable_task_workers = true;
    cfg.task_worker_count = 2;
    cfg.enable_task_scheduler = true;

    qihse_resp_server_t* server = qihse_resp_server_create(&cfg);
    if (!server || !qihse_resp_server_start(server)) {
        printf("FAILED_TO_START\\n");
        return 1;
    }
    printf("STARTED_ON_PORT_%u\\n", qihse_resp_server_port(server));
    fflush(stdout);

    while (g_running) {
        usleep(50000);
    }
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(kv);
    return 0;
}
"""
    harness_c = os.path.join(qihse_root, "tests/qihse_task_server_harness.c")
    harness_bin = os.path.join(qihse_root, "tests/qihse_task_server_harness")

    with open(harness_c, "w") as f:
        f.write(harness_src)

    subprocess.run(
        ["gcc", "-std=c99", "-I" + os.path.join(qihse_root, "include"), "-I" + os.path.join(qihse_root, "core"),
         "-I/usr/include/luajit-2.1", "-fPIC", "-O3", "-o", harness_bin, harness_c,
         "-L" + qihse_root, "-lqihse", "-lpthread", "-lm", "-ldl"],
        check=True
    )

    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = qihse_root
    env["PYTHONPATH"] = os.path.dirname(os.path.abspath(__file__)) + ":" + qihse_root
    proc = subprocess.Popen([harness_bin, str(test_port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

    try:
        line = proc.stdout.readline().decode("utf-8").strip()
        assert "STARTED_ON_PORT_" in line, f"Server failed to start: {line}"
        active_port = int(line.split("_")[-1])
        print(f"  [✔] Background QIHSE Task RESP server started on port {active_port}")

        client = TaskClient(port=active_port)

        # Test 1: Direct raw task submission
        print("  [•] Submitting raw JSON task...")
        task_id = client.submit("math_q", {"func": "test_python_task.add_numbers", "args": [40, 2]})
        print(f"  [✔] Submitted task ID: {task_id[:16]}...")

        # Test 2: Poll result with timeout
        res = client.get_result(task_id, timeout=5.0)
        assert res == 42, f"Expected 42, got {res}"
        print(f"  [✔] Task result verified: {res}")

        # Test 3: @task decorator and .delay()
        set_default_client(client)
        print("  [•] Testing @task decorator .delay()...")
        async_res = remote_multiply.delay(6, 7, factor=2)
        assert isinstance(async_res.id, str) and len(async_res.id) == 96
        val = async_res.get(timeout=5.0)
        assert val == 84, f"Expected 84, got {val}"
        assert async_res.ready()
        assert async_res.successful()
        print(f"  [✔] @task.delay() -> AsyncResult.get() = {val}")

        # Test 4: @task .apply_async() with custom priority
        print("  [•] Testing .apply_async() with CRITICAL priority...")
        async_res2 = remote_multiply.apply_async(args=(10, 10), priority="CRITICAL")
        val2 = async_res2.get(timeout=5.0)
        assert val2 == 100, f"Expected 100, got {val2}"
        print(f"  [✔] .apply_async(priority='CRITICAL') = {val2}")

        # Test 5: Queue stats
        stats = client.stats()
        assert int(stats.get("total_executed", 0)) >= 3
        print(f"  [✔] Task stats reported: {stats.get('total_executed')} tasks executed")

        # Test 6: Worker info
        workers = client.workers()
        assert len(workers) == 2
        print(f"  [✔] Worker info verified: {len(workers)} active worker threads")

        # Test 7: Periodic Scheduling
        print("  [•] Testing schedule management...")
        assert client.schedule_add("nightly_sync", "0 4 * * *", "sync_q", {"func": "test_python_task.add_numbers", "args": [1, 1]})
        scheds = client.schedule_list()
        assert "nightly_sync" in scheds
        next_fire = client.schedule_next("nightly_sync")
        assert "T04:00:00Z" in next_fire
        assert client.schedule_remove("nightly_sync")
        print(f"  [✔] Schedule added, verified (next: {next_fire}), and removed")

        print("=== All Python Task Queue SDK Tests Passed Successfully ===")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()
        if os.path.exists(harness_c):
            os.remove(harness_c)
        if os.path.exists(harness_bin):
            os.remove(harness_bin)

if __name__ == "__main__":
    main()

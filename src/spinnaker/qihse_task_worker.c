#include "qihse_task_worker.h"
#include "qihse_cluster_numa.h"
#include "qihse_lua_injector.h"
#include "qihse_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <poll.h>
#include <errno.h>
#include <inttypes.h>

typedef struct qihse_worker_thread {
    pthread_t thread;
    uint32_t worker_id;
    int cpu_core_id;
    int numa_node_id;
    qihse_worker_state_t state;
    char current_task_id[QIHSE_TASK_ID_LEN + 1];
    uint64_t tasks_completed;
    uint64_t tasks_failed;
    uint64_t start_time_sec;
    struct qihse_task_worker_pool* pool;
} qihse_worker_thread_t;

struct qihse_task_worker_pool {
    qihse_task_queue_t* queue;
    qihse_worker_thread_t* workers;
    uint32_t worker_count;
    bool pin_cores;
    int numa_node_id;
    char python_binary[256];
    qihse_task_handler_fn custom_handler;
    void* custom_handler_ctx;
    bool running;
    bool paused;
    pthread_mutex_t pool_lock;
};

void qihse_task_worker_pool_config_init(qihse_task_worker_pool_config_t* config) {
    if (!config) return;
    config->queue = NULL;
    config->worker_count = 0; /* auto */
    config->pin_cores = true;
    config->numa_node_id = -1;
    config->python_binary = "python3";
    config->custom_handler = NULL;
    config->custom_handler_ctx = NULL;
}

static bool execute_lua_task(
    const qihse_task_t* task,
    uint8_t** out_result,
    size_t* out_len,
    char* out_error,
    size_t err_len
) {
    lua_State* L = luaL_newstate();
    if (!L) {
        snprintf(out_error, err_len, "Failed to initialize Lua state");
        return false;
    }
    luaL_openlibs(L);

    const char* script = (const char*)task->payload;
    if (strncasecmp(script, "lua:", 4) == 0) script += 4;
    while (*script == ' ' || *script == '\t') script++;

    /* Execute Lua script */
    if (luaL_dostring(L, script) != 0) {
        const char* err = lua_tostring(L, -1);
        snprintf(out_error, err_len, "Lua error: %s", err ? err : "unknown");
        lua_close(L);
        return false;
    }

    /* Extract return value if any */
    if (lua_gettop(L) > 0) {
        const char* res_str = lua_tostring(L, -1);
        if (res_str) {
            size_t rlen = strlen(res_str);
            *out_result = (uint8_t*)strdup(res_str);
            *out_len = rlen;
        } else {
            *out_result = (uint8_t*)strdup("");
            *out_len = 0;
        }
    } else {
        *out_result = (uint8_t*)strdup("");
        *out_len = 0;
    }

    lua_close(L);
    return true;
}

static bool execute_python_subprocess(
    const char* python_bin,
    const qihse_task_t* task,
    uint8_t** out_result,
    size_t* out_len,
    char* out_error,
    size_t err_len
) {
    int in_pipe[2];
    int out_pipe[2];
    int err_pipe[2];

    if (pipe(in_pipe) < 0 || pipe(out_pipe) < 0 || pipe(err_pipe) < 0) {
        snprintf(out_error, err_len, "pipe() failed: %s", strerror(errno));
        return false;
    }

    const char* py_script =
        "import sys, os, json, importlib\n"
        "sys.path.insert(0, '')\n"
        "sys.path.insert(0, os.getcwd())\n"
        "try:\n"
        "    try:\n"
        "        import msgpack\n"
        "        raw = sys.stdin.buffer.read()\n"
        "        try:\n"
        "            data = msgpack.unpackb(raw, raw=False)\n"
        "        except Exception:\n"
        "            data = json.loads(raw.decode('utf-8'))\n"
        "    except ImportError:\n"
        "        raw = sys.stdin.read()\n"
        "        data = json.loads(raw)\n"
        "    if isinstance(data, dict) and 'func' in data:\n"
        "        mod_name, func_name = data['func'].rsplit('.', 1)\n"
        "        mod = importlib.import_module(mod_name)\n"
        "        fn = getattr(mod, func_name)\n"
        "        args = data.get('args', [])\n"
        "        kwargs = data.get('kwargs', {})\n"
        "        res = fn(*args, **kwargs)\n"
        "    elif isinstance(data, str):\n"
        "        res = eval(data)\n"
        "    else:\n"
        "        res = data\n"
        "    try:\n"
        "        import msgpack\n"
        "        sys.stdout.buffer.write(msgpack.packb(res))\n"
        "    except Exception:\n"
        "        sys.stdout.write(json.dumps(res))\n"
        "except Exception as e:\n"
        "    import traceback\n"
        "    sys.stderr.write(traceback.format_exc())\n"
        "    sys.exit(1)\n";

    pid_t pid = fork();
    if (pid < 0) {
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        snprintf(out_error, err_len, "fork() failed: %s", strerror(errno));
        return false;
    }

    if (pid == 0) {
        /* Child */
        close(in_pipe[1]);
        close(out_pipe[0]);
        close(err_pipe[0]);

        dup2(in_pipe[0], STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);

        close(in_pipe[0]);
        close(out_pipe[1]);
        close(err_pipe[1]);

        const char* py = python_bin && python_bin[0] ? python_bin : "python3";
        execlp(py, py, "-c", py_script, (char*)NULL);
        _exit(127);
    }

    /* Parent */
    close(in_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[1]);

    /* Write task payload to child stdin */
    if (task->payload && task->payload_len > 0) {
        size_t written = 0;
        while (written < task->payload_len) {
            ssize_t n = write(in_pipe[1], task->payload + written, task->payload_len - written);
            if (n <= 0) break;
            written += (size_t)n;
        }
    }
    close(in_pipe[1]);

    /* Poll with timeout */
    uint64_t timeout_ms = task->opts.timeout_ms ? task->opts.timeout_ms : QIHSE_TASK_DEFAULT_TIMEOUT_MS;
    struct pollfd pfd[2];
    pfd[0].fd = out_pipe[0];
    pfd[0].events = POLLIN;
    pfd[1].fd = err_pipe[0];
    pfd[1].events = POLLIN;

    size_t out_cap = 65536;
    size_t out_size = 0;
    uint8_t* out_buf = (uint8_t*)malloc(out_cap);

    size_t err_cap = 4096;
    size_t err_size = 0;
    char* err_buf = (char*)malloc(err_cap);

    uint64_t start_ms = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    start_ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;

    bool timed_out = false;
    bool child_done = false;
    int child_exit_status = -1;
    bool child_exited = false;

    while (!child_done) {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t now_ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
        if (now_ms - start_ms >= timeout_ms) {
            timed_out = true;
            kill(pid, SIGKILL);
            break;
        }

        int remaining_ms = (int)(timeout_ms - (now_ms - start_ms));
        if (remaining_ms > 100) remaining_ms = 100;

        int prc = poll(pfd, 2, remaining_ms);
        if (prc > 0) {
            if (pfd[0].revents & POLLIN) {
                if (out_size + 4096 >= out_cap) {
                    out_cap *= 2;
                    out_buf = (uint8_t*)realloc(out_buf, out_cap);
                }
                ssize_t n = read(out_pipe[0], out_buf + out_size, 4096);
                if (n > 0) out_size += (size_t)n;
            }
            if (pfd[1].revents & POLLIN) {
                if (err_size + 1024 >= err_cap) {
                    err_cap *= 2;
                    err_buf = (char*)realloc(err_buf, err_cap);
                }
                ssize_t n = read(err_pipe[0], err_buf + err_size, 1024);
                if (n > 0) err_size += (size_t)n;
            }
            if ((pfd[0].revents & (POLLHUP | POLLERR)) && (pfd[1].revents & (POLLHUP | POLLERR))) {
                child_done = true;
            }
        }

        int status = 0;
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            child_done = true;
            child_exit_status = status;
            child_exited = true;
        }
    }

    /* Drain any remaining output */
    ssize_t n;
    while ((n = read(out_pipe[0], out_buf + out_size, 4096)) > 0) {
        out_size += (size_t)n;
        if (out_size + 4096 >= out_cap) {
            out_cap *= 2;
            out_buf = (uint8_t*)realloc(out_buf, out_cap);
        }
    }
    while ((n = read(err_pipe[0], err_buf + err_size, 1024)) > 0) {
        err_size += (size_t)n;
        if (err_size + 1024 >= err_cap) {
            err_cap *= 2;
            err_buf = (char*)realloc(err_buf, err_cap);
        }
    }

    close(out_pipe[0]);
    close(err_pipe[0]);

    if (!child_exited) {
        int status = 0;
        pid_t w = waitpid(pid, &status, 0);
        if (w == pid) {
            child_exit_status = status;
            child_exited = true;
        }
    }

    if (err_buf) err_buf[err_size < err_cap ? err_size : err_cap - 1] = '\0';

    if (timed_out) {
        snprintf(out_error, err_len, "Task timed out after %" PRIu64 " ms", timeout_ms);
        free(out_buf);
        free(err_buf);
        return false;
    }

    if (child_exited && WIFEXITED(child_exit_status) && WEXITSTATUS(child_exit_status) == 0) {
        *out_result = out_buf;
        *out_len = out_size;
        free(err_buf);
        return true;
    }

    snprintf(out_error, err_len, "%s", err_size > 0 ? err_buf : "Python execution exited with error");
    free(out_buf);
    free(err_buf);
    return false;
}

static void* worker_thread_func(void* arg) {
    qihse_worker_thread_t* worker = (qihse_worker_thread_t*)arg;
    qihse_task_worker_pool_t* pool = worker->pool;

    /* Apply core and NUMA binding if requested */
    if (pool->pin_cores && worker->cpu_core_id >= 0) {
        qihse_cluster_binding_result_t bind_res;
        qihse_cluster_bind_current_thread(worker->cpu_core_id, worker->numa_node_id, false, &bind_res);
    }

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    worker->start_time_sec = (uint64_t)ts.tv_sec;

    while (pool->running) {
        if (pool->paused) {
            worker->state = QIHSE_WORKER_PAUSED;
            usleep(50000); /* 50ms */
            continue;
        }

        worker->state = QIHSE_WORKER_IDLE;
        worker->current_task_id[0] = '\0';

        /* Pop task from queue with 100ms timeout */
        qihse_task_t* task = qihse_task_pop(pool->queue, 100u);
        if (!task) continue;

        if (pool->paused) {
            /* If paused while waiting on pop, re-enqueue the task */
            qihse_task_submit(pool->queue, task->queue_name, task->priority, task->payload, task->payload_len, &task->opts, NULL, 0);
            continue;
        }

        if (task->cancel_requested) {
            qihse_task_fail(pool->queue, task->task_id, "Task was cancelled prior to execution");
            continue;
        }

        worker->state = QIHSE_WORKER_BUSY;
        snprintf(worker->current_task_id, sizeof(worker->current_task_id), "%s", task->task_id);

        uint8_t* result = NULL;
        size_t result_len = 0;
        char error_msg[QIHSE_TASK_ERROR_MAX] = {0};
        bool success = false;

        if (pool->custom_handler) {
            success = pool->custom_handler(task, &result, &result_len, error_msg, sizeof(error_msg), pool->custom_handler_ctx);
        } else if (task->payload && task->payload_len >= 4 &&
                   (strncasecmp((char*)task->payload, "lua:", 4) == 0 ||
                    strstr((char*)task->payload, "return ") != NULL)) {
            success = execute_lua_task(task, &result, &result_len, error_msg, sizeof(error_msg));
        } else {
            success = execute_python_subprocess(pool->python_binary, task, &result, &result_len, error_msg, sizeof(error_msg));
        }

        if (success) {
            qihse_task_complete(pool->queue, task->task_id, result, result_len);
            worker->tasks_completed++;
        } else {
            qihse_task_fail(pool->queue, task->task_id, error_msg[0] ? error_msg : "Execution failed");
            worker->tasks_failed++;
        }

        if (result) free(result);
    }

    worker->state = QIHSE_WORKER_STOPPED;
    return NULL;
}

qihse_task_worker_pool_t* qihse_task_worker_pool_create(const qihse_task_worker_pool_config_t* config) {
    if (!config || !config->queue) return NULL;

    qihse_task_worker_pool_t* pool = (qihse_task_worker_pool_t*)calloc(1, sizeof(qihse_task_worker_pool_t));
    if (!pool) return NULL;

    pool->queue = config->queue;
    pool->pin_cores = config->pin_cores;
    pool->numa_node_id = config->numa_node_id;
    snprintf(pool->python_binary, sizeof(pool->python_binary), "%s", config->python_binary ? config->python_binary : "python3");
    pool->custom_handler = config->custom_handler;
    pool->custom_handler_ctx = config->custom_handler_ctx;
    pthread_mutex_init(&pool->pool_lock, NULL);

    /* Determine worker count */
    uint32_t count = config->worker_count;
    if (count == 0) {
        int cpu_ids[64];
        size_t avail = qihse_cluster_available_cpus(cpu_ids, 64);
        count = avail > 2 ? (uint32_t)(avail / 2) : 2;
        if (count > 8) count = 8;
    }
    pool->worker_count = count;

    pool->workers = (qihse_worker_thread_t*)calloc(count, sizeof(qihse_worker_thread_t));
    if (!pool->workers) {
        pthread_mutex_destroy(&pool->pool_lock);
        free(pool);
        return NULL;
    }

    int cpu_ids[64];
    size_t avail_cpus = qihse_cluster_available_cpus(cpu_ids, 64);

    for (uint32_t i = 0; i < count; i++) {
        pool->workers[i].worker_id = i;
        pool->workers[i].pool = pool;
        pool->workers[i].state = QIHSE_WORKER_IDLE;
        pool->workers[i].cpu_core_id = avail_cpus > 0 ? cpu_ids[i % avail_cpus] : (int)i;
        pool->workers[i].numa_node_id = config->numa_node_id;
    }

    return pool;
}

bool qihse_task_worker_pool_start(qihse_task_worker_pool_t* pool) {
    if (!pool) return false;
    pthread_mutex_lock(&pool->pool_lock);
    if (pool->running) {
        pthread_mutex_unlock(&pool->pool_lock);
        return true;
    }
    pool->running = true;
    pool->paused = false;

    for (uint32_t i = 0; i < pool->worker_count; i++) {
        pthread_create(&pool->workers[i].thread, NULL, worker_thread_func, &pool->workers[i]);
    }
    pthread_mutex_unlock(&pool->pool_lock);
    return true;
}

void qihse_task_worker_pool_pause(qihse_task_worker_pool_t* pool) {
    if (!pool) return;
    pthread_mutex_lock(&pool->pool_lock);
    pool->paused = true;
    pthread_mutex_unlock(&pool->pool_lock);
}

void qihse_task_worker_pool_resume(qihse_task_worker_pool_t* pool) {
    if (!pool) return;
    pthread_mutex_lock(&pool->pool_lock);
    pool->paused = false;
    pthread_mutex_unlock(&pool->pool_lock);
}

void qihse_task_worker_pool_stop(qihse_task_worker_pool_t* pool) {
    if (!pool) return;
    pthread_mutex_lock(&pool->pool_lock);
    if (!pool->running) {
        pthread_mutex_unlock(&pool->pool_lock);
        return;
    }
    pool->running = false;
    pthread_mutex_unlock(&pool->pool_lock);

    for (uint32_t i = 0; i < pool->worker_count; i++) {
        pthread_join(pool->workers[i].thread, NULL);
    }
}

void qihse_task_worker_pool_destroy(qihse_task_worker_pool_t* pool) {
    if (!pool) return;
    qihse_task_worker_pool_stop(pool);
    pthread_mutex_destroy(&pool->pool_lock);
    if (pool->workers) free(pool->workers);
    free(pool);
}

bool qihse_task_worker_pool_get_info(
    qihse_task_worker_pool_t* pool,
    qihse_worker_info_t** out_info,
    size_t* out_count
) {
    if (!pool || !out_info || !out_count) return false;
    pthread_mutex_lock(&pool->pool_lock);
    size_t count = (size_t)pool->worker_count;
    qihse_worker_info_t* info = (qihse_worker_info_t*)malloc(count * sizeof(qihse_worker_info_t));
    if (!info) {
        pthread_mutex_unlock(&pool->pool_lock);
        return false;
    }

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_sec = (uint64_t)ts.tv_sec;

    for (size_t i = 0; i < count; i++) {
        info[i].worker_id = pool->workers[i].worker_id;
        info[i].cpu_core_id = pool->workers[i].cpu_core_id;
        info[i].numa_node_id = pool->workers[i].numa_node_id;
        info[i].state = pool->workers[i].state;
        snprintf(info[i].current_task_id, sizeof(info[i].current_task_id), "%s", pool->workers[i].current_task_id);
        info[i].tasks_completed = pool->workers[i].tasks_completed;
        info[i].tasks_failed = pool->workers[i].tasks_failed;
        info[i].uptime_seconds = (now_sec >= pool->workers[i].start_time_sec) ? (now_sec - pool->workers[i].start_time_sec) : 0;
    }
    pthread_mutex_unlock(&pool->pool_lock);

    *out_info = info;
    *out_count = count;
    return true;
}

void qihse_task_worker_pool_free_info(qihse_worker_info_t* info) {
    if (info) free(info);
}

bool qihse_task_worker_pool_set_count(
    qihse_task_worker_pool_t* pool,
    uint32_t new_count
) {
    if (!pool || new_count == 0) return false;
    qihse_task_worker_pool_stop(pool);

    pthread_mutex_lock(&pool->pool_lock);
    free(pool->workers);
    pool->worker_count = new_count;
    pool->workers = (qihse_worker_thread_t*)calloc(new_count, sizeof(qihse_worker_thread_t));
    if (!pool->workers) {
        pthread_mutex_unlock(&pool->pool_lock);
        return false;
    }

    int cpu_ids[64];
    size_t avail_cpus = qihse_cluster_available_cpus(cpu_ids, 64);
    for (uint32_t i = 0; i < new_count; i++) {
        pool->workers[i].worker_id = i;
        pool->workers[i].pool = pool;
        pool->workers[i].state = QIHSE_WORKER_IDLE;
        pool->workers[i].cpu_core_id = avail_cpus > 0 ? cpu_ids[i % avail_cpus] : (int)i;
        pool->workers[i].numa_node_id = pool->numa_node_id;
    }
    pthread_mutex_unlock(&pool->pool_lock);

    return qihse_task_worker_pool_start(pool);
}

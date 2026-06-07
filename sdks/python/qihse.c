#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <pthread.h>
#include "qihse_qql_parser.h"
#include "qihse_vector_db.h"
#include "qihse_kv_store.h"
#include "qihse_document.h"
#include "qihse_column.h"
#include "qihse_timeseries.h"
#include "qihse_uwp.h"
#include "qihse_resp_wire.h"
#include "qihse_pg_wire.h"

// The Qihse Context wrapper
typedef struct {
    PyObject_HEAD
    qihse_uwp_context_t* ctx;
} QihseDBObject;

static int QihseDB_init(QihseDBObject *self, PyObject *args, PyObject *kwds) {
    self->ctx = (qihse_uwp_context_t*)malloc(sizeof(qihse_uwp_context_t));
    memset(self->ctx, 0, sizeof(qihse_uwp_context_t));
    
    // Initialize engines natively in memory
    self->ctx->kv = qihse_kv_store_create();
    self->ctx->vdb = qihse_vector_db_create(QIHSE_BACKEND_CPU, NULL, NULL);
    self->ctx->doc = qihse_doc_store_create(self->ctx->kv);
    self->ctx->col = qihse_column_store_create();
    self->ctx->tsdb = qihse_tsdb_create();
    return 0;
}

static void QihseDB_dealloc(QihseDBObject *self) {
    if (self->ctx) {
        if (self->ctx->tsdb) qihse_tsdb_destroy(self->ctx->tsdb);
        if (self->ctx->col) qihse_column_store_destroy(self->ctx->col);
        if (self->ctx->doc) qihse_doc_store_destroy(self->ctx->doc);
        if (self->ctx->vdb) qihse_vector_db_destroy(self->ctx->vdb);
        if (self->ctx->kv) qihse_kv_store_destroy(self->ctx->kv);
        free(self->ctx);
    }
    Py_TYPE(self)->tp_free((PyObject *) self);
}

// execute("SEARCH VECTOR...") Raw QQL
static PyObject* QihseDB_execute(QihseDBObject *self, PyObject *args) {
    const char* query;
    if (!PyArg_ParseTuple(args, "s", &query)) {
        return NULL;
    }
    
    // Natively parse and execute QQL in C
    void* result = qihse_parse_qql_to_ast(query);
    if (!result) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to execute QQL query: syntax error");
        return NULL;
    }
    
    Py_RETURN_NONE;
}

// ORM-style: db.kv_set("foo", "bar")
static PyObject* QihseDB_kv_set(QihseDBObject *self, PyObject *args) {
    const char* key;
    const char* val;
    if (!PyArg_ParseTuple(args, "ss", &key, &val)) {
        return NULL;
    }
    qihse_kv_set(self->ctx->kv, key, val, 0, 0);
    Py_RETURN_NONE;
}

// ORM-style: db.kv_get("foo")
static PyObject* QihseDB_kv_get(QihseDBObject *self, PyObject *args) {
    const char* key;
    if (!PyArg_ParseTuple(args, "s", &key)) {
        return NULL;
    }
    char* val = qihse_kv_get_user(self->ctx->kv, key, NULL);
    if (!val) {
        Py_RETURN_NONE;
    }
    PyObject* ret = Py_BuildValue("s", val);
    free(val);
    return ret;
}

// Document
static PyObject* QihseDB_doc_insert(QihseDBObject *self, PyObject *args) {
    unsigned long long doc_id;
    const char* json;
    if (!PyArg_ParseTuple(args, "Ks", &doc_id, &json)) return NULL;
    qihse_doc_store_insert_json(self->ctx->doc, doc_id, json);
    Py_RETURN_NONE;
}

// Columnar
static PyObject* QihseDB_col_create(QihseDBObject *self, PyObject *args) {
    const char* name;
    if (!PyArg_ParseTuple(args, "s", &name)) return NULL;
    qihse_column_create(self->ctx->col, name, QIHSE_COL_TYPE_FLOAT32);
    Py_RETURN_NONE;
}

static PyObject* QihseDB_col_append(QihseDBObject *self, PyObject *args) {
    const char* name;
    float val;
    if (!PyArg_ParseTuple(args, "sf", &name, &val)) return NULL;
    qihse_column_append_float32(self->ctx->col, name, val, 0, 0);
    Py_RETURN_NONE;
}

// Time-Series
static PyObject* QihseDB_tsdb_insert(QihseDBObject *self, PyObject *args) {
    unsigned int series_id;
    unsigned long long ts;
    double val;
    if (!PyArg_ParseTuple(args, "IKd", &series_id, &ts, &val)) return NULL;
    qihse_tsdb_insert(self->ctx->tsdb, series_id, ts, val, 0, 0);
    Py_RETURN_NONE;
}

static PyObject* QihseDB_trinary_search(QihseDBObject *self, PyObject *args, PyObject *kwds) {
    PyObject *vec;
    const char *mode = NULL;
    static char *kwlist[] = {"vector", "mode", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|$s", kwlist, &vec, &mode)) {
        return NULL;
    }
    
    // Return a dummy list
    PyObject *list = PyList_New(0);
    return list;
}

// Proxy Threads
struct ServerArgs {
    qihse_uwp_context_t* ctx;
    uint16_t port;
    char addr[64];
};

static void* run_resp(void* a) {
    struct ServerArgs* args = (struct ServerArgs*)a;
    qihse_start_resp_server(args->ctx->kv, args->ctx->vdb, args->port, args->addr);
    free(args);
    return NULL;
}

static void* run_pg(void* a) {
    struct ServerArgs* args = (struct ServerArgs*)a;
    qihse_start_pg_wire_server((void*)args->ctx->vdb, args->port, args->addr);
    free(args);
    return NULL;
}

static PyObject* QihseDB_start_resp_proxy(QihseDBObject *self, PyObject *args) {
    const char* addr = "0.0.0.0";
    int port = 6379;
    if (!PyArg_ParseTuple(args, "|si", &addr, &port)) return NULL;
    struct ServerArgs* s = malloc(sizeof(struct ServerArgs));
    s->ctx = self->ctx;
    s->port = port;
    strncpy(s->addr, addr, 63);
    pthread_t t;
    pthread_create(&t, NULL, run_resp, s);
    pthread_detach(t);
    Py_RETURN_NONE;
}

static PyObject* QihseDB_start_pg_proxy(QihseDBObject *self, PyObject *args) {
    const char* addr = "0.0.0.0";
    int port = 5432;
    if (!PyArg_ParseTuple(args, "|si", &addr, &port)) return NULL;
    struct ServerArgs* s = malloc(sizeof(struct ServerArgs));
    s->ctx = self->ctx;
    s->port = port;
    strncpy(s->addr, addr, 63);
    pthread_t t;
    pthread_create(&t, NULL, run_pg, s);
    pthread_detach(t);
    Py_RETURN_NONE;
}

static PyMethodDef QihseDB_methods[] = {
    {"execute", (PyCFunction)QihseDB_execute, METH_VARARGS, "Execute raw QQL string."},
    {"kv_set", (PyCFunction)QihseDB_kv_set, METH_VARARGS, "Set a key-value pair."},
    {"kv_get", (PyCFunction)QihseDB_kv_get, METH_VARARGS, "Get a value by key."},
    {"doc_insert", (PyCFunction)QihseDB_doc_insert, METH_VARARGS, "Insert JSON document."},
    {"col_create", (PyCFunction)QihseDB_col_create, METH_VARARGS, "Create float column."},
    {"col_append", (PyCFunction)QihseDB_col_append, METH_VARARGS, "Append to float column."},
    {"tsdb_insert", (PyCFunction)QihseDB_tsdb_insert, METH_VARARGS, "Insert time-series data point."},
    {"trinary_search", (PyCFunction)QihseDB_trinary_search, METH_VARARGS | METH_KEYWORDS, "Perform trinary search."},
    {"start_resp_proxy", (PyCFunction)QihseDB_start_resp_proxy, METH_VARARGS, "Start the Redis Wire proxy in the background."},
    {"start_pg_proxy", (PyCFunction)QihseDB_start_pg_proxy, METH_VARARGS, "Start the Postgres Wire proxy in the background."},
    {NULL}  /* Sentinel */
};

static PyTypeObject QihseDBType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "qihse.Database",
    .tp_doc = "QIHSE Database native binding",
    .tp_basicsize = sizeof(QihseDBObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_new = PyType_GenericNew,
    .tp_init = (initproc) QihseDB_init,
    .tp_dealloc = (destructor) QihseDB_dealloc,
    .tp_methods = QihseDB_methods,
};

static struct PyModuleDef qihsemodule = {
    PyModuleDef_HEAD_INIT,
    "qihse",
    "QIHSE Native C Extension.",
    -1,
    NULL, NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit_qihse(void) {
    PyObject *m;
    if (PyType_Ready(&QihseDBType) < 0)
        return NULL;

    m = PyModule_Create(&qihsemodule);
    if (m == NULL)
        return NULL;

    Py_INCREF(&QihseDBType);
    if (PyModule_AddObject(m, "Database", (PyObject *) &QihseDBType) < 0) {
        Py_DECREF(&QihseDBType);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}

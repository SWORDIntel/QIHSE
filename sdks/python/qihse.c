#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "qihse_qql_parser.h"
#include "qihse_vector_db.h"
#include "qihse_kv_store.h"
#include "qihse_uwp.h"

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
    
    // For vector_db, we can just omit it or pass proper args.
    // For this POC, we'll leave it NULL and let QQL parser execute FTS/KV.
    self->ctx->vdb = NULL; 
    return 0;
}

static void QihseDB_dealloc(QihseDBObject *self) {
    if (self->ctx) {
        if (self->ctx->kv) qihse_kv_store_destroy(self->ctx->kv);
        // if (self->ctx->vdb) qihse_vector_db_free(self->ctx->vdb);
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
    qihse_parse_qql_to_ast(query);
    
    Py_RETURN_NONE;
}

// ORM-style: db.kv_set("foo", "bar")
static PyObject* QihseDB_kv_set(QihseDBObject *self, PyObject *args) {
    const char* key;
    const char* val;
    if (!PyArg_ParseTuple(args, "ss", &key, &val)) {
        return NULL;
    }
    qihse_kv_set(self->ctx->kv, key, val);
    Py_RETURN_NONE;
}

// ORM-style: db.kv_get("foo")
static PyObject* QihseDB_kv_get(QihseDBObject *self, PyObject *args) {
    const char* key;
    if (!PyArg_ParseTuple(args, "s", &key)) {
        return NULL;
    }
    // qihse_kv_get is char* qihse_kv_get(qihse_kv_store_t* store, const char* key);
    char* val = qihse_kv_get(self->ctx->kv, key);
    if (!val) {
        Py_RETURN_NONE;
    }
    PyObject* ret = Py_BuildValue("s", val);
    free(val);
    return ret;
}

static PyMethodDef QihseDB_methods[] = {
    {"execute", (PyCFunction)QihseDB_execute, METH_VARARGS, "Execute raw QQL string."},
    {"kv_set", (PyCFunction)QihseDB_kv_set, METH_VARARGS, "Set a key-value pair."},
    {"kv_get", (PyCFunction)QihseDB_kv_get, METH_VARARGS, "Get a value by key."},
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

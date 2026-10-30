#include <qihse/qihse_vector_db.h>
#include <qihse/qihse_uwp_sql_txn_schema.h>
#include <qihse/qihse_schema.h>
#include <qihse/qihse_sql_fts.h>
#include <qihse/qihse_sql_row_index.h>
#include <qihse/qihse_pg_wire.h>
#include <qihse/qihse_kv_store.h>
#include <qihse/qihse_auth_maintenance.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    /* Retain the authenticated constructor symbol without opening any store. */
    qihse_kv_store_t *(*volatile create_user)(qihse_user_t *) =
        qihse_kv_store_create_user;
    if (!create_user) return 8;
    qihse_auth_maintenance_status_t (*volatile capabilities)(
        const qihse_user_t *, qihse_auth_maintenance_caps_t *) =
        qihse_auth_maintenance_capabilities;
    if (!capabilities || capabilities(NULL, NULL) == QIHSE_AUTH_MAINT_OK)
        return 9;
    char *vector = NULL;
    bool ok = qihse_sql_to_tsvector_english("running", &vector);
    if (argc == 2 && strcmp(argv[1], "missing-stemmer") == 0) {
        free(vector);
        return ok ? 1 : 0;
    }
    if (!ok || !vector || !strstr(vector, "'run':1")) {
        free(vector);
        return 2;
    }
    free(vector);
    /* Public SQL symbols must link; NULL readiness must fail closed. */
    if (qihse_uwp_sql_durable_ready(NULL)) return 3;
    qihse_sql_ast_free(NULL);
    qihse_sql_row_index_destroy(NULL);
    /* Link the authenticated handler without opening a connection or listener. */
    void (*volatile handler)(int, qihse_uwp_context_t*, qihse_cluster_topology_t*) =
        qihse_pg_wire_handle_client_uwp;
    if (!handler) return 4;
    errno = 0;
    if (qihse_pg_wire_listener_open_uwp(NULL, NULL, "127.0.0.1", 0) ||
        errno != EINVAL) return 5;
    errno = 0;
    if (qihse_pg_wire_listener_open_tls_uwp(NULL, NULL, "127.0.0.1", 0,
                                          NULL, NULL) || errno != EINVAL) return 6;
    if (qihse_pg_wire_listener_port(NULL) != 0 ||
        qihse_pg_wire_listener_accept_once(NULL, 0) != -1) return 7;
    qihse_pg_wire_listener_close(NULL);
    puts("installed public API consumer: OK");
    return 0;
}

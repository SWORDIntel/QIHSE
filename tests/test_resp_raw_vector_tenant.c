#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_container_keys_fixture.h"
#include "qihse_resp_wire.h"
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "../persistence/qihse_vector_store.h"
#include <assert.h>
#include <ftw.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Exercise the old wire fallback deliberately, without inducing resource
 * exhaustion in the primary RESP server or adding a production test bypass. */
bool __wrap_qihse_resp_engine_handle_legacy(int fd, qihse_kv_store_t* kv,
                                            qihse_vector_db_t vdb) {
    (void)fd; (void)kv; (void)vdb; return false;
}
typedef struct { int fd; qihse_kv_store_t* kv; qihse_vector_db_t vdb; } server_args;
static void* serve(void* arg) {
    server_args* s = arg;
    qihse_resp_handle_client(s->fd,s->kv,s->vdb);
    return NULL;
}
static void exchange(int fd, const char* request, unsigned lines,
                      char* reply, size_t capacity) {
    size_t size = strlen(request), sent = 0;
    while (sent < size) {
        ssize_t n = write(fd,request+sent,size-sent); assert(n > 0); sent += (size_t)n;
    }
    size_t used = 0;
    for (;;) {
        struct pollfd p = {.fd=fd,.events=POLLIN}; assert(poll(&p,1,5000) > 0);
        assert(used+1 < capacity);
        ssize_t n = read(fd,reply+used,capacity-used-1); assert(n > 0);
        used += (size_t)n; reply[used] = 0;
        unsigned got = 0;
        for (size_t i=1;i<used;i++) if (reply[i-1]=='\r' && reply[i]=='\n') got++;
        if (got >= lines) return;
    }
}
static void authenticate(int fd, qihse_user_t* user, const char* password) {
    char command[256], reply[512];
    assert(snprintf(command,sizeof(command),"AUTH %s %s\r\n",
        qihse_user_get_username(user),password) < (int)sizeof(command));
    exchange(fd,command,1,reply,sizeof(reply));
    assert(!strcmp(reply,"+OK\r\n"));
}
static int remove_entry(const char* path, const struct stat* s, int kind, struct FTW* w) {
    (void)s; (void)kind; (void)w; return remove(path);
}
int main(void) {
    char root[] = "tests/resp-raw-vector-XXXXXX"; assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR",root,1) == 0);
    assert(setenv("QIHSE_FIPS_MODE","disabled",1) == 0);
    qihse_test_container_keys(root);
    assert(qihse_auth_init());
    const char* op_password = "RawVectorOperator123!";
    const char* tenant_password = "RawVectorTenant123!";
    const char* low_password = "RawVectorLowClearance123!";
    assert(qihse_auth_bootstrap_operator(op_password));
    qihse_user_t* op = qihse_auth_get_user(0); assert(op);
    qihse_user_t* tenant = qihse_auth_create_tenant_user(op,8,88,
        QIHSE_ROLE_ANALYST,QIHSE_CLASS_UNCLASSIFIED,QIHSE_SCI_NONE,tenant_password,false);
    qihse_user_t* low = qihse_auth_create_user(op,89,QIHSE_ROLE_ANALYST,
        QIHSE_CLASS_UNCLASSIFIED,QIHSE_SCI_NONE,low_password,false);
    assert(tenant && low);

    /* Private test snapshot: foreign-tenant public data and SECRET/SI data. */
    float vectors[2][2] = {{12.5f,25.0f},{946.125f,314.25f}};
    const char tag[] = "t:7/private";
    qihse_index_row_t rows[2] = {{0}};
    for (unsigned i=0;i<2;i++) {
        rows[i].vector_id = i+1; rows[i].vector_offset = i*sizeof(vectors[0]);
        rows[i].metadata_size = sizeof(tag)-1; rows[i].commit_generation = 1;
        rows[i].row_flags = QIHSE_ROW_F_LIVE;
    }
    rows[1].classification = QIHSE_CLASS_SECRET; rows[1].sci_compartment = QIHSE_SCI_SI;
    qihse_vector_store_flush_t image = {0};
    image.vector_dims = 2; image.commit_generation = 1; image.rows = rows; image.row_count = 2;
    image.vectors = vectors; image.vector_bytes = sizeof(vectors);
    image.metadata = tag; image.metadata_bytes = sizeof(tag)-1;
    char path[256]; snprintf(path,sizeof(path),"%s/vectors.qdb",root);
    assert(qihse_vector_store_flush(path,&image));
    qihse_vector_db_t db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,NULL,path,QIHSE_VDB_OPEN_FILE_BACKED);
    qihse_kv_store_t* kv = qihse_kv_store_create(); assert(db && kv);
    int pair[2]; assert(socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
    server_args args = {.fd=pair[1],.kv=kv,.vdb=db}; pthread_t thread;
    assert(pthread_create(&thread,NULL,serve,&args) == 0);
    char reply[1024];
    authenticate(pair[0],tenant,tenant_password);
    const char* denied[] = {"VECGET 1\r\n","VECGET 2\r\n",
        "VECSET 1 2 99 99\r\n","VECSET 3 2 99 99\r\n","VECSEARCH 2 1 12.5 25\r\n"};
    for (unsigned i=0;i<sizeof(denied)/sizeof(*denied);i++) {
        exchange(pair[0],denied[i],1,reply,sizeof(reply));
        assert(strstr(reply,"NOPERM") && !strstr(reply,"946.125") && !strstr(reply,"12.5"));
    }
    authenticate(pair[0],low,low_password);
    exchange(pair[0],"VECGET 2\r\n",1,reply,sizeof(reply));
    assert(reply[0]=='-' && !strstr(reply,"946.125"));
    exchange(pair[0],"VECSET 2 2 99 99\r\n",1,reply,sizeof(reply)); assert(reply[0]=='-');
    authenticate(pair[0],op,op_password);
    exchange(pair[0],"VECGET 2\r\n",5,reply,sizeof(reply));
    assert(strstr(reply,"946.125") && strstr(reply,"314.25"));
    exchange(pair[0],"VECSET 1 2 5 6\r\n",1,reply,sizeof(reply)); assert(!strcmp(reply,"+OK\r\n"));
    /* Bulk replies must not truncate at the legacy 1 KiB/64 KiB scratch sizes. */
    const size_t large_size = 40000;
    char* large = malloc(large_size+1); assert(large);
    memset(large,'Z',large_size); large[large_size] = 0;
    assert(qihse_kv_set_user(kv,"raw-large-a",large,0,0,op));
    assert(qihse_kv_set_user(kv,"raw-large-b",large,0,0,op));
    char* bulk = malloc(2*large_size+256); assert(bulk);
    exchange(pair[0],"GET raw-large-a\r\n",2,bulk,2*large_size+256);
    assert(!strncmp(bulk,"$40000\r\n",8) && strlen(bulk)==large_size+10);
    assert(!memcmp(bulk+8,large,large_size));
    exchange(pair[0],"MGET raw-large-a raw-large-b\r\n",5,bulk,2*large_size+256);
    assert(!strncmp(bulk,"*2\r\n$40000\r\n",12) && strlen(bulk)==2*large_size+24);
    assert(!memcmp(bulk+12,large,large_size));
    assert(!memcmp(bulk+large_size+22,large,large_size));
    free(bulk); free(large);
    close(pair[0]); assert(pthread_join(thread,NULL) == 0);
    float got[2]; size_t dims;
    assert(qihse_vector_db_get_vector_by_id_user(db,op,1,got,&dims) && got[0]==5 && got[1]==6);
    assert(qihse_vector_db_get_vector_by_id_user(db,op,2,got,&dims) && got[0]==vectors[1][0] && got[1]==vectors[1][1]);
    assert(!qihse_vector_db_get_vector_by_id_user(db,op,3,got,&dims));
    qihse_vector_db_destroy(db); qihse_kv_store_destroy(kv);
    assert(qihse_auth_destroy_user(op,88)); assert(qihse_auth_destroy_user(op,89));
    qihse_auth_shutdown_rate_limiter(); qihse_auth_shutdown_volume_limiter();
    qihse_audit_shutdown();
    assert(nftw(root,remove_entry,16,FTW_DEPTH|FTW_PHYS) == 0);
    puts("PASS raw RESP vector tenant/classification denial and Operator access");
    return 0;
}

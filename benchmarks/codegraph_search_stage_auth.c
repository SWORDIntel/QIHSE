#include "qihse_auth.h"
#include "qihse_kv_store.h"
extern int __real_qihse_kv_load_user(qihse_kv_store_t *,const char *,qihse_user_t *);
#include <stdint.h>
#include <stdio.h>
#include <time.h>
static uint64_t stamp(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec; }
#define REPORT(name) fprintf(stderr,"CG_AUTH stage=%s wall_us=%llu\n",name,(unsigned long long)((stamp()-start)/1000))
int __wrap_qihse_kv_load_user(qihse_kv_store_t *store,const char *path,qihse_user_t *user) { uint64_t start=stamp(); int value=__real_qihse_kv_load_user(store,path,user); REPORT("snapshot_kv_load"); return value; }
extern bool __real_qihse_auth_init(void);
bool __wrap_qihse_auth_init(void) { uint64_t start=stamp(); bool value=__real_qihse_auth_init(); REPORT("init"); return value; }
extern bool __real_qihse_auth_bootstrap_operator(const char *);
bool __wrap_qihse_auth_bootstrap_operator(const char *password) { uint64_t start=stamp(); bool value=__real_qihse_auth_bootstrap_operator(password); REPORT("bootstrap"); return value; }
extern qihse_user_t *__real_qihse_auth_authenticate_id(uint32_t,const char *);
qihse_user_t *__wrap_qihse_auth_authenticate_id(uint32_t id,const char *password) { uint64_t start=stamp(); qihse_user_t *value=__real_qihse_auth_authenticate_id(id,password); REPORT("authenticate"); return value; }
extern qihse_user_t *__real_qihse_auth_create_user(const qihse_user_t *,uint32_t,uint16_t,uint16_t,uint16_t,const char *,bool);
qihse_user_t *__wrap_qihse_auth_create_user(const qihse_user_t *creator,uint32_t id,uint16_t role,uint16_t level,uint16_t sci,const char *password,bool hardware) { uint64_t start=stamp(); qihse_user_t *value=__real_qihse_auth_create_user(creator,id,role,level,sci,password,hardware); REPORT("create_reader"); return value; }

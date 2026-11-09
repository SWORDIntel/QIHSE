#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_backup.h"
#include "qihse_cluster_reclaim.h"
#include "aimem_fixture_cleanup.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#define QIHSE_BACKUP_CLI_NO_MAIN
#include "../tools/qihse_backup_cli.c"

static void backup(qihse_kv_store_t* s, qihse_user_t* u, const char* p) {
    assert(qihse_backup_full_user(s,u,p,NULL)==0);
}
static void value(qihse_kv_store_t* s,qihse_user_t* u,const char* k,const char* v) {
    char* p=qihse_kv_get_user(s,k,u);assert(p && !strcmp(p,v));free(p);
}
static uint64_t now_ms(void) { struct timespec t; clock_gettime(CLOCK_REALTIME,&t);
    return (uint64_t)t.tv_sec*1000u+(uint64_t)t.tv_nsec/1000000u; }
int main(void) {
    char dir[]="build/backup-merge-XXXXXX";assert(mkdtemp(dir));
    assert(!setenv("QIHSE_DATA_DIR",dir,1));assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("MergeOperatorTest123!"));
    qihse_user_t* op=qihse_auth_authenticate_id(0,"MergeOperatorTest123!");assert(op);
    qihse_user_t* low=qihse_auth_create_user(op,6211,QIHSE_ROLE_GUEST,0,0,"MergeGuestTest123!",false);
    assert(low && qihse_auth_authenticate_id(6211,"MergeGuestTest123!")==low);
    qihse_kv_store_t* s=qihse_kv_store_create_user(op);assert(s);
    char a[512],b[512],o[512],c[512];
    snprintf(a,sizeof a,"%s/base.bak",dir);snprintf(b,sizeof b,"%s/incoming.bak",dir);
    snprintf(o,sizeof o,"%s/union.bak",dir);snprintf(c,sizeof c,"%s/conflict.bak",dir);
    assert(qihse_kv_set_user(s,"shared","same",0,0,op));
    assert(qihse_kv_set_user(s,"base","base-value",3,9,op));backup(s,op,a);
    qihse_kv_clear_user(s,op);
    assert(qihse_kv_set_user(s,"shared","same",0,0,op)); /* Different local seq. */
    uint64_t expiry=now_ms()+3600000;
    qihse_kv_batch_set_record_t row={.key="t:7/app:new",.value="classified",.classification=5,
        .sci_compartment=9,.expire_time_ms=expiry};
    assert(qihse_kv_set_batch_durable_user(s,&row,1,op));backup(s,op,b);
    qihse_backup_merge_stats_t st;
    assert(qihse_backup_merge_user(op,a,b,o,1<<20,100,&st)==0);
    assert(st.added==1 && st.identical==1 && !st.conflicts);
    assert(!qihse_restore_user(s,op,o));value(s,op,"base","base-value");
    value(s,op,"shared","same");value(s,op,row.key,"classified");
    qihse_kv_record_meta_t m;assert(qihse_kv_meta_user(s,row.key,op,&m));
    assert(m.expire_time_ms==expiry && m.classification==5 && m.sci_compartment==9);
    /* Conflicting payload, label and expiry each refuse without replacing output. */
    for(int kind=0;kind<3;kind++) {
        qihse_kv_clear_user(s,op);
        qihse_kv_batch_set_record_t conflict={.key="shared",.value=kind==0?"different":"same",
            .classification=kind==1?4:0,.sci_compartment=kind==1?2:0,
            .expire_time_ms=kind==2?expiry:0};
        assert(qihse_kv_set_batch_durable_user(s,&conflict,1,op));backup(s,op,c);
        assert(qihse_backup_merge_user(op,a,c,o,1<<20,100,&st)==QIHSE_BACKUP_EXPORT_CONFLICT);
        assert(st.conflicts==1);
        assert(!qihse_restore_user(s,op,o));value(s,op,row.key,"classified");
    }
    st.added=st.identical=st.conflicts=99;
    assert(qihse_backup_merge_user(low,a,b,o,1<<20,100,&st)==QIHSE_BACKUP_EXPORT_DENIED);
    assert(!st.added && !st.identical && !st.conflicts);
    assert(qihse_backup_merge_user(NULL,a,b,o,1<<20,100,&st)!=0);
    assert(qihse_backup_merge_user(op,a,b,a,1<<20,100,&st)!=0);
    char alias[512];snprintf(alias,sizeof alias,"%s/alias",dir);assert(!link(a,alias));
    assert(qihse_backup_merge_user(op,a,b,alias,1<<20,100,&st)!=0);
    assert(qihse_backup_merge_user(op,a,b,o,1,100,&st)!=0);
    assert(qihse_backup_merge_user(op,a,b,o,1<<20,1,&st)!=0);
    /* Corruption is verified before a new output can be published. */
    int fd=open(b,O_RDWR);assert(fd>=0);unsigned char byte;
    assert(pread(fd,&byte,1,70)==1);byte^=1;assert(pwrite(fd,&byte,1,70)==1);close(fd);
    assert(qihse_backup_merge_user(op,a,b,o,1<<20,100,&st)!=0);
    assert(!qihse_backup_verify_user(op,o));
    char* args[]={"backup","merge","--data-dir",dir,"--base",a,"--incoming",c,"--output",o};
    qihse_backup_cli_options_t opts;assert(qihse_backup_cli_parse(10,args,&opts));
    (void)qihse_backup_cli_load_password;
    qihse_backup_cli_clean_password(NULL);
    assert(opts.max_bytes == ((size_t)1 << 30) && opts.max_records == 2000000u);
    char* bad_limits[]={"backup","merge","--data-dir",dir,"--base",a,"--incoming",c,"--output",o,"--max-records","999999999999999999999999999"};
    qihse_backup_cli_options_t rejected;assert(!qihse_backup_cli_parse(12,bad_limits,&rejected));
    FILE* response=tmpfile();assert(response);
    assert(qihse_backup_cli_execute(&opts,NULL,low,response)==QIHSE_BACKUP_CLI_AUTH_FAILED);
    fclose(response);
    assert(qihse_cluster_key_is_node_local("t:7/aimem:abc"));
    assert(qihse_cluster_key_is_node_local("t:7/aimem-index-gen:p:3:pending"));
    assert(qihse_cluster_key_is_node_local("t:7/aimem-forget:42:receipt"));
    assert(!qihse_cluster_key_is_node_local("t:7/app:new"));
    assert(!qihse_cluster_key_is_node_local("t:no/aimem:abc"));
    assert(!qihse_cluster_key_is_node_local("sabot/tool:key"));
    qihse_cluster_topology_t* topo=qihse_cluster_topology_create();assert(topo);
    qihse_cluster_node_t n={0};uint16_t local,peer;
    strcpy(n.id,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");strcpy(n.host,"127.0.0.1");
    n.port=7100;n.role=QIHSE_CLUSTER_NODE_PRIMARY;n.healthy=true;n.primary_index=QIHSE_CLUSTER_NODE_NONE;
    assert(qihse_cluster_topology_upsert_node(topo,&n,&local));
    strcpy(n.id,"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");n.port=7101;
    assert(qihse_cluster_topology_upsert_node(topo,&n,&peer));
    assert(qihse_cluster_topology_set_local_node(topo,local));
    assert(qihse_cluster_topology_assign_range(topo,0,16383,peer));
    qihse_kv_clear_user(s,op);
    const char* families[]={"aimem:","aimemv:","aimem-knowledge:","aimem-grant:","aimem-forget:",
        "aimem-index-state:","aimem-index-gen:","aimem-handoff:","aimem-maint:"};
    for(size_t i=0;i<sizeof families/sizeof families[0];i++) {char key[128];
        snprintf(key,sizeof key,"t:7/%sprotected",families[i]);
        assert(qihse_kv_set_user(s,key,"protected",5,9,op));}
    assert(qihse_kv_set_user(s,"t:7/app:key","shardable",0,0,op));
    assert(qihse_cluster_reclaim_foreign_slots(s,topo,local,op)==1);
    assert(qihse_kv_count_user(s,op)==9);
    qihse_cluster_topology_destroy(topo);qihse_kv_store_destroy(s);
    aimem_fixture_cleanup(dir);
    puts("PASS authenticated bounded backup merge, conflict preservation, scoped AIMEM reclaim");
    return 0;
}

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "qihse_auth.h"
#include "qihse_cluster_maintenance.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#define OP_PASS "MaintRespOperator1!"
#define GUEST_PASS "MaintRespGuest1!"
typedef struct { qihse_resp_server_t *server; int fd; } server_arg_t;
typedef struct { int fd; pthread_t thread; } client_t;
static void *serve(void *p) { server_arg_t *a=p; (void)qihse_resp_server_handle_client_fd(a->server,a->fd); return NULL; }
static void send_command(int fd,size_t n,const char *const *v) {
    char b[64]; int k=snprintf(b,sizeof b,"*%zu\r\n",n); assert(write(fd,b,k)==k);
    for(size_t i=0;i<n;i++){ k=snprintf(b,sizeof b,"$%zu\r\n",strlen(v[i])); assert(write(fd,b,k)==k); assert(write(fd,v[i],strlen(v[i]))==(ssize_t)strlen(v[i])); assert(write(fd,"\r\n",2)==2); }
}
static int complete(const char *b,size_t n,size_t *used,unsigned depth){
    if(!n||depth>32)return 0;
    const char *e=memmem(b,n,"\r\n",2);
    if(!e)return 0;
    size_t head=(size_t)(e-b)+2; if(b[0]=='$'){long z=strtol(b+1,NULL,10);if(z<0){*used=head;return 1;}size_t total=head+(size_t)z+2;if(n<total)return 0;*used=total;return 1;}
    if(b[0]=='*'){long count=strtol(b+1,NULL,10);size_t pos=head;for(long i=0;i<count;i++){size_t child=0;int ok=complete(b+pos,n-pos,&child,depth+1);if(ok<=0)return ok;pos+=child;}*used=pos;return 1;}
    *used=head;return 1;
}
static char *reply(client_t *c) {
    char *b=calloc(1,65536); assert(b); size_t n=0,used=0;
    while(complete(b,n,&used,0)<=0){ssize_t r=read(c->fd,b+n,65535-n);assert(r>0);n+=(size_t)r;b[n]=0;}
    return b;
}
static void expect(client_t*c,const char*needle){char*r=reply(c); if(!strstr(r,needle)){fprintf(stderr,"expected %s, got %s\n",needle,r);abort();} free(r);}
static void command(client_t*c,size_t n,const char*const*v,const char*want){send_command(c->fd,n,v);expect(c,want);}
static client_t client(qihse_resp_server_t*s){int f[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,f)==0);server_arg_t*a=malloc(sizeof *a);assert(a);*a=(server_arg_t){s,f[1]};client_t c={.fd=f[0]};assert(pthread_create(&c.thread,NULL,serve,a)==0);return c;}
static void auth(client_t*c,const char*u,const char*p){const char*v[]={"AUTH",u,p};command(c,3,v,"+OK");}
int main(void){
    char dir[]="build/test_cluster_maintenance_resp_XXXXXX"; assert(mkdtemp(dir)); assert(setenv("QIHSE_DATA_DIR",dir,1)==0); assert(setenv("QIHSE_FIPS_MODE","disabled",1)==0);
    assert(qihse_auth_init()&&qihse_auth_bootstrap_operator(OP_PASS)); qihse_user_t*op=qihse_auth_get_user(0); assert(op);
    assert(qihse_auth_create_user(op,991,QIHSE_ROLE_GUEST,0,0,GUEST_PASS,false));
    qihse_kv_store_t*store=qihse_kv_store_create(); assert(store);
    qihse_cluster_maintenance_t*gate=qihse_cluster_maintenance_create(); assert(gate);
    qihse_resp_server_config_t cfg; qihse_resp_server_config_init(&cfg); cfg.store=store; cfg.port=0; cfg.auth_required=true; cfg.enable_task_workers=false; cfg.enable_task_scheduler=false; cfg.maintenance_gate=gate;
    qihse_resp_server_t*s=qihse_resp_server_create(&cfg); assert(s);
    client_t anon=client(s); const char*begin[]={"CLUSTER","MAINTENANCE","BEGIN","0","5000"}; command(&anon,5,begin,"NOPERM"); const char*status[]={"CLUSTER","MAINTENANCE","STATUS"}; command(&anon,3,status,"NOPERM"); const char*rel[]={"CLUSTER","MAINTENANCE","RELEASE","1", "0000000000000000000000000000000000000000000000000000000000000000"}; command(&anon,5,rel,"NOPERM");
    auth(&anon,"User_991",GUEST_PASS); command(&anon,5,begin,"NOPERM"); command(&anon,3,status,"NOPERM"); command(&anon,5,rel,"NOPERM");
    client_t admin=client(s); auth(&admin,qihse_user_get_username(op),OP_PASS);
    /* This in-process fixture has no daemon startup-GC loop. Production daemon
     * registers RECLAIM around its actual pending/in-flight work. */
    assert(qihse_cluster_maintenance_register(gate,QIHSE_MAINT_WRITER_RECLAIM,true));
    assert(qihse_cluster_maintenance_register(gate,QIHSE_MAINT_WRITER_REPLICA,true));
    assert(qihse_cluster_maintenance_register(gate,QIHSE_MAINT_WRITER_BRAIN,true));
    send_command(admin.fd,5,begin); char*r=reply(&admin); assert(strstr(r,"HELD"));
    char *p=strchr(r,':'); assert(p); char gen[32],token[65]; p++; char *ge=strstr(p,"\r\n"); assert(ge); snprintf(gen,sizeof gen,"%.*s",(int)(ge-p),p);
    p=strstr(r,"$64\r\n"); assert(p); p+=5; memcpy(token,p,64); token[64]=0; for(size_t i=0;i<64;i++)assert(isxdigit((unsigned char)token[i])); free(r);
    send_command(admin.fd,3,status); r=reply(&admin); assert(strstr(r,"HELD")&&strstr(r,"\r\n:1\r\n:0\r\n:0\r\n:0\r\n:0\r\n:0\r\n")&&strstr(r,"task_worker")&&strstr(r,"bus_federation")&&strstr(r,"brain")&&!strstr(r,token)); free(r);
    const char*set[]={"SET","maintenance-test","x"}; command(&admin,3,set,"BUSY"); const char*ping[]={"PING"}; command(&admin,1,ping,"PONG"); const char*info[]={"INFO"}; command(&admin,1,info,"# Server"); const char*cluster_info[]={"CLUSTER","INFO"}; command(&admin,2,cluster_info,"cluster_state");
    const char*bad[]={"CLUSTER","MAINTENANCE","RELEASE","999",token}; command(&admin,5,bad,"rejected");
    char wrong[65]; strcpy(wrong,token); wrong[0]=wrong[0]=='0'?'1':'0'; const char*badtoken[]={"CLUSTER","MAINTENANCE","RELEASE",gen,wrong}; command(&admin,5,badtoken,"rejected");
    const char*save[]={"BGSAVE"}; command(&admin,1,save,"BUSY"); const char*good[]={"CLUSTER","MAINTENANCE","RELEASE",gen,token}; command(&admin,5,good,"+OK");
    close(anon.fd); pthread_join(anon.thread,NULL); close(admin.fd); pthread_join(admin.thread,NULL);
    qihse_resp_server_destroy(s); qihse_cluster_maintenance_destroy(gate); qihse_kv_store_destroy(store);
    puts("PASS RESP authenticated cluster maintenance gate"); return 0;
}

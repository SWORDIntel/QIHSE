#define _GNU_SOURCE
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t,size_t);
extern void *__libc_realloc(void *,size_t);
extern void __libc_free(void *);
static _Atomic uint64_t allocations, frees, bytes;
static int log_fd=-1;
void *malloc(size_t size) { void *p=__libc_malloc(size); if(p){ atomic_fetch_add_explicit(&allocations,1,memory_order_relaxed); atomic_fetch_add_explicit(&bytes,size,memory_order_relaxed); } return p; }
void *calloc(size_t n,size_t size) { void *p=__libc_calloc(n,size); if(p){ atomic_fetch_add_explicit(&allocations,1,memory_order_relaxed); atomic_fetch_add_explicit(&bytes,n*size,memory_order_relaxed); } return p; }
void *realloc(void *old,size_t size) { void *p=__libc_realloc(old,size); if(p){ atomic_fetch_add_explicit(&allocations,1,memory_order_relaxed); atomic_fetch_add_explicit(&bytes,size,memory_order_relaxed); } return p; }
void free(void *p) { if(p) atomic_fetch_add_explicit(&frees,1,memory_order_relaxed); __libc_free(p); }
static size_t number(char *p,uint64_t value) { char tmp[32];size_t n=0,k=0;do{tmp[n++]=(char)('0'+value%10);value/=10;}while(value);while(n)p[k++]=tmp[--n];return k; }
static void dump(int sig) { (void)sig; if(log_fd<0)return;char line[128];size_t n=0;n+=number(line+n,(uint64_t)getpid());line[n++]=' ';n+=number(line+n,atomic_load_explicit(&allocations,memory_order_relaxed));line[n++]=' ';n+=number(line+n,atomic_load_explicit(&frees,memory_order_relaxed));line[n++]=' ';n+=number(line+n,atomic_load_explicit(&bytes,memory_order_relaxed));line[n++]='\n';(void)write(log_fd,line,n); }
__attribute__((constructor)) static void init(void) {const char *path=getenv("CG_ALLOC_LOG");const char *fd=getenv("CG_ALLOC_FD");if(fd){log_fd=atoi(fd);fcntl(log_fd,F_SETFD,FD_CLOEXEC);unsetenv("CG_ALLOC_FD");}else if(path)log_fd=open(path,O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC,0600);struct sigaction action={0};action.sa_handler=dump;sigemptyset(&action.sa_mask);action.sa_flags=SA_RESTART;sigaction(SIGUSR1,&action,0);}
__attribute__((destructor)) static void finish(void) {dump(0);if(log_fd>=0)close(log_fd);}

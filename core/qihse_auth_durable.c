#include "qihse_auth_durable.h"
#include "qihse_principal_record.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static bool selected, ready;
static int directory_fd = -1, lock_fd = -1;
static qihse_auth_archive_keys_t archive_keys, transfer_keys;
static uint8_t authority_id[16], provision_binding[48];
static qihse_user_t protected_root;
static qihse_auth_position_t position;
static size_t retry_count;
static qihse_auth_retry_t retries[QIHSE_AUTH_RETRY_MAX];
static size_t root_encode(const qihse_user_t *u, uint8_t out[2048]);

bool qihse_auth_durable_active(void) {
 return __atomic_load_n(&selected, __ATOMIC_ACQUIRE);
}
bool qihse_auth_durable_ready(void) {
 return __atomic_load_n(&ready, __ATOMIC_ACQUIRE);
}
void qihse_auth_durable_verified(void) {
 __atomic_store_n(&ready, true, __ATOMIC_RELEASE);
 qihse_auth_durable_set_ready(true);
}
void qihse_auth_durable_fence(void) {
 __atomic_store_n(&ready, false, __ATOMIC_RELEASE);
 qihse_auth_durable_set_ready(false);
}
const uint8_t *qihse_auth_durable_authority_id(void) { return authority_id; }
const qihse_auth_archive_keys_t *qihse_auth_durable_archive_keys(void) { return &transfer_keys; }
static qihse_auth_archive_config_t local_config(const qihse_auth_position_t *at,
 const uint8_t archive_id[16]) {
 qihse_auth_archive_config_t config;
 memset(&config,0,sizeof(config)); config.keys=archive_keys;
 config.binding.version=QIHSE_AUTH_ARCHIVE_VERSION;
 config.binding.purpose=QIHSE_AUTH_ARCHIVE_PURPOSE_DURABLE;
 config.binding.mode=QIHSE_AUTH_AUTHORITY_STANDALONE;
 memcpy(config.binding.source_authority,authority_id,16);
 memcpy(config.binding.target_authority,authority_id,16);
 config.binding.source=config.binding.target=*at;
 memcpy(config.binding.archive_id,archive_id,16);
 return config;
}
qihse_auth_position_t qihse_auth_durable_position(void) { return position; }
bool qihse_auth_durable_image_metadata(const qihse_auth_image_context_t *context,
 qihse_auth_image_t *image) {
 if (!image || !qihse_auth_image_context_valid(context)) return false;
 image->position = position;
 memcpy(image->bootstrap_binding,provision_binding,48);
 image->retry_count = retry_count;
 memcpy(image->retries, retries, sizeof(retries));
 return true;
}
bool qihse_auth_durable_bootstrap(const qihse_auth_image_context_t *context,
 qihse_user_t *root) {
 if (!root || !selected || !qihse_auth_image_context_valid(context)) return false;
 *root = protected_root;
 return true;
}

static void put(uint8_t **p, uint64_t value, size_t n) {
 for (size_t i = 0; i < n; ++i) { *(*p)++ = (uint8_t)value; value >>= 8; }
}
static uint64_t get(const uint8_t **p, size_t n) {
 uint64_t value = 0;
 for (size_t i = 0; i < n; ++i) value |= (uint64_t)*(*p)++ << (8*i);
 return value;
}
/* Bootstrap file and durable binding use this explicit portable encoding.
 * All reserved/transient fields are excluded. */
static size_t root_encode(const qihse_user_t *u, uint8_t out[2048]) {
 uint8_t *p = out;
 memcpy(p, "QABOOT01", 8); p += 8;
 put(&p, u->role, 2); put(&p, u->classification_level, 2);
 put(&p, u->sci_compartments, 2); put(&p, u->tenant_id, 4);
 put(&p, (u->requires_hardware_token ? 1u : 0u) |
         (u->can_create_users ? 2u : 0u), 1);
 memcpy(p, u->username, 64); p += 64;
 memcpy(p, u->fido2_credential_id, 64); p += 64;
 put(&p, u->verifier.version, 2); put(&p, u->verifier.algorithm, 2);
 put(&p, u->verifier.iterations, 4);
 memcpy(p, u->verifier.salt, QIHSE_PW_SALT_BYTES); p += QIHSE_PW_SALT_BYTES;
 memcpy(p, u->verifier.verifier, QIHSE_PW_HASH_BYTES); p += QIHSE_PW_HASH_BYTES;
 put(&p, u->object_acl_count, 1);
 for (size_t i = 0; i < u->object_acl_count; ++i) {
  put(&p, u->object_acl[i].namespace_id, 4);
  put(&p, u->object_acl[i].resource_id, 8);
  put(&p, u->object_acl[i].access_flags, 1);
 }
 return (size_t)(p-out);
}
static bool root_decode(const uint8_t *data, size_t length, qihse_user_t *u) {
 const size_t base = 8+6+4+1+64+64+8+QIHSE_PW_SALT_BYTES+QIHSE_PW_HASH_BYTES+1;
 if (length < base || memcmp(data, "QABOOT01", 8)) return false;
 memset(u, 0, sizeof(*u));
 const uint8_t *p = data+8;
 u->role = (uint16_t)get(&p, 2); u->classification_level = (uint16_t)get(&p, 2);
 u->sci_compartments = (uint16_t)get(&p, 2); u->tenant_id = (uint32_t)get(&p, 4);
 uint8_t flags = (uint8_t)get(&p, 1);
 if (flags & ~3u) return false;
 u->requires_hardware_token = (flags & 1u) != 0;
 u->can_create_users = (flags & 2u) != 0;
 memcpy(u->username, p, 64); p += 64;
 memcpy(u->fido2_credential_id, p, 64); p += 64;
 u->verifier.version = (uint16_t)get(&p, 2);
 u->verifier.algorithm = (uint16_t)get(&p, 2);
 u->verifier.iterations = (uint32_t)get(&p, 4);
 memcpy(u->verifier.salt, p, QIHSE_PW_SALT_BYTES); p += QIHSE_PW_SALT_BYTES;
 memcpy(u->verifier.verifier, p, QIHSE_PW_HASH_BYTES); p += QIHSE_PW_HASH_BYTES;
 u->object_acl_count = (uint8_t)get(&p, 1);
 if (u->object_acl_count > QIHSE_OBJECT_ACL_MAX_ENTRIES ||
     length != base + 13u*u->object_acl_count) return false;
 for (size_t i = 0; i < u->object_acl_count; ++i) {
  u->object_acl[i].namespace_id = (uint32_t)get(&p, 4);
  u->object_acl[i].resource_id = get(&p, 8);
  u->object_acl[i].access_flags = (uint8_t)get(&p, 1);
  if (!u->object_acl[i].access_flags || (u->object_acl[i].access_flags & ~7u)) return false;
 }
 u->password_set = true;
 return qihse_principal_fields_valid(u,true);
}
static bool private_fd(int fd, bool directory) {
 struct stat st;
 return fd >= 0 && fstat(fd, &st) == 0 && st.st_uid == geteuid() &&
  !(st.st_mode & 0077) && (directory ? S_ISDIR(st.st_mode) :
  (S_ISREG(st.st_mode) && st.st_nlink == 1));
}
static bool read_exact(int fd, uint8_t *p, size_t n) {
 while (n) {
  ssize_t got = read(fd, p, n);
  if (got < 0 && errno == EINTR) continue;
  if (got <= 0) return false;
  p += got; n -= (size_t)got;
 }
 return true;
}
static bool write_exact(int fd, const uint8_t *p, size_t n) {
 while (n) {
  ssize_t done = write(fd, p, n);
  if (done < 0 && errno == EINTR) continue;
  if (done <= 0) return false;
  p += done; n -= (size_t)done;
 }
 return true;
}

qihse_auth_maintenance_status_t qihse_auth_bootstrap_provision(
 const char *file, const char *username, const char *password,
 bool requires_hardware_token, const char *credential_id, bool can_create_users) {
 if (!file || !*file || !username || !*username || strlen(username)>=64 ||
     !password || !credential_id || strlen(credential_id)>=64 ||
     (requires_hardware_token && !*credential_id)) return QIHSE_AUTH_MAINT_INVALID;
 qihse_auth_lifecycle_enter();
 qihse_auth_maintenance_status_t status=QIHSE_AUTH_MAINT_DENIED;
 qihse_user_t root; memset(&root,0,sizeof(root));
 uint8_t encoded[2048];
 char *path=strdup(file);
 int dir=-1, fd=-1;
 char temporary[64]={0}; bool candidate=false;
 if (!path || selected) goto done;
 char *slash=strrchr(path,'/');
 const char *name=path;
 if (slash) { *slash=0; name=slash+1; }
 if (!*name || !strcmp(name,".") || !strcmp(name,"..")) goto done;
 dir=open(slash ? (*path ? path : "/") : ".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if (!private_fd(dir,true)) goto done;
 root.role=QIHSE_ROLE_OPERATOR; root.classification_level=UINT16_MAX;
 root.sci_compartments=UINT16_MAX; root.tenant_id=QIHSE_TENANT_SYSTEM;
 root.can_create_users=can_create_users; root.requires_hardware_token=requires_hardware_token;
 memcpy(root.username,username,strlen(username));
 memcpy(root.fido2_credential_id,credential_id,strlen(credential_id));
 if (!qihse_password_compute(password,0,&root.verifier)) { status=QIHSE_AUTH_MAINT_INVALID; goto done; }
 root.password_set=true;
 if (!qihse_principal_fields_valid(&root,true)) { status=QIHSE_AUTH_MAINT_INVALID; goto done; }
 size_t length=root_encode(&root,encoded);
 uint8_t nonce[16];
 if (RAND_bytes(nonce,sizeof(nonce))!=1) { status=QIHSE_AUTH_MAINT_IO; goto done; }
 snprintf(temporary,sizeof(temporary),".bootstrap.%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
  nonce[0],nonce[1],nonce[2],nonce[3],nonce[4],nonce[5],nonce[6],nonce[7],
  nonce[8],nonce[9],nonce[10],nonce[11],nonce[12],nonce[13],nonce[14],nonce[15]);
 fd=openat(dir,temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
 if (fd<0) { status=QIHSE_AUTH_MAINT_IO; goto done; }
 candidate=true;
 bool ok=write_exact(fd,encoded,length) && fsync(fd)==0;
 if (close(fd)) ok=false;
 fd=-1;
 if (!ok) { status=QIHSE_AUTH_MAINT_IO; goto done; }
 /* Publish create-only with one link even if we crash immediately afterwards.
  * Neither link/unlink nor replacing rename is a safe fallback. */
 #if defined(__linux__) && defined(RENAME_NOREPLACE)
 if (renameat2(dir,temporary,dir,name,RENAME_NOREPLACE)) {
  int error=errno;
  status=error==EEXIST?QIHSE_AUTH_MAINT_CONFLICT:
   (error==ENOSYS || error==EINVAL || error==EOPNOTSUPP)?
   QIHSE_AUTH_MAINT_UNSUPPORTED:QIHSE_AUTH_MAINT_IO;
  goto done;
 }
 #else
 status=QIHSE_AUTH_MAINT_UNSUPPORTED; goto done;
 #endif
 candidate=false;
 /* Publication has happened: a failed directory sync cannot be rolled back. */
 status=fsync(dir)==0?QIHSE_AUTH_MAINT_OK:QIHSE_AUTH_MAINT_UNCERTAIN;
 done:
 if (fd>=0) close(fd);
 if (candidate) unlinkat(dir,temporary,0);
 if (dir>=0) close(dir);
 free(path); OPENSSL_cleanse(&root,sizeof(root)); OPENSSL_cleanse(encoded,sizeof(encoded));
 qihse_auth_lifecycle_leave(); return status;
}

qihse_auth_maintenance_status_t qihse_auth_durable_open(
 const qihse_auth_startup_config_t *config,
 const qihse_auth_image_context_t *context, qihse_user_t *bootstrap,
 qihse_auth_image_t **image) {
 if (!config || !bootstrap || !image || !context || !context->recovery ||
     !qihse_auth_recovery_valid(context->recovery)) return QIHSE_AUTH_MAINT_DENIED;
 *image = NULL;
 if (selected) return QIHSE_AUTH_MAINT_CONFLICT;
 __atomic_store_n(&selected, true, __ATOMIC_RELEASE);
 if (config->mode != QIHSE_AUTH_AUTHORITY_STANDALONE)
  return config->mode == QIHSE_AUTH_AUTHORITY_CONSENSUS ?
   QIHSE_AUTH_MAINT_UNSUPPORTED : QIHSE_AUTH_MAINT_INVALID;
 if (!config->state_directory || !config->bootstrap_file ||
     !config->archive_keys.recipient_public_file || !config->archive_keys.recipient_private_file ||
     !config->archive_keys.signer_public_file || !config->archive_keys.signer_private_file ||
     !config->epoch || (config->action != QIHSE_AUTH_START_PROVISION &&
                       config->action != QIHSE_AUTH_START_RECOVER)) return QIHSE_AUTH_MAINT_INVALID;
 uint8_t zero[16] = {0};
 if (!memcmp(zero, config->node, 16) || !memcmp(zero,config->authority_id,16) ||
     (config->action==QIHSE_AUTH_START_RECOVER &&
      (!memcmp(zero,config->expected_history,16) || !config->minimum_generation)) ||
     (config->action==QIHSE_AUTH_START_PROVISION && config->minimum_generation))
  return QIHSE_AUTH_MAINT_INVALID;
 memcpy(authority_id,config->authority_id,16);
 int fd = open(config->bootstrap_file, O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
 uint8_t root_bytes[2048];
 struct stat st;
 bool ok = private_fd(fd, false) && fstat(fd, &st) == 0 && st.st_size > 0 &&
  st.st_size <= (off_t)sizeof(root_bytes) && read_exact(fd, root_bytes, (size_t)st.st_size) &&
  root_decode(root_bytes, (size_t)st.st_size, bootstrap);
 if (ok) SHA384(root_bytes,(size_t)st.st_size,provision_binding);
 if (fd >= 0) close(fd);
 OPENSSL_cleanse(root_bytes, sizeof(root_bytes));
 if (!ok) return QIHSE_AUTH_MAINT_CORRUPT;
 protected_root = *bootstrap;
 directory_fd = open(config->state_directory, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if (!private_fd(directory_fd, true)) return QIHSE_AUTH_MAINT_DENIED;
 lock_fd = openat(directory_fd, "authority.lock", O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600);
 if (!private_fd(lock_fd, false) || flock(lock_fd, LOCK_EX|LOCK_NB)) return QIHSE_AUTH_MAINT_CONFLICT;
 archive_keys=config->archive_keys;
 archive_keys.recipient_public_file=strdup(config->archive_keys.recipient_public_file);
 archive_keys.recipient_private_file=strdup(config->archive_keys.recipient_private_file);
 archive_keys.signer_public_file=strdup(config->archive_keys.signer_public_file);
 archive_keys.signer_private_file=strdup(config->archive_keys.signer_private_file);
 if (!archive_keys.recipient_public_file || !archive_keys.recipient_private_file ||
     !archive_keys.signer_public_file || !archive_keys.signer_private_file) return QIHSE_AUTH_MAINT_LIMIT;
 transfer_keys=config->transfer_keys;
 #define COPY_TRANSFER_PATH(field) do { \
  if (config->transfer_keys.field) { \
   transfer_keys.field=strdup(config->transfer_keys.field); \
   if (!transfer_keys.field) return QIHSE_AUTH_MAINT_LIMIT; \
  } \
 } while (0)
 COPY_TRANSFER_PATH(recipient_public_file);
 COPY_TRANSFER_PATH(recipient_private_file);
 COPY_TRANSFER_PATH(signer_public_file);
 COPY_TRANSFER_PATH(signer_private_file);
 #undef COPY_TRANSFER_PATH
 fd = openat(directory_fd, "authority.state", O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
 if (config->action == QIHSE_AUTH_START_PROVISION) {
  if (fd >= 0) { close(fd); return QIHSE_AUTH_MAINT_CONFLICT; }
  if (errno != ENOENT) return QIHSE_AUTH_MAINT_IO;
  *image = calloc(1, sizeof(**image));
  if (!*image) return QIHSE_AUTH_MAINT_LIMIT;
  memcpy(position.node, config->node, 16); position.epoch = config->epoch;
  if (memcmp(config->expected_history,zero,16)) memcpy(position.history,config->expected_history,16);
  else if (RAND_bytes(position.history, 16) != 1) { qihse_auth_image_free(*image); *image=NULL; return QIHSE_AUTH_MAINT_IO; }
  (*image)->position = position;
  (*image)->root_generation = 1;
  return QIHSE_AUTH_MAINT_OK;
 }
 if (!private_fd(fd, false) || fstat(fd, &st) || st.st_size < 80 ||
     st.st_size > QIHSE_AUTH_ARCHIVE_MAX_BYTES + 8192u) {
  if (fd >= 0) close(fd);
  return QIHSE_AUTH_MAINT_CORRUPT;
 }
 size_t n = (size_t)st.st_size;
 uint8_t *bytes = malloc(n);
 if (!bytes) { close(fd); return QIHSE_AUTH_MAINT_LIMIT; }
 ok = read_exact(fd, bytes, n); close(fd);
 qihse_auth_maintenance_status_t status = QIHSE_AUTH_MAINT_CORRUPT;
 /* Untrusted prefix selects only generation/archive nonce. All fields are
  * subsequently matched against the authenticated, purpose-bound envelope. */
 if (ok && !memcmp(bytes, "QADUR002", 8) && !CRYPTO_memcmp(bytes+8, provision_binding, 48)) {
  const uint8_t *generation_bytes=bytes+56;
  qihse_auth_position_t recovered={0};
  memcpy(recovered.history,config->expected_history,16);
  memcpy(recovered.node,config->node,16); recovered.epoch=config->epoch;
  recovered.generation=get(&generation_bytes,8);
  qihse_auth_archive_config_t envelope=local_config(&recovered,bytes+64);
  status = qihse_auth_archive_open(context, bytes+80, n-80, &envelope, image);
  if (status == QIHSE_AUTH_MAINT_OK) {
   uint8_t root_check[2048]; qihse_user_t verified_root;
   size_t root_length=0;
   if ((*image)->has_local_root && (*image)->local_root.object_acl_count<=QIHSE_OBJECT_ACL_MAX_ENTRIES)
    root_length=root_encode(&(*image)->local_root,root_check);
   bool root_ok=(*image)->has_local_root &&
    root_decode(root_check,root_length,&verified_root);
   OPENSSL_cleanse(root_check,sizeof(root_check));
   OPENSSL_cleanse(&verified_root,sizeof(verified_root));
   if (!root_ok || CRYPTO_memcmp((*image)->bootstrap_binding, provision_binding, 48) ||
       memcmp((*image)->position.history,config->expected_history,16) ||
       (*image)->position.generation<config->minimum_generation ||
       memcmp((*image)->position.node, config->node, 16) ||
       (*image)->position.epoch != config->epoch || !(*image)->position.generation) {
    qihse_auth_image_free(*image); *image=NULL; status=QIHSE_AUTH_MAINT_CONFLICT;
   } else {
    *bootstrap=(*image)->local_root; bootstrap->hardware_token_present=false;
    protected_root=*bootstrap;
    position = (*image)->position; retry_count=(*image)->retry_count;
    memcpy(retries, (*image)->retries, sizeof(retries));
   }
  }
 }
 OPENSSL_cleanse(bytes, n); free(bytes);
 return status;
}

qihse_auth_maintenance_status_t qihse_auth_durable_commit(
 const qihse_auth_image_context_t *context, qihse_auth_image_t *image,
 const qihse_user_t *root) {
 if (!selected || directory_fd < 0 || !image || !root || !qihse_auth_image_context_valid(context))
  return QIHSE_AUTH_MAINT_DENIED;
 if (position.generation == UINT64_MAX) return QIHSE_AUTH_MAINT_LIMIT;
 image->local_root=*root; image->local_root.hardware_token_present=false;
 root=&image->local_root;
 image->position = position; image->position.generation++;
 uint8_t header[80], encoded[2048];
 if (root->user_id!=0 || root->hardware_token_present ||
     !qihse_principal_fields_valid(root,true)) return QIHSE_AUTH_MAINT_INVALID;
 size_t length = root_encode(root, encoded);
 qihse_user_t checked;
 bool valid_root=root_decode(encoded,length,&checked);
 OPENSSL_cleanse(&checked,sizeof(checked));
 if (!valid_root) { OPENSSL_cleanse(encoded,sizeof(encoded)); return QIHSE_AUTH_MAINT_INVALID; }
 memcpy(image->bootstrap_binding,provision_binding,48);
 image->has_local_root=true; image->local_root=*root;
 image->local_root.hardware_token_present=false;
 OPENSSL_cleanse(encoded, sizeof(encoded));
 memcpy(header, "QADUR002", 8);
 memcpy(header+8, provision_binding, 48);
 uint8_t *numeric=header+56; put(&numeric,image->position.generation,8);
 if (RAND_bytes(header+64,16)!=1) return QIHSE_AUTH_MAINT_IO;
 qihse_auth_archive_config_t envelope=local_config(&image->position,header+64);
 qihse_auth_sealed_t *sealed = NULL;
 qihse_auth_maintenance_status_t status = qihse_auth_archive_seal(context, image, &envelope, &sealed);
 if (status != QIHSE_AUTH_MAINT_OK) return status;
 /* Unique O_EXCL candidates cannot strand future writers after a crash. */
 char temporary[80];
 snprintf(temporary,sizeof(temporary),"authority.pending.%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
  header[64],header[65],header[66],header[67],header[68],header[69],header[70],header[71],
  header[72],header[73],header[74],header[75],header[76],header[77],header[78],header[79]);
 int fd = openat(directory_fd, temporary, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
 bool ok = fd >= 0 && write_exact(fd, header, sizeof(header)) &&
  write_exact(fd, qihse_auth_sealed_data(sealed), qihse_auth_sealed_size(sealed)) && fsync(fd) == 0;
 if (fd >= 0 && close(fd)) ok = false;
 bool published=false;
 if (ok) { published=renameat(directory_fd, temporary, directory_fd, "authority.state")==0; ok=published; }
 if (ok) ok = fsync(directory_fd) == 0;
 if (!published && fd>=0) unlinkat(directory_fd,temporary,0);
 qihse_auth_sealed_free(sealed);
 OPENSSL_cleanse(header, sizeof(header));
 if (!ok) { qihse_auth_durable_fence();
  return published?QIHSE_AUTH_MAINT_UNCERTAIN:QIHSE_AUTH_MAINT_IO; }
 position = image->position; protected_root = *root;
 retry_count=image->retry_count; memcpy(retries, image->retries, sizeof(retries));
 return QIHSE_AUTH_MAINT_OK;
}

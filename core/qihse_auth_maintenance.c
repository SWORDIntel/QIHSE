#include "qihse_auth_durable.h"
#include "qihse_pqc_crypto.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

struct qihse_auth_recovery { uint8_t nonce[32]; bool valid; };
static qihse_auth_recovery_t internal_recovery, startup_recovery;
static bool start_attempted;

const qihse_auth_recovery_t *qihse_auth_durable_recovery_context(void) {
 return internal_recovery.valid ? &internal_recovery : NULL;
}
bool qihse_auth_recovery_valid(const qihse_auth_recovery_t *context) {
 return context && ((context==&internal_recovery && internal_recovery.valid) ||
                    (context==&startup_recovery && startup_recovery.valid));
}
bool qihse_auth_image_context_valid(const qihse_auth_image_context_t *context) {
 if (!context || (!!context->actor == !!context->recovery)) return false;
 return context->recovery ? qihse_auth_recovery_valid(context->recovery) :
  qihse_auth_maintenance_actor_valid(context->actor);
}
void qihse_auth_maintenance_recovery_release(qihse_auth_recovery_t *context) {
 qihse_auth_lifecycle_enter();
 if (context==&startup_recovery) {
  startup_recovery.valid=false;
  OPENSSL_cleanse(startup_recovery.nonce,sizeof(startup_recovery.nonce));
 }
 qihse_auth_lifecycle_leave();
}
qihse_auth_maintenance_status_t qihse_auth_maintenance_start(
 const qihse_auth_startup_config_t *config, qihse_auth_recovery_t **out) {
 if (out) *out=NULL;
 if (!config || !out) return QIHSE_AUTH_MAINT_INVALID;
 qihse_auth_lifecycle_enter();
 qihse_auth_maintenance_status_t status=QIHSE_AUTH_MAINT_CONFLICT;
 qihse_auth_image_t *image=NULL;
 qihse_user_t root; memset(&root,0,sizeof(root));
 if (start_attempted) goto done;
 start_attempted=true;
 /* One-shot protected startup provenance: capabilities cannot be minted by a
  * protocol user or by calling ordinary auth initialization first. */
 if (RAND_bytes(internal_recovery.nonce,32)!=1 || RAND_bytes(startup_recovery.nonce,32)!=1) {
  status=QIHSE_AUTH_MAINT_IO; goto done;
 }
 qihse_pqc_init_providers();
 internal_recovery.valid=true;
 qihse_auth_image_context_t context={NULL,&internal_recovery};
 status=qihse_auth_durable_open(config,&context,&root,&image);
 if (status!=QIHSE_AUTH_MAINT_OK) goto done;
 if (!qihse_auth_durable_prepare(&root)) { status=QIHSE_AUTH_MAINT_CONFLICT; goto done; }
 if (config->action==QIHSE_AUTH_START_PROVISION) {
  status=qihse_auth_durable_commit(&context,image,&root);
  if (status!=QIHSE_AUTH_MAINT_OK) goto done;
 }
 status=qihse_auth_image_publish(&context,image);
 if (status==QIHSE_AUTH_MAINT_OK) { startup_recovery.valid=true; *out=&startup_recovery; }
 done:
 if (status!=QIHSE_AUTH_MAINT_OK) {
  qihse_auth_durable_fence(); internal_recovery.valid=false; startup_recovery.valid=false;
 }
 qihse_auth_image_free(image); OPENSSL_cleanse(&root,sizeof(root));
 qihse_auth_lifecycle_leave(); return status;
}
static bool position_equal(const qihse_auth_position_t *a,const qihse_auth_position_t *b) {
 return a && b && !memcmp(a->history,b->history,16) && !memcmp(a->node,b->node,16) &&
  a->epoch==b->epoch && a->generation==b->generation;
}
static qihse_auth_maintenance_status_t maintenance_gate(
 const qihse_auth_image_context_t *context,const qihse_auth_position_t *expected) {
 if (!qihse_auth_image_context_valid(context)) return QIHSE_AUTH_MAINT_DENIED;
 if (!qihse_auth_durable_active() || !qihse_auth_durable_ready()) return QIHSE_AUTH_MAINT_NOT_READY;
 qihse_auth_position_t current=qihse_auth_durable_position();
 if (!position_equal(expected,&current)) return QIHSE_AUTH_MAINT_CONFLICT;
 return QIHSE_AUTH_MAINT_OK;
}
qihse_auth_maintenance_status_t qihse_auth_maintenance_capabilities(
 const qihse_user_t *actor,qihse_auth_maintenance_caps_t *out) {
 if (!out) return QIHSE_AUTH_MAINT_INVALID;
 memset(out,0,sizeof(*out));
 qihse_auth_lifecycle_enter();
 qihse_auth_maintenance_status_t status=QIHSE_AUTH_MAINT_DENIED;
 if (qihse_auth_maintenance_actor_valid(actor)) {
  out->mode=qihse_auth_durable_active()?QIHSE_AUTH_AUTHORITY_STANDALONE:QIHSE_AUTH_AUTHORITY_DISABLED;
  out->ready=qihse_auth_durable_ready();
  const qihse_auth_archive_keys_t *keys=qihse_auth_durable_archive_keys();
  uint8_t zero[48]={0};
  bool pinned=memcmp(keys->recipient_pin,zero,48) && memcmp(keys->signer_pin,zero,48);
  out->export_supported=out->ready && pinned && keys->recipient_public_file && keys->signer_private_file;
  out->import_supported=out->ready && pinned && keys->recipient_private_file && keys->signer_public_file;
  out->checkpoint_supported=out->ready;
  if (out->ready) out->position=qihse_auth_durable_position();
  status=QIHSE_AUTH_MAINT_OK;
 }
 qihse_auth_lifecycle_leave(); return status;
}
qihse_auth_maintenance_status_t qihse_auth_maintenance_transfer_config(
 const qihse_user_t *actor,const qihse_auth_archive_binding_t *binding,
 const uint8_t recipient_pin[48],const uint8_t signer_pin[48],
 qihse_auth_archive_config_t *out) {
 if (!out || !binding || !recipient_pin || !signer_pin) return QIHSE_AUTH_MAINT_INVALID;
 memset(out,0,sizeof(*out)); qihse_auth_lifecycle_enter();
 qihse_auth_maintenance_status_t status=QIHSE_AUTH_MAINT_DENIED;
 const qihse_auth_archive_keys_t *keys=qihse_auth_durable_archive_keys();
 if (qihse_auth_maintenance_actor_valid(actor) && qihse_auth_durable_ready()) {
  uint8_t zero[48]={0};
  if (!memcmp(keys->recipient_pin,zero,48) || !memcmp(keys->signer_pin,zero,48))
   status=QIHSE_AUTH_MAINT_UNSUPPORTED;
  else if (binding->version!=QIHSE_AUTH_ARCHIVE_VERSION ||
      binding->purpose!=QIHSE_AUTH_ARCHIVE_PURPOSE_TRANSFER ||
      binding->mode!=QIHSE_AUTH_AUTHORITY_STANDALONE ||
      CRYPTO_memcmp(keys->recipient_pin,recipient_pin,48) ||
      CRYPTO_memcmp(keys->signer_pin,signer_pin,48)) status=QIHSE_AUTH_MAINT_CONFLICT;
  else { out->keys=*keys; out->binding=*binding; status=QIHSE_AUTH_MAINT_OK; }
 }
 qihse_auth_lifecycle_leave(); return status;
}
qihse_auth_maintenance_status_t qihse_auth_maintenance_export(
 const qihse_user_t *actor,const qihse_auth_position_t *expected,
 const qihse_auth_archive_config_t *transfer,qihse_auth_sealed_t **out) {
 if (!out) return QIHSE_AUTH_MAINT_INVALID;
 *out=NULL; qihse_auth_lifecycle_enter();
 qihse_auth_image_context_t context={actor,NULL};
 qihse_auth_maintenance_status_t status=maintenance_gate(&context,expected);
 qihse_auth_image_t *image=NULL;
 if (status==QIHSE_AUTH_MAINT_OK) status=qihse_auth_image_capture(&context,&image);
 if (status==QIHSE_AUTH_MAINT_OK && (!transfer ||
     transfer->binding.purpose!=QIHSE_AUTH_ARCHIVE_PURPOSE_TRANSFER ||
     !position_equal(&transfer->binding.source,expected) ||
     memcmp(transfer->binding.source_authority,qihse_auth_durable_authority_id(),16)))
  status=QIHSE_AUTH_MAINT_CONFLICT;
 if (status==QIHSE_AUTH_MAINT_OK) {
  qihse_auth_archive_config_t trusted;
  status=qihse_auth_maintenance_transfer_config(actor,&transfer->binding,
   transfer->keys.recipient_pin,transfer->keys.signer_pin,&trusted);
  if (status==QIHSE_AUTH_MAINT_OK) status=qihse_auth_archive_seal(&context,image,&trusted,out);
 }
 qihse_auth_image_free(image); qihse_auth_lifecycle_leave(); return status;
}
qihse_auth_maintenance_status_t qihse_auth_maintenance_checkpoint(
 const qihse_user_t *actor,const qihse_auth_position_t *expected,qihse_auth_position_t *out) {
 if (!out) return QIHSE_AUTH_MAINT_INVALID;
 memset(out,0,sizeof(*out)); qihse_auth_lifecycle_enter();
 qihse_auth_image_context_t context={actor,NULL};
 qihse_auth_maintenance_status_t status=maintenance_gate(&context,expected);
 qihse_auth_image_t *image=NULL; qihse_user_t root; memset(&root,0,sizeof(root));
 if (status==QIHSE_AUTH_MAINT_OK) status=qihse_auth_image_capture(&context,&image);
 if (status==QIHSE_AUTH_MAINT_OK && !qihse_auth_durable_bootstrap(&context,&root)) status=QIHSE_AUTH_MAINT_NOT_READY;
 if (status==QIHSE_AUTH_MAINT_OK) status=qihse_auth_durable_commit(&context,image,&root);
 if (status==QIHSE_AUTH_MAINT_OK) *out=qihse_auth_durable_position();
 OPENSSL_cleanse(&root,sizeof(root)); qihse_auth_image_free(image);
 qihse_auth_lifecycle_leave(); return status;
}
static bool request_digest(const uint8_t *bytes,size_t length,
 const qihse_auth_position_t *expected,const qihse_auth_archive_config_t *transfer,uint8_t out[48]) {
 uint8_t numeric[16], binding_numeric[25];
 for(size_t i=0;i<8;++i) {
  binding_numeric[i]=(uint8_t)(transfer->binding.source.epoch>>(8*i));
  binding_numeric[8+i]=(uint8_t)(transfer->binding.source.generation>>(8*i));
  binding_numeric[16+i]=(uint8_t)((uint64_t)transfer->binding.version>>(8*i));
 }
 binding_numeric[24]=transfer->binding.allow_node_relocation?1:0;
 for(size_t i=0;i<8;++i) { numeric[i]=(uint8_t)(expected->epoch>>(8*i));
  numeric[8+i]=(uint8_t)(expected->generation>>(8*i)); }
 EVP_MD_CTX *md=EVP_MD_CTX_new(); unsigned n=0;
 bool ok=md && EVP_DigestInit_ex(md,EVP_sha384(),NULL)==1 &&
  EVP_DigestUpdate(md,"QIHSE-PRINCIPAL-IMPORT-v1",25)==1 &&
  EVP_DigestUpdate(md,expected->history,16)==1 && EVP_DigestUpdate(md,expected->node,16)==1 &&
  EVP_DigestUpdate(md,numeric,sizeof(numeric))==1 &&
  EVP_DigestUpdate(md,transfer->binding.source_authority,16)==1 &&
  EVP_DigestUpdate(md,transfer->binding.target_authority,16)==1 &&
  EVP_DigestUpdate(md,transfer->binding.source.history,16)==1 &&
  EVP_DigestUpdate(md,transfer->binding.source.node,16)==1 &&
  EVP_DigestUpdate(md,transfer->binding.archive_id,16)==1 &&
  EVP_DigestUpdate(md,binding_numeric,sizeof(binding_numeric))==1 &&
  EVP_DigestUpdate(md,transfer->keys.recipient_pin,48)==1 &&
  EVP_DigestUpdate(md,transfer->keys.signer_pin,48)==1 && EVP_DigestUpdate(md,bytes,length)==1 &&
  EVP_DigestFinal_ex(md,out,&n)==1 && n==48;
 EVP_MD_CTX_free(md); return ok;
}
static qihse_auth_maintenance_status_t maintenance_import(
 const qihse_auth_image_context_t *context,const qihse_auth_position_t *expected,
 const uint8_t request_id[16],const qihse_auth_archive_config_t *transfer,
 const uint8_t *sealed,size_t length,qihse_auth_position_t *out) {
 if (!out || !expected || !request_id || !transfer || !sealed || !length || length>QIHSE_AUTH_ARCHIVE_MAX_BYTES)
  return QIHSE_AUTH_MAINT_INVALID;
 memset(out,0,sizeof(*out));
 uint8_t zero[16]={0}; if (!memcmp(request_id,zero,16)) return QIHSE_AUTH_MAINT_INVALID;
 qihse_auth_lifecycle_enter();
 qihse_auth_maintenance_status_t status=QIHSE_AUTH_MAINT_DENIED;
 qihse_auth_image_t *image=NULL,*current=NULL;
 uint8_t digest[48]; uint32_t actor_id=UINT32_MAX; uint64_t actor_generation=0;
 if (!qihse_auth_image_context_valid(context)) goto done;
 if (!qihse_auth_durable_ready()) { status=QIHSE_AUTH_MAINT_NOT_READY; goto done; }
 if (transfer->binding.version!=QIHSE_AUTH_ARCHIVE_VERSION ||
     transfer->binding.mode!=QIHSE_AUTH_AUTHORITY_STANDALONE ||
     transfer->binding.purpose!=QIHSE_AUTH_ARCHIVE_PURPOSE_TRANSFER ||
     !position_equal(&transfer->binding.target,expected) ||
     memcmp(transfer->binding.target_authority,qihse_auth_durable_authority_id(),16) ||
     memcmp(transfer->binding.source_authority,transfer->binding.target_authority,16)) {
  status=QIHSE_AUTH_MAINT_CONFLICT; goto done;
 }
 if (context->actor && !qihse_auth_actor_identity(context->actor,&actor_id,&actor_generation)) goto done;
 if (!request_digest(sealed,length,expected,transfer,digest)) { status=QIHSE_AUTH_MAINT_IO; goto done; }
 status=qihse_auth_image_capture(context,&current);
 if (status!=QIHSE_AUTH_MAINT_OK) goto done;
 for (size_t i=0;i<current->retry_count;++i) {
  const qihse_auth_retry_t *retry=&current->retries[i];
  if (memcmp(retry->request_id,request_id,16)) continue;
  if (retry->actor_id!=actor_id || retry->actor_generation!=actor_generation ||
      CRYPTO_memcmp(retry->digest,digest,48)) { status=QIHSE_AUTH_MAINT_CONFLICT; goto done; }
  *out=retry->result; status=QIHSE_AUTH_MAINT_OK; goto done;
 }
 status=maintenance_gate(context,expected); if (status!=QIHSE_AUTH_MAINT_OK) goto done;
 if (current->retry_count==QIHSE_AUTH_RETRY_MAX) { status=QIHSE_AUTH_MAINT_LIMIT; goto done; }
 qihse_auth_archive_config_t trusted=*transfer;
 const qihse_auth_archive_keys_t *configured=qihse_auth_durable_archive_keys();
 if (CRYPTO_memcmp(configured->recipient_pin,transfer->keys.recipient_pin,48) ||
     CRYPTO_memcmp(configured->signer_pin,transfer->keys.signer_pin,48)) {
  status=QIHSE_AUTH_MAINT_DENIED; goto done;
 }
 trusted.keys=*configured;
 status=qihse_auth_archive_open(context,sealed,length,&trusted,&image);
 if (status!=QIHSE_AUTH_MAINT_OK) goto done;
 /* Images are node-authority snapshots, never consensus prefixes. Import is
  * a new local generation, and cannot erase durable tombstone history. */
 if (image->has_local_root ||
     (!transfer->binding.allow_node_relocation && memcmp(image->position.node,current->position.node,16)) ||
     memcmp(image->position.history,current->position.history,16) ||
     image->position.epoch!=current->position.epoch ||
     image->position.generation<current->position.generation ||
     current->position.generation==UINT64_MAX) { status=QIHSE_AUTH_MAINT_CONFLICT; goto done; }
 if (context->actor) {
  bool delegates=qihse_user_can_create_users(context->actor);
  bool token_required=qihse_user_requires_hardware_token(context->actor);
  for (size_t i=0;i<image->count;++i) if (image->rows[i].active &&
      ((image->rows[i].principal.can_create_users && !delegates) ||
       (token_required && !image->rows[i].principal.requires_hardware_token))) {
   status=QIHSE_AUTH_MAINT_DENIED; goto done;
  }
 }
 size_t a=0,b=0,count=0;
 qihse_auth_image_row_t *merged=calloc(QIHSE_AUTH_IMAGE_MAX_PRINCIPALS,sizeof(*merged));
 if (!merged) { status=QIHSE_AUTH_MAINT_LIMIT; goto done; }
 while(a<current->count || b<image->count) {
  const qihse_auth_image_row_t *old=a<current->count?&current->rows[a]:NULL;
  const qihse_auth_image_row_t *incoming=b<image->count?&image->rows[b]:NULL;
  if (count==QIHSE_AUTH_IMAGE_MAX_PRINCIPALS) { status=QIHSE_AUTH_MAINT_LIMIT; goto merge_failed; }
  qihse_auth_image_row_t *row=&merged[count++];
  if (!incoming || (old && old->user_id<incoming->user_id)) {
   *row=*old; row->active=false; memset(&row->principal,0,sizeof(row->principal)); a++;
  } else if (!old || incoming->user_id<old->user_id) { *row=*incoming; b++; }
  else {
   if ((!old->active && incoming->active) ||
       (old->active && incoming->active &&
        ((old->principal.requires_hardware_token && !incoming->principal.requires_hardware_token) ||
         (old->principal.fido2_credential_id[0] &&
          strcmp(old->principal.fido2_credential_id,incoming->principal.fido2_credential_id))))) {
    status=QIHSE_AUTH_MAINT_CONFLICT; goto merge_failed;
   }
   *row=*incoming; a++; b++;
  }
  if (old && old->user_id==row->user_id) {
   uint64_t base=old->generation>row->generation?old->generation:row->generation;
   if (base==UINT64_MAX) { status=QIHSE_AUTH_MAINT_LIMIT; goto merge_failed; }
   row->generation=base+1;
   if (row->lockout_until<old->lockout_until) row->lockout_until=old->lockout_until;
   if (row->failed_count<old->failed_count) row->failed_count=old->failed_count;
  }
 }
 if (image->rows) { OPENSSL_cleanse(image->rows,image->count*sizeof(*image->rows)); free(image->rows); }
 image->rows=merged; image->count=count;
 image->root_generation=current->root_generation;
 image->root_failed_count=current->root_failed_count;
 image->root_lockout_until=current->root_lockout_until;
 image->position=current->position; image->position.generation++;
 image->retry_count=current->retry_count;
 memcpy(image->retries,current->retries,sizeof(image->retries));
 qihse_auth_retry_t *retry=&image->retries[image->retry_count++];
 memcpy(retry->request_id,request_id,16); memcpy(retry->digest,digest,48);
 retry->actor_id=actor_id; retry->actor_generation=actor_generation; retry->result=image->position;
 /* A successful import retires every nonroot handle and advances its generation.
  * Retry identity must describe the committed principal, not its retired handle. */
 if (actor_id && actor_id!=UINT32_MAX) {
  bool found=false;
  for (size_t i=0;i<image->count;++i) if (image->rows[i].user_id==actor_id && image->rows[i].active) {
   const qihse_user_t *principal=&image->rows[i].principal;
   if (principal->role==QIHSE_ROLE_OPERATOR && principal->tenant_id==QIHSE_TENANT_SYSTEM &&
       principal->classification_level==UINT16_MAX && principal->sci_compartments==UINT16_MAX) {
    retry->actor_generation=image->rows[i].generation; found=true;
   }
   break;
  }
  if (!found) { status=QIHSE_AUTH_MAINT_DENIED; goto done; }
 }
 status=qihse_auth_image_publish(context,image);
 if (status==QIHSE_AUTH_MAINT_OK) *out=qihse_auth_durable_position();
 goto done;
 merge_failed:
 OPENSSL_cleanse(merged,QIHSE_AUTH_IMAGE_MAX_PRINCIPALS*sizeof(*merged)); free(merged);
 done:
 qihse_auth_image_free(image); qihse_auth_image_free(current); OPENSSL_cleanse(digest,sizeof(digest));
 qihse_auth_lifecycle_leave(); return status;
}
qihse_auth_maintenance_status_t qihse_auth_maintenance_import(
 const qihse_user_t *actor,const qihse_auth_position_t *expected,const uint8_t request_id[16],
 const qihse_auth_archive_config_t *transfer,const uint8_t *sealed,size_t length,qihse_auth_position_t *out) {
 qihse_auth_image_context_t context={actor,NULL};
 return maintenance_import(&context,expected,request_id,transfer,sealed,length,out);
}
qihse_auth_maintenance_status_t qihse_auth_maintenance_recover_import(
 qihse_auth_recovery_t *recovery,const qihse_auth_position_t *expected,const uint8_t request_id[16],
 const qihse_auth_archive_config_t *transfer,const uint8_t *sealed,size_t length,qihse_auth_position_t *out) {
 qihse_auth_image_context_t context={NULL,recovery};
 return maintenance_import(&context,expected,request_id,transfer,sealed,length,out);
}
const char *qihse_auth_maintenance_status_string(qihse_auth_maintenance_status_t status) {
 static const char *const names[]={"OK","INVALID","DENIED","UNSUPPORTED","NOT_READY",
  "CONFLICT","IO","CORRUPT","LIMIT","UNCERTAIN"};
 return (unsigned)status<sizeof(names)/sizeof(names[0])?names[status]:"INVALID";
}

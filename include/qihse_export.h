#ifndef QIHSE_EXPORT_H
#define QIHSE_EXPORT_H

/* U7 — tenant-subset export (SESSION_DELIVERY_UPGRADES.md).
 *
 * Produces a portable artifact containing one tenant's data: every KV record
 * under the tenant's "t:<id>/" namespace plus the shared "commons/"
 * namespace, and the blob manifest entries visible to the caller. Records
 * the caller may not read (above clearance) are excluded by the
 * authorization-aware iteration, so the artifact never discloses protected
 * payload. Deletion/migration of a tenant follows from the same artifact.
 *
 * SECURITY (invariant #1): takes a mandatory qihse_user_t*; a tenant-scoped
 * principal may only export its OWN tenant; NULL is denied.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "qihse_auth.h"
#include "qihse_blob.h"
#include "qihse_kv_store.h"

#ifdef __cplusplus
extern "C" {
#endif

bool qihse_export_tenant_user(qihse_kv_store_t* kv, qihse_blob_store_t* blobs,
                              uint32_t tenant_id, qihse_user_t* user,
                              const char* out_path,
                              char* err, size_t err_cap);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_EXPORT_H */

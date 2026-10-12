#ifndef QIHSE_AUTH_REGISTRY_H
#define QIHSE_AUTH_REGISTRY_H

#include <stdbool.h>

/* Internal transition guard for a future committed principal registry.
 * Requires a configured system Operator verifier and no other active users.
 * Once set, direct auth
 * mutation APIs and auth reinitialization fail closed for this process.
 * This does not publish replayed principals or make the registry ready. */
bool qihse_auth_fence_direct_mutations(void);

/* Select a future committed-registry boot before any ordinary auth init.
 * Requires a configured system Operator verifier. Direct mutations and
 * password logins remain closed until an atomic publication path exists.
 * Source-only prerequisite: no daemon calls this yet. */
bool qihse_auth_init_registry_pre_serve(void);

#endif

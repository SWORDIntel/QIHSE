#ifndef QIHSE_AUTH_ARCHIVE_H
#define QIHSE_AUTH_ARCHIVE_H
#include "qihse_auth_maintenance_internal.h"
/* Complete expected binding, including archive ID and target generation, is
 * mandatory. Foreign-authority/history UID merge is refused. Authenticated
 * digest and row/retry counts are verified before releasing an image. The
 * public codec never contains root policy; local-root data is only accepted
 * by the private DURABLE-purpose seal/open codec. */
#endif

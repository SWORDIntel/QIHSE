# Repository Snapshots

APT repository state is represented as an immutable snapshot object so a
deployment can name the exact package closure it was assembled from.

## Record

```c
typedef struct {
    qihse_uuid_t snapshot_id;
    char repository[128];
    char snapshot_digest[129];      /* Release/InRelease digest */
    char release[64];               /* suite or channel */
    uint64_t package_count;
    char signing_key_handle[160];   /* a handle, never the key */
    uint64_t created_hlc_physical;
    qihse_uuid_t created_by;
} qihse_repo_snapshot_t;
```

## Immutability and query

`qihse_repo_snapshot_put()` refuses to overwrite an existing snapshot, and
`qihse_repo_snapshot_foreach()` lists snapshots optionally filtered by
repository. Snapshots are therefore immutable and queryable, which is
acceptance criterion 19.

## Deployment lineage

Root images reference the exact repository snapshot from which their package
closure was resolved, and node deployments reference exact root-image
generations. The provenance graph records these as `DERIVED_FROM` edges, which
produces the full chain:

```
node -> root image -> repository snapshot -> package -> artifact -> build -> source
```

and supports traversal in the reverse direction.

## High-value queries

The provenance graph answers:

- Which nodes contain artifact digest X?
- Which images include source revision Y?
- Which releases include outputs from builder Z?
- Which deployed systems depend on vulnerable component C?
- Which artifacts were built with toolchain digest T?
- Which images were assembled from repository snapshot R?

KEYSTONE may accelerate these queries but does not become authoritative for
them.

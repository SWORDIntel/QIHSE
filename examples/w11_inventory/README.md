# W11 inventory reservation example

From a repository checkout with the QIHSE build dependencies installed, run:

```sh
./examples/w11_inventory/run.sh
```

To reuse an already-built library during local development, set
`QIHSE_PREBUILT_LIB_DIR` to the directory containing `libqihse.so`; CI leaves
it unset and builds the checkout's library.

The program exercises the public in-process UWP SQL dispatcher. It creates
stock, orders, outbox-intent, and restricted-inventory tables; atomically
updates stock and inserts an order plus its outbox intent in one serializable
SQL transaction; then reads the committed rows back.

The example also creates a clearance-0 guest, grants READ on the ordinary
stock table, and confirms that the same principal is denied access to the
restricted table without receiving its marker. The current SQL row store has
table-level ACLs and in-memory transaction shadows; it does not carry
per-row classification metadata or provide restart durability. This example
demonstrates atomic in-process reservation behavior, not crash-safe inventory
accounting or external message delivery.

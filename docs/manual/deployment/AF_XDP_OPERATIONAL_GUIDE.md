# QIHSE AF_XDP (Kernel Bypass) Operational Guide

The QIHSE engine supports an extreme-performance networking mode utilizing Linux eBPF and AF_XDP. This enables zero-copy packet ingestion directly from the network interface card (NIC) into the database memory space, bypassing the entire Linux networking stack.

## Activation
AF_XDP is disabled by default and gracefully falls back to the standard, highly-optimized `io_uring` POSIX socket implementation. 

To activate AF_XDP, set the `QIHSE_XDP_IFACE` environment variable to your target network interface when starting the server:

```bash
export QIHSE_XDP_IFACE=eth0
./qihse_server
```

## Why AF_XDP Is Not Enabled By Default (The Trade-offs)

While AF_XDP provides unparalleled latency reductions and throughput increases, operators must consciously opt-in due to the severe architectural trade-offs that come with bypassing the Linux kernel.

### 1. Bypassing the Kernel means Bypassing its Security
When AF_XDP pulls packets straight into QIHSE user space, it ignores `iptables`, `nftables`, `UFW`, and SELinux network rules. Unless QIHSE implements its own exhaustive firewall logic, operators lose the robust defense-in-depth provided by the Linux network stack.

### 2. Loss of IPsec, WireGuard, and Routing
If operators rely on kernel-level VPNs (like WireGuard) or IPsec to encrypt data in transit before it hits the database, kernel-bypass breaks this. Raw encrypted Ethernet frames are handed directly to QIHSE rather than being decrypted by the Linux stack.

### 3. The "TCP State Machine" Problem
AF_XDP feeds raw Ethernet frames into user space. If QIHSE is communicating over TCP (like the PostgreSQL wire proxy), dropping the kernel stack means QIHSE must implement its own complete TCP state machine in user space to handle sliding windows, packet reordering, and retransmission. Without a heavy user-space TCP stack, pulling raw TCP packets will result in broken connections. AF_XDP is primarily designed for UDP or custom stateless protocols.

### 4. Privilege Requirements
Loading eBPF programs and binding AF_XDP sockets requires elevated privileges (`CAP_NET_ADMIN`, `CAP_BPF`, or `CAP_SYS_ADMIN`). In strictly confined Docker containers or Kubernetes clusters, security teams often refuse to grant these elevated privileges to application-level databases.

### 5. Hardware Queue Monopolization
Binding to a network interface's receive queue with AF_XDP often steals all traffic on that specific queue away from the rest of the operating system. If the database shares a network card with other critical services on the same machine, routing becomes highly complex.

## Recommendation

**Use AF_XDP when:** You are deploying QIHSE as a dedicated bare-metal appliance where extreme sub-microsecond latency is the singular priority, you fully control the network perimeter, and you are using lightweight, custom UDP-based protocols.

**Use Standard `io_uring` POSIX Sockets when:** You are deploying in a shared cloud environment, Docker container, or Kubernetes cluster, or you rely on Linux networking features like `iptables`, WireGuard, or robust TCP handling. Standard `io_uring` still delivers world-class performance without breaking OS assumptions.

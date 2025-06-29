#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define NFS_PORT 2049
#define CACHE_SIZE 1024
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

// RPC头结构
struct rpc_header {
    __u32 xid;
    __u32 msg_type; // 0=CALL, 1=REPLY
    __u32 rpc_version;
    __u32 program;
    __u32 version;
    __u32 procedure;
};

// 缓存键
struct nfs_cache_key {
    __u32 xid;
    __u32 client_ip;
    __u64 ino;
    __u64 offset;
};

// 缓存值
struct nfs_cache_value {
    __u64 timestamp;
    __u32 len;
    __u8 data[1024];
};

// LRU哈希映射定义
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CACHE_SIZE);
    __type(key, struct nfs_cache_key);
    __type(value, struct nfs_cache_value);
} nfs_cache SEC(".maps");

// 判断是否为读操作
static __always_inline int is_read_op(__u32 proc) {
    /
    return (proc == 1); // READ操作
}

// 判断是否为写操作
static __always_inline int is_write_op(__u32 proc) {

    return (proc == 2); // WRITE操作
}

// 快速回复函数
static __always_inline int reply_nfs(struct xdp_md *ctx, struct nfs_cache_value *cached) {

    return XDP_PASS;
}

SEC("xdp")
int xdp_nfs_handler(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // 只处理IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // 解析IP头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // 只处理TCP
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    // 解析TCP头
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    // 检查目标端口是否为NFS
    if (tcp->dest != bpf_htons(NFS_PORT)) return XDP_PASS;

    // 解析RPC头
    void *payload = (void *)tcp + (tcp->doff * 4);
    if (payload + sizeof(struct rpc_header) > data_end) return XDP_PASS;

    struct rpc_header *rpc = payload;
    
    // 只处理请求(CALL)
    if (rpc->msg_type != 0) return XDP_PASS;

    // 构建缓存键
    struct nfs_cache_key key = {
        .xid = rpc->xid,
        .client_ip = ip->saddr,
        .ino = 0,    /
        .offset = 0  
    };

    // 处理写请求：删除缓存
    if (is_write_op(rpc->procedure)) {
        bpf_map_delete_elem(&nfs_cache, &key);
        return XDP_PASS;
    }

    // 处理读请求：检查缓存
    if (is_read_op(rpc->procedure)) {
        struct nfs_cache_value *cached = bpf_map_lookup_elem(&nfs_cache, &key);
        if (cached) {
            return reply_nfs(ctx, cached);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

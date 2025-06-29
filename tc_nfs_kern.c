#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_CACHE_ENTRIES 1024
#define NFS_PORT 2049
#define MAX_DATA_LEN 1024

struct rpc_header {
    __u32 xid;
    __u32 type;
};

// 缓存键结构
struct nfs_cache_key {
    __u32 xid;
    __u32 client_ip;
    __u64 ino;
    __u64 offset;
};

// 缓存值结构
struct nfs_cache_value {
    __u64 timestamp;
    __u32 len;
    __u8 data[MAX_DATA_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CACHE_ENTRIES);
    __type(key, struct nfs_cache_key);
    __type(value, struct nfs_cache_value);
} nfs_cache SEC(".maps");

// 辅助函数：判断是否是 NFS 读请求
static __always_inline int is_read_op(struct rpc_header *rpc) {

    return 1;
}

SEC("tc")
int tc_nfs_out_handler(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

    if (tcp->dest != bpf_htons(NFS_PORT)) return TC_ACT_OK;

    // 计算 TCP payload 起始位置
    void *payload = (void *)tcp + tcp->doff * 4;
    if (payload + sizeof(struct rpc_header) > data_end) return TC_ACT_OK;

    struct rpc_header *rpc = payload;
    if (rpc->type != 1 || !is_read_op(rpc)) {
        return TC_ACT_OK;
    }

    struct nfs_cache_key key = {};
    key.xid = rpc->xid;
    key.client_ip = ip->saddr;
    key.ino = 0;     // 从 payload 中解析
    key.offset = 0;

    struct nfs_cache_value value = {};
    value.timestamp = bpf_ktime_get_ns();
    value.len = (__u32)((void *)data_end - payload);
    if (value.len > MAX_DATA_LEN) {
        value.len = MAX_DATA_LEN;
    }

    // 计算偏移并加载数据
    __u64 payload_offset = (void *)payload - data;
    if (bpf_skb_load_bytes(skb, payload_offset, value.data, value.len) < 0) {
        return TC_ACT_OK;
    }

    bpf_map_update_elem(&nfs_cache, &key, &value, BPF_ANY);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";


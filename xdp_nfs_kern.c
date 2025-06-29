#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/nfs.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>

#define htons __builtin_bswap16
#define ntohs __builtin_bswap16  

#define NFS_PORT 2049
#define MAX_CACHE_ENTRIES 1024
#define MAX_BLOCKED_IPS 256

struct rpc_header {
    __u32 xid;
    __u32 msg_type;
    __u32 rpc_version;
    __u32 prog;
    __u32 vers;
    __u32 proc;
    __u32 cred_flavor;
    __u32 cred_len;
    __u32 auth;
    __u32 verifier
    
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
    __u8 data[1024];
    __u32 len;
    __u64 timestamp;
};

// 安全配置
struct security_config {
    __u32 blocked_ips[MAX_BLOCKED_IPS];
    __u32 read_only_ips[MAX_BLOCKED_IPS];
    __u32 rate_limits[MAX_BLOCKED_IPS];  // 次数/秒
    __u64 last_access_time[MAX_BLOCKED_IPS]; // 上次访问时间戳（纳秒）
    __u32 ip_index_map[MAX_BLOCKED_IPS]; // 存储对应 IP
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CACHE_ENTRIES);
    __type(key, struct nfs_cache_key);
    __type(value, struct nfs_cache_value);
} nfs_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct security_config);
} security_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} monitor_data SEC(".maps");

SEC("xdp_nfs")
int xdp_nfs_handler(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest != htons(NFS_PORT))
        return XDP_PASS;

    int zero = 0;
    struct security_config *config = bpf_map_lookup_elem(&security_config, &zero);
    if (!config)
        return XDP_PASS;

    // IP 黑名单检测
    for (int i = 0; i < MAX_BLOCKED_IPS; i++) {
        if (config->blocked_ips[i] == ip->saddr) {
            bpf_printk("Blocked request from blacklisted IP: %x\n", ip->saddr);
            return XDP_DROP;
        }
    }

    // 速率限制检测
    for (int i = 0; i < MAX_BLOCKED_IPS; i++) {
        if (config->ip_index_map[i] == ip->saddr) {
            __u32 limit = config->rate_limits[i];
            if (limit > 0) {
                __u64 now = bpf_ktime_get_ns();
                __u64 last = config->last_access_time[i];
                if (now - last < 1000000000ULL / limit) {
                    bpf_printk("Rate limit exceeded for IP: %x\n", ip->saddr);
                    return XDP_DROP;
                }
                config->last_access_time[i] = now;
            }
        }
    }

    //  NFS 请求解析
    void *payload = (void *)(tcp + 1);
    if (payload + sizeof(struct rpc_header) > data_end)
        return XDP_PASS;

    struct rpc_header *rpc = payload;

    struct nfs_cache_key key = {
        .xid = rpc->xid,
        .client_ip = ip->saddr,
        .ino = 12345,   
        .offset = 0     
    };

    struct nfs_cache_value *cached = bpf_map_lookup_elem(&nfs_cache, &key);
    if (cached) {
        // 命中缓存
        bpf_printk("NFS cache hit for xid=%u\n", rpc->xid);

        // 把包头裁剪掉，预留空间构造响应
        if (bpf_xdp_adjust_head(ctx, 0 - (int)(sizeof(struct ethhdr) + sizeof(*ip) + sizeof(*tcp)))) {
            return XDP_ABORTED;
        }

        void *new_data = (void *)(long)ctx->data;
        void *new_end = (void *)(long)ctx->data_end;
        if (new_data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + cached->len > new_end) {
            return XDP_ABORTED;
        }

        // 构造简化响应包
        struct ethhdr *new_eth = new_data;
        struct iphdr *new_ip = (void *)(new_eth + 1);
        struct tcphdr *new_tcp = (void *)(new_ip + 1);
        __u8 *payload = (void *)(new_tcp + 1);

        // 复制缓存数据
        bpf_memcpy(payload, cached->data, cached->len);

        // 伪构造头部（不计算校验和）
        new_eth->h_proto = htons(ETH_P_IP);
        bpf_memcpy(new_eth->h_dest, eth->h_source, ETH_ALEN);
        bpf_memcpy(new_eth->h_source, eth->h_dest, ETH_ALEN);

        new_ip->version = 4;
        new_ip->ihl = 5;
        new_ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + cached->len);
        new_ip->protocol = IPPROTO_TCP;
        new_ip->saddr = ip->daddr;
        new_ip->daddr = ip->saddr;

        new_tcp->source = tcp->dest;
        new_tcp->dest = tcp->source;
        new_tcp->seq = tcp->ack_seq;
        new_tcp->ack_seq = tcp->seq + 1;
        new_tcp->doff = 5;
        new_tcp->ack = 1;
        new_tcp->psh = 1;

        // 返回构造包
        return XDP_TX;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";


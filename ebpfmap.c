#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/tcp.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";
__u32 VERSION SEC("version") = 1;

// TCP连接键定义：基于五元组
struct tcp_conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// TCP连接值：记录原始 seq/ack 的偏移值
struct tcp_seqack_val {
    __u32 seq_offset;
    __u32 ack_offset;
};

// Map 1: TCP 连接代理 map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tcp_conn_key);
    __type(value, struct tcp_seqack_val);
    __uint(max_entries, 1024);
    __uint(map_flags, 0);
} tcp_conn_map SEC(".maps");

// RPC连接键定义：XID + 五元组（用于唯一定位一个RPC请求）
struct rpc_xid_key {
    __u32 original_xid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// RPC连接值：新的XID
struct rpc_xid_val {
    __u32 mapped_xid;
};

// Map 2: RPC XID 映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rpc_xid_key);
    __type(value, struct rpc_xid_val);
    __uint(max_entries, 2048);
    __uint(map_flags, 0);
} rpc_xid_map SEC(".maps");

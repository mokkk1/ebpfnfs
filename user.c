#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// 和内核共享结构体
struct tcp_conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct tcp_seqack_val {
    __u32 seq_offset;
    __u32 ack_offset;
};

struct rpc_xid_key {
    __u32 original_xid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct rpc_xid_val {
    __u32 mapped_xid;
};

int main(int argc, char **argv) {
    struct bpf_object *obj;
    int tcp_map_fd, rpc_map_fd;

    // 加载 ebpfmap.o 文件
    obj = bpf_object__open_file("ebpfmap.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening BPF object file.\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error loading BPF object.\n");
        return 1;
    }

    // 查找 Map 句柄
    tcp_map_fd = bpf_object__find_map_fd_by_name(obj, "tcp_conn_map");
    if (tcp_map_fd < 0) {
        fprintf(stderr, "Cannot find tcp_conn_map\n");
        return 1;
    }

    rpc_map_fd = bpf_object__find_map_fd_by_name(obj, "rpc_xid_map");
    if (rpc_map_fd < 0) {
        fprintf(stderr, "Cannot find rpc_xid_map\n");
        return 1;
    }

    // 示例 TCP 映射写入
    struct tcp_conn_key tkey = {
        .src_ip = inet_addr("192.168.1.100"),
        .dst_ip = inet_addr("192.168.1.200"),
        .src_port = htons(12345),
        .dst_port = htons(2049)
    };
    struct tcp_seqack_val tval = {
        .seq_offset = 1000,
        .ack_offset = 2000
    };

    if (bpf_map_update_elem(tcp_map_fd, &tkey, &tval, BPF_ANY) != 0) {
        perror("bpf_map_update_elem (tcp)");
        return 1;
    }

    // 示例 RPC XID 映射写入
    struct rpc_xid_key xid_key = {
        .original_xid = 0xdeadbeef,
        .src_ip = inet_addr("192.168.1.100"),
        .dst_ip = inet_addr("192.168.1.200"),
        .src_port = htons(12345),
        .dst_port = htons(2049)
    };
    struct rpc_xid_val xid_val = {
        .mapped_xid = 0xbeefdead
    };

    if (bpf_map_update_elem(rpc_map_fd, &xid_key, &xid_val, BPF_ANY) != 0) {
        perror("bpf_map_update_elem (rpc)");
        return 1;
    }

    printf("TCP & RPC map entries added successfully.\n");

    bpf_object__close(obj);
    return 0;
}

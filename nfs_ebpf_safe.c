#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>

static struct bpf_object *xdp_obj = NULL;
static struct bpf_object *tc_obj = NULL;
static int xdp_prog_fd = -1;
static int tc_prog_fd = -1;
static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

static void cleanup() {
    if (xdp_obj) bpf_object__close(xdp_obj);
    if (tc_obj) bpf_object__close(tc_obj);
}

static int load_and_attach_xdp(const char *ifname) {
    struct bpf_program *prog;
    int ifindex;

    xdp_obj = bpf_object__open_file("xdp_nfs_kern.o", NULL);
    if (libbpf_get_error(xdp_obj)) {
        fprintf(stderr, "Error opening XDP BPF object file\n");
        return 1;
    }

    if (bpf_object__load(xdp_obj)) {
        fprintf(stderr, "Error loading XDP BPF object\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(xdp_obj, "xdp_nfs");
    if (!prog) {
        fprintf(stderr, "Can't find XDP program\n");
        return 1;
    }

    xdp_prog_fd = bpf_program__fd(prog);
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    if (bpf_set_link_xdp_fd(ifindex, xdp_prog_fd, xdp_flags) < 0) {
        fprintf(stderr, "Error attaching XDP program\n");
        return 1;
    }

    return 0;
}

static int load_and_attach_tc(const char *ifname) {
    struct bpf_program *prog;
    char tc_cmd[256];

    tc_obj = bpf_object__open_file("tc_nfs_kern.o", NULL);
    if (libbpf_get_error(tc_obj)) {
        fprintf(stderr, "Error opening TC BPF object file\n");
        return 1;
    }

    if (bpf_object__load(tc_obj)) {
        fprintf(stderr, "Error loading TC BPF object\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(tc_obj, "tc_nfs_out");
    if (!prog) {
        fprintf(stderr, "Can't find TC program\n");
        return 1;
    }

    tc_prog_fd = bpf_program__fd(prog);

    // 使用tc命令加载eBPF程序
    snprintf(tc_cmd, sizeof(tc_cmd),
             "tc qdisc add dev %s clsact", ifname);
    system(tc_cmd);

    snprintf(tc_cmd, sizeof(tc_cmd),
             "tc filter add dev %s egress bpf direct-action obj tc_nfs_kern.o sec tc_nfs_out",
             ifname);
    system(tc_cmd);

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    atexit(cleanup);

    if (load_and_attach_xdp(argv[1])) {
        fprintf(stderr, "Failed to load XDP program\n");
        return 1;
    }

    if (load_and_attach_tc(argv[1])) {
        fprintf(stderr, "Failed to load TC program\n");
        return 1;
    }

    printf("eBPF NFS加速器已启动，按Ctrl+C退出\n");

    // 在这里可以添加安全配置更新和监控数据读取逻辑
    while (1) {
        sleep(1);
    }

    return 0;
}

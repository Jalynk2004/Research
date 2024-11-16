# virtio-note - bi0sCTF 2024

OOB Read/Write in virtio driver

Communicate with virtio driver (because it is a hardware abstraction layer) using a kernel module

Using setcontext trick to create a ROP chain to open/read/write (try to find which fd can print out the flag for you, otherwise your ropchain should connect to a reverse shell and write out the flag in it)

Exploit can be found at [Exploit](./exp.c)
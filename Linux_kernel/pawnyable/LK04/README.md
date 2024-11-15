# LK04 - Race condition with userfaultfd

This is my baby step to Linux kernel exploit

## Bug: Race condition
- One thread is reading a block of data, and another thread is trying to free, then allocate some specific data (tty struct as an example). Leverage to leak kernel base and heap (arbitrary read)
- One thread is editing a block of data, and another is trying to allocate some tty struct. Heap spray to overwrite tty->ops with our desired value (arbitrary write)

**Final exploit**: [Here](./exp.c)
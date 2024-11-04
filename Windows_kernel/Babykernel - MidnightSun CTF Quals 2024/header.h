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
#define MAXIMUM_FILENAME_LENGTH 255 

struct NamedPipe{
    HANDLE read;
    HANDLE write;
};

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

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

typedef struct SYSTEM_HANDLE
{
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION_, * PSYSTEM_HANDLE_INFORMATION_;

typedef struct SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct IRP {
    SHORT Type;
    USHORT Size;
    PVOID MdlAddress;
    ULONG Flags;
    PVOID AssociatedIrp;
    LIST_ENTRY ThreadListEntry;
    IO_STATUS_BLOCK IoStatus;
    CHAR RequestorMode;
    BOOLEAN PendingReturned;
    CHAR StackCount;
    CHAR CurrentLocation;
    BOOLEAN Cancel;
    UCHAR CancelIrql;
    CCHAR ApcEnvironment;
    UCHAR AllocationFlags;
    PVOID UserIosb;
    PVOID UserEvent;
    char Overlay[16];
    PVOID CancelRoutine;
    PVOID UserBuffer;
    CHAR TailIsWrong;
} IRP;

typedef struct DATA_QUEUE_ENTRY {
    uint64_t Flink;
    uint64_t Blink;
    IRP* Irp;
    uint64_t SecurityContext;
    uint32_t EntryType;
    uint32_t QuotaInEntry;
    uint32_t DataSize;
    uint32_t x;
} DATA_QUEUE_ENTRY;
#pragma once
#include <ntddk.h>

#include "..\Common.h"
#include "..\Utils\LDasm.h"
#include <limits.h>
#include "..\Intel\VMX.h"

typedef struct _HOOK_CONTEXT
{
	BOOLEAN Hook;           // TRUE to hook page, FALSE to unhook
	ULONG64 DataPagePFN;    // Physical data page PFN
	ULONG64 CodePagePFN;    // Physical code page PFN
} HOOK_CONTEXT, *PHOOK_CONTEXT;
#pragma pack(push, 1)
typedef struct _JUMP_THUNK
{
	UCHAR PushOp;           // 0x68
	ULONG AddressLow;       // 
	ULONG MovOp;            // 0x042444C7
	ULONG AddressHigh;      // 
	UCHAR RetOp;            // 0xC3
} JUMP_THUNK, *PJUMP_THUNK;
#pragma pack(pop)
typedef enum _PAGE_TYPE
{
	DATA_PAGE = 0,
	CODE_PAGE = 1,
} PAGE_TYPE;
typedef struct _PAGE_HOOK_ENTRY
{
	LIST_ENTRY Link;
	PVOID OriginalPtr;      // Original function VA	原始函数的VA
	PVOID DataPageVA;       // Data page VA
	ULONG64 DataPagePFN;    // Data page PFN
	PVOID CodePageVA;       // Executable page VA	可执行页面的VA
	ULONG64 CodePagePFN;    // Executable page PFN
	ULONG OriginalSize;     // Size of original data
	UCHAR OriginalData[80]; // Original bytes + jump
} PAGE_HOOK_ENTRY, *PPAGE_HOOK_ENTRY;

PPAGE_HOOK_ENTRY PHGetHookEntry(IN PVOID ptr);

NTSTATUS PHHook(IN PVOID pFunc, IN PVOID pHook);

VOID PHpInitJumpThunk(IN OUT PJUMP_THUNK pThunk, IN ULONG64 To);

NTSTATUS PHpCopyCode(IN PVOID pFunc, OUT PUCHAR OriginalStore, OUT PULONG pSize);

VOID PHpHookCallbackDPC(IN PRKDPC Dpc, IN PVOID Context, IN PVOID SystemArgument1, IN PVOID SystemArgument2);

NTSTATUS PHRestore(IN PVOID pFunc);

ULONG PHPageHookCount(IN PVOID ptr, IN PAGE_TYPE Type);

PPAGE_HOOK_ENTRY PHGetHookEntryByPage(IN PVOID ptr, IN PAGE_TYPE Type);

/// <summary>
/// Get hook data by Physical page frame number
/// </summary>
/// <param name="pfn">PFN</param>
/// <param name="Type">Page type</param>
/// <returns>Found hook entry or NULL</returns>
PPAGE_HOOK_ENTRY PHGetHookEntryByPFN(IN ULONG64 pfn, IN PAGE_TYPE Type);
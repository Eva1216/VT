#pragma once
#include <ntddk.h>
#include "..\Common.h"
#include "..\Include\Native.h"
#include "..\Include\CPU.h"
#include "..\Include\PE.h"
CPU_VENDOR UtilCPUVendor();

NTSTATUS UtilScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID * ppFound);

NTSTATUS UtilQueryPhysicalMemory();

NTSTATUS UtilProtectNonpagedMemory(IN PVOID ptr, IN ULONG64 size, IN ULONG protection);

PVOID UtilSSDTEntry(IN ULONG index );

PSYSTEM_SERVICE_DESCRIPTOR_TABLE UtilSSDTBase();

PVOID UtilKernelBase(OUT PULONG pSize);

NTSTATUS UtilSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID * base, IN ULONG_PTR size, OUT PVOID * ppFound);

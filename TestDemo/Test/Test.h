#pragma once
#include <ntddk.h>
#include "..\Hook\PageHook.h"
#include "..\Common.h"
NTSTATUS hkNtClose(HANDLE handle);
NTSTATUS hkNtClose2(HANDLE handle);
ULONG64 TestFn(ULONG64 in1, ULONG64 in2);
ULONG64 hkTestFn(ULONG64 in1, ULONG64 in2);
VOID TestPageHook();
VOID TestPrintResults();

VOID TestStart(IN BOOLEAN SyscallHook, IN BOOLEAN PageHook1, IN IN BOOLEAN PageHook2);

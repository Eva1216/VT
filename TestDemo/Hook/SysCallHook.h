#include <ntddk.h>
#include "..\Common.h"
#include "..\Utils\Utils.h"
#include "..\Intel\VMX.h"

NTSTATUS SHInitHook();

VOID SHpHookCallbackDPC(PRKDPC Dpc, PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2);

NTSTATUS SHHookSyscall(IN ULONG index, IN PVOID hookPtr, IN CHAR argCount);

VOID InitData();

#pragma once 
#include <ntddk.h>

PVOID HookKernelApi(IN PVOID ApiAddress, IN PVOID Proxy_ApiAddress, OUT PVOID * Original_ApiAddress, OUT ULONG * PatchSize);



 

ULONG GetPatchSize2(PUCHAR Address);

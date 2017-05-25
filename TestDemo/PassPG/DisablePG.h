#pragma once 
#include <ntddk.h>

VOID InitDisablePatchGuard();

NTSTATUS DisablePatchProtection();

VOID DisablePatchProtectionSystemThreadRoutine(IN PVOID Nothing);

VOID UnLoadDisablePatchGuard();



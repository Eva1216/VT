#pragma once

#include <ntddk.h>
#include "../Common.h"
BOOLEAN HvmIsHVSupported();

VOID HvmCheckFeatures();

NTSTATUS StartHV();

VOID HvmpHVCallbackDPC(PRKDPC Dpc, PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2);

VOID IntelSubvertCPU(IN PVCPU Vcpu, IN PVOID SystemDirectoryTableBase);

NTSTATUS StopHV();

VOID AMDSubvertCPU(IN PVCPU Vcpu, IN PVOID arg);

VOID IntelRestoreCPU(IN PVCPU Vcpu);

VOID AMDRestoreCPU(IN PVCPU Vcpu);

#pragma once

VOID VmExitEvent(IN PGUEST_STATE GuestState);

VOID VmExitUnknown(IN PGUEST_STATE GuestState);

VOID VmExitTripleFault(IN PGUEST_STATE GuestState);

VOID VmExitCPUID(IN PGUEST_STATE GuestState);

void CmClearBit32(ULONG * dword, ULONG bit);

VOID VmxpAdvanceEIP(IN PGUEST_STATE GuestState);

VOID VmExitINVD(IN PGUEST_STATE GuestState);

VOID VmExitRdtsc(IN PGUEST_STATE GuestState);

VOID VmExitVmCall(IN PGUEST_STATE GuestState);

VOID VmExitVMOP(IN PGUEST_STATE GuestState);

VOID VmExitCR(IN PGUEST_STATE GuestState);

VOID VmExitMSRRead(IN PGUEST_STATE GuestState);

VOID VmExitMSRWrite(IN PGUEST_STATE GuestState);

VOID VmExitStartFailed(IN PGUEST_STATE GuestState);

VOID VmExitMTF(IN PGUEST_STATE GuestState);

VOID VmExitRdtscp(IN PGUEST_STATE GuestState);

VOID VmExitXSETBV(IN PGUEST_STATE GuestState);

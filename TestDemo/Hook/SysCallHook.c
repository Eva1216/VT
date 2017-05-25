#include "SysCallHook.h"


#define MAX_SYSCALL_INDEX  0x1000

CHAR HookEnabled[MAX_SYSCALL_INDEX] = { 0 };
CHAR ArgTble[MAX_SYSCALL_INDEX] = { 0 };
PVOID HookTable[MAX_SYSCALL_INDEX] = { 0 };


ULONG64 KiServiceCopyEndPtr = 0;    // KiSystemServiceCopyEnd address
ULONG64 KiSystemCall64Ptr = 0;    // Original LSTAR value



ULONG64 GuestSyscallHandler;
ULONG64 NtSyscallHandler32;
ULONG64 NtKernelsyscallBase;
ULONG64 NtSyscallHandler;

ULONG64 KiUmsCallEntry;
ULONG64 KiSaveDebugRegisterState;
ULONG64 KeServiceDescriptorTable;
ULONG64 KeServiceDescriptorTableShadow;
ULONG64 KiSystemServiceExit;
ULONG64 KeGdiFlushUserBatch;
ULONG64 KiSystemServiceRepeat;
ULONG64 KiSystemServiceCopyEnd;
//»ã±à
VOID SyscallEntryPoint();

/// <summary>
/// Per-CPU LSTAR hook/unhook routine
/// </summary>
/// <param name="Dpc">Unused</param>
/// <param name="Context">New LASTAR value if hooking, 0 if unhooking</param>
/// <param name="SystemArgument1">Unused</param>
/// <param name="SystemArgument2">Unused</param>
VOID SHpHookCallbackDPC(PRKDPC Dpc, PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(Dpc);

	__vmx_vmcall(Context != NULL ? HYPERCALL_HOOK_LSTAR : HYPERCALL_UNHOOK_LSTAR, (ULONG64)Context, 0, 0);
	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}
/// <summary>
/// Perform LSTAR hooking
/// </summary>
/// <returns>Status code</returns>
NTSTATUS SHInitHook()
{
	NTSTATUS status = STATUS_SUCCESS;

	// No SSDT
	if (!UtilSSDTBase())
	{
		DPRINT("HyperBone: CPU %d: %s: SSDT base not found\n", CPU_IDX, __FUNCTION__);
		return STATUS_NOT_FOUND;
	}

	// KiSystemServiceCopyEnd
	// F7 05 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? 0F 85 ? ? ? ? ? ? ? ? 41 FF D2
	if (KiServiceCopyEndPtr == 0)
	{
		CHAR pattern[] = "\xF7\x05\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x0F\x85\xcc\xcc\xcc\xcc\x41\xFF\xD2";
		status = UtilScanSection(".text", (PCUCHAR)pattern, 0xCC, sizeof(pattern) - 1, (PVOID)&KiServiceCopyEndPtr);
		if (!NT_SUCCESS(status))
		{
			DPRINT("HyperBone: CPU %d: %s: KiSystemServiceCopyEnd not found\n", CPU_IDX, __FUNCTION__);
			return status;
		}
	}
	//haha1
	// Hook LSTAR
	if (KiSystemCall64Ptr == 0)
	{
		KiSystemCall64Ptr = __readmsr(MSR_LSTAR);

		// Something isn't right
		if (KiSystemCall64Ptr == 0)
			return STATUS_UNSUCCESSFUL;

		KeGenericCallDpc(SHpHookCallbackDPC, SyscallEntryPoint);
		return STATUS_SUCCESS;
	}

	return STATUS_SUCCESS;
}




/// <summary>
/// Hook specific SSDT entry
/// </summary>
/// <param name="index">SSDT index</param>
/// <param name="hookPtr">Hook address</param>
/// <param name="argCount">Number of function arguments</param>
/// <returns>Status code</returns>
NTSTATUS SHHookSyscall(IN ULONG index, IN PVOID hookPtr, IN CHAR argCount)
{
	NTSTATUS status = STATUS_SUCCESS;
	if (index > MAX_SYSCALL_INDEX || hookPtr == NULL)
		return STATUS_INVALID_PARAMETER;

	KIRQL irql = KeGetCurrentIrql();
	if (irql < DISPATCH_LEVEL)
		irql = KeRaiseIrqlToDpcLevel();

	InterlockedExchange64((PLONG64)&HookTable[index], (LONG64)hookPtr);
	InterlockedExchange8(&ArgTble[index], argCount);
	InterlockedExchange8(&HookEnabled[index], TRUE);

	if (KeGetCurrentIrql() > irql)
		KeLowerIrql(irql);

	return status;
}

VOID InitData() {


	NtKernelsyscallBase = (ULONG64)__readmsr(MSR_LSTAR);//kisystemcall64 entry point

	NtSyscallHandler = (ULONG64)__readmsr(MSR_LSTAR);

	NtSyscallHandler32 = (ULONG64)__readmsr(MSR_CSTAR);

	GuestSyscallHandler = (ULONG64)&SyscallEntryPoint;

	//	proxyNtQueryWindow = ssdt_GetSSDTShaDowFuncX64(16);

}
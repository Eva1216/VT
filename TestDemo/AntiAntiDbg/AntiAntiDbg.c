#include "AntiAntiDbg.h"
#include "..\KernelStruct\KernelStruct.h"
#include "..\DbgTool\DbgTool.h"
#include "..\Common.h"
#include "..\R3R0\GlobalData.h"
#include "..\ResetDbg\Dbg.h"
#include "..\ProtectWindow\ProtectWindow.h"
#include "..\Hook\HookFunction\HookFunction.h"

typedef NTSTATUS(__fastcall* pfKiAttachProcess)(
	IN PKTHREAD Thread,
	IN PKPROCESS Process,
	IN PKLOCK_QUEUE_HANDLE ApcLock,
	IN PRKAPC_STATE SavedApcState);
typedef (__fastcall *pfnNtReadVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN ULONG BufferLength,
	OUT PULONG ReturnLength OPTIONAL
	);
typedef (__fastcall *pfnNtWriteVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN ULONG BufferLength,
	OUT PULONG ReturnLength OPTIONAL
	);
ULONG pslp_patch_size9 = 0;		//ObpCallPreOperationCallbacks被修改了N字节
PUCHAR pslp_head_n_byte9 = NULL;	//ObpCallPreOperationCallbacks的前N字节数组
PVOID ori_pslp9 = NULL;			//ObpCallPreOperationCallbacks的原函数

ULONG pslp_patch_size10 = 0;		//ExGetCallBackBlockRoutine被修改了N字节
PUCHAR pslp_head_n_byte10 = NULL;	//ExGetCallBackBlockRoutine的前N字节数组
PVOID ori_pslp10 = NULL;			//ExGetCallBackBlockRoutine的原函数

ULONG pslp_patch_size19 = 0;		//NtQueryInformationThread被修改了N字节
PUCHAR pslp_head_n_byte19 = NULL;	//NtQueryInformationThread的前N字节数组
PVOID ori_pslp19 = NULL;			//NtQueryInformationThread的原函数


ULONG pslp_patch_size20 = 0;		//ExCompareExchangeCallBack被修改了N字节
PUCHAR pslp_head_n_byte20 = NULL;	//ExCompareExchangeCallBack的前N字节数组
PVOID ori_pslp20 = NULL;			//ExCompareExchangeCallBack的原函数


ULONG pslp_patch_size21 = 0;		//proxyPsLookupThreadByThreadId被修改了N字节
PUCHAR pslp_head_n_byte21 = NULL;	//proxyPsLookupThreadByThreadId的前N字节数组
PVOID ori_pslp21 = NULL;			//proxyPsLookupThreadByThreadId的原函数


ULONG pslp_patch_size22 = 0;		//proxyPsLookupProcessByProcessId被修改了N字节
PUCHAR pslp_head_n_byte22 = NULL;	//proxyPsLookupProcessByProcessId的前N字节数组
PVOID ori_pslp22 = NULL;			//proxyPsLookupProcessByProcessId的原函数


ULONG pslp_patch_size23 = 0;		//KiRestoreDebugRegisterState被修改了N字节
PUCHAR pslp_head_n_byte23 = NULL;	//KiRestoreDebugRegisterState的前N字节数组
PVOID ori_pslp23 = NULL;			//KiRestoreDebugRegisterState的原函数


ULONG pslp_patch_size24 = 0;		//KiSaveDebugRegisterState被修改了N字节
PUCHAR pslp_head_n_byte24 = NULL;	//KiSaveDebugRegisterState的前N字节数组
PVOID ori_pslp24 = NULL;			//KiSaveDebugRegisterState的原函数


ULONG pslp_patch_size25 = 0;		//RtlpCopyLegacyContextX86被修改了N字节
PUCHAR pslp_head_n_byte25 = NULL;	//RtlpCopyLegacyContextX86的前N字节数组
PVOID ori_pslp25 = NULL;			//RtlpCopyLegacyContextX86的原函数

ULONG pslp_patch_size26 = 0;		//pfKiAttachProcess被修改了N字节
PUCHAR pslp_head_n_byte26 = NULL;	//pfKiAttachProcess的前N字节数组
pfKiAttachProcess ori_pslp26 = NULL;			//pfKiAttachProcess的原函数

ULONG pslp_patch_size27 = 0;		//ReadProcessMemory被修改了N字节
PUCHAR pslp_head_n_byte27 = NULL;	//ReadProcessMemory的前N字节数组
pfnNtReadVirtualMemory ori_pslp27 = NULL;			//ReadProcessMemory的原函数

ULONG pslp_patch_size28 = 0;		//WriteProcessMemory被修改了N字节
PUCHAR pslp_head_n_byte28 = NULL;	//WriteProcessMemory的前N字节数组
pfnNtWriteVirtualMemory ori_pslp28 = NULL;			//WriteProcessMemory的原函数
ULONG64 ExGetCallBackBlockRoutine;
ULONG64 ObpCallPreOperationCallbacks;
ULONG64 NtQueryInformationThread;
ULONG64 ExCompareExchangeCallBack;
ULONG64 RtlpCopyLegacyContextX86 = NULL;
ULONG64 KiAttachProcess;
ULONG64 KiRestoreDebugRegisterState;
PVOID obHandle = NULL, obHandle2 = NULL;
NTKERNELAPI PEPROCESS IoThreadToProcess(IN PETHREAD Thread);

extern p_save_handlentry PmainList;
NTSTATUS ObProtectProcess(BOOLEAN Enable)
{
	if (Enable == TRUE)
	{
		NTSTATUS obst1 = 0, obst2 = 0;
		OB_CALLBACK_REGISTRATION obReg, obReg2;
		OB_OPERATION_REGISTRATION opReg, opReg2;
		//reg ob callback 1
		memset(&obReg, 0, sizeof(obReg));
		obReg.Version = ObGetFilterVersion();
		obReg.OperationRegistrationCount = 1;
		obReg.RegistrationContext = NULL;
		RtlInitUnicodeString(&obReg.Altitude, L"321124xz");
		obReg.OperationRegistration = &opReg;
		memset(&opReg, 0, sizeof(opReg));
		opReg.ObjectType = PsProcessType;
		opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preCall;
		obst1 = ObRegisterCallbacks(&obReg, &obHandle);
		//reg ob callback 2
		memset(&obReg2, 0, sizeof(obReg2));
		obReg2.Version = ObGetFilterVersion();
		obReg2.OperationRegistrationCount = 1;
		obReg2.RegistrationContext = NULL;
		RtlInitUnicodeString(&obReg2.Altitude, L"321125xz");
		obReg2.OperationRegistration = &opReg2;
		memset(&opReg2, 0, sizeof(opReg2));
		opReg2.ObjectType = PsThreadType;
		opReg2.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		opReg2.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preCall2;
		obst1 = ObRegisterCallbacks(&obReg2, &obHandle2);
		return NT_SUCCESS(obst1) & NT_SUCCESS(obst2);
	}
	else
	{
		if (obHandle != NULL)
			ObUnRegisterCallbacks(obHandle);
		if (obHandle2 != NULL)
			ObUnRegisterCallbacks(obHandle2);
		return TRUE;
	}
}


OB_PREOP_CALLBACK_STATUS preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
#define PROCESS_TERMINATE 0x1

	HANDLE pid;
	if (pOperationInformation->ObjectType != *PsProcessType)
		goto exit_sub;
	pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
	//DbgPrint("[OBCALLBACK][Process]PID=%ld\n", pid);
	UNREFERENCED_PARAMETER(RegistrationContext);
	if (IsProtectedProcess((PEPROCESS)pOperationInformation->Object))
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			//pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess=0;
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_LIMITED_INFORMATION;

			}
		}
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		{
			//pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess=0;
			if ((pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			{
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_LIMITED_INFORMATION;
			}
		}
	}
exit_sub:
	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS preCall2(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
#define THREAD_TERMINATE2 0x1
	PEPROCESS ep;
	PETHREAD et;
	HANDLE pid;
	if (pOperationInformation->ObjectType != *PsThreadType)
		goto exit_sub;
	et = (PETHREAD)pOperationInformation->Object;
	ep = IoThreadToProcess(et);
	pid = PsGetProcessId(ep);
	//DbgPrint("[OBCALLBACK][Thread]PID=%ld; TID=%ld\n", pid, PsGetThreadId(et));
	UNREFERENCED_PARAMETER(RegistrationContext);
	if (IsProtectedProcess(ep))
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			//pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess=0;
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & THREAD_TERMINATE2) == THREAD_TERMINATE2)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE2;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SET_CONTEXT;
			}
		}
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		{
			//pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess=0;
			if ((pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & THREAD_TERMINATE2) == THREAD_TERMINATE2)
			{
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE2;
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_SET_CONTEXT;
			}
		}
	}
exit_sub:
	return OB_PREOP_SUCCESS;
}


BOOLEAN IsProtectedProcess(PEPROCESS eprocess)
{
	UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
	p_save_handlentry Padd = NULL;
	Padd = QueryList(PmainList, NULL, eprocess);

	/*
	char *processName = PsGetProcessImageFileName(PsGetCurrentProcess());
	char *processName2 = PsGetProcessImageFileName(eprocess);*/
	/*if (strstr(processName, "BlackCipher") != NULL && strstr(processName2, "cstrike-on") != NULL)///NGS Cant Read and Write Process MEmory!
	{

	return TRUE;
	}*/
	if (Padd != NULL) {
		if (eprocess == PsGetCurrentProcess())
		{
			return FALSE;

		}
		else
		{
			return TRUE;
		}

	}
	return FALSE;
}

VOID RemoveListEntry(PLIST_ENTRY ListEntry)
{
	KIRQL OldIrql;
	OldIrql = KeRaiseIrqlToDpcLevel();
	if (ListEntry->Flink != ListEntry &&
		ListEntry->Blink != ListEntry &&
		ListEntry->Blink->Flink == ListEntry &&
		ListEntry->Flink->Blink == ListEntry)
	{
		ListEntry->Flink->Blink = ListEntry->Blink;
		ListEntry->Blink->Flink = ListEntry->Flink;
		ListEntry->Flink = ListEntry;
		ListEntry->Blink = ListEntry;
	}
	KeLowerIrql(OldIrql);
}


VOID unload() {

	UnhookKernelApi(ObpCallPreOperationCallbacks, pslp_head_n_byte9, pslp_patch_size9);
	UnhookKernelApi(NtQueryInformationThread, pslp_head_n_byte19, pslp_patch_size19);
	UnhookKernelApi(RtlpCopyLegacyContextX86, pslp_head_n_byte25, pslp_patch_size25);
	//	UnhookKernelApi(KiAttachProcess, pslp_head_n_byte26, pslp_patch_size26);
	UnhookKernelApi(fc_DbgkGetAdrress("PsLookupProcessByProcessId"), pslp_head_n_byte22, pslp_patch_size22);
	UnhookKernelApi(NtReadVirtualMemory, pslp_head_n_byte27, pslp_patch_size27);
	UnhookKernelApi(NtWriteVirtualMemory, pslp_head_n_byte28, pslp_patch_size28);
	/*
	/*

	/*
	UnhookKernelApi(KiSaveDebugRegisterState, pslp_head_n_byte24, pslp_patch_size24);
	UnhookKernelApi(KiRestoreDebugRegisterState, pslp_head_n_byte23, pslp_patch_size23);*/
	/*
	UnhookKernelApi(ExCompareExchangeCallBack, pslp_head_n_byte20, pslp_patch_size20);
	*/

	/*
	UnhookKernelApi(fc_DbgkGetAdrress(L"PsLookupThreadByThreadId"), pslp_head_n_byte21, pslp_patch_size21);
	*/

	//	UnhookKernelApi(ExGetCallBackBlockRoutine, pslp_head_n_byte10, pslp_patch_size10);

	/*	UnhookKernelApi(NtQueryInformationThread, pslp_head_n_byte19, pslp_patch_size19);*/
	/*UnHookKernelApi4_6bit(ExGetCallBackBlockRoutine, &orgcode);

	*/



}

//传入：被HOOK函数地址，原始数据，补丁长度
VOID UnhookKernelApi(IN PVOID ApiAddress, IN PVOID OriCode, IN ULONG PatchSize)
{
	KIRQL irql;
	irql = WPOFFx64();
	memcpy(ApiAddress, OriCode, PatchSize);
	WPONx64(irql);
}

 
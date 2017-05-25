#include "SSDTHook.h"
#include "..\R3R0\GlobalData.h"
#include "..\ResetDbg\ResetDbg.h"
#include "HookFunction\HookFunction.h"
#include "..\AntiAntiDbg\AntiAntiDbg.h"
ULONG64 NtDebugContinue;
ULONG64 myNtRemoveProcessDebug;
ULONG64 NtDebugActiveProcess;
ULONG64 NtWaitForDebugEvent;
ULONG64 NtCreateDebugObject;


ULONG pslp_patch_size40 = 0;		//proxyNtCreateDebugObject被修改了N字节
PUCHAR pslp_head_n_byte40 = NULL;	//proxyNtCreateDebugObject的前N字节数组
PVOID ori_pslp40 = NULL;			//proxyNtCreateDebugObject的原函数
ULONG64 NtCreateDebugObject;


ULONG pslp_patch_size41 = 0;		//proxyNtWaitForDebugEvent被修改了N字节
PUCHAR pslp_head_n_byte41 = NULL;	//proxyNtWaitForDebugEvent的前N字节数组
PVOID ori_pslp41 = NULL;			//proxyNtWaitForDebugEvent的原函数
ULONG64 NtWaitForDebugEvent;


ULONG pslp_patch_size42 = 0;		//proxyNtDebugContinue被修改了N字节
PUCHAR pslp_head_n_byte42 = NULL;	//proxyNtDebugContinue的前N字节数组
PVOID ori_pslp42 = NULL;			//proxyNtDebugContinue的原函数
ULONG64 NtDebugContinue;

ULONG pslp_patch_size43 = 0;		//proxyNtDebugActiveProcess被修改了N字节
PUCHAR pslp_head_n_byte43 = NULL;	//proxyNtDebugActiveProcess的前N字节数组
PVOID ori_pslp43 = NULL;			//proxyNtDebugActiveProcess的原函数
ULONG64 NtDebugActiveProcess;

ULONG pslp_patch_size44 = 0;		//myNtRemoveProcessDebug被修改了N字节
PUCHAR pslp_head_n_byte44 = NULL;	//myNtRemoveProcessDebug的前N字节数组
PVOID ori_pslp44 = NULL;			//myNtRemoveProcessDebug的原函数



VOID InitIalzeSsdtInlineHook() {

	pslp_head_n_byte40 = HookKernelApi(NtCreateDebugObject,
		(PVOID)proxyNtCreateDebugObject,
		&ori_pslp40,
		&pslp_patch_size40);

	pslp_head_n_byte41 = HookKernelApi(NtWaitForDebugEvent,
		(PVOID)proxyNtWaitForDebugEvent,
		&ori_pslp41,
		&pslp_patch_size41);

	pslp_head_n_byte42 = HookKernelApi(NtDebugContinue,
		(PVOID)proxyNtDebugContinue,
		&ori_pslp42,
		&pslp_patch_size42);

	pslp_head_n_byte43 = HookKernelApi(NtDebugActiveProcess,
		(PVOID)proxyNtDebugActiveProcess,
		&ori_pslp43,
		&pslp_patch_size43);

	pslp_head_n_byte44 = HookKernelApi(myNtRemoveProcessDebug,
		(PVOID)NtRemoveProcessDebug,
		&ori_pslp44,
		&pslp_patch_size44);

}

VOID UnLoadSSDTInlineHook() {

	UnhookKernelApi(NtCreateDebugObject, pslp_head_n_byte40, pslp_patch_size40);
	UnhookKernelApi(NtWaitForDebugEvent, pslp_head_n_byte41, pslp_patch_size41);
	UnhookKernelApi(NtDebugContinue, pslp_head_n_byte42, pslp_patch_size42);
	UnhookKernelApi(NtDebugActiveProcess, pslp_head_n_byte43, pslp_patch_size43);
	UnhookKernelApi(myNtRemoveProcessDebug, pslp_head_n_byte44, pslp_patch_size44);

}
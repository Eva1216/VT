#include "MiNiHook.h"
#include "..\ResetDbg\ResetDbg.h"
#include "..\R3R0\GlobalData.h"
#include "..\Hook\HookFunction\HookFunction.h"
#include "..\AntiAntiDbg\AntiAntiDbg.h"
#include "..\KernelStruct\KernelStruct.h"
LONG64 DbgkCopyProcessDebugPort;
ULONG64 KiDispatchException;
ULONG64 DbgkForwardException;
ULONG64 DbgkOpenProcessDebugPort;
ULONG64 DbgkUnMapViewOfSection;
ULONG64 DbgkMapViewOfSection;
ULONG64 DbgkExitProcess;
ULONG64 DbgkExitThread;
ULONG pslp_patch_size2 = 0;		//DbgkCopyProcessDebugPort被修改了N字节
PUCHAR pslp_head_n_byte2 = NULL;	//DbgkCopyProcessDebugPort的前N字节数组
PVOID ori_pslp2 = NULL;			//DbgkCopyProcessDebugPort的原函数

ULONG pslp_patch_size3 = 0;		//DbgkForwardException被修改了N字节
PUCHAR pslp_head_n_byte3 = NULL;	//DbgkForwardException的前N字节数组
PVOID ori_pslp3 = NULL;			//DbgkForwardException的原函数

ULONG pslp_patch_size4 = 0;		//DbgkOpenProcessDebugPort被修改了N字节
PUCHAR pslp_head_n_byte4 = NULL;	//DbgkOpenProcessDebugPort的前N字节数组
PVOID ori_pslp4 = NULL;			//DbgkOpenProcessDebugPort的原函数

ULONG pslp_patch_size5 = 0;		//DbgkUnMapViewOfSection被修改了N字节
PUCHAR pslp_head_n_byte5 = NULL;	//DbgkUnMapViewOfSection的前N字节数组
PVOID ori_pslp5 = NULL;			//DbgkUnMapViewOfSection的原函数

ULONG pslp_patch_size6 = 0;		//DbgkMapViewOfSection被修改了N字节
PUCHAR pslp_head_n_byte6 = NULL;	//DbgkMapViewOfSection的前N字节数组
PVOID ori_pslp6 = NULL;			//DbgkMapViewOfSection的原函数


ULONG pslp_patch_size7 = 0;		//DbgkExitThread被修改了N字节
PUCHAR pslp_head_n_byte7 = NULL;	//DbgkExitThread的前N字节数组
PVOID ori_pslp7 = NULL;			//DbgkExitThread的原函数

ULONG pslp_patch_size8 = 0;		//DbgkExitProcess被修改了N字节
PUCHAR pslp_head_n_byte8 = NULL;	//DbgkExitProcess的前N字节数组
PVOID ori_pslp8 = NULL;			//DbgkExitProcess的原函数

ULONG pslp_patch_size11 = 0;		//DbgkExitProcess被修改了N字节
PUCHAR pslp_head_n_byte11 = NULL;	//DbgkExitProcess的前N字节数组
PVOID ori_pslp11 = NULL;			//DbgkExitProcess的原函数

ULONG pslp_patch_size12 = 0;		//DbgkpSetProcessDebugObject_2被修改了N字节
PUCHAR pslp_head_n_byte12 = NULL;	//DbgkpSetProcessDebugObject_2的前N字节数组
PVOID ori_pslp12 = NULL;			//DbgkpSetProcessDebugObject_2的原函数



NTSTATUS __fastcall	DbgkpQueueMessage_2(
	IN PEPROCESS_S Process,
	IN PETHREAD Thread,
	IN OUT PDBGKM_MSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject
);
VOID	__fastcall	proxyDbgkCopyProcessDebugPort(IN PEPROCESS Process,IN PEPROCESS Parent);
NTSTATUS	__fastcall	proxyDbgkOpenProcessDebugPort(IN PEPROCESS Process,IN KPROCESSOR_MODE PreviousMode,OUT HANDLE *DebugHandle);
VOID InstallMiniHOOK() {
	KIRQL irq;


	pslp_head_n_byte3 = HookKernelApi(DbgkForwardException,
		(PVOID)proxyDbgkForwardException,
		&ori_pslp3,
		&pslp_patch_size3);

	/*pslp_head_n_byte12 = HookKernelApi(DbgkpSetProcessDebugObject,
	(PVOID)DbgkpSetProcessDebugObject_2,
	&ori_pslp12,
	&pslp_patch_size12);*/


	pslp_head_n_byte2 = HookKernelApi(DbgkCopyProcessDebugPort,
		(PVOID)proxyDbgkCopyProcessDebugPort,
		&ori_pslp2,
		&pslp_patch_size2);



	pslp_head_n_byte4 = HookKernelApi(DbgkOpenProcessDebugPort,
		(PVOID)proxyDbgkOpenProcessDebugPort,
		&ori_pslp4,
		&pslp_patch_size4);

	/*
	pslp_head_n_byte5 = HookKernelApi(DbgkUnMapViewOfSection,
	(PVOID)proxyDbgkUnMapViewOfSection,
	&ori_pslp5,
	&pslp_patch_size5);

	pslp_head_n_byte6 = HookKernelApi(DbgkMapViewOfSection,
	(PVOID)proxyDbgkMapViewOfSection,
	&ori_pslp6,
	&pslp_patch_size6);*/




	/*pslp_head_n_byte7 = HookKernelApi(DbgkExitThread,
	(PVOID)proxyDbgkExitThread,
	&ori_pslp7,
	&pslp_patch_size7);

	pslp_head_n_byte8 = HookKernelApi(DbgkExitProcess,
	(PVOID)proxyDbgkExitProcess,
	&ori_pslp8,
	&pslp_patch_size8);
	*/

	pslp_head_n_byte11 = HookKernelApi(DbgkpQueueMessage,
		(PVOID)DbgkpQueueMessage_2,
		&ori_pslp11,
		&pslp_patch_size11);
	/*

	irq=WPOFFx64();
	memcpy(KiDispatchException + 0x241, orgcode, 2);
	//_InterlockedExchange16(KiDispatchException + 0x241, 0x90E9);
	WPONx64(irq);*/
	//initANti();
}



VOID  UnLoadMiniHook() {
	KIRQL irq;

	UnhookKernelApi(DbgkForwardException, pslp_head_n_byte3, pslp_patch_size3);
	/*
	UnhookKernelApi(DbgkpSetProcessDebugObject, pslp_head_n_byte12, pslp_patch_size12);
	*/

	UnhookKernelApi(DbgkCopyProcessDebugPort, pslp_head_n_byte2, pslp_patch_size2);



	UnhookKernelApi(DbgkOpenProcessDebugPort, pslp_head_n_byte4, pslp_patch_size4);

	/*
	UnhookKernelApi(DbgkUnMapViewOfSection, pslp_head_n_byte5, pslp_patch_size5);

	UnhookKernelApi(DbgkMapViewOfSection, pslp_head_n_byte6, pslp_patch_size6);*/

	/*
	UnhookKernelApi(DbgkExitThread, pslp_head_n_byte7, pslp_patch_size7);
	UnhookKernelApi(DbgkExitProcess, pslp_head_n_byte8, pslp_patch_size8);*/
	UnhookKernelApi(DbgkpQueueMessage, pslp_head_n_byte11, pslp_patch_size11);

	/*irq = WPOFFx64();
	memcpy(KiDispatchException + 0x241, Irgcode, 2);
	//_InterlockedExchange16(KiDispatchException + 0x241, 0x850f);
	WPONx64(irq);*/
	unload();
}


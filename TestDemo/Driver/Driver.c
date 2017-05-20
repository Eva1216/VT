#include "Driver.h"
#include "..\DbgTool\DbgTool.h"
#include "..\Test\Test.h"
BOOLEAN DriverEnable = FALSE;
BOOLEAN MainVtMode = FALSE;
PDEVICE_OBJECT g_DevObject;

BOOLEAN OpenVtMode = TRUE;//LOAD VT MODE
typedef int(*LDE_DISASM)(void *p, int dw);
LDE_DISASM LDE;
PGLOBAL_DATA g_Data = NULL;
p_save_handlentry PmainList;


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	UNICODE_STRING ustrLinkName;
	UNICODE_STRING ustrDevName;

	NTSTATUS Status;
	//设置分发函数和卸载例程
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	//pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDriverObj->DriverUnload = DriverUnload;
	//创建一个设备
	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	Status= IoCreateDevice(pDriverObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DevObject);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	//判断支持的WDM版本，其实这个已经不需要了，纯属WIN9X和WINNT并存时代的残留物
	if (IoIsWdmVersionAvailable(1, 0x10))
	{
		RtlInitUnicodeString(&ustrLinkName, LINK_GLOBAL_NAME);
	}
	else
	{
		RtlInitUnicodeString(&ustrLinkName, LINK_NAME);
	}
	//创建符号连接
	Status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(Status))
	{
		IoDeleteDevice(g_DevObject);
		return Status;
	}

	DbgPrint("VV-DBG \n");
	//PmainList = CreateList();//创建记录DBG工具的链表

	LDE_init();
	BypassCheckSign(pDriverObj);//过标签
	//InitialzeDbgprocessList();	//初始化调试信息链表
	if (OpenVtMode)
	{
		InitialzeR3EPTHOOK();//初始化R3内存欺骗
		LoadHV();//加载VT模式
	}
	//	PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)LoadImageNotifyRoutine);
	return STATUS_SUCCESS;
}

NTSTATUS LoadHV() 
{
	// 检测是否支持VT
	if (!HvmIsHVSupported())
	{
		DPRINT("HyperBone: CPU %d: %s: VMX/AMD-V is not supported, aborting\n", CPU_IDX, __FUNCTION__);
		return STATUS_HV_FEATURE_UNAVAILABLE;
	}
	
	// Initialize internal structures
	if (UtilSSDTEntry(0) == NULL)
	{
		DPRINT("HyperBone: CPU %d: %s: Failed to Get SSDT/Kernel base, can't continue\n", CPU_IDX, __FUNCTION__);
		return STATUS_UNSUCCESSFUL;
	}
	
	g_Data = AllocGlobalData();
	if (g_Data == NULL)
	{
		DPRINT("HyperBone: CPU %d: %s: Failed to allocate global data\n", CPU_IDX, __FUNCTION__);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	//
	// Get physical memory regions
	if (!NT_SUCCESS(UtilQueryPhysicalMemory()))
	{
		DPRINT("HyperBone: CPU %d: %s: Failed to query physical memory ranges\n", CPU_IDX, __FUNCTION__);
		FreeGlobalData(g_Data);
		return STATUS_UNSUCCESSFUL;
	}
	
	// Fill available CPU features	检查的CPU参数  ETP, VPID, VMFUNC, etc.
	
	HvmCheckFeatures();
	
	DPRINT("HyperBone: CPU %d: %s: Subverting started...\n", CPU_IDX, __FUNCTION__);

	 
	if (!NT_SUCCESS(StartHV()))
	{
		DPRINT("HyperBone: CPU %d: %s: StartHV() failed\n", CPU_IDX, __FUNCTION__);
		FreeGlobalData(g_Data);
		return STATUS_UNSUCCESSFUL;
	}


	MainVtMode = TRUE;
	DPRINT("HyperBone: CPU %d: %s: Subverting finished\n", CPU_IDX, __FUNCTION__);

	TestStart(TRUE, TRUE, TRUE);
	
}

VOID BypassCheckSign(PDRIVER_OBJECT DriverObject)
{
	//STRUCT FOR WIN64
	typedef struct _LDR_DATA                         			// 24 elements, 0xE0 bytes (sizeof)
	{
		struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)
		struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)
		struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)
		VOID*        DllBase;
		VOID*        EntryPoint;
		ULONG32      SizeOfImage;
		UINT8        _PADDING0_[0x4];
		struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)
		struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)
		ULONG32      Flags;
	}LDR_DATA, *PLDR_DATA;
	PLDR_DATA ldr;
	ldr = (PLDR_DATA)(DriverObject->DriverSection);
	ldr->Flags |= 0x20;
}

VOID LDE_init()
{
	LDE = ExAllocatePool(NonPagedPool, 12800);
	memcpy(LDE, ShellCode, 12800);		//不太懂
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObj)
{

	UNREFERENCED_PARAMETER(pDriverObj);
	CCHAR i;
	KIRQL OldIrql;
	KAFFINITY OldAffinity;
	UNICODE_STRING strLink;

	//删除符号连接和设备
	RtlInitUnicodeString(&strLink, LINK_NAME);
	IoDeleteSymbolicLink(&strLink);
	IoDeleteDevice(pDriverObj->DeviceObject);
	/**
	for (i=0; i<KeNumberProcessors; i++)
	{
	OldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1<<i));
	OldIrql = KeRaiseIrqlToDpcLevel();
	_StopVirtualization();
	KeLowerIrql(OldIrql);
	KeRevertToUserAffinityThreadEx(OldAffinity);
	}


	HvmSpitOutBluepill ();
	*/

	if (DriverEnable)
	{
		//ObProtectProcess(FALSE);
		
		
		//DbgNoVtHookMyDbgKr(FALSE);
		
		//UnLoadProtectWindow();
		
	}


	if (MainVtMode)
	{
		UnloadHV();
	}

	return STATUS_SUCCESS;
}

NTSTATUS UnloadHV() {

	TestPrintResults();
	//TestStop();

	//NTSTATUS status = StopHV();
	MainVtMode = FALSE;
	//FreeGlobalData(g_Data);
}

/// <summary>
/// Allocate global data
/// </summary>
/// <returns>Allocated data or NULL</returns>
PGLOBAL_DATA AllocGlobalData()
{
	PHYSICAL_ADDRESS low = { 0 }, high = { 0 };
	high.QuadPart = MAXULONG64;

	ULONG cpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);	//逻辑处理器的数量
	ULONG_PTR size = FIELD_OFFSET(GLOBAL_DATA, cpu_data) + cpu_count * sizeof(VCPU);
	PGLOBAL_DATA pData = (PGLOBAL_DATA)ExAllocatePoolWithTag(NonPagedPoolNx, size, HB_POOL_TAG);
	if (pData == NULL)
		return NULL;

	RtlZeroMemory(pData, size);

	pData->MSRBitmap = ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, HB_POOL_TAG);
	if (pData->MSRBitmap == NULL)
	{
		ExFreePoolWithTag(pData, HB_POOL_TAG);
		return NULL;
	}

	RtlZeroMemory(pData->MSRBitmap, PAGE_SIZE);

	pData->CPUVendor = UtilCPUVendor();

	for (ULONG i = 0; i < cpu_count; i++)
	{
		PVCPU Vcpu = &pData->cpu_data[i];

		InitializeListHead(&Vcpu->EPT.PageList);

		for (ULONG j = 0; j < EPT_PREALLOC_PAGES; j++)
		{
			Vcpu->EPT.Pages[j] = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low, high, low, MmNonCached);
			if (Vcpu->EPT.Pages[j] != NULL)
			{
				UtilProtectNonpagedMemory(Vcpu->EPT.Pages[j], PAGE_SIZE, PAGE_READWRITE);
				RtlZeroMemory(Vcpu->EPT.Pages[j], PAGE_SIZE);
			}
		}
	}

	return pData;
}


/// <summary>
/// Free global data
/// </summary>
/// <param name="pData">Data pointer</param>
VOID FreeGlobalData(IN PGLOBAL_DATA pData)
{
	if (pData == NULL)
		return;

	ULONG cpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	for (ULONG i = 0; i < cpu_count; i++)
	{
		PVCPU Vcpu = &pData->cpu_data[i];
		if (Vcpu->VMXON)
			MmFreeContiguousMemory(Vcpu->VMXON);
		if (Vcpu->VMCS)
			MmFreeContiguousMemory(Vcpu->VMCS);
		if (Vcpu->VMMStack)
			MmFreeContiguousMemory(Vcpu->VMMStack);

		for (ULONG j = 0; j < EPT_PREALLOC_PAGES; j++)
			if (Vcpu->EPT.Pages[j] != NULL)
				MmFreeContiguousMemory(Vcpu->EPT.Pages[j]);
	}

	if (pData->Memory)
		ExFreePoolWithTag(pData->Memory, HB_POOL_TAG);
	if (pData->MSRBitmap)
		ExFreePoolWithTag(pData->MSRBitmap, HB_POOL_TAG);

	ExFreePoolWithTag(pData, HB_POOL_TAG);
}
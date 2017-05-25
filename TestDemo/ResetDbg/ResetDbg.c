#include "ResetDbg.h"
#include "..\KernelStruct\KernelStruct.h"
#include "..\ProcessDbgList\ActiveProcessDbgList.h"
#include "..\DbgTool\DbgTool.h"
#include "..\Include\Txoo.h"
#include "..\DRRWE\DRRWE.h"
#include "Dbg.h"


#define PspSetProcessFlag(Flags, Flag) \
	RtlInterlockedSetBitsDiscardReturn (Flags, Flag)
NTKERNELAPI	VOID KeStackAttachProcess(__inout PEPROCESS PROCESS,__out PKAPC_STATE ApcState);
void ZwFlushInstructionCache(HANDLE process, ULONG64 UNKNOW, ULONG64 UNKNOW1);
NTSTATUS DbgkpSetProcessDebugObject_2(IN PEPROCESS_S Process, IN PDEBUG_OBJECT DebugObject, IN NTSTATUS MsgStatus, IN PETHREAD LastThread);
NTKERNELAPI VOID KeUnstackDetachProcess(__in PKAPC_STATE ApcState);
NTSTATUS DbgkpPostFakeProcessCreateMessages_2(IN PEPROCESS_S Process, IN PDEBUG_OBJECT DebugObject, IN PETHREAD * pLastThread);
NTSTATUS NTAPI DbgkClearProcessDebugObject(IN PEPROCESS_S Process, IN PDEBUG_OBJECT SourceDebugObject OPTIONAL);
POBJECT_TYPE CreateNewObjectType(POBJECT_TYPE_S *OrigDebugObjectType);
VOID DbgkpDeleteObject(IN PVOID DebugObject);
VOID DbgkpCloseObject(IN PEPROCESS_S Process, IN PVOID Object, IN ACCESS_MASK GrantedAccess, IN ULONG_PTR ProcessHandleCount, IN ULONG_PTR SystemHandleCount);
VOID DbgkpWakeTarget(IN PDEBUG_EVENT DebugEvent);
VOID DbgkpFreeDebugEvent(IN PDEBUG_EVENT DebugEvent);

#define ProbeForWriteGenericType(Ptr, Type)                                    \
	do {                                                                       \
	if ((ULONG_PTR)(Ptr) + sizeof(Type) - 1 < (ULONG_PTR)(Ptr) ||          \
	(ULONG_PTR)(Ptr) + sizeof(Type) - 1 >= (ULONG_PTR)MmUserProbeAddress) { \
	ExRaiseAccessViolation();                                          \
								}                                                                      \
		*(volatile Type *)(Ptr) = *(volatile Type *)(Ptr);                     \
							} while (0)

#define ProbeForWriteHandle(Ptr) ProbeForWriteGenericType(Ptr, HANDLE)
NTSTATUS AddAllThreadContextToList(PEPROCESS_S Process);
NTSTATUS DbgkpQueueMessage_2(IN PEPROCESS_S Process, IN PETHREAD Thread, IN OUT PDBGKM_MSG ApiMsg, IN ULONG Flags, IN PDEBUG_OBJECT TargetDebugObject);
VOID SendForWarExcept_Thread();
VOID proxyDbgkCopyProcessDebugPort(IN PEPROCESS_S TargetProcess, IN PEPROCESS_S SourceProcess, IN ULONG64 unknow, IN ULONG64 unknow1);

NTSTATUS proxyDbgkOpenProcessDebugPort(IN PEPROCESS_S Process, IN KPROCESSOR_MODE PreviousMode, OUT HANDLE * DebugHandle);
extern p_save_handlentry PmainList;

typedef NTSTATUS
(*ObDuplicateObject1)(
	IN PEPROCESS_S SourceProcess,
	IN HANDLE SourceHandle,
	IN PEPROCESS_S TargetProcess OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options,
	IN KPROCESSOR_MODE PreviousMode
	);

typedef PETHREAD(__fastcall *PsGetNextProcessThreadx)(PEPROCESS_S process, PKTHREAD THREAD);
typedef NTSTATUS(__fastcall *MmGetFileNameForSectionx)(IN PVOID Thread, OUT POBJECT_NAME_INFORMATION FileName OPTIONAL);
typedef NTSTATUS(__fastcall *PsTerminateProcessx)(IN PEPROCESS_S Process, NTSTATUS STATUS);
typedef NTSTATUS(__fastcall *DbgkpPostModuleMessagesx)(PEPROCESS_S process, PKTHREAD THREAD, PDEBUG_OBJECT debug);
typedef NTSTATUS(__fastcall *PsGetNextProcessx)(POBJECT_TYPE object);
typedef NTSTATUS(__fastcall *KeThawAllThreadsx)();
typedef NTSTATUS(__fastcall *PsResumeThreadx)(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
typedef NTSTATUS(__fastcall *KeFreezeAllThreadsx)();
typedef NTSTATUS(__fastcall *PsSuspendThreadx)(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
typedef NTSTATUS
(__fastcall*
	proxyDbgkpSendApiMessage)(
		IN ULONG SuspendProcess, IN OUT PDBGKM_MSG ApiMsg);

typedef NTSTATUS(__fastcall*
	proxyDbgkpQueueMessage)(
		IN PEPROCESS_S Process,
		IN PETHREAD Thread,
		IN OUT PDBGKM_MSG ApiMsg,
		IN ULONG Flags,
		IN PDEBUG_OBJECT TargetDebugObject
		);
typedef
VOID
(__fastcall*
	PfDbgkpFreeDebugEvent)(IN PDEBUG_EVENT DebugEvent);
typedef NTSTATUS(__stdcall *OBCREATEOBJECT)(
	__in KPROCESSOR_MODE ProbeMode,
	__in POBJECT_TYPE ObjectType,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in KPROCESSOR_MODE OwnershipMode,
	__inout_opt PVOID ParseContext,
	__in ULONG ObjectBodySize,
	__in ULONG PagedPoolCharge,
	__in ULONG NonPagedPoolCharge,
	__out PVOID *Object
	);

typedef
NTSTATUS
(__fastcall* DbgkpPostFakeThreadMessagesx)(IN PEPROCESS_S Process,
	IN ULONG64 DebugObject,
	IN PETHREAD StartThread,
	OUT PETHREAD *FirstThread,
	OUT PETHREAD *LastThread);

typedef NTSTATUS(__fastcall * pfMmGetFileNameForAddress)(PIMAGE_NT_HEADERS pnt, PUNICODE_STRING modname);


typedef NTSTATUS(__fastcall*
	pfDbgkpSetProcessDebugObject)(
		IN PEPROCESS_S Process,
		IN PDEBUG_OBJECT DebugObject,
		IN NTSTATUS MsgStatus,
		IN PETHREAD LastThread);

typedef NTSTATUS(__fastcall* pfDbgkpPostFakeProcessCreateMessages)(
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD *pLastThread
	);

typedef LONG(*EXSYSTEMEXCEPTIONFILTER)(VOID);

typedef NTSTATUS
(*OBINSERTOBJECT)(
	__in PVOID Object,
	__inout_opt PACCESS_STATE PassedAccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in ULONG ObjectPointerBias,
	__out_opt PVOID *NewObject,
	__out_opt PHANDLE Handle
	);
typedef NTSTATUS
(*OBOPENOBJECTBYPOINTER)(
	__in PVOID Object,
	__in ULONG HandleAttributes,
	__in_opt PACCESS_STATE PassedAccessState,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__out PHANDLE Handle
	);
typedef VOID(__fastcall* KiCheckForKernelApcDelivery1)();

DbgkpPostModuleMessagesx DbgkpPostModuleMessages;
ObDuplicateObject1 ObDuplicateObject;
ULONG64 *PspSystemDlls;
POBJECT_TYPE_S DbgkDebugObjectType;
typedef NTSTATUS(__fastcall *LpcRequestWaitReplyPortExx)(PVOID64 port, PPORT_MESSAGE Message, PPORT_MESSAGE Buffer);
LpcRequestWaitReplyPortExx LpcRequestWaitReplyPortEx;
MmGetFileNameForSectionx MmGetFileNameForSection;

PsGetNextProcessx PsGetNextProcess;
PsTerminateProcessx PsTerminateProcess;
proxyDbgkpSendApiMessage DbgkpSendApiMessage;
proxyDbgkpQueueMessage DbgkpQueueMessage;
pfMmGetFileNameForAddress MmGetFileNameForAddress;
PsGetNextProcessThreadx PsGetNextProcessThread;
KeThawAllThreadsx KeThawAllThreads;

PsResumeThreadx PsResumeThread;
KeFreezeAllThreadsx KeFreezeAllThreads;
PsSuspendThreadx PsSuspendThread;
DbgkpPostFakeThreadMessagesx DbgkpPostFakeThreadMessages;
ULONG64 DbgkpProcessDebugPortMutex;
POBJECT_TYPE_S *ObTypeIndexTable = 0;
pfDbgkpSetProcessDebugObject DbgkpSetProcessDebugObject;
pfDbgkpPostFakeProcessCreateMessages DbgkpPostFakeProcessCreateMessages;
PfDbgkpFreeDebugEvent DbgkpWakeTarget_2;
EXSYSTEMEXCEPTIONFILTER  ExSystemExceptionFilter;
OBINSERTOBJECT ObInsertObject;
OBCREATEOBJECT ObCreateObject;
KiCheckForKernelApcDelivery1 KiCheckForKernelApcDelivery12;
OBOPENOBJECTBYPOINTER ObOpenObjectByPointer;

FAST_MUTEX DbgkFastMutex;
PFAST_MUTEX DbgkFastMutex2;

POBJECT_TYPE_S NewDbgObject;

proxyDbgkpQueueMessage DbgkpQueueMessage;
NTSTATUS NTAPI InitDbgKernel() {
	InitDbgPortList();
	ExSystemExceptionFilter = fc_DbgkGetAdrress(L"ExSystemExceptionFilter");
	ObInsertObject = fc_DbgkGetAdrress(L"ObInsertObject");
	ObCreateObject = fc_DbgkGetAdrress(L"ObCreateObject");
	ObOpenObjectByPointer = fc_DbgkGetAdrress(L"ObOpenObjectByPointer");
	KiCheckForKernelApcDelivery12 = fc_DbgkGetAdrress(L"KiCheckForKernelApcDelivery");
	ExInitializeFastMutex(&DbgkFastMutex);
	DbgkFastMutex2 = (PFAST_MUTEX)DbgkpProcessDebugPortMutex;



	//NewDbgObject =*(ULONG64*)DbgkDebugObjectType; 

	NewDbgObject = CreateNewObjectType(DbgkDebugObjectType);

	if (NewDbgObject == NULL) {

		DbgPrint("NewDbgObject is NULL");
	}


}


POBJECT_TYPE CreateNewObjectType(POBJECT_TYPE_S *OrigDebugObjectType)
{
	NTSTATUS					status;
	POBJECT_TYPE_S				NewObjectType;

	UNICODE_STRING				usObjectTypeName, usFuncName;
	OBCREATEOBJECTTYPE			ObCreateObjectType;
	OBJECT_TYPE_INITIALIZER_S	Object_Type_Init = { 0 };

	NewObjectType = NULL;

	if (OrigDebugObjectType == NULL || *OrigDebugObjectType == NULL || ObTypeIndexTable == NULL)
	{
		return NULL;
	}


	RtlInitUnicodeString(&usObjectTypeName, L"VV-DBG");
	RtlInitUnicodeString(&usFuncName, L"ObCreateObjectType");
	ObCreateObjectType = (OBCREATEOBJECTTYPE)MmGetSystemRoutineAddress(&usFuncName);
	if (ObCreateObjectType == NULL)
	{
		return NULL;
	}

	memset(&Object_Type_Init, 0x00, sizeof(OBJECT_TYPE_INITIALIZER_S));
	memcpy(&Object_Type_Init, &(*OrigDebugObjectType)->TypeInfo, sizeof(OBJECT_TYPE_INITIALIZER_S));
	Object_Type_Init.DeleteProcedure = &DbgkpDeleteObject;
	Object_Type_Init.CloseProcedure = &DbgkpCloseObject;
	Object_Type_Init.ValidAccessMask = 0x1f000f;
	status = ObCreateObjectType(&usObjectTypeName, &Object_Type_Init, NULL, &NewObjectType);
	if (status == STATUS_OBJECT_NAME_COLLISION)
	{
		ULONG Index = 2;
		while (ObTypeIndexTable[Index])
		{
			if (RtlCompareUnicodeString(&ObTypeIndexTable[Index]->Name, &usObjectTypeName, FALSE) == 0)
			{
				return (POBJECT_TYPE)ObTypeIndexTable[Index];
			}
			Index++;
		}
	}

	return (POBJECT_TYPE)NewObjectType;
}

VOID
__fastcall
DbgkpDeleteObject(IN PVOID DebugObject)
{
	PAGED_CODE();


	ASSERT(IsListEmpty(&((PDEBUG_OBJECT)DebugObject)->EventList));
}


VOID __fastcall
DbgkpCloseObject(
	IN PEPROCESS_S Process,
	IN PVOID Object,
	IN ACCESS_MASK GrantedAccess,
	IN ULONG_PTR ProcessHandleCount,
	IN ULONG_PTR SystemHandleCount
)
/*++

Routine Description:

Called by the object manager when a handle is closed to the object.

Arguments:

Process - Process doing the close
Object - Debug object being deleted
GrantedAccess - Access ranted for this handle
ProcessHandleCount - Unused and unmaintained by OB
SystemHandleCount - Current handle count for this object

Return Value:

None.

--*/
{
	PDEBUG_OBJECT DebugObject = Object;
	PDEBUG_EVENT DebugEvent;
	PLIST_ENTRY ListPtr;
	BOOLEAN Deref;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(GrantedAccess);
	UNREFERENCED_PARAMETER(ProcessHandleCount);

	//
	// If this isn't the last handle then do nothing.
	//
	if (SystemHandleCount > 1) {
		return;
	}

	ExAcquireFastMutex(&DebugObject->Mutex);

	//
	// Mark this object as going away and wake up any processes that are waiting.
	//
	DebugObject->Flags |= DEBUG_OBJECT_DELETE_PENDING;

	//
	// Remove any events and queue them to a temporary queue
	//
	ListPtr = DebugObject->EventList.Flink;
	InitializeListHead(&DebugObject->EventList);

	ExReleaseFastMutex(&DebugObject->Mutex);

	//
	// Wake anyone waiting. They need to leave this object alone now as its deleting
	//
	KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);

	//
	// Loop over all processes and remove the debug port from any that still have it.
	// Debug port propagation was disabled by setting the delete pending flag above so we only have to do this
	// once. No more refs can appear now.
	//
	ExAcquireFastMutex(&DbgkFastMutex);
	Deref = Port_RemoveDbgItem(NULL, DebugObject);
	ExReleaseFastMutex(&DbgkFastMutex);


	if (Deref) {
		//	DbgkpMarkProcessPeb(Process);
		//
		// If the caller wanted process deletion on debugger dying (old interface) then kill off the process.
		//
		if (DebugObject->Flags&DEBUG_OBJECT_KILL_ON_CLOSE) {
			//PsTerminateProcess(Process, STATUS_DEBUGGER_INACTIVE);
		}
		ObDereferenceObject(DebugObject);
	}
	/*
	for (Process = PsGetNextProcess(NULL);
	Process != NULL;
	Process = PsGetNextProcess(Process)) {

	if (Process->Pcb.newdbgport == DebugObject)

	{
	Deref = FALSE;
	ExAcquireFastMutex(&DbgkFastMutex);
	if (Process->Pcb.newdbgport == DebugObject) {
	Process->Pcb.newdbgport = NULL;
	Deref = TRUE;
	}
	ExReleaseFastMutex(&DbgkFastMutex);


	if (Deref) {
	//	DbgkpMarkProcessPeb(Process);
	//
	// If the caller wanted process deletion on debugger dying (old interface) then kill off the process.
	//
	if (DebugObject->Flags&DEBUG_OBJECT_KILL_ON_CLOSE) {
	PsTerminateProcess(Process, STATUS_DEBUGGER_INACTIVE);
	}
	ObDereferenceObject(DebugObject);
	}
	}
	}*/
	//
	// Wake up all the removed threads.
	//
	while (ListPtr != &DebugObject->EventList) {
		DebugEvent = CONTAINING_RECORD(ListPtr, DEBUG_EVENT, EventList);
		ListPtr = ListPtr->Flink;
		DebugEvent->Status = STATUS_DEBUGGER_INACTIVE;
		DbgkpWakeTarget(DebugEvent);
	}

}

VOID
NTAPI
DbgkpWakeTarget(IN PDEBUG_EVENT DebugEvent)
{
	PETHREAD Thread = DebugEvent->Thread;
	PAGED_CODE();


	if (DebugEvent->Flags & DEBUG_EVENT_SUSPEND) PsResumeThread(Thread, NULL);


	if (DebugEvent->Flags & DEBUG_EVENT_RELEASE)
	{

		ExReleaseRundownProtection(&Thread->RundownProtect);
	}


	if (DebugEvent->Flags & DEBUG_EVENT_NOWAIT)
	{

		DbgkpFreeDebugEvent(DebugEvent);
	}
	else
	{

		KeSetEvent(&DebugEvent->ContinueEvent, IO_NO_INCREMENT, FALSE);
	}
}

VOID
NTAPI
DbgkpFreeDebugEvent(IN PDEBUG_EVENT DebugEvent)
{
	PHANDLE Handle = NULL;
	PAGED_CODE();


	switch (DebugEvent->ApiMsg.ApiNumber)
	{

	case DbgKmCreateProcessApi:


		Handle = &DebugEvent->ApiMsg.CreateProcess.FileHandle;
		break;


	case DbgKmLoadDllApi:


		Handle = &DebugEvent->ApiMsg.LoadDll.FileHandle;

	default:
		break;
	}

	if ((Handle) && (*Handle)) ObCloseHandle(*Handle, KernelMode);


	ObDereferenceObject(DebugEvent->Process);
	ObDereferenceObject(DebugEvent->Thread);
	ExFreePoolWithTag(DebugEvent, 'EgbD');
}
NTSTATUS __fastcall proxyNtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags)
{
	p_save_handlentry Padd = NULL;


	NTSTATUS status;
	HANDLE Handle;
	PDEBUG_OBJECT DebugObject;
	KPROCESSOR_MODE        PreviousMode;

	PreviousMode = ExGetPreviousMode();



	DbgPrint("HOOK NTCREATEDEBUGOBJECT");
	try {
		if (PreviousMode != KernelMode) {
			ProbeForWriteHandle(DebugObjectHandle);

			*DebugObjectHandle = *DebugObjectHandle;
		}
		*DebugObjectHandle = NULL;

	} except(ExSystemExceptionFilter()) {
		return GetExceptionCode();
	}

	if (Flags & ~DEBUG_KILL_ON_CLOSE) {
		return STATUS_INVALID_PARAMETER;
	}

	/*
	Padd = querylist(PmainList, PsGetCurrentProcessId(), PsGetCurrentProcess());
	if (Padd == NULL)
	{
	DbgPrint("proxyNtCreateDebugObject");
	return ori_pslp40(DebugObjectHandle, DesiredAccess, ObjectAttributes, Flags);

	}*/

	//创建调试对象
	status = ObCreateObject(
		PreviousMode,
		NewDbgObject,
		ObjectAttributes,
		PreviousMode,
		NULL,
		sizeof(DEBUG_OBJECT),
		0,
		0,
		(PVOID*)&DebugObject);


	if (!NT_SUCCESS(status)) {
		DbgPrint("创建出错");
		return status;
	}
	//初始化调试对象
	ExInitializeFastMutex(&DebugObject->Mutex);
	InitializeListHead(&DebugObject->EventList);
	KeInitializeEvent(&DebugObject->EventsPresent, NotificationEvent, FALSE);

	if (Flags & DEBUG_KILL_ON_CLOSE) {
		DebugObject->Flags = DEBUG_OBJECT_KILL_ON_CLOSE;
	}
	else {
		DebugObject->Flags = 0;
	}


	status = ObInsertObject(
		DebugObject,
		NULL,
		DesiredAccess,
		0,
		NULL,
		&Handle);
	if (!NT_SUCCESS(status)) {
		DbgPrint("插入出错");
		return status;
	}

	try {
		*DebugObjectHandle = Handle;
	} except(ExSystemExceptionFilter()) {
		status = GetExceptionCode();
	}

	return status;
}



NTSTATUS
__fastcall
proxyNtWaitForDebugEvent(IN HANDLE DebugHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PDBGUI_WAIT_STATE_CHANGE StateChange)
{
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	LARGE_INTEGER LocalTimeOut;
	PEPROCESS Process;
	LARGE_INTEGER StartTime;
	PETHREAD Thread;
	BOOLEAN GotEvent;
	LARGE_INTEGER NewTime;
	PDEBUG_OBJECT DebugObject;
	DBGUI_WAIT_STATE_CHANGE WaitStateChange;
	NTSTATUS Status;
	PDEBUG_EVENT DebugEvent = NULL, DebugEvent2;
	PLIST_ENTRY ListHead, NextEntry, NextEntry2;
	PAGED_CODE();

	DbgProcess dbgmsg = { 0 };
	RtlZeroMemory(&WaitStateChange, sizeof(WaitStateChange));
	LocalTimeOut.QuadPart = 0;


	if (PreviousMode != KernelMode)
	{

		try
		{

			if (Timeout)
			{

				//ProbeForReadLargeInteger(Timeout);


				LocalTimeOut = *Timeout;
				Timeout = &LocalTimeOut;
			}


			ProbeForWrite(StateChange, sizeof(*StateChange), sizeof(ULONG));
		}
		except(EXCEPTION_EXECUTE_HANDLER)
		{

			return GetExceptionCode();
		}

	}
	else
	{

		if (Timeout) LocalTimeOut = *Timeout;
	}

	/*dbgmsg.DbgHanle = DebugHandle;
	if (Debug_FindMyNeedData(&dbgmsg) == FALSE){

	return ori_pslp41(DebugHandle, Alertable, Timeout, StateChange);
	}*/

	if (Timeout) KeQuerySystemTime(&StartTime);


	Status = ObReferenceObjectByHandle(DebugHandle,
		DEBUG_OBJECT_WAIT_STATE_CHANGE,
		NewDbgObject,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);

	if (!NT_SUCCESS(Status)) return Status;


	Process = NULL;
	Thread = NULL;


	while (TRUE)
	{
		Status = KeWaitForSingleObject(&DebugObject->EventsPresent,
			Executive,
			PreviousMode,
			Alertable,
			Timeout);
		if (!NT_SUCCESS(Status) ||
			(Status == STATUS_TIMEOUT) ||
			(Status == STATUS_ALERTED) ||
			(Status == STATUS_USER_APC))
		{

			break;
		}


		GotEvent = FALSE;
		ExAcquireFastMutex(&DebugObject->Mutex);


		if (DebugObject->DebuggerInactive)
		{

			Status = STATUS_DEBUGGER_INACTIVE;
		}
		else
		{

			ListHead = &DebugObject->EventList;
			NextEntry = ListHead->Flink;
			while (ListHead != NextEntry)
			{

				DebugEvent = CONTAINING_RECORD(NextEntry,
					DEBUG_EVENT,
					EventList);



				if (!(DebugEvent->Flags & (DEBUG_EVENT_INACTIVE | DEBUG_EVENT_READ)))
				{

					GotEvent = TRUE;


					NextEntry2 = DebugObject->EventList.Flink;
					while (NextEntry2 != NextEntry)
					{

						DebugEvent2 = CONTAINING_RECORD(NextEntry2,
							DEBUG_EVENT,
							EventList);

						if (DebugEvent2->ClientId.UniqueProcess ==
							DebugEvent->ClientId.UniqueProcess)
						{

							DebugEvent->Flags |= DEBUG_EVENT_INACTIVE;
							DebugEvent->BackoutThread = NULL;
							GotEvent = FALSE;
							break;
						}


						NextEntry2 = NextEntry2->Flink;
					}


					if (GotEvent) break;
				}


				NextEntry = NextEntry->Flink;
			}


			if (GotEvent)
			{

				Process = DebugEvent->Process;
				Thread = DebugEvent->Thread;
				ObReferenceObject(Process);
				ObReferenceObject(Thread);


				DbgkpConvertKernelToUserStateChange(&WaitStateChange,
					DebugEvent);


				DebugEvent->Flags |= DEBUG_EVENT_READ;
			}
			else
			{

				KeClearEvent(&DebugObject->EventsPresent);
			}


			Status = STATUS_SUCCESS;
		}


		ExReleaseFastMutex(&DebugObject->Mutex);
		if (!NT_SUCCESS(Status)) break;


		if (!GotEvent)
		{

			if (LocalTimeOut.QuadPart < 0)
			{

				KeQuerySystemTime(&NewTime);


				LocalTimeOut.QuadPart += (NewTime.QuadPart - StartTime.QuadPart);
				StartTime = NewTime;


				if (LocalTimeOut.QuadPart >= 0)
				{

					Status = STATUS_TIMEOUT;
					break;
				}
			}
		}
		else
		{

			DbgkpOpenHandles(&WaitStateChange, Process, Thread);
			ObDereferenceObject(Process);
			ObDereferenceObject(Thread);
			break;
		}
	}


	ObDereferenceObject(DebugObject);


	try
	{

		*StateChange = WaitStateChange;
	}
	except(ExSystemExceptionFilter())
	{

		Status = GetExceptionCode();
	}


	return Status;
}


VOID
NTAPI
DbgkpOpenHandles(IN PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
	IN PEPROCESS Process,
	IN PETHREAD Thread)
{
	NTSTATUS Status;
	HANDLE Handle;
	PHANDLE DupHandle;
	PAGED_CODE();



	switch (WaitStateChange->NewState)
	{

	case DbgCreateThreadStateChange:


		Status = ObOpenObjectByPointer(Thread,
			0,
			NULL,
			THREAD_ALL_ACCESS,
			*PsThreadType,
			KernelMode,
			&Handle);
		if (NT_SUCCESS(Status))
		{

			WaitStateChange->
				StateInfo.CreateThread.HandleToThread = Handle;
		}
		return;


	case DbgCreateProcessStateChange:


		Status = ObOpenObjectByPointer(Thread,
			0,
			NULL,
			THREAD_ALL_ACCESS,
			*PsThreadType,
			KernelMode,
			&Handle);
		if (NT_SUCCESS(Status))
		{

			WaitStateChange->
				StateInfo.CreateProcessInfo.HandleToThread = Handle;
		}

		Status = ObOpenObjectByPointer(Process,
			0,
			NULL,
			PROCESS_ALL_ACCESS,
			*PsProcessType,
			KernelMode,
			&Handle);
		if (NT_SUCCESS(Status))
		{

			WaitStateChange->
				StateInfo.CreateProcessInfo.HandleToProcess = Handle;
		}


		DupHandle = &WaitStateChange->
			StateInfo.CreateProcessInfo.NewProcess.FileHandle;
		break;

	case DbgLoadDllStateChange:


		DupHandle = &WaitStateChange->StateInfo.LoadDll.FileHandle;
		break;


	default:
		return;
	}


	Handle = *DupHandle;
	if (Handle)
	{

		Status = ObDuplicateObject(PsGetCurrentProcess(),
			Handle,
			PsGetCurrentProcess(),
			DupHandle,
			0,
			0,
			DUPLICATE_SAME_ACCESS,
			KernelMode);
		if (!NT_SUCCESS(Status)) *DupHandle = NULL;


		ObCloseHandle(Handle, KernelMode);
	}
}

VOID
NTAPI
DbgkpConvertKernelToUserStateChange(IN PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
	IN PDEBUG_EVENT DebugEvent)
{


	WaitStateChange->AppClientId = DebugEvent->ClientId;


	switch (DebugEvent->ApiMsg.ApiNumber)
	{

	case DbgKmCreateProcessApi:


		WaitStateChange->NewState = DbgCreateProcessStateChange;


		WaitStateChange->StateInfo.CreateProcessInfo.NewProcess =
			DebugEvent->ApiMsg.CreateProcess;


		DebugEvent->ApiMsg.CreateProcess.FileHandle = NULL;
		break;


	case DbgKmCreateThreadApi:


		WaitStateChange->NewState = DbgCreateThreadStateChange;


		WaitStateChange->StateInfo.CreateThread.NewThread.StartAddress =
			DebugEvent->ApiMsg.CreateThread.StartAddress;
		WaitStateChange->StateInfo.CreateThread.NewThread.SubSystemKey =
			DebugEvent->ApiMsg.CreateThread.SubSystemKey;
		break;


	case DbgKmExceptionApi:


		if ((NTSTATUS)DebugEvent->ApiMsg.Exception.ExceptionRecord.ExceptionCode ==
			STATUS_BREAKPOINT)
		{

			WaitStateChange->NewState = DbgBreakpointStateChange;
		}
		else if ((NTSTATUS)DebugEvent->ApiMsg.Exception.ExceptionRecord.ExceptionCode ==
			STATUS_SINGLE_STEP)
		{

			WaitStateChange->NewState = DbgSingleStepStateChange;
		}
		else
		{

			WaitStateChange->NewState = DbgExceptionStateChange;
		}


		WaitStateChange->StateInfo.Exception.ExceptionRecord =
			DebugEvent->ApiMsg.Exception.ExceptionRecord;

		WaitStateChange->StateInfo.Exception.FirstChance =
			DebugEvent->ApiMsg.Exception.FirstChance;
		break;


	case DbgKmExitProcessApi:

		WaitStateChange->NewState = DbgExitProcessStateChange;
		WaitStateChange->StateInfo.ExitProcess.ExitStatus =
			DebugEvent->ApiMsg.ExitProcess.ExitStatus;
		break;


	case DbgKmExitThreadApi:


		WaitStateChange->NewState = DbgExitThreadStateChange;
		WaitStateChange->StateInfo.ExitThread.ExitStatus =
			DebugEvent->ApiMsg.ExitThread.ExitStatus;
		break;


	case DbgKmLoadDllApi:


		WaitStateChange->NewState = DbgLoadDllStateChange;


		WaitStateChange->StateInfo.LoadDll = DebugEvent->ApiMsg.LoadDll;


		DebugEvent->ApiMsg.LoadDll.FileHandle = NULL;
		break;


	case DbgKmUnloadDllApi:


		WaitStateChange->NewState = DbgUnloadDllStateChange;
		WaitStateChange->StateInfo.UnloadDll.BaseAddress =
			DebugEvent->ApiMsg.UnloadDll.BaseAddress;
		break;

	default:


		ASSERT(FALSE);
	}
}
NTSTATUS
NTAPI
proxyNtDebugContinue(IN HANDLE DebugHandle,
	IN PCLIENT_ID AppClientId,
	IN NTSTATUS ContinueStatus)
{
	DbgProcess dbgmsg = { 0 };
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	PDEBUG_OBJECT DebugObject;
	NTSTATUS Status;
	PDEBUG_EVENT DebugEvent = NULL, DebugEventToWake = NULL;
	PLIST_ENTRY ListHead, NextEntry;
	BOOLEAN NeedsWake = FALSE;
	CLIENT_ID ClientId;
	PAGED_CODE();

	/*dbgmsg.DbgHanle = DebugHandle;
	dbgmsg.DebugProcess = AppClientId->UniqueProcess;
	if (Debug_FindMyNeedData(&dbgmsg) == FALSE){

	return ori_pslp42(DebugHandle, AppClientId, ContinueStatus);
	}
	*/

	if (PreviousMode != KernelMode)
	{

		try
		{

			ProbeForRead(AppClientId, sizeof(CLIENT_ID), sizeof(ULONG));
			ClientId = *AppClientId;
			AppClientId = &ClientId;
		}
		except(EXCEPTION_EXECUTE_HANDLER)
		{

			return GetExceptionCode();
		}
	}


	if ((ContinueStatus != DBG_CONTINUE) &&
		(ContinueStatus != DBG_EXCEPTION_HANDLED) &&
		(ContinueStatus != DBG_EXCEPTION_NOT_HANDLED) &&
		(ContinueStatus != DBG_TERMINATE_THREAD) &&
		(ContinueStatus != DBG_TERMINATE_PROCESS))
	{

		Status = STATUS_INVALID_PARAMETER;
	}
	else
	{



		Status = ObReferenceObjectByHandle(DebugHandle,
			DEBUG_OBJECT_WAIT_STATE_CHANGE,
			NewDbgObject,
			PreviousMode,
			(PVOID*)&DebugObject,
			NULL);
		/*	Status = ObReferenceObjectByHandle(DebugHandle,
		DEBUG_OBJECT_WAIT_STATE_CHANGE,
		*(ULONG64*)DbgkDebugObjectType,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);*/
		if (NT_SUCCESS(Status))
		{

			ExAcquireFastMutex(&DebugObject->Mutex);

			ListHead = &DebugObject->EventList;
			NextEntry = ListHead->Flink;
			while (ListHead != NextEntry)
			{

				DebugEvent = CONTAINING_RECORD(NextEntry,
					DEBUG_EVENT,
					EventList);


				if (DebugEvent->ClientId.UniqueProcess ==
					AppClientId->UniqueProcess)
				{

					if (NeedsWake)
					{

						DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
						KeSetEvent(&DebugObject->EventsPresent,
							IO_NO_INCREMENT,
							FALSE);
						break;
					}


					if ((DebugEvent->ClientId.UniqueThread ==
						AppClientId->UniqueThread) && (DebugEvent->Flags & DEBUG_EVENT_READ))
					{

						RemoveEntryList(NextEntry);


						NeedsWake = TRUE;
						DebugEventToWake = DebugEvent;
					}
				}


				NextEntry = NextEntry->Flink;
			}


			ExReleaseFastMutex(&DebugObject->Mutex);


			ObDereferenceObject(DebugObject);


			if (NeedsWake)
			{

				DebugEventToWake->ApiMsg.ReturnedStatus = ContinueStatus;
				DebugEventToWake->Status = STATUS_SUCCESS;


				DbgkpWakeTarget(DebugEventToWake);
			}
			else
			{

				Status = STATUS_INVALID_PARAMETER;
			}
		}
	}


	return Status;
}



BOOLEAN
__fastcall
proxyDbgkForwardException(IN PEXCEPTION_RECORD ExceptionRecord,
	IN BOOLEAN DebugPort,
	IN BOOLEAN SecondChance)
{
	DBGKM_MSG ApiMessage;
	PDBGKM_EXCEPTION DbgKmException = &ApiMessage.Exception;
	NTSTATUS Status = TRUE;
	PEPROCESS_S Process = PsGetCurrentProcess();
	PVOID Port = NULL;
	DbgProcess dbgmsg = { 0 };
	BOOLEAN UseLpc = FALSE;
	PAGED_CODE();



	/*
	dbgmsg.DebugProcess = Process;
	if (Debug_FindMyNeedData(&dbgmsg) == NULL)
	{
	DbgPrint("proxyDbgkForwardException");
	ori_pslp3(ExceptionRecord, DebugPort, SecondChance);
	}
	*/

	/* Setup the API Message */
	ApiMessage.h.u1.Length = sizeof(DBGKM_MSG) << 16 |
		(8 + sizeof(DBGKM_EXCEPTION));
	ApiMessage.h.u2.ZeroInit = 0;
	ApiMessage.h.u2.s2.Type = LPC_DEBUG_EVENT;
	ApiMessage.ApiNumber = DbgKmExceptionApi;

	/* Check if this is to be sent on the debug port */
	if (DebugPort)
	{
		/* Use the debug port, unless the thread is being hidden */
		//	Port = Process->Pcb.newdbgport;
		Port = Port_GetPort(Process);
		// Process->Pcb.newdbgport;
	}
	else
	{
		/* Otherwise, use the exception port */
		//	Port = Process->ExceptionPort;
		//ApiMessage.h.u2.ZeroInit = 0;
		//ApiMessage.h.u2.s2.Type = LPC_EXCEPTION;
		UseLpc = TRUE;
	}
	DbgPrint("异常");
	/* Break out if there's no port */
	if (!Port) return FALSE;
	MarkDbgProcess();
	/* Fill out the exception information */
	DbgKmException->ExceptionRecord = *ExceptionRecord;
	DbgKmException->FirstChance = !SecondChance;

	/* Check if we should use LPC */
	if (UseLpc)
	{
		/* Send the message on the LPC Port */
		//Status = DbgkpSendApiMessageLpc(&ApiMessage, Port, DebugPort);
	}
	else
	{
		/* Use native debug object */
		Status = DbgkpSendApiMessage_2(&ApiMessage, DebugPort);
	}

	/* Check if we failed, and for a debug port, also check the return status */
	if (!(NT_SUCCESS(Status)) ||
		((DebugPort) &&
		(!(NT_SUCCESS(ApiMessage.ReturnedStatus)) ||
			(ApiMessage.ReturnedStatus == DBG_EXCEPTION_NOT_HANDLED))))
	{
		/* Fail */
		return FALSE;
	}

	/* Otherwise, we're ok */
	return TRUE;
}
BOOLEAN	DbgkpSuspendProcess(VOID)
{


	if ((((PEPROCESS_S)PsGetCurrentProcess())->Flags &
		PS_PROCESS_FLAGS_PROCESS_DELETE) == 0) {
		KeFreezeAllThreads();
		return TRUE;
	}
	return FALSE;
}
NTSTATUS
__fastcall
DbgkpSendApiMessage_2(IN OUT PDBGKM_MSG ApiMsg,
	IN BOOLEAN SuspendProcess)
{
	NTSTATUS Status;
	BOOLEAN Suspended = FALSE;
	PAGED_CODE();

	/* Suspend process if required */
	if (SuspendProcess) Suspended = DbgkpSuspendProcess();

	/* Set return status */
	ApiMsg->ReturnedStatus = STATUS_PENDING;

	/* Set create process reported state */

	//PspSetFlag(&((PEPROCESS_S)PsGetCurrentProcess())->Flags, PS_PROCESS_FLAGS_CREATE_REPORTED);

	/* Send the LPC command */
	Status = DbgkpQueueMessage_2(PsGetCurrentProcess(),
		PsGetCurrentThread(),
		ApiMsg,
		((SuspendProcess & 0x2) << 0x5),
		NULL);

	/* Flush the instruction cache */
	ZwFlushInstructionCache(NtCurrentProcess(), NULL, 0);

	/* Resume the process if it was suspended */
	if (Suspended) DbgkpResumeProcess();
	return Status;
}
VOID
NTAPI
DbgkpResumeProcess(VOID)
{
	PAGED_CODE();


	KeThawAllThreads();
}
BOOLEAN __fastcall MarkDbgProcess() {
	PEPROCESS_S Process = PsGetCurrentProcess();
	PDbgPortList DbgList = NULL;

	DbgList = Port_FindProcessList(Process, NULL);
	if (DbgList != NULL && MmIsAddressValid(DbgList) == TRUE && DbgList->markdbg == FALSE)
	{

		InterlockedExchange8(&DbgList->markdbg, TRUE);
		//	Process->Pcb.Unused3 = TRUE;
		SendForWarExcept_Thread(); //SendCreateThreadMsg

		return TRUE;

	}
	else {


		return FALSE;
	}





}


VOID SendForWarExcept_Thread() {

	DBGKM_MSG ApiMessage = { 0 };
	PDBGKM_CREATE_THREAD CreateThreadArgs = &ApiMessage.CreateThread;


	ApiMessage.h.u1.Length = sizeof(DBGKM_MSG) << 16 |
		(8 + sizeof(DBGKM_CREATE_THREAD));
	ApiMessage.h.u2.ZeroInit = 0;
	ApiMessage.h.u2.s2.Type = LPC_DEBUG_EVENT;
	ApiMessage.ApiNumber = DbgKmCreateThreadApi;

	CreateThreadArgs->StartAddress = 0x1008611;
	CreateThreadArgs->SubSystemKey = 0;
	DbgkpSendApiMessage_2(&ApiMessage, FALSE);

}

VOID
proxyDbgkCopyProcessDebugPort(
	IN PEPROCESS_S TargetProcess,
	IN PEPROCESS_S SourceProcess
	, IN ULONG64 unknow, IN ULONG64 unknow1
)

{
	PDEBUG_OBJECT DebugObject;
	p_save_handlentry Padd = NULL;

	PAGED_CODE();

	/*Padd = querylist(PmainList, PsGetCurrentProcessId(), PsGetCurrentProcess());
	if (Padd == NULL)
	{
	return ori_pslp2(TargetProcess, SourceProcess, unknow, unknow1);

	}*/

	//TargetProcess->Pcb.newdbgport = NULL; // New process. Needs no locks.


	if (Port_IsPort(SourceProcess))

		//if (SourceProcess->Pcb.newdbgport != NULL) 
	{
		ExAcquireFastMutex(&DbgkFastMutex);
		//DebugObject = SourceProcess->Pcb.newdbgport;
		DebugObject = Port_GetPort(SourceProcess);
		if (DebugObject != NULL && (SourceProcess->Flags&PS_PROCESS_FLAGS_NO_DEBUG_INHERIT) == 0) {
			//
			// We must not propagate a debug port thats got no handles left.
			//
			ExAcquireFastMutex(&DebugObject->Mutex);

			//
			// If the object is delete pending then don't propagate this object.
			//
			if ((DebugObject->Flags&DEBUG_OBJECT_DELETE_PENDING) == 0) {
				ObReferenceObject(DebugObject);

				//TargetProcess->Pcb.newdbgport = DebugObject;
				Port_SetPort(TargetProcess, DebugObject);
			}

			ExReleaseFastMutex(&DebugObject->Mutex);
		}
		ExReleaseFastMutex(&DbgkFastMutex);
	}
}


NTSTATUS
__fastcall
proxyDbgkOpenProcessDebugPort(IN PEPROCESS_S Process,
	IN KPROCESSOR_MODE PreviousMode,
	OUT HANDLE *DebugHandle)
{
	PDEBUG_OBJECT DebugObject;
	NTSTATUS Status;
	DbgProcess dbgmsg = { 0 };
	PAGED_CODE();
	/*
	dbgmsg.DebugProcess = Process;
	if (Debug_FindMyNeedData(&dbgmsg)==FALSE)
	{
	return ori_pslp4(Process, PreviousMode, DebugHandle);
	}
	*/

	//if (!Process->Pcb.newdbgport) return STATUS_PORT_NOT_SET;

	if (!Port_IsPort(Process)) return STATUS_PORT_NOT_SET;

	ExAcquireFastMutex(&DbgkFastMutex);


	//DebugObject = Process->Pcb.newdbgport;
	DebugObject = Port_GetPort(Process);
	if (DebugObject) ObReferenceObject(DebugObject);


	ExReleaseFastMutex(&DbgkFastMutex);


	if (!DebugObject) return STATUS_PORT_NOT_SET;


	Status = ObOpenObjectByPointer(DebugObject,
		0,
		NULL,
		MAXIMUM_ALLOWED,
		NewDbgObject,
		PreviousMode,
		DebugHandle);
	if (!NT_SUCCESS(Status)) ObDereferenceObject(DebugObject);


	return Status;
}


NTSTATUS
__fastcall
proxyNtDebugActiveProcess(IN HANDLE ProcessHandle,
	IN HANDLE DebugHandle)
{
	PDbgPortList DbgList = NULL;
	DbgProcess dbgmsg = { 0 };
	PEPROCESS_S Process;
	PDEBUG_OBJECT DebugObject;
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	PETHREAD LastThread;
	NTSTATUS Status;
	p_save_handlentry Padd = NULL;
	PAGED_CODE();


	Status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_SUSPEND_RESUME,
		*PsProcessType,
		PreviousMode,
		(PVOID*)&Process,
		NULL);
	if (!NT_SUCCESS(Status)) return Status;


	if ((Process == PsGetCurrentProcess()) ||
		(Process == PsInitialSystemProcess))
	{

		ObDereferenceObject(Process);
		return STATUS_ACCESS_DENIED;
	}

	DbgList = Port_FindProcessList(Process, NULL);
	if (DbgList != NULL)
	{
		if (MmIsAddressValid(DbgList) == TRUE) {
			InterlockedExchange8(&DbgList->markdbg, FALSE);//sendfirstexpt!;
		}


	}



	Padd = QueryList(PmainList, PsGetCurrentProcessId(), PsGetCurrentProcess());
	if (Padd != NULL)
	{
		/*DbgPrint("proxyNtDebugActiveProcess");
		ObDereferenceObject(Process);
		return ori_pslp43(ProcessHandle, DebugHandle);*/

		DbgPrint("my process attachprocess");
		AddAllThreadContextToList(Process);

	}


	Status = ObReferenceObjectByHandle(DebugHandle,
		DEBUG_OBJECT_ADD_REMOVE_PROCESS,
		NewDbgObject,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);

	if (!NT_SUCCESS(Status))
	{

		ObDereferenceObject(Process);
		return Status;
	}





	if (!ExAcquireRundownProtection(&Process->RundownProtect))
	{

		ObDereferenceObject(Process);
		ObDereferenceObject(DebugObject);
		return STATUS_PROCESS_IS_TERMINATING;
	}
	/*dbgmsg.DbgHanle = DebugHandle;
	dbgmsg.DebugProcess = Process;
	dbgmsg.DebugObject = DebugObject;
	dbgmsg.Process = PsGetCurrentProcess();
	Debug_AddStructToList(&dbgmsg);*/
	Status = DbgkpPostFakeProcessCreateMessages_2(Process,
		DebugObject,
		&LastThread);
	Status = DbgkpSetProcessDebugObject_2(Process,
		DebugObject,
		Status,
		LastThread);


	ExReleaseRundownProtection(&Process->RundownProtect);

	ObDereferenceObject(Process);
	ObDereferenceObject(DebugObject);
	return Status;
}


NTSTATUS __fastcall
DbgkpSetProcessDebugObject_2(//反汇编OK
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT DebugObject,
	IN NTSTATUS MsgStatus,
	IN PETHREAD LastThread
)
{
	NTSTATUS Status;
	PETHREAD ThisThread;
	LIST_ENTRY TempList;
	PLIST_ENTRY Entry;
	PDEBUG_EVENT DebugEvent;
	BOOLEAN First;
	PETHREAD Thread;
	BOOLEAN GlobalHeld;
	PETHREAD FirstThread;

	PAGED_CODE();

	ThisThread = (PETHREAD)PsGetCurrentThread();

	InitializeListHead(&TempList);

	First = TRUE;
	GlobalHeld = FALSE;

	if (!NT_SUCCESS(MsgStatus))
	{
		LastThread = NULL;
		Status = MsgStatus;
	}
	else
	{
		Status = STATUS_SUCCESS;
	}


	if (NT_SUCCESS(Status))
	{
		while (1)
		{
			GlobalHeld = TRUE;
			ExAcquireFastMutex(&DbgkFastMutex);

			/*	if (Process->Pcb.newdbgport!= NULL)
			{
			Status = STATUS_PORT_ALREADY_SET;
			break;
			}*/
			if (Port_IsPort(Process))
			{
				Status = STATUS_PORT_ALREADY_SET;
				break;
			}
			Port_SetPort(Process, DebugObject);
			//Process->Pcb.newdbgport = DebugObject;

			ObReferenceObject(LastThread);

			Thread = PsGetNextProcessThread(Process, LastThread);
			if (Thread != NULL)
			{
				//Process->DebugPort = NULL; /*------ DebugPort -----------*/

				//Process->Pcb.newdbgport = NULL;
				Port_RemoveDbgItem(Process, NULL);
				ExReleaseFastMutex(&DbgkFastMutex);
				GlobalHeld = FALSE;
				ObDereferenceObject(LastThread);

				Status = DbgkpPostFakeThreadMessages(
					Process,
					DebugObject,
					Thread,
					&FirstThread,
					&LastThread);
				if (!NT_SUCCESS(Status))
				{
					LastThread = NULL;
					break;
				}
				ObDereferenceObject(FirstThread);
			}
			else
			{
				break;
			}
		}
	}
	ExAcquireFastMutex(&DebugObject->Mutex);

	if (NT_SUCCESS(Status))
	{
		if ((DebugObject->Flags&DEBUG_OBJECT_DELETE_PENDING) == 0) {
			PspSetProcessFlag(&Process->Flags, PS_PROCESS_FLAGS_NO_DEBUG_INHERIT | PS_PROCESS_FLAGS_CREATE_REPORTED);
			ObReferenceObject(DebugObject);//Process->NoDebugInherit 为1就表示有调试了。
		}
		else
		{
			//	Process->Pcb.newdbgport = NULL; /*------ DebugPort -----------*/
			Port_RemoveDbgItem(Process, NULL);
			Status = STATUS_DEBUGGER_INACTIVE;
		}
	}

	for (Entry = DebugObject->EventList.Flink;
		Entry != &DebugObject->EventList;
		)
	{
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		Entry = Entry->Flink;

		if ((DebugEvent->Flags&DEBUG_EVENT_INACTIVE) != 0 && DebugEvent->BackoutThread == ThisThread) {
			Thread = DebugEvent->Thread;

			if (NT_SUCCESS(Status))
			{
				if ((DebugEvent->Flags&DEBUG_EVENT_PROTECT_FAILED) != 0) {
					PspSetProcessFlag(&Thread->CrossThreadFlags,
						PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG);
					RemoveEntryList(&DebugEvent->EventList);
					InsertTailList(&TempList, &DebugEvent->EventList);
				}
				else {

					if (First) {
						DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
						KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
						First = FALSE;
					}

					DebugEvent->BackoutThread = NULL;
					PspSetProcessFlag(&Thread->CrossThreadFlags,
						PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG);

				}
			}
			else
			{
				RemoveEntryList(&DebugEvent->EventList);
				InsertTailList(&TempList, &DebugEvent->EventList);
			}

			if (DebugEvent->Flags&DEBUG_EVENT_RELEASE) {
				DebugEvent->Flags &= ~DEBUG_EVENT_RELEASE;
				ExReleaseRundownProtection(&Thread->RundownProtect);
			}

		}
	}

	ExReleaseFastMutex(&DebugObject->Mutex);

	if (GlobalHeld) {
		ExReleaseFastMutex(&DbgkFastMutex);
	}

	if (LastThread != NULL) {
		ObDereferenceObject(LastThread);
	}

	while (!IsListEmpty(&TempList)) {
		Entry = RemoveHeadList(&TempList);
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		DbgkpWakeTarget_2(DebugEvent);
	}


	return STATUS_SUCCESS;
}
NTSTATUS DbgkpPostFakeProcessCreateMessages_2(
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD *pLastThread
)
{
	NTSTATUS	status;
	KAPC_STATE	ApcState;
	PETHREAD	StartThread, Thread;
	PETHREAD	LastThread;

	//收集所有线程创建的消息
	StartThread = 0;
	status = DbgkpPostFakeThreadMessages(
		Process,
		DebugObject,
		StartThread,
		&Thread,
		&LastThread);

	if (NT_SUCCESS(status))
	{
		KeStackAttachProcess((PEPROCESS)Process, &ApcState);

		//收集模块创建的消息
		DbgkpPostModuleMessages(Process, Thread, DebugObject);

		KeUnstackDetachProcess(&ApcState);

		ObfDereferenceObject(Thread);
	}
	else {
		LastThread = 0;
	}

	*pLastThread = LastThread;
	return	status;
}


NTSTATUS
NTAPI
NtRemoveProcessDebug(IN HANDLE ProcessHandle,
	IN HANDLE DebugHandle)
{
	DbgProcess dbgmsg = { 0 };
	PEPROCESS_S Process;
	PDEBUG_OBJECT DebugObject;
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	NTSTATUS Status;
	PAGED_CODE();
	PDbgProcess pdbgmsg = NULL;


	/*dbgmsg.DbgHanle = DebugHandle;
	pdbgmsg = Debug_FindMyNeedData(&dbgmsg);
	if (pdbgmsg == FALSE)
	{

	return ori_pslp44(ProcessHandle, DebugHandle);

	}*/
	Status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_SUSPEND_RESUME,
		*PsProcessType,
		PreviousMode,
		(PVOID*)&Process,
		NULL);
	if (!NT_SUCCESS(Status)) return Status;


	Status = ObReferenceObjectByHandle(DebugHandle,
		DEBUG_OBJECT_ADD_REMOVE_PROCESS,
		NewDbgObject,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);
	/*Status = ObReferenceObjectByHandle(DebugHandle,
	DEBUG_OBJECT_ADD_REMOVE_PROCESS,
	*(ULONG64*)DbgkDebugObjectType,
	PreviousMode,
	(PVOID*)&DebugObject,
	NULL);*/
	if (!NT_SUCCESS(Status))
	{

		ObDereferenceObject(Process);
		return Status;
	}


	Status = DbgkClearProcessDebugObject(Process, DebugObject);

	//	Debug_ExFreeItem(pdbgmsg);
	ObDereferenceObject(Process);
	ObDereferenceObject(DebugObject);
	return Status;
}


NTSTATUS
NTAPI
DbgkClearProcessDebugObject(IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT SourceDebugObject OPTIONAL)
{
	PDEBUG_OBJECT DebugObject = NULL;
	PDEBUG_EVENT DebugEvent;
	LIST_ENTRY TempList;
	PLIST_ENTRY NextEntry;
	PAGED_CODE();



	ExAcquireFastMutex(&DbgkFastMutex);


	//DebugObject = Process->Pcb.newdbgport;

	DebugObject = Port_GetPort(Process);
	if ((DebugObject) &&
		((DebugObject == SourceDebugObject) ||
		(SourceDebugObject == NULL)))
	{

		//	Process->Pcb.newdbgport = NULL;
		Port_RemoveDbgItem(Process, NULL);
		ExReleaseFastMutex(&DbgkFastMutex);
		//DbgkpMarkProcessPeb(Process);
	}
	else
	{

		ExReleaseFastMutex(&DbgkFastMutex);
		return STATUS_PORT_NOT_SET;
	}

	InitializeListHead(&TempList);


	ExAcquireFastMutex(&DebugObject->Mutex);

	NextEntry = DebugObject->EventList.Flink;
	while (NextEntry != &DebugObject->EventList)
	{

		DebugEvent = CONTAINING_RECORD(NextEntry, DEBUG_EVENT, EventList);
		NextEntry = NextEntry->Flink;


		if (DebugEvent->Process == Process)
		{

			RemoveEntryList(&DebugEvent->EventList);
			InsertTailList(&TempList, &DebugEvent->EventList);
		}
	}


	ExReleaseFastMutex(&DebugObject->Mutex);


	ObDereferenceObject(DebugObject);

	while (!IsListEmpty(&TempList))
	{

		NextEntry = RemoveHeadList(&TempList);
		DebugEvent = CONTAINING_RECORD(NextEntry, DEBUG_EVENT, EventList);


		DebugEvent->Status = STATUS_DEBUGGER_INACTIVE;
		DbgkpWakeTarget(DebugEvent);
	}


	return STATUS_SUCCESS;
}


NTSTATUS __fastcall
DbgkpQueueMessage_2(
	IN PEPROCESS_S Process,
	IN PETHREAD Thread,
	IN OUT PDBGKM_MSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject
)

{
	PDEBUG_EVENT DebugEvent;
	DEBUG_EVENT StaticDebugEvent;
	PDEBUG_OBJECT DebugObject;
	NTSTATUS Status;
	DbgProcess dbgmsg = { 0 };
	/*
	dbgmsg.DebugProcess = Process;
	if (Debug_FindMyNeedData(&dbgmsg)==FALSE)
	{
	return ori_pslp11(Process, Thread, ApiMsg, Flags, TargetDebugObject);
	}*/
	PAGED_CODE();

	if (Flags&DEBUG_EVENT_NOWAIT) {
		DebugEvent = ExAllocatePoolWithQuotaTag(NonPagedPool | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE,
			sizeof(*DebugEvent),
			'EgbD');
		if (DebugEvent == NULL) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		DebugEvent->Flags = Flags | DEBUG_EVENT_INACTIVE;
		ObReferenceObject(Process);
		ObReferenceObject(Thread);
		DebugEvent->BackoutThread = PsGetCurrentThread();
		DebugObject = TargetDebugObject;
	}
	else {
		DebugEvent = &StaticDebugEvent;
		DebugEvent->Flags = Flags;

		ExAcquireFastMutex(&DbgkFastMutex);

		//DebugObject = Process->Pcb.newdbgport;
		//DebugObject = Process->Pcb.newdbgport;
		DebugObject = Port_GetPort(Process);
		//
		// See if this create message has already been sent.
		//
		if (ApiMsg->ApiNumber == DbgKmCreateThreadApi ||
			ApiMsg->ApiNumber == DbgKmCreateProcessApi) {
			if (Thread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG) {
				DebugObject = NULL;
			}
		}
		if (ApiMsg->ApiNumber == DbgKmLoadDllApi &&
			Thread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG &&
			Flags & 0x40) {
			DebugObject = NULL;
		}
		//
		// See if this exit message is for a thread that never had a create
		//
		if (ApiMsg->ApiNumber == DbgKmExitThreadApi ||
			ApiMsg->ApiNumber == DbgKmExitProcessApi) {
			if (Thread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG) {
				DebugObject = NULL;
			}
		}

		KeInitializeEvent(&DebugEvent->ContinueEvent, SynchronizationEvent, FALSE);

	}


	DebugEvent->Process = Process;
	DebugEvent->Thread = Thread;
	DebugEvent->ApiMsg = *ApiMsg;
	DebugEvent->ClientId = Thread->Cid;

	if (DebugObject == NULL) {
		Status = STATUS_PORT_NOT_SET;
	}
	else {

		//
		// We must not use a debug port thats got no handles left.
		//
		ExAcquireFastMutex(&DebugObject->Mutex);

		//
		// If the object is delete pending then don't use this object.
		//
		if ((DebugObject->Flags&DEBUG_OBJECT_DELETE_PENDING) == 0) {
			InsertTailList(&DebugObject->EventList, &DebugEvent->EventList);
			//
			// Set the event to say there is an unread event in the object
			//
			if ((Flags&DEBUG_EVENT_NOWAIT) == 0) {
				KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
			}
			Status = STATUS_SUCCESS;
		}
		else {
			Status = STATUS_DEBUGGER_INACTIVE;
		}

		ExReleaseFastMutex(&DebugObject->Mutex);
	}


	if ((Flags&DEBUG_EVENT_NOWAIT) == 0) {
		ExReleaseFastMutex(&DbgkFastMutex);

		if (NT_SUCCESS(Status)) {
			KeWaitForSingleObject(&DebugEvent->ContinueEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL);

			Status = DebugEvent->Status;
			*ApiMsg = DebugEvent->ApiMsg;
		}
	}
	else {
		if (!NT_SUCCESS(Status)) {
			ObDereferenceObject(Process);
			ObDereferenceObject(Thread);
			ExFreePool(DebugEvent);
		}
	}

	return Status;
}



VOID RemoveDbgtoolMsg(BOOLEAN  isload) {
	if (isload)
	{
		PsSetCreateProcessNotifyRoutine(GetCloseDbgtoolMsg, FALSE);

	}
	else
	{
		PsSetCreateProcessNotifyRoutine(GetCloseDbgtoolMsg, TRUE);

	}

}


VOID GetCloseDbgtoolMsg(
	IN HANDLE hParentId,
	IN HANDLE hProcessId,
	IN BOOLEAN bCreate)
{
	p_save_handlentry Padd = NULL;
	if (!bCreate) {

		Padd = QueryList(PmainList, hProcessId, NULL);
		if (Padd != NULL) {

			DeleteList(Padd);//删除节点
		}

	}

}



NTSTATUS AddAllThreadContextToList(PEPROCESS_S Process) {
	PKTRAP_FRAME pframe = NULL;
	PETHREAD Thread = NULL;

	THREAD_dr_List t = { 0 };
	PPROCESS_List PList = NULL;
	if (Process != NULL)
	{
		PList = Dr_AddProcessToList(Process);
	}
	else
	{
		return FALSE;
	}
	Thread = PsGetNextProcessThread(Process, NULL);
	DbgPrint("Process : %p", Process);
	while (Thread != NULL) {
		DbgPrint("Thread : %p", Thread);
		if (Thread != NULL) {
			if (ExAcquireRundownProtection(&Thread->RundownProtect))
			{
				pframe = PspGetThreadTrapFrame(Thread);

				//Thread->Tcb.TrapFrame;

				DbgPrint("Thread Frame: %p", pframe);
				if (MmIsAddressValid(pframe) == TRUE)
				{
					/*t.Dr0 = ((PLARGE_INTEGER)(pframe->Dr0))->LowPart;
					t.Dr1 = HIDWORD(pframe->Dr1);
					t.Dr2 = HIDWORD(pframe->Dr2);
					t.Dr3 = HIDWORD(pframe->Dr3);
					t.Dr6 = HIDWORD(pframe->Dr6);
					t.Dr7 = HIDWORD(pframe->Dr7);*/
					t.Dr0 = ((PLARGE_INTEGER)(&pframe->Dr0))->LowPart;
					t.Dr1 = ((PLARGE_INTEGER)(&pframe->Dr1))->LowPart;
					t.Dr2 = ((PLARGE_INTEGER)(&pframe->Dr2))->LowPart;
					t.Dr3 = ((PLARGE_INTEGER)(&pframe->Dr3))->LowPart;
					t.Dr6 = ((PLARGE_INTEGER)(&pframe->Dr6))->LowPart;
					t.Dr7 = ((PLARGE_INTEGER)(&pframe->Dr7))->LowPart;
					t.eflag = pframe->EFlags;
					//	pframe->EFlags |= 0x100;;


					//Clear Thread Context
					pframe->Dr0 = 0;
					pframe->Dr1 = 0;
					pframe->Dr2 = 0;
					pframe->Dr3 = 0;
					pframe->Dr6 = 0;
					pframe->Dr7 = 0;

					t.Thread = Thread;
					Dr_AddThreadStructToList(PList, &t);
					DbgPrint("thread: %p dr0: %d dr1 :%d dr2 :%d dr3 :%d dr6:%d dr7:%d", Thread, t.Dr0, t.Dr1, t.Dr2, t.Dr3, t.Dr6, t.Dr7);
				}
				else {


					/////////FIXME
				}

				ExReleaseRundownProtection(&Thread->RundownProtect);


			}



		}



		Thread = PsGetNextProcessThread(Process, Thread);

	}
	return STATUS_SUCCESS;

	/////////////

}


FORCEINLINE PKTRAP_FRAME PspGetThreadTrapFrame(PETHREAD Thread)
{
#define KERNEL_STACK_CONTROL_LENGTH sizeof(KERNEL_STACK_CONTROL)  
#define KTRAP_FRAME_LENGTH sizeof(KTRAP_FRAME)  

	ULONG64 InitialStack;
	PKERNEL_STACK_CONTROL StackControl;
	__try {
		InitialStack = (ULONG64)Thread->Tcb.InitialStack;
		StackControl = (PKERNEL_STACK_CONTROL)InitialStack;
		if (StackControl == NULL)
		{
			DbgPrint("StackControl Thread:%p Is NULL!", Thread);
			return NULL;
		}
		if (MmIsAddressValid(&StackControl->Previous.StackBase) == FALSE)
		{
			return NULL;
		}
		while (StackControl->Previous.StackBase != 0)
		{
			InitialStack = StackControl->Previous.InitialStack;
			StackControl = (PKERNEL_STACK_CONTROL)InitialStack;
		}

	}except(EXCEPTION_EXECUTE_HANDLER) {
		return NULL;

	}



	return (PKTRAP_FRAME)(InitialStack - KTRAP_FRAME_LENGTH);
}
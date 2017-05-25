#pragma once 
#include <ntddk.h>

/////#include "..\KernelStruct\KernelStruct.h"
#ifndef _DBGKTYPES_H
#define _DBGKTYPES_H

//
// Dependencies
//



//
// Debug Object Access Masks
//
#define DEBUG_OBJECT_WAIT_STATE_CHANGE      0x0001
#define DEBUG_OBJECT_ADD_REMOVE_PROCESS     0x0002
#define DEBUG_OBJECT_SET_INFORMATION        0x0004
#define DEBUG_OBJECT_ALL_ACCESS             (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x0F)

//
// Debug Event Flags
//
#define DEBUG_EVENT_READ                  (0x01)
#define DEBUG_EVENT_NOWAIT                (0x02)
#define DEBUG_EVENT_INACTIVE              (0x04)
#define DEBUG_EVENT_RELEASE               (0x08)
#define DEBUG_EVENT_PROTECT_FAILED        (0x10)
#define DEBUG_EVENT_SUSPEND               (0x20)

//
// NtCreateDebugObject Flags
//
#define DBGK_KILL_PROCESS_ON_EXIT         (0x1)
#define DBGK_ALL_FLAGS                    (DBGK_KILL_PROCESS_ON_EXIT)

typedef enum _LPC_TYPE
{
	LPC_NEW_MESSAGE,
	LPC_REQUEST1,
	LPC_REPLY1,
	LPC_DATAGRAM1,
	LPC_LOST_REPLY1,
	LPC_PORT_CLOSED1,
	LPC_CLIENT_DIED1,
	LPC_EXCEPTION1,
	LPC_DEBUG_EVENT1,
	LPC_ERROR_EVENT1,
	LPC_CONNECTION_REQUEST1,
	LPC_CONNECTION_REFUSED,
	LPC_MAXIMUM
} LPC_TYPE;

//
// Debug Object Information Classes for NtQueryDebugObject
//
typedef enum _DEBUGOBJECTINFOCLASS
{
	DebugObjectUnusedInformation,
	DebugObjectKillProcessOnExitInformation
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;

//
// Debug Message API Number
//
typedef enum _DBGKM_APINUMBER
{
	DbgKmExceptionApi = 0,
	DbgKmCreateThreadApi = 1,
	DbgKmCreateProcessApi = 2,
	DbgKmExitThreadApi = 3,
	DbgKmExitProcessApi = 4,
	DbgKmLoadDllApi = 5,
	DbgKmUnloadDllApi = 6,
	DbgKmErrorReportApi = 7,
	DbgKmMaxApiNumber = 8,
} DBGKM_APINUMBER;

//
// Debug Object Information Structures
//
typedef struct _DEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION
{
	ULONG KillProcessOnExit;
} DEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION, *PDEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION;

#ifndef NTOS_MODE_USER

//
// Debug Object
//
typedef struct _DEBUG_OBJECT
{
	KEVENT EventsPresent;
	FAST_MUTEX Mutex;
	LIST_ENTRY64 EventList;
	union
	{
		ULONG Flags;
		struct
		{
			UCHAR DebuggerInactive : 1;
			UCHAR KillProcessOnExit : 1;
		};
	};
} DEBUG_OBJECT, *PDEBUG_OBJECT;

#endif

//
// Debug States
//
typedef enum _DBG_STATE
{
	DbgIdle,
	DbgReplyPending,
	DbgCreateThreadStateChange,
	DbgCreateProcessStateChange,
	DbgExitThreadStateChange,
	DbgExitProcessStateChange,
	DbgExceptionStateChange,
	DbgBreakpointStateChange,
	DbgSingleStepStateChange,
	DbgLoadDllStateChange,
	DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

//
// Debug Message Structures
//
typedef struct _DBGKM_EXCEPTION
{
	EXCEPTION_RECORD ExceptionRecord;
	ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD
{
	ULONG SubSystemKey;
	PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS
{
	ULONG SubSystemKey;
	HANDLE FileHandle;
	PVOID BaseOfImage;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD
{
	NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS
{
	NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL
{
	HANDLE FileHandle;
	PVOID BaseOfDll;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL
{
	PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;

//
// User-Mode Debug State Change Structure
//
typedef struct _DBGUI_WAIT_STATE_CHANGE
{
	DBG_STATE NewState;
	CLIENT_ID AppClientId;
	union
	{
		struct
		{
			HANDLE HandleToThread;
			DBGKM_CREATE_THREAD NewThread;
		} CreateThread;
		struct
		{
			HANDLE HandleToProcess;
			HANDLE HandleToThread;
			DBGKM_CREATE_PROCESS NewProcess;
		} CreateProcessInfo;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_EXCEPTION Exception;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	} StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;
typedef struct _PORT_MESSAGE
{
	union
	{
		struct
		{
			CSHORT DataLength;
			CSHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			CSHORT Type;
			CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG32 MessageId;
	union
	{
		ULONGLONG ClientViewSize;
		ULONG32 CallbackId;
	};
} PORT_MESSAGE, *PPORT_MESSAGE;
//
// LPC Debug Message
//
typedef struct _DBGKM_MSG
{
	PORT_MESSAGE h;
	DBGKM_APINUMBER ApiNumber;
	NTSTATUS ReturnedStatus;
	union
	{
		DBGKM_EXCEPTION Exception;
		DBGKM_CREATE_THREAD CreateThread;
		DBGKM_CREATE_PROCESS CreateProcess;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	};
	UCHAR unknow[0x40];
} DBGKM_MSG, *PDBGKM_MSG;

#ifndef NTOS_MODE_USER

//
// Debug Event
//
typedef struct _DEBUG_EVENT
{
	LIST_ENTRY EventList;
	KEVENT ContinueEvent;
	CLIENT_ID ClientId;
	PEPROCESS Process;
	PETHREAD Thread;
	NTSTATUS Status;
	ULONG32 Flags;
	PETHREAD BackoutThread;
	DBGKM_MSG ApiMsg;

} DEBUG_EVENT, *PDEBUG_EVENT;


#endif

#endif



NTSTATUS InitDbgKernel();
NTSTATUS __fastcall proxyNtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags);

NTSTATUS
__fastcall
proxyNtWaitForDebugEvent(IN HANDLE DebugHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PDBGUI_WAIT_STATE_CHANGE StateChange);

NTSTATUS
NTAPI
proxyNtDebugContinue(IN HANDLE DebugHandle,
	IN PCLIENT_ID AppClientId,
	IN NTSTATUS ContinueStatus);

VOID DbgkpOpenHandles(IN PDBGUI_WAIT_STATE_CHANGE WaitStateChange, IN PEPROCESS Process, IN PETHREAD Thread);

VOID DbgkpConvertKernelToUserStateChange(IN PDBGUI_WAIT_STATE_CHANGE WaitStateChange, IN PDEBUG_EVENT DebugEvent);

BOOLEAN proxyDbgkForwardException(IN PEXCEPTION_RECORD ExceptionRecord, IN BOOLEAN DebugPort, IN BOOLEAN SecondChance);

BOOLEAN DbgkpSuspendProcess(VOID);

NTSTATUS DbgkpSendApiMessage_2(IN OUT PDBGKM_MSG ApiMsg, IN BOOLEAN SuspendProcess);

VOID DbgkpResumeProcess(VOID);

BOOLEAN MarkDbgProcess();



NTSTATUS
__fastcall
proxyNtDebugActiveProcess(IN HANDLE ProcessHandle,
	IN HANDLE DebugHandle);



NTSTATUS
NTAPI
NtRemoveProcessDebug(IN HANDLE ProcessHandle,
	IN HANDLE DebugHandle);

VOID RemoveDbgtoolMsg(BOOLEAN isload);

VOID GetCloseDbgtoolMsg(IN HANDLE hParentId, IN HANDLE hProcessId, IN BOOLEAN bCreate);

FORCEINLINE PKTRAP_FRAME PspGetThreadTrapFrame(PETHREAD Thread);



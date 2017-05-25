#include <ntddk.h>
typedef struct _DbgProcess
{
	LIST_ENTRY64 DbgProcessList;
	PEPROCESS DebugProcess;
	PEPROCESS Process;
	POBJECT_TYPE DebugObject;
	HANDLE DbgHanle;
}DbgProcess, *PDbgProcess;
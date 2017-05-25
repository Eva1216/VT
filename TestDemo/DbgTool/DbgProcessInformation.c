#include "DbgProcessInformation.h"

typedef struct _DbgProcess
{
	LIST_ENTRY64 DbgProcessList;
	PEPROCESS DebugProcess;
	PEPROCESS Process;
	POBJECT_TYPE DebugObject;
	HANDLE DbgHanle;
}DbgProcess, *PDbgProcess;

static LIST_ENTRY64 DbgList;
static KSPIN_LOCK d_lock;

VOID InitialzeDbgprocessList() {

	KeInitializeSpinLock(&d_lock);
	InitializeListHead(&DbgList);
}
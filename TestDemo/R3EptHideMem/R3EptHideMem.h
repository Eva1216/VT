#pragma once
#include <ntddk.h>
#include "..\Intel\VMX.h"
#include "..\DbgTool\DbgTool.h"
#include "..\Intel\EPT.h"

typedef struct _R3EPT_HOOK {
	ULONG64 Code_PAGE_VA;
	ULONG64 Code_PAGE_PFN;
	ULONG64 Data_PAGE_VA;
	ULONG64 Data_PAGE_PFN;
	ULONG64 OriginalPtr;
	PEPROCESS TargetProcess;
	ULONG64 TargetCr3;
	BOOLEAN IsHook;
	PMDL mdl;
	ULONG RefCount;
	LIST_ENTRY PageList;
}R3EPT_HOOK, *PR3EPT_HOOK;
VOID InitialzeR3EPTHOOK();
BOOLEAN R3_HideMEM_Violation(IN PGUEST_STATE GuestState);

PR3EPT_HOOK Page_FindStructByGvaBase(ULONG64 GVA);

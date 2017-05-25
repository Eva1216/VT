#pragma ocne 
#include <ntddk.h>

NTSTATUS ObProtectProcess(BOOLEAN Enable);

OB_PREOP_CALLBACK_STATUS preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);

OB_PREOP_CALLBACK_STATUS preCall2(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);

BOOLEAN IsProtectedProcess(PEPROCESS eprocess);

VOID RemoveListEntry(PLIST_ENTRY ListEntry);

VOID UnhookKernelApi(IN PVOID ApiAddress, IN PVOID OriCode, IN ULONG PatchSize);

VOID unload();

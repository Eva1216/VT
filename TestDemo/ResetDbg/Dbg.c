#include "Dbg.h"

ULONG64 fc_DbgkGetAdrress(PUNICODE_STRING64 FunctionName) {
	UNICODE_STRING64 usFuncName;
	RtlInitUnicodeString(&usFuncName, FunctionName);
	return MmGetSystemRoutineAddress(&usFuncName);

}
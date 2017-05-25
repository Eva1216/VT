#include "AntiHookSwapContext.h"

ULONG64 SwapContext_PatchXRstor;
ULONG64 SwapContext;
ULONG64 jmp_SwapContextTp;
ULONG64 jmp_SwapContext_PatchXRstor;
ULONG64 jmp_SwapContext;
VOID InitializeHookSwapContext() {

	jmp_SwapContext_PatchXRstor = SwapContext_PatchXRstor + 0x121;

	jmp_SwapContext = SwapContext + 0x29;
	jmp_SwapContextTp = SwapContext + 0x1B;

}
#pragma once

#include <ntddk.h>

VOID LoadProtectWindow();

KIRQL WPOFFx64();

VOID WPONx64(KIRQL irql);

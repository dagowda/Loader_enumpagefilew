#include <windows.h>
#include <iostream>
#include <cstring>
#include <shlwapi.h> // Make sure this is included for PathStripPath

#pragma comment(lib, "shlwapi.lib") // Automatically link the library

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID Reserved1[2];
    PVOID DllBase;
    PVOID Reserved2[2];
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PPEB_LDR_DATA Ldr;  // The loader data table
} PEB, *PPEB;

HMODULE MyGetModuleHandleA(LPCSTR moduleName) {
    PPEB peb = (PPEB)__readgsqword(0x60);  // Correct for x64
    if (!peb) {
        std::cerr << "[ERROR] Failed to get PEB\n";
        return NULL;
    }

    std::cout << "[DEBUG] Got PEB at: " << peb << "\n";

    // Use manual offset to extract LDR
    PPEB_LDR_DATA ldr = *(PPEB_LDR_DATA*)((BYTE*)peb + 0x18);
    if (!ldr || ldr == (PPEB_LDR_DATA)-1) {
        std::cerr << "[ERROR] Invalid LDR address: " << ldr << "\n";
        return NULL;
    }
    std::cout << "[DEBUG] Got LDR at: " << ldr << "\n";

    PLIST_ENTRY moduleList = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY entry = moduleList->Flink;

    while (entry && entry != moduleList) {
        PLDR_DATA_TABLE_ENTRY moduleEntry = (PLDR_DATA_TABLE_ENTRY)entry;
        if (!moduleEntry || moduleEntry == (PLDR_DATA_TABLE_ENTRY)-1) {
            std::cerr << "[ERROR] Invalid module entry\n";
            return NULL;
        }

        char moduleBaseName[MAX_PATH] = {0};
        int nameLen = WideCharToMultiByte(CP_ACP, 0, moduleEntry->BaseDllName.Buffer,
                                          moduleEntry->BaseDllName.Length / sizeof(WCHAR),
                                          moduleBaseName, MAX_PATH, NULL, NULL);
        moduleBaseName[nameLen] = '\0';

        // Log the full module name for debugging
        std::cout << "[DEBUG] Found module: " << moduleBaseName << "\n";

        // Extract base module name from path (if it's a full path)
        PathStripPath(moduleBaseName);  // Remove the path, leave just the base name

        std::cout << "[DEBUG] Base module name: " << moduleBaseName << "\n";  // Added debug for the base name

        // Case-insensitive comparison using _stricmp
        if (_stricmp(moduleBaseName, moduleName) == 0) {
            std::cout << "[SUCCESS] Found module: " << moduleName
                      << " at " << moduleEntry->DllBase << "\n";
            return (HMODULE)moduleEntry->DllBase;
        }

        entry = entry->Flink;
    }

    std::cerr << "[ERROR] Module not found: " << moduleName << "\n";
    return NULL;
}

int main() {
    std::cout << "[INFO] Looking for kernel32.dll...\n";
    HMODULE hKernel32 = MyGetModuleHandleA("KERNEL32.DLL");
    if (hKernel32) {
        std::cout << "[SUCCESS] kernel32.dll found at: " << hKernel32 << "\n";
    } else {
        std::cerr << "[ERROR] Failed to locate kernel32.dll\n";
    }
    return 0;
}

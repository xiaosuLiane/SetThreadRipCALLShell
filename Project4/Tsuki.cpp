#include <iostream>
#include <Windows.h>
using namespace std;

int main()
{
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    CONTEXT threadContent = { 0 };
    RtlZeroMemory(&si, sizeof(si));
    RtlZeroMemory(&pi, sizeof(pi));
    RtlZeroMemory(&threadContent, sizeof(threadContent));
    si.cb = sizeof(si);
    if (!CreateProcess("C:\\Users\\fw\\Desktop\\a.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        cout << "����һ���½��̳�����һ������." << endl; return 0;
    }
    BYTE Shellcode[] = {
        0xB8,0x16,0x13,0x40,0x00,0xFF,0xD0,0xB8,0xCB,0x11,0x40,0x00,0xFF,0xE0
    };
    LPVOID VirtualAddress = VirtualAllocEx(pi.hProcess, NULL, sizeof(Shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (VirtualAddress == NULL)
    {
        cout << "�����ڴ����." << endl; return 0;
    }

    if (WriteProcessMemory(pi.hProcess, VirtualAddress, Shellcode, sizeof(Shellcode), NULL) == NULL)
    {
        cout << "д��Shellcode����." << endl; return 0;
    }
    threadContent.ContextFlags = CONTEXT_FULL;
    if (GetThreadContext(pi.hThread, &threadContent) == NULL)
    {
        cout << "���ThreadContext����." << endl; return 0;
    }
    threadContent.Rip = (DWORD)VirtualAddress;
    if (SetThreadContext(pi.hThread, &threadContent) == NULL)
    {
        cout << "����ThreadContext����." << endl; return 0;
    }
    ResumeThread(pi.hThread);
    return 0;
} 
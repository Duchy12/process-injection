#include  <windows.h>

/*
BOOL WINAPI DllMain(
  _In_ HINSTANCE hinstDLL,
  _In_ DWORD     fdwReason,
  _In_ LPVOID    lpvReserved
);
*/


BOOL WINAPI DllMain(HINSTANCE hModule, DWORD Reason, LPVOID lpvReserved)
{
	switch (Reason)
	{
		case DLL_PROCESS_ATTACH:
			MessageBox(NULL, L"Hello from DLL", L"Hi", MB_OK);
			break;
	}
	return TRUE;
}
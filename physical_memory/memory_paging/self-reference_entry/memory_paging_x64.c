#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

int main() {

	HANDLE pid;
	pid = GetCurrentProcess();
	ULONGLONG allocate_address = 0x0000000044444444;
	LPVOID allocate_buffer;
	allocate_buffer = VirtualAlloc((LPVOID*)allocate_address, 0x20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (allocate_buffer == NULL) {
		printf("[!] Error while allocating shellcode: %d\n", GetLastError());
		return 1;
	}
	
	char *allocation_buffer;
	DWORD allocation_size = 0x20;
	allocation_buffer = (char *)malloc(allocation_size);
	memset(allocation_buffer, 0x41, allocation_size);

	BOOL WPMresult;
	SIZE_T written;
	WPMresult = WriteProcessMemory(pid, (LPVOID)allocate_address, allocation_buffer, allocation_size, &written);
	if (WPMresult == 0)
	{
		printf("[!] Error while calling WriteProcessMemory: %d\n", GetLastError());
		return 1;
	}

	printf("[+] Memory allocated at: %I64x\n", allocate_address);
	printf("[+] Press ENTER to trigger the vulnerability\n");
	getchar();
	
	return 0;
}

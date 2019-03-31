// download_file_example.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <stdio.h>
#include <urlmon.h> //"urlmon.h: No such file or directory found"
#pragma comment(lib, "urlmon.lib")

int main()
{

	const char *dst = "C:\\Users\\sickness\\Desktop\\test.txt";
	const char *url = "http://192.168.25.129/index.html";
	char file[MAX_PATH];

	HRESULT hr;
	//hr = URLDownloadToFileA(NULL, LPCSTR(url), LPCSTR(dst), 0, 0);
	hr = URLDownloadToCacheFileA(NULL, LPCSTR(url), LPSTR(file), MAX_PATH, 0, 0);
	if (hr == S_OK) {
		printf("w00t!\n");
		printf("%s\n", file);
	}
	else {
		printf(":(\n");
		return 1;
	}

	return 0;
}
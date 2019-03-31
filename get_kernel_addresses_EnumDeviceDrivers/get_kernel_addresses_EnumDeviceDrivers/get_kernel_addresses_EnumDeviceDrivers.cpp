// get_kernel_addresses_EnumDeviceDrivers.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <Psapi.h>

#pragma comment (lib,"psapi")

LPVOID GetBaseAddr(const char *drvname) {

	LPVOID drivers[1024];
	DWORD cbNeeded;
	int nDrivers, i = 0;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {

		char szDrivers[1024];
		nDrivers = cbNeeded / sizeof(drivers[0]);
		for (i = 0; i < nDrivers; i++) {
			if (GetDeviceDriverBaseNameA(drivers[i], szDrivers, sizeof(szDrivers) / sizeof(szDrivers[0]))) {
				if (strcmp(szDrivers, drvname) == 0) {
					//printf("%s (%p)\n", szDrivers, drivers[i]);
					return drivers[i];
				}
			}
		}
	}
	return 0;
}

int main() {

	LPVOID kernel_base = GetBaseAddr("ntoskrnl.exe");
	LPVOID hal_base = GetBaseAddr("hal.dll");
	printf("[+] Kernel found at: %p\n", kernel_base);
	printf("[+] HAL.dll found at: %p\n", hal_base);

	return 0;
}
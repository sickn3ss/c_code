// get_kernel_addresses_NtQuerySystemInformation.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"

#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <WinIoCtl.h>
#include <string.h>
#include <stdio.h>



typedef struct {
	PVOID   Unknown1;
	PVOID   Unknown2;
	PVOID   Base;
	ULONG   Size;
	ULONG   Flags;
	USHORT  Index;
	USHORT  NameLength;
	USHORT  LoadCount;
	USHORT  PathLength;
	CHAR    ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct {
	ULONG   Count;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11,
	SystemHandleInformation = 16
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI *_NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(__stdcall *_NtQueryIntervalProfile)(DWORD ProfileSource, PULONG Interval);
typedef NTSTATUS(__stdcall *_NtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress,
	ULONG_PTR ZeroBits, PSIZE_T RegionSize,
	ULONG AllocationType, ULONG Protect);


FARPROC GetKernAddr(HMODULE UserKernBase, PVOID RealKernBase, LPCSTR FunctionName) {

	PUCHAR KernBase = (PUCHAR)UserKernBase;
	PUCHAR RealBase = (PUCHAR)RealKernBase;
	PUCHAR FuncAddr = (PUCHAR)GetProcAddress(UserKernBase, FunctionName);
	if (FuncAddr == NULL) {
		printf(" [>] Error while getting the address of %s", FunctionName);
		return FALSE;
	}

	FARPROC RealAddr;
	RealAddr = (FARPROC)(FuncAddr - KernBase + RealBase);
	printf(" [>] %s address: %p\n", FunctionName, RealAddr);
	return RealAddr;
}

BOOL GetKernelBase() {

	_NtQuerySystemInformation NtQuerySystemInformation;
	PSYSTEM_MODULE_INFORMATION pModuleInfo;

	HMODULE ntdllHandle;
	ntdllHandle = GetModuleHandleA("ntdll.dll");
	if (!ntdllHandle) {
		printf(" [>] Failed while getting a handle to ntdll.\n");
		return FALSE;
	}

	NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdllHandle, "NtQuerySystemInformation");
	if (!NtQuerySystemInformation) {
		printf(" [>] Failed while getting the NtQuerySystemInformation function.\n");
		return FALSE;
	}

	ULONG len, i;
	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
	pModuleInfo = (PSYSTEM_MODULE_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
	NtQuerySystemInformation(SystemModuleInformation, pModuleInfo, len, &len);

	PVOID kernelBase;
	char kernelImage[256];

	strcpy(kernelImage, pModuleInfo->Module[0].ImageName);
	kernelBase = pModuleInfo->Module[0].Base;
	printf(" [>] Kernel version: %s\n", kernelImage);
	printf(" [>] Kernel base address: %p\n", kernelBase);

	int h;
	for (h = 0; h < pModuleInfo->Count; h++) {
		if (strstr(pModuleInfo->Module[h].ImageName, "hal.dll") != NULL) {
			printf(" [>] Found the %s base addr: %p\n", pModuleInfo->Module[h].ImageName, pModuleInfo->Module[h].ImageName);
		}
	}

	LPSTR load_kernel;
	load_kernel = strrchr(kernelImage, '\\');
	HMODULE KHandle;
	KHandle = LoadLibraryA(++load_kernel);
	if (KHandle == NULL) {
		return FALSE;
	}

	ULONG_PTR HalDispatchTable;
	HalDispatchTable = (ULONG_PTR)GetKernAddr(KHandle, kernelBase, "HalDispatchTable");

	return TRUE;
}

int main() {

	GetKernelBase();
	return 0;
}
#include <wdm.h>

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	(void)DriverObject, (void)RegistryPath;
	const char* pTest = "Hello, World\n";
	DbgPrint("%s", pTest);
	DbgBreakPoint();
	return STATUS_NOT_IMPLEMENTED;
}
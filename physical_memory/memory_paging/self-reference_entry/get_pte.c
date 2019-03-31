#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

_int64 get_pxe_address_64(_int64 address) {

	_int64 result = address >> 9;
	result = result | 0xFFFFF68000000000;
	result = result & 0xFFFFF6FFFFFFFFF8;
	return result;

}

int get_pxe_address_86(int address) {

	int result = address >> 9;
	result = result | 0xC0000000;
	result = result & 0xC07FFFF8;
	return result;

}

int main() {

	_int64 address_x64 = 0x0000000044000000;
	_int64 result_x64 = get_pxe_address_64(address_x64);
	printf("[>] x64 PTE entry for %llx is %llx\n", address_x64, result_x64);
	
	int address_x86 = 0x044000000;
	int result_x86 = get_pxe_address_86(address_x86);
	printf("[>] x86 PTE entry for %lx is %lx\n", address_x86, result_x86);
	
	return 0;

}
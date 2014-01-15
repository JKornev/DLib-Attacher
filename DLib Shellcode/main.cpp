#include "main.h"
#include "../DLib Attacher/DLibShellStructs.h"
#include <stdio.h>
#include <stdarg.h>

extern struct Shellcode_Struct data;

int main()
{
	printf("My address: %p", GetModuleHandle(NULL));
/*
	LoadLibraryExW((LPWSTR)"testlib.dll", NULL, 0);
	printf("GetLE %d", GetLastError());*/
	getchar();
	return 0;
}

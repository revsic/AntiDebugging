#include <Windows.h>
#include <TlHelp32.h>
#include <DbgHelp.h>

#include <stdio.h>
#include <string.h>

#include <thread>

typedef struct {
	LPVOID lpVirtualAddress;
	DWORD dwSizeOfRawData;
} SECTIONINFO, *PSECTIONINFO;

typedef struct {
	DWORD64 dwRealHash;
	SECTIONINFO SectionInfo;
} HASHSET, *PHASHSET;

HMODULE GetCurrentModule() {
	MODULEENTRY32W mEntry;
	memset(&mEntry, 0, sizeof(mEntry));
	mEntry.dwSize = sizeof(MODULEENTRY32);

	HMODULE hCurrentModule = NULL;
	DWORD curPid = GetCurrentProcessId();

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, NULL);
	if (Module32FirstW(hSnapshot, &mEntry)) {
		do {
			if (mEntry.th32ProcessID == curPid && wcsstr(mEntry.szModule, L"exe")) {
				hCurrentModule = mEntry.hModule;
			}
		} while (Module32NextW(hSnapshot, &mEntry));
	}

	CloseHandle(hSnapshot);

	return hCurrentModule;
}

int GetTextSectionInfo(PSECTIONINFO info) {
	HMODULE hCurrentModule = GetCurrentModule();
	if (hCurrentModule == NULL) {
		return -1;
	}

	PIMAGE_NT_HEADERS pNtHdr = ImageNtHeader(hCurrentModule);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(pNtHdr + 1);

	LPVOID lpTextAddr = NULL;
	DWORD dwSizeOfRawData = NULL;

	for (int i = 0; i < pNtHdr->FileHeader.NumberOfSections; ++i) {
		char *name = (char *)pSectionHeader->Name;

		if (!strcmp(name, ".text")) {
			info->lpVirtualAddress = (LPVOID)((DWORD64)hCurrentModule + pSectionHeader->VirtualAddress);
			info->dwSizeOfRawData = pSectionHeader->SizeOfRawData;
			break;
		}

		++pSectionHeader;
	}

	if (info->dwSizeOfRawData == NULL) {
		return -1;
	}

	return 0;
}

DWORD64 HashSection(LPVOID lpSectionAddress, DWORD dwSizeOfRawData) {
	DWORD64 hash = 0;
	PBYTE str = (PBYTE)lpSectionAddress;
	for (int i = 0; i < dwSizeOfRawData; ++i) {
		if (*str) {
			hash = *str + (hash << 6) + (hash << 16) - hash;
		}
	
		++str;
	}

	return hash;
}

bool bTerminateThread = false;

void CheckTextHash(PHASHSET pHashSet) {
	DWORD64 dwRealHash = pHashSet->dwRealHash;
	DWORD dwSizeOfRawData = pHashSet->SectionInfo.dwSizeOfRawData;
	LPVOID lpVirtualAddress = pHashSet->SectionInfo.lpVirtualAddress;

	while (1) {
		Sleep(1000);

		DWORD64 dwCurrentHash = HashSection(lpVirtualAddress, dwSizeOfRawData);
		if (dwRealHash != dwCurrentHash) {
			MessageBoxW(NULL, L"DebugAttached", L"WARN", MB_OK);
			exit(1);
		}

		if (bTerminateThread) {
			return;
		}
	}
}

int ExitThread(std::thread& thread) {
	bTerminateThread = true;
	thread.join();

	return 0;
}

int main() {
	SECTIONINFO info;
	GetTextSectionInfo(&info);

	DWORD64 dwRealHash = HashSection(info.lpVirtualAddress, info.dwSizeOfRawData);
	PHASHSET pHashSet = new HASHSET;

	pHashSet->dwRealHash = dwRealHash;
	pHashSet->SectionInfo = info;

	std::thread checksum(CheckTextHash, pHashSet);

	int num1, num2;
	printf("[*] num1 num2 : ");
	scanf("%d %d", &num1, &num2);

	printf("[*] result : %d\n\n", num1 + num2);

	printf("[*] wait for terminating thread..\n");
	ExitThread(checksum);

	return 0;
}

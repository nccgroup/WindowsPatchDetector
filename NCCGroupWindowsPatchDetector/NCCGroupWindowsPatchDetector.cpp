/*
A Microsoft Windows in-memory versus disk verification

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/olliencc/WindowsPatchDetector

Released under AGPL see LICENSE for more information
*/

#include "stdafx.h"

// Global 
HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
bool bVerbose = false;

_NtQueryInformationProcess __NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueryInformationProcess");


//
// Function	: AnalyzeModule
// Role		: Analyze the particular module, find its .text section in memory and disk
//            then compare the two.
// Notes	: This function uses code from this 1996 article by the legend Matt Pietrek
//            http://www.microsoft.com/msj/archive/S2058.aspx
//
bool IsInRelocation(VOID *dataRelocation, USHORT RelocationSize, DWORD dwOffset, PVOID pBaseAddress){


	//
	// OK we've read the base relocations table into our space now
	//  - http://www.pelib.com/resources/luevel.txt
	//  - https://github.com/Cr4sh/DrvHide-PoC/blob/master/driver/src/ldr.cpp
	//  - http://uninformed.org/index.cgi?v=6&a=3&p=2
	// 
	
	ULONG Size = 0;
	PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)dataRelocation;
	while (RelocationSize > Size && pRelocation->SizeOfBlock)
	{
		ULONG Number = (pRelocation->SizeOfBlock - 8) / 2;
		PUSHORT Rel = (PUSHORT)((PUCHAR)pRelocation + 8);

		//fprintf(stdout, "[i] %p of %u\n", ((DWORD)pBaseAddress + pRelocation->VirtualAddress), pRelocation->SizeOfBlock);
		//fprintf(stdout, "[i] %p of %u\n", pRelocation->VirtualAddress, pRelocation->SizeOfBlock);


		for (ULONG i = 0; i < Number; i++)
		{
			if (Rel[i] > 0)
			{
				USHORT Type = (Rel[i] & 0xF000) >> 12;

				DWORD Addr = (DWORD)((DWORD)pBaseAddress + pRelocation->VirtualAddress + (Rel[i] & 0x0FFF));
				DWORD Addr2 = (DWORD)(pRelocation->VirtualAddress + (Rel[i] & 0x0FFF));
			
				fprintf(stdout, "[i] %p %p %p \n", Addr, Addr2, dwOffset);

				//if (Type == IMAGE_REL_BASED_HIGHLOW){
					if (dwOffset >= Addr2 && dwOffset <= (Addr2 + 4)) {
						return true;
					}
				//}
			}
		}

		pRelocation = (PIMAGE_BASE_RELOCATION)((PUCHAR)pRelocation + pRelocation->SizeOfBlock);
		Size += pRelocation->SizeOfBlock;
	}


	return false;
}


//
// Function	: AnalyzeModule
// Role		: Analyze the particular module, find its .text section in memory and disk
//            then compare the two.
// Notes	: This function uses code from this 1996 article by the legend Matt Pietrek
//            http://www.microsoft.com/msj/archive/S2058.aspx
//
void AnalyzeModule(HANDLE hProcess, PVOID pBaseAddress, DWORD dwSize, HANDLE hFile, TCHAR *strDLLName)
{
	unsigned char *pFileMem = (unsigned char *)malloc(dwSize);
	unsigned char *pFileMemCmp = pFileMem;
	unsigned char *pFileDisk = (unsigned char *)malloc(dwSize);
	unsigned char *pFileDiskPtr = pFileDisk;
	VOID *dataRelocation = NULL;
	ULONG RelocationSize = 0;

	memset(pFileMem, 0x00, dwSize);
	memset(pFileDisk, 0x00, dwSize);

	SIZE_T szReadMem = 0;
	SIZE_T szReadDisk = 0;
	DWORD dwDiffs = 0;

	if (pFileMem == NULL) {
		fprintf(stdout, "[!] Failed to allocate for memory read %d\n", dwSize);
		return;
	}
	if (pFileDisk == NULL) {
		fprintf(stdout, "[!] Failed to allocate for memory read %d\n", dwSize);
		free(pFileDisk);
		return;
	}


	//
	// Some reading in the different headers we need i.e. DOS then NT
	//
	IMAGE_DOS_HEADER imgDOSHdr;
	if (!ReadProcessMemory(hProcess, pBaseAddress, &imgDOSHdr, sizeof(imgDOSHdr), &szReadMem))
	{
		free(pFileMem);
		free(pFileDisk);
		return;
	}

	// fprintf(stdout, "[i] Offset of PE header %p\n", imgDOSHdr.e_lfanew);
	DWORD peHdrOffs = (DWORD)pBaseAddress + imgDOSHdr.e_lfanew;

	IMAGE_NT_HEADERS ntHdr;

	if (!ReadProcessMemory(hProcess, (PVOID)peHdrOffs, &ntHdr, sizeof(ntHdr), &szReadMem))
	{
		free(pFileMem);
		free(pFileDisk);
		return;
	}


	if (IMAGE_NT_SIGNATURE != ntHdr.Signature)
	{
		free(pFileMem);
		free(pFileDisk);
		return;
	}

	//
	// This is all related to finding and reading the base relocations
	//
	fprintf(stdout, "[i] relocations at %08x of %u bytes\n", ((DWORD)pBaseAddress + ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress), ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

	if (ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
		dataRelocation = malloc(ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
		if (dataRelocation == NULL){
			free(pFileMem);
			free(pFileDisk);
			return;
		}
		else {
			DWORD dwBaseRelocAddress = (DWORD)pBaseAddress + ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
			if (!ReadProcessMemory(hProcess,
				(LPCVOID)dwBaseRelocAddress,
				dataRelocation,
				ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size,
				&szReadMem))
			{
				fprintf(stdout, "[!] Failed to read base relocations\n");
				free(pFileMem);
				free(pFileDisk);
				free(dataRelocation);
				return;
			}

			RelocationSize = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		}
	}

	//
	// This works out where the .text is we need in memory
	//
	PVOID sectionHdrOffs = (PVOID)(
		peHdrOffs
		+ FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader)
		+ ntHdr.FileHeader.SizeOfOptionalHeader);

	#define MAX_SECTIONS 128

	IMAGE_SECTION_HEADER sections[MAX_SECTIONS];
	PIMAGE_SECTION_HEADER pSection;


	DWORD cSections = min(ntHdr.FileHeader.NumberOfSections, MAX_SECTIONS);

	if (!ReadProcessMemory(hProcess,
		sectionHdrOffs,
		&sections,
		cSections * IMAGE_SIZEOF_SECTION_HEADER,
		&szReadMem))
	{
		free(pFileMem);
		free(pFileDisk);
		free(dataRelocation);
		return;
	}


	// Loop through and the find the modules
	// main code section (.text)
	char strSection[MAX_PATH] = { 0 };
	DWORD dwSection = 0;
	pSection = (PIMAGE_SECTION_HEADER)&sections;
	bool bFound = false;
	for (DWORD i = 0; i < cSections; i++, pSection++)
	{
		DWORD endRVA = pSection->VirtualAddress
			+ max(pSection->SizeOfRawData, pSection->Misc.VirtualSize);
		strcpy_s(strSection, (char *)pSection->Name);
		if (strcmp(strSection, ".text") == 0){
			bFound = true;
			break;
		}
	}

	// OK we've found it now compare the RAM
	// versus disk version
	if (bFound == true){
		_ftprintf(stdout, TEXT("[i] Module %s .text section at virtual address %p has %d relocations\n"), strDLLName, ((DWORD)pBaseAddress + pSection->VirtualAddress), pSection->NumberOfRelocations);

		// Read the process copy
		if (ReadProcessMemory(hProcess, (PVOID)((DWORD)pBaseAddress + pSection->VirtualAddress), pFileMem, pSection->Misc.VirtualSize, &szReadMem)){
			//fprintf(stdout, "[i] Read process memory copy - asked for %d got %d\n", pSection->Misc.VirtualSize, szReadMem);
		}
		else {
			fprintf(stdout, "[!] Failed process memory read %d\n", GetLastError());
		}

		if (ReadFile(hFile, pFileDisk, dwSize, &szReadDisk, NULL)){
			//fprintf(stdout, "[i] Read disk copy - asked for %d got %d\n", dwSize, szReadDisk);
		}
		else {
			fprintf(stdout, "[!] Failed disk read with %d of %d bytes at %p\n", GetLastError(), pSection->Misc.VirtualSize, pSection->PointerToRawData);
		}


		if ((pSection->PointerToRawData + pSection->Misc.VirtualSize) > dwSize)
		{
			fprintf(stdout, "[!] Pointer looks duff\n"); 
		}
		else 
		{
			// Move the pointer on to sections data
			pFileDiskPtr += pSection->PointerToRawData;

			if (memcmp(pFileMem, pFileDiskPtr, pSection->Misc.VirtualSize) == 0){
				//fprintf(stdout, "[*****] Same\n");
			}
			else {
				//fprintf(stdout, "[!!!!!] Different\n");
				
				dwDiffs = 0;
				for (DWORD dwCount = 0; dwCount < pSection->Misc.VirtualSize; dwCount++){
					if (memcmp(pFileMemCmp, pFileDiskPtr, 1) != 0)  {
						if (bVerbose == true) fprintf(stdout, "[diff] Offset %08x (of %08x: %02x versus %02x diff %02x\n", dwCount, pSection->Misc.VirtualSize, *pFileMemCmp, *pFileDiskPtr, (*pFileMemCmp - *pFileDiskPtr) & 0xff);
						if (IsInRelocation(dataRelocation, RelocationSize, dwCount, pBaseAddress)){
							
						}
						else{
							dwDiffs++;
							
						}
					}
					pFileMemCmp++;
					pFileDiskPtr++;
				}
				fprintf(stdout, "[!] %d bytes different from a total of %d \n", dwDiffs, pSection->Misc.VirtualSize);
			}
		}
	}
	
	free(pFileMem);
	free(pFileDisk);
	free(dataRelocation);
}

//
// Function	: AnalyzePEB
// Role		: For a given process handle analyze the PEB
//            to get the location of modules and then
//            pass off the memory analysis routine
// Notes	: 
// 
void AnalyzePEB(HANDLE hProcess)
{


	PPEB_LDR_DATA pLDRE = NULL;
	//LIST_ENTRY lstEntry;
	VOID *pInfo = (VOID *)malloc(sizeof(PVOID) * 6);


	NTSTATUS ntStatus = __NtQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		pInfo, // 
		sizeof(PVOID) * 6,
		NULL);

	// TODO: Check here for return for above function

	// Copy the PEB to our address space
	PPEB pPEB = (PPEB)((PVOID*)pInfo)[1];
	PEB PEBCopy;
	PEB_LDR_DATA PEBLDRData;

	BOOL bRes = ReadProcessMemory(hProcess, pPEB, &PEBCopy, sizeof(PEB), NULL);
	if (bRes == 0){
		fprintf(stdout, "[!] +-- Error during ReadProcessMemory in AnalyzePEB - PEB - %d\n", GetLastError());
		return;
	}
	else
	{
		// fprintf(stdout, "[i] PEB Address %p - Session ID %u - Being Debuged %d \n",PEBCopy.Ldr, PEBCopy.SessionId,PEBCopy.BeingDebugged);
	}

	// Copy the PEB LDR to our address space
	bRes = ReadProcessMemory(hProcess, PEBCopy.Ldr, &PEBLDRData, sizeof(PEB_LDR_DATA), NULL);
	if (bRes == 0){
		fprintf(stdout, "[!] +-- Error during ReadProcessMemory in AnalyzePEB - PEBLDRData - %d\n", GetLastError());
		return;
	}
	else
	{
		//fprintf(stdout, "[i] Top of module list at %p\n", PEBLDRData.InMemoryOrderModuleList.Flink);
	}

	LIST_ENTRY* pMod = PEBLDRData.InMemoryOrderModuleList.Flink;
	LIST_ENTRY* pStart = pMod;
	do
	{
		LDR_DATA_TABLE_ENTRY* entryBase = CONTAINING_RECORD(pMod, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		LDR_DATA_TABLE_ENTRY ldrMod = { 0 };
		if (ReadProcessMemory(hProcess, entryBase, &ldrMod, sizeof(ldrMod), NULL))
		{
			TCHAR dllName[MAX_PATH] = { 0 };
			//fprintf(stdout, "[i] Top of module list at %p\n", ldrMod.FullDllName);
			if (ReadProcessMemory(hProcess, ldrMod.FullDllName.Buffer, &dllName, ldrMod.FullDllName.Length, NULL) && ldrMod.DllBase != NULL)
			{
				//_ftprintf(stdout, TEXT("[i] Module Fullname %s - DLL Base %p\n"), dllName,ldrMod.DllBase);
				unsigned char *strFoo[4] = {0};
				if (ReadProcessMemory(hProcess, ldrMod.DllBase, &strFoo, sizeof(strFoo), NULL))
				{

					//if (_tcsncicmp(dllName, TEXT("C:\\windows\\SYSTEM32\\"), _tcsclen(TEXT("C:\\Windows\\System32\\"))) == 0){
					//	pMod = ldrMod.InMemoryOrderLinks.Flink;
						//continue;
					//}
					HANDLE hFile = CreateFile(dllName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

					if (hFile == INVALID_HANDLE_VALUE){
						fprintf(stdout, "[!] +-- Error during CreateFile in AnalyzePEB - %d\n", GetLastError());
						return;
					}
					else {
						DWORD dwSize = GetFileSize(hFile, NULL);
						AnalyzeModule(hProcess, ldrMod.DllBase, dwSize, hFile,dllName);
						CloseHandle(hFile);
					}
					
				}
			}
			pMod = ldrMod.InMemoryOrderLinks.Flink;
		}
	}
	while (pMod != pStart);

}


//
// Function	: AnalyzeProcess
// Role		: Analyses a particular process ID
// Notes	: 
// 
void AnalyzeProcess(DWORD dwPID)
{
	DWORD dwRet=0, dwMods=0;
	HANDLE hProcess=NULL;
	HMODULE hModule[9000];
	TCHAR cProcess[MAX_PATH];
	//TCHAR cModule[MAX_PATH];

	bool bFirstError = false;

	hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, dwPID);
	if (hProcess == NULL)
	{
		if (GetLastError() == 5){
			bFirstError = true;
			hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, dwPID);

			if (hProcess == NULL){

				PWTS_PROCESS_INFO pProcessInfo;
				DWORD dwProcessCount = 0;

				if (WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pProcessInfo, &dwProcessCount) == 0){
					fprintf(stderr, "[!] OpenProcess fallback failed (%d),%d\n", dwPID, GetLastError());
					return;
				}
				else{
					for (DWORD dwCount = 0; dwCount<dwProcessCount; dwCount++){
						if (pProcessInfo[dwCount].ProcessId == dwPID){
							_tcscpy_s(cProcess, MAX_PATH, pProcessInfo[dwCount].pProcessName);
						}
					}
					WTSFreeMemory(pProcessInfo);
				}
			}
		}
		else { // Last error wasn't access denied 
			fprintf(stderr, "[!] OpenProcess failed (%d),%d\n", dwPID, GetLastError());
			return;
		}
	}
	else { // Process handle not NULL

		if (EnumProcessModules(hProcess, hModule, 9000 * sizeof(HMODULE), &dwRet) == 0)
		{
			if (GetLastError() == 299){
				fprintf(stderr, "[i] 64bit process and we're 32bit - sad panda! skipping PID %d\n", dwPID);
			}
			else {
				fprintf(stderr, "[!] EnumProcessModules(%d),%d\n", dwPID, GetLastError());
			}
			return;
		}
		dwMods = dwRet / sizeof(HMODULE);

		GetModuleBaseName(hProcess, hModule[0], cProcess, MAX_PATH);
	}


	DWORD dwSessionID = 0;
	ProcessIdToSessionId(dwPID, &dwSessionID);

	PWTS_SESSION_INFO pSessionInfo;
	DWORD dwSessionInfo = 0;
	WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &dwSessionInfo);
	DWORD dwCount = 0;
	for (dwCount = 0; dwCount<dwSessionInfo; dwCount++){
		if (pSessionInfo[dwCount].SessionId == dwSessionID) break;
	}

	_ftprintf(stdout, TEXT("[i] %S [%s - PID: %d in session %d - window station %s]\n"), TEXT("+> Process"), cProcess, dwPID, dwSessionID, pSessionInfo[dwCount].pWinStationName);
	
	AnalyzePEB(hProcess);

	CloseHandle(hProcess);
}

//
// Function	: EnumerateProcesses
// Role		: Enumerate the running processes on the box
// Notes	: 
// 
void EnumerateProcesses()
{
	DWORD dwPIDArray[2048], dwRet, dwPIDS, intCount;


	if (EnumProcesses(dwPIDArray, 4096 * sizeof(DWORD), &dwRet) == 0)
	{
		fprintf(stderr, "[!]  EnumerateProcesses(),%d\n", GetLastError());
		return;
	}

	dwPIDS = dwRet / sizeof(DWORD);

	for (intCount = 0; intCount<dwPIDS; intCount++)
	{
		AnalyzeProcess(dwPIDArray[intCount]);
	}
}


//
// Function	: PrintHelp
// Role		: 
// Notes	: 
// 
void PrintHelp(TCHAR *strExe){

	_ftprintf(stdout, TEXT("    i.e. %s [-p <PID>] [-v] [-h]\n"), strExe);
	fprintf(stdout, "    -p [PID] just analyse this specific PID\n");
	fprintf(stdout, "    -v Turn on verbose diffs for each section compared\n");
	fprintf(stdout, "\n");
	ExitProcess(1);
}


//
// Function	: _tmain
// Role		: Entry point
// Notes	: 
// 
int _tmain(int argc, _TCHAR* argv[])
{

	DWORD dwPID = 0;
	bool	bHelp = false;
	char	chOpt;

	printf("[*] Windows Patching Detector - https://github.com/nccgroup/WindowsPatchDetector\n");
	printf("[*] NCC Group Plc - http://www.nccgroup.com/ \n");
	printf("[*] -h for help \n");


	// Extract all the options
	while ((chOpt = getopt(argc, argv, _T("p:vh"))) != EOF)
		switch (chOpt)
	{
		case _T('p'):
			dwPID = _tstoi(optarg);
			break;
		case _T('v'):
			bVerbose = true;
			break;
		case _T('h'): // Help
			bHelp = true;
			break;
		default:
			fwprintf(stderr, L"[!] No handler - %c\n", chOpt);
			break;
	}

	if (bHelp) PrintHelp(argv[0]);


	if (dwPID == 0){
		EnumerateProcesses();
	}
	else {
		AnalyzeProcess(dwPID);
	}

	return 0;
}


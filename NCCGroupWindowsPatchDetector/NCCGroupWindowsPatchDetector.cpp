/*
A Microsoft Windows in-memory versus disk verification

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/olliencc/WindowsPatchDetector

Released under AGPL see LICENSE for more information
*/

// Includes
#include "stdafx.h"

// Globals
HANDLE	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
bool	bVerbose = false;
TCHAR	strErrMsg[1024];

// Manual imports
_NtQueryInformationProcess __NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueryInformationProcess");
typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process = fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms684139(v=vs.85).aspx
BOOL IsWow64()
{
	BOOL bIsWow64 = FALSE;

	if (NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64))
		{
			return false;
		}
	}
	return bIsWow64;
}

//
// Function	: PrintRelocations
// Role		: Used for printing and checking if an address is in a relocation
//
bool PrintRelocations(VOID *dataRelocation, DWORD RelocationSize, DWORD_PTR pBaseAddress, DWORD dwOffset, bool bPrint, bool bPrintNoMatch, bool bPrintMatch){


	DWORD dwRelocs = 0;

	//
	// OK we've read the base relocations table into our space now
	//  - http://www.pelib.com/resources/luevel.txt
	//  - https://github.com/Cr4sh/DrvHide-PoC/blob/master/driver/src/ldr.cpp
	//  - http://uninformed.org/index.cgi?v=6&a=3&p=2
	// 

	ULONG Size = 0;
	PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)dataRelocation;
	DWORD_PTR Addr2 = 0;
	DWORD_PTR Addr3 = 0;
	//fprintf(stdout, "[i] Total Size %d %08x\n", RelocationSize, RelocationSize);

	while (RelocationSize > Size && pRelocation->SizeOfBlock)
	{
		//fprintf(stdout, "[i] Relocation block size %u\n", pRelocation->SizeOfBlock);
		ULONG Number = (pRelocation->SizeOfBlock - 8) / 2;
		//fprintf(stdout, "[i] Number of relocations %u\n", Number);
		PUSHORT Rel = (PUSHORT)((PUCHAR)pRelocation + 8);

		//fprintf(stdout, "[i] %p of %u\n", ((DWORD)pBaseAddress + pRelocation->VirtualAddress), pRelocation->SizeOfBlock);
		//fprintf(stdout, "[i] %p of %u\n", pRelocation->VirtualAddress, pRelocation->SizeOfBlock);

		for (ULONG i = 0; i < Number; i++)
		{
			//if (bCursor) AdvanceCursor();
			if (Rel[i] > 0)
			{
				USHORT Type = (Rel[i] & 0xF000) >> 12;

				//DWORD Addr = (DWORD)((DWORD)pBaseAddress + pRelocation->VirtualAddress + (Rel[i] & 0x0FFF));
				//(DWORD)(pRelocation->VirtualAddress +
				Addr2 = (pRelocation->VirtualAddress + ( Rel[i] & 0x0FFF));
				Addr3 = Rel[i] & 0x0FFF;
				if (dwOffset >= Addr2 && dwOffset <= (Addr2 + 4)) {
					if(bPrintMatch) fprintf(stdout, "[i] Match 1\n");
					return true;
				}
				else if (dwOffset >= Addr3 && dwOffset <= (Addr3 + 4)) {
					if (bPrintMatch) fprintf(stdout, "[i] Match 2\n");
					return true;
				}
				else if (bPrintNoMatch == true) fprintf(stdout, "[i] Nomatch %08x %08x, %08x\n", Addr2, Addr3, dwOffset);
				else if (dwOffset == 0 && bPrint == true) fprintf(stdout, "[i] Relocation %08x %08x, %08x\n", Addr2, Addr3, dwOffset);
				//fprintf(stdout, "[i] %p\n", Addr2);
				dwRelocs++;
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
void AnalyzeModule(HANDLE hProcess, DWORD_PTR pBaseAddress, DWORD dwSize, HANDLE hFile, TCHAR *strDLLName)
{
	unsigned char *pFileMem = (unsigned char *)malloc(dwSize);
	unsigned char *pFileMemCmp = pFileMem;
	unsigned char *pFileDisk = (unsigned char *)malloc(dwSize);
	unsigned char *pFileDiskPtr = pFileDisk;
	VOID *dataRelocation = NULL;
	ULONG RelocationSize = 0;
	DWORD dwRelocs = 0;

	memset(pFileMem, 0x00, dwSize);
	memset(pFileDisk, 0x00, dwSize);

	DWORD szReadMem = 0;
	DWORD szReadDisk = 0;
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
	if (!ReadProcessMemory(hProcess, (LPCVOID)pBaseAddress, &imgDOSHdr, sizeof(imgDOSHdr), (SIZE_T*)&szReadMem))
	{
		free(pFileMem);
		free(pFileDisk);
		return;
	}

	// fprintf(stdout, "[i] Offset of PE header %p\n", imgDOSHdr.e_lfanew);
	DWORD_PTR peHdrOffs = pBaseAddress + imgDOSHdr.e_lfanew;

	IMAGE_NT_HEADERS ntHdr;

	if (!ReadProcessMemory(hProcess, (LPCVOID)peHdrOffs, &ntHdr, sizeof(ntHdr), (SIZE_T*)&szReadMem))
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
	if (ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
		dataRelocation = malloc(ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
		if (dataRelocation == NULL){
			free(pFileMem);
			free(pFileDisk);
			return;
		}
		else {
			DWORD_PTR dwBaseRelocAddress = pBaseAddress + ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
			if (!ReadProcessMemory(hProcess,
				(LPCVOID)dwBaseRelocAddress,
				dataRelocation,
				ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size,
				(SIZE_T*)&szReadMem))
			{
				fprintf(stdout, "[!] Failed to read base relocations\n");
				free(pFileMem);
				free(pFileDisk);
				free(dataRelocation);
				return;
			}
		}
	}

	//
	// This works out where the .text is we need in memory
	//
	DWORD_PTR sectionHdrOffs = (
								peHdrOffs
								+ FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader)
								+ ntHdr.FileHeader.SizeOfOptionalHeader
								);

	#define MAX_SECTIONS 128

	IMAGE_SECTION_HEADER sections[MAX_SECTIONS];
	PIMAGE_SECTION_HEADER pSection;


	DWORD cSections = min(ntHdr.FileHeader.NumberOfSections, MAX_SECTIONS);

	if (!ReadProcessMemory(hProcess,
		(LPCVOID)sectionHdrOffs,
		&sections,
		cSections * IMAGE_SIZEOF_SECTION_HEADER,
		(SIZE_T*)&szReadMem))
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
		DWORD endRVA = pSection->VirtualAddress	+ max(pSection->SizeOfRawData, pSection->Misc.VirtualSize);
		strcpy_s(strSection, (char *)pSection->Name);
		if (strcmp(strSection, ".text") == 0){
			bFound = true;
			break;
		}
	}

	// OK we've found it now compare the RAM
	// versus disk version
	if (bFound == true){
		//_ftprintf(stdout, TEXT("[i] Module %s .text section at virtual address %p has %d relocations\n"), strDLLName, ((DWORD)pBaseAddress + pSection->VirtualAddress), pSection->NumberOfRelocations);
		_ftprintf(stdout, TEXT("[i] Module %s .text section at virtual address %p of %d bytes\n"), strDLLName, ((DWORD)pBaseAddress + pSection->VirtualAddress), pSection->SizeOfRawData);

		fprintf(stdout, "[i] Relocations at %p of %u bytes\n", (pBaseAddress + ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress), ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
		RelocationSize = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		//PrintRelocations(dataRelocation, RelocationSize, pBaseAddress,0, true, false, false,false);

		// Read the process copy
		if (ReadProcessMemory(hProcess, (LPCVOID)(pBaseAddress + pSection->VirtualAddress), pFileMem, pSection->Misc.VirtualSize, (SIZE_T*)&szReadMem)){
			//fprintf(stdout, "[i] Read process memory copy - asked for %d got %d\n", pSection->Misc.VirtualSize, szReadMem);
		}
		else {
			fprintf(stdout, "[!] Failed process memory read %d\n", GetLastError());
		}

		if (ReadFile(hFile, pFileDisk, dwSize, &szReadDisk, NULL)){
			//fprintf(stdout, "[i] Read disk copy - asked for %d got %d\n", dwSize, szReadDisk);
		}
		else {
			DWORD dwRet = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, strErrMsg, 1023, NULL);
			if (dwRet != 0){
				_ftprintf(stdout, TEXT("[!] Failed disk read with of %d bytes at %p - %s"), pSection->Misc.VirtualSize, pSection->PointerToRawData,strErrMsg);
			}
			else
			{
				_ftprintf(stdout, TEXT("[!] Failed disk read with of %d bytes at %p - Error: %d\n"), pSection->Misc.VirtualSize, pSection->PointerToRawData, GetLastError());
			}
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

			}
			else {
				dwDiffs = 0;
				for (DWORD dwCount = 0; dwCount < pSection->Misc.VirtualSize; dwCount++){
					if (memcmp(pFileMemCmp, pFileDiskPtr, 1) != 0)  {
						if (PrintRelocations(dataRelocation, RelocationSize, (DWORD_PTR)pBaseAddress, (pSection->VirtualAddress + dwCount), false, false, false) == false){
							dwDiffs++;
							if (bVerbose == true) fprintf(stdout, "[diff] Offset %08x (%08x) of %d: %02x versus %02x diff %02x\n", dwCount, (pSection->VirtualAddress + dwCount), pSection->Misc.VirtualSize, *pFileMemCmp, *pFileDiskPtr, (*pFileMemCmp - *pFileDiskPtr) & 0xff);
						}
					}
					pFileMemCmp++;
					pFileDiskPtr++;
				}
				fprintf(stdout, "[!] %d bytes different from a total of %d - relocs %d \n", dwDiffs, pSection->Misc.VirtualSize, dwRelocs);
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
	DWORD_PTR *pInfo = (DWORD_PTR *)malloc(sizeof(DWORD_PTR) * 6);


	NTSTATUS ntStatus = __NtQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		pInfo, // 
		sizeof(DWORD_PTR) * 6,
		NULL);

	// TODO: Check here for return for above function

	// Copy the PEB to our address space
	PPEB pPEB = (PPEB)((DWORD_PTR*)pInfo)[1];
	PEB PEBCopy;
	PEB_LDR_DATA PEBLDRData;

	BOOL bRes = ReadProcessMemory(hProcess, pPEB, &PEBCopy, sizeof(PEB), NULL);
	if (bRes == 0)
	{
		DWORD dwRet = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, strErrMsg, 1023, NULL);
		if (dwRet != 0){
			_ftprintf(stdout, TEXT("[!] Error during ReadProcessMemory in AnalyzePEB - PEB- %s"), strErrMsg);
		}
		else
		{
			_ftprintf(stdout, TEXT("[!] Error during ReadProcessMemory in AnalyzePEB - PEB - Error: %d\n"), GetLastError());
		}
		return;
	}
	else
	{
		// fprintf(stdout, "[i] PEB Address %p - Session ID %u - Being Debuged %d \n",PEBCopy.Ldr, PEBCopy.SessionId,PEBCopy.BeingDebugged);
	}

	// Copy the PEB LDR to our address space
	bRes = ReadProcessMemory(hProcess, PEBCopy.Ldr, &PEBLDRData, sizeof(PEB_LDR_DATA), NULL);
	if (bRes == 0)
	{
		DWORD dwRet = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, strErrMsg, 1023, NULL);
		if (dwRet != 0){
			_ftprintf(stdout, TEXT("[!] Error during ReadProcessMemory in AnalyzePEB - PEBLDRData - %s"), strErrMsg);
		}
		else
		{
			_ftprintf(stdout, TEXT("[!] Error during ReadProcessMemory in AnalyzePEB - PEBLDRData - Error: %d\n"), GetLastError());
		}
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
			if (ReadProcessMemory(hProcess, ldrMod.FullDllName.Buffer, &dllName, ldrMod.FullDllName.Length, NULL) && ldrMod.DllBase != NULL)
			{
				
				HANDLE hFile = CreateFile(dllName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (hFile == INVALID_HANDLE_VALUE){
					DWORD dwRet = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, strErrMsg, 1023, NULL);
					if (dwRet != 0){
						_ftprintf(stdout, TEXT("[!] Error during CreateFile in AnalyzePEB - %s"), strErrMsg);
					}
					else
					{
						_ftprintf(stdout, TEXT("[!] Error during CreateFile in AnalyzePEB - Error: %d\n"), GetLastError());
					}
					return;
				}
				else {
					DWORD dwSize = GetFileSize(hFile, NULL);
					AnalyzeModule(hProcess, (DWORD_PTR)ldrMod.DllBase, dwSize, hFile, dllName);
					CloseHandle(hFile);
				}
			}
			pMod = ldrMod.InMemoryOrderLinks.Flink;
		}
	}
	while (pMod != pStart);

}


//
// Function	: PrintProcessInfo
// Role		: Print a little about the process
// Notes	: 
// 
void PrintProcessInfo(TCHAR *cProcess, DWORD dwPID){
	// 
	DWORD dwSessionID = 0;
	ProcessIdToSessionId(dwPID, &dwSessionID);
	PWTS_SESSION_INFO pSessionInfo;
	DWORD dwSessionInfo = 0;
	if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &dwSessionInfo) == 0){
		DWORD dwRet = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, strErrMsg, 1023, NULL);
		if (dwRet != 0){
			_ftprintf(stdout, TEXT("[!] WTSEnumerateSessions failed (%d) - %s"), dwPID, strErrMsg);
		}
		else
		{
			_ftprintf(stdout, TEXT("[!] WTSEnumerateSessions failed (%d) - Error: %d\n"), dwPID, GetLastError());
		}
		return;
	}

	DWORD dwCount = 0;
	for (dwCount = 0; dwCount<dwSessionInfo; dwCount++)
	{
		if (pSessionInfo[dwCount].SessionId == dwSessionID) break;
	}

	// 
	_ftprintf(stdout, TEXT("[i] %S [%s - PID: %d in session %d - window station %s]\n"), TEXT("+> Process"), cProcess, dwPID, dwSessionID, pSessionInfo[dwCount].pWinStationName);
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
	TCHAR cProcess[MAX_PATH] = { 0 };
	bool bFirstError = false;

	PWTS_PROCESS_INFO pProcessInfo;
	DWORD dwProcessCount = 0;

	if (WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pProcessInfo, &dwProcessCount) == 0)
	{
		DWORD dwRet = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, strErrMsg, 1023, NULL);
		if (dwRet != 0){
			_ftprintf(stdout, TEXT("[!] WTSEnumerateProcesses failed (%d) - %s"), dwPID, strErrMsg);
		}
		else
		{
			_ftprintf(stdout, TEXT("[!] WTSEnumerateProcesses failed (%d) - Error: %d\n"), dwPID, GetLastError());
		}
		return;
	}
	else
	{
		for (DWORD dwCount = 0; dwCount<dwProcessCount; dwCount++)
		{
			if (pProcessInfo[dwCount].ProcessId == dwPID)
			{
				_tcscpy_s(cProcess, MAX_PATH, pProcessInfo[dwCount].pProcessName);
				PrintProcessInfo(cProcess, dwPID);
			}
		}
		WTSFreeMemory(pProcessInfo);
	}

	// Open the process
	hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, dwPID);
	if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE)
	{ // Uh oh
		DWORD dwRet = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, strErrMsg, 1023, NULL);
		if (dwRet != 0){
			_ftprintf(stdout, TEXT("[!] OpenProcess failed for PID %d - %s"), dwPID, strErrMsg);
		}
		else
		{
			_ftprintf(stdout, TEXT("[!] OpenProcess failed (%d) - Error:\n"), dwPID, GetLastError());
		}
		return;
	}
	else 
	{ // Process handle not NULL
		if (EnumProcessModules(hProcess, hModule, 9000 * sizeof(HMODULE), &dwRet) == 0)
		{
			if (GetLastError() == 299 && IsWow64())
			{
				fprintf(stdout, "[i] 64bit process and we're 32bit - skipping PID %d!\n", dwPID);
			}
			else 
			{
				DWORD dwRet = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, strErrMsg, 1023, NULL);
				if (dwRet != 0){
					_ftprintf(stdout, TEXT("[!] EnumProcessModules() failed (%d) - %s"), dwPID, strErrMsg);
				}
				else
				{
					_ftprintf(stdout, TEXT("[!] EnumProcessModules() failed (%d) - Error: %d\n"), dwPID, GetLastError());
				}
			}
			return;
		}
		dwMods = dwRet / sizeof(HMODULE);
		if (GetModuleBaseName(hProcess, hModule[0], cProcess, MAX_PATH) == 0){
			DWORD dwRet = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, strErrMsg, 1023, NULL);
			if (dwRet != 0){
				_ftprintf(stdout, TEXT("[!] GetModuleBaseName failed for PID %d - %s"), dwPID, strErrMsg);
			}
			else
			{
				_ftprintf(stdout, TEXT("[!] GetModuleBaseName failed (%d) - Error:\n"), dwPID, GetLastError());
			}
			return;
		}
	}

	
	if (hProcess != INVALID_HANDLE_VALUE){
		// Main heavy lifting
		AnalyzePEB(hProcess);
		CloseHandle(hProcess);
	}
	else {
		_ftprintf(stdout, TEXT("[!] AnalyzeProcess unknown error!\n"));
	}

	
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
		DWORD dwRet = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, strErrMsg, 1023, NULL);
		if (dwRet != 0){
			_ftprintf(stdout, TEXT("[!] EnumProcesses() failed - %s"), strErrMsg);
		}
		else
		{
			_ftprintf(stdout, TEXT("[!] EnumProcesses() - Error: %d\n"), GetLastError());
		}
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

	printf("[*] Experimental Windows Patch Detector - https://github.com/olliencc/WindowsPatchDetector\n");
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
			fwprintf(stdout, L"[!] No handler for the paramater- %c\n", chOpt);
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


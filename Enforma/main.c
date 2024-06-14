#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <Psapi.h>


INT wmain(INT argc, WCHAR* argv[]) {

	wprintf(L"\n"
		L"\t   XXXXXXXXXXXXX\n"
		L"\tXXX   Enforma   XXX\n"
		L"\t   XXXXXXXXXXXXX\n\n");

	// Getting a snapshot of running processes in the system
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		wprintf(L"[-] CreateToolhelp32Snapshot Failed With Error: %lu\n", GetLastError());
		return 1;
	}
	
	PROCESSENTRY32W ProcEnt = { sizeof(ProcEnt) };
	if (!Process32FirstW(hSnapshot, &ProcEnt)) {
		wprintf(L"[-] Process32FirstW Failed With Error: %lu\n", GetLastError());
		return 1;
	}

	while (Process32NextW(hSnapshot, &ProcEnt)) {
		
		if (lstrcmpW(argv[1], L"-name") == 0 && argc > 2) {
			if (lstrcmpW(argv[2], ProcEnt.szExeFile) != 0) {
				continue;
			}
		}
		else if (lstrcmpW(argv[1], L"-pid") == 0 && argc > 2) {
			if (wcstoul(argv[2], NULL, 0) != ProcEnt.th32ProcessID) {
				continue;
			}
		}
		else if (lstrcmpW(argv[1], L"-all") != 0) {
			wprintf(
				L"[-] Usages:\n"
				L"- Enforma.exe -all\n"
				L"- Enforma.exe -pid  <Process ID>\n"
				L"- Enforma.exe -name <Process Name>\n"
			);
			return 1;
		}
		
		WCHAR  szPriorityClass[MAX_PATH];
		switch (ProcEnt.pcPriClassBase) {
		case 4:
			lstrcpyW(szPriorityClass, L"Low");
			break;
		case 6:
			lstrcpyW(szPriorityClass, L"Below normal");
			break;
		case 8:
			lstrcpyW(szPriorityClass, L"Normal");
			break;
		case 10:
			lstrcpyW(szPriorityClass, L"Above normal");
			break;
		case 13:
			lstrcpyW(szPriorityClass, L"High");
			break;
		case 24:
			lstrcpyW(szPriorityClass, L"Realtime");
			break;
		default:
			lstrcpyW(szPriorityClass, L"Uknown");
			break;
		}

		wprintf(
			L"\n"
			L"(%ws, %lu)\n"
			L"\tParent process: %lu\n"
			L"\tThreads: %lu\n"
			L"\tPriority: %ws\n",
			ProcEnt.szExeFile, ProcEnt.th32ProcessID, ProcEnt.th32ParentProcessID,
			ProcEnt.cntThreads, szPriorityClass
		);
	
	 	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcEnt.th32ProcessID);
		if (hProcess) {
			
			DWORD dwHandles;
			if (!GetProcessHandleCount(hProcess, &dwHandles)) {
				wprintf(L"[-] GetProcessHandleCount Failed With Error: %lu\n", GetLastError());
				return 1;
			}

			FILETIME creationTime, exitTime, kernelTime, userTime;
			if (!GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
				wprintf(L"[-] GetProcessTimes Failed With Error: %lu\n", GetLastError());
				return 1;
			}

			if (!FileTimeToLocalFileTime(&creationTime, &creationTime)) {
				wprintf(L"[-] FileTimeToLocalFileTime Failed With Error: %lu\n", GetLastError());
				return 1;
			}

			SYSTEMTIME creationTimeSys;
			if (!FileTimeToSystemTime(&creationTime, &creationTimeSys)) {
				wprintf(L"[-] FileTimeToSystemTime Failed With Error: %lu\n", GetLastError());
				return 1;
			}

			WCHAR szProgramPath[MAX_PATH];
			DWORD dwProgramPathLen = _countof(szProgramPath);
			if (!QueryFullProcessImageNameW(hProcess, 0, szProgramPath, &dwProgramPathLen)) {
				wprintf(L"[-] K32GetProcessImageFileNameW Failed With Error: %lu\n", GetLastError());
				return 1;
			}

			CloseHandle(hProcess);

			wprintf(
				L"\tTotal Handles: %lu\n"
				L"\tProcess started at: %02d:%02d:%02d (%02d/%02d/%04d)\n"
				L"\tProgram path: %ws\n\n",
				dwHandles, creationTimeSys.wHour, creationTimeSys.wMinute,
				creationTimeSys.wSecond, creationTimeSys.wDay, creationTimeSys.wMonth,
				creationTimeSys.wYear, szProgramPath
			);

		}
		else {
			wprintf(L"\tTo view more info you need higher privilages.\n");
		}

	}

	CloseHandle(hSnapshot);

	PERFORMACE_INFORMATION performanceInfo = { sizeof(performanceInfo) };
	if (!K32GetPerformanceInfo(&performanceInfo, sizeof(performanceInfo))) {
		wprintf(L"[-] K32GetPerformanceInfo Failed With Error: %lu\n", GetLastError());
		return 1;
	}

	wprintf(
		L"\n"
		L"[i] Total Running Processes: %lu\n"
		L"[i] Total Running Threads: %lu\n"
		L"[i] Total Open Handles: %lu\n",
		performanceInfo.ProcessCount, performanceInfo.ThreadCount, performanceInfo.HandleCount
	);


	return ERROR_SUCCESS;
}
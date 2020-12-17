// ConsoleApplication1.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#define _UNICODE 1
#define UNICODE 1

#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <tchar.h>
#include<iostream>
#include<cstdio> 
#include<ctime>
#include<vector>

using namespace std;
#include <Psapi.h>

#pragma comment (lib,"Psapi.lib")
// Link with the Wintrust.lib file.
#pragma comment (lib, "wintrust")

std::vector<std::basic_string<TCHAR>> blacklist;
std::vector<std::basic_string<TCHAR>> whitelist;
int KillProcess(DWORD ProcessId){
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, ProcessId);
	if (hProcess == NULL)
		return FALSE;
	if (!TerminateProcess(hProcess, 0))
		return FALSE;
	return TRUE;
}

BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile,DWORD ProcID)
{
	LONG lStatus;
	DWORD dwLastError;


	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = pwszSourceFile;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;


	memset(&WinTrustData, 0, sizeof(WinTrustData));

	WinTrustData.cbStruct = sizeof(WinTrustData);

	// Use default code signing EKU.
	WinTrustData.pPolicyCallbackData = NULL;

	// No data to pass to SIP.
	WinTrustData.pSIPClientData = NULL;

	// Disable WVT UI.
	WinTrustData.dwUIChoice = WTD_UI_NONE;

	// No revocation checking.
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

	// Verify an embedded signature on a file.
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

	// Verify action.
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	// Verification sets this value.
	WinTrustData.hWVTStateData = NULL;

	// Not used.
	WinTrustData.pwszURLReference = NULL;

	// This is not applicable if there is no UI because it changes 
	// the UI to accommodate running applications instead of 
	// installing applications.
	WinTrustData.dwUIContext = 0;

	// Set pFile.
	WinTrustData.pFile = &FileData;

	// WinVerifyTrust verifies signatures as specified by the GUID and Wintrust_Data.
	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);

	switch (lStatus)
	{
	case ERROR_SUCCESS:
		/*
		Signed file:
		- Hash that represents the subject is trusted.

		- Trusted publisher without any verification errors.

		- UI was disabled in dwUIChoice. No publisher or
		time stamp chain errors.

		- UI was enabled in dwUIChoice and the user clicked
		"Yes" when asked to install and run the signed
		subject.
		*/
		break;

	case TRUST_E_NOSIGNATURE:
		// The file was not signed or had a signature that was not valid.

		// Get the reason for no signature.
	{dwLastError = GetLastError();
	if (TRUST_E_NOSIGNATURE == dwLastError ||
		TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
		TRUST_E_PROVIDER_UNKNOWN == dwLastError)
	{
		// The file was not signed.
		TCHAR msg[1025] = { 0 };
		LPCWSTR str = TEXT("进程没有签名，可能不可信，是否继续运行该进程？");
		wcscat_s(msg, pwszSourceFile);
		wcscat_s(msg, str);
		LPCWSTR warn = msg;


		if (MessageBox(NULL, warn, TEXT("警告"), MB_YESNO) == 6) {
			
			whitelist.push_back(pwszSourceFile);

		}
		else {
			blacklist.push_back(pwszSourceFile);
			KillProcess(ProcID);
		}

	}
	else
	{
		// The signature was not valid or there was an error opening the file.
		wprintf_s(L"An unknown error occurred trying to "
			L"verify the signature of the \"%s\" file.\n",
			pwszSourceFile);
	}

	break;
	}
	case TRUST_E_EXPLICIT_DISTRUST:
		// The hash that represents the subject or the publisher  is not allowed by the admin or user.
	{TCHAR msg[1025] = { 0 };
	LPCWSTR str = TEXT("签名未被授权，可能不可信，是否继续运行该进程？");
	wcscat_s(msg, pwszSourceFile);
	wcscat_s(msg, str);
	LPCWSTR warn = msg;


	if (MessageBox(NULL, warn, TEXT("警告"), MB_YESNO) == 6) {
		whitelist.push_back(pwszSourceFile);
	}
	else {
		blacklist.push_back(pwszSourceFile);
		KillProcess(ProcID);
	}
	break;
	}
	case TRUST_E_SUBJECT_NOT_TRUSTED:
	{
		TCHAR msg[1025] = { 0 };
		LPCWSTR str = TEXT("签名虽然存在但不可信，是否继续运行该进程？");
		wcscat_s(msg, pwszSourceFile);
		wcscat_s(msg, str);
		LPCWSTR warn = msg;


		if (MessageBox(NULL, warn, TEXT("警告"), MB_YESNO) == 6) {
			whitelist.push_back(pwszSourceFile);
		}
		else {
			blacklist.push_back(pwszSourceFile);
			KillProcess(ProcID);
		}
		break;
	}
	case CRYPT_E_SECURITY_SETTINGS:
		/*
		The hash that represents the subject or the publisher
		was not explicitly trusted by the admin and the
		admin policy has disabled user trust. No signature,
		publisher or time stamp errors.
		*/
	{wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
		L"representing the subject or the publisher wasn't "
		L"explicitly trusted by the admin and admin policy "
		L"has disabled user trust. No signature, publisher "
		L"or timestamp errors.\n");
	break;
	}

	default:
		// The UI was disabled in dwUIChoice or the admin policy 
		// has disabled user trust. lStatus contains the 
		// publisher or time stamp chain error.
	{TCHAR msg[1025] = { 0 };
	LPCWSTR str = TEXT("签名未被授权，可能不可信，是否继续运行该进程？");
	wcscat_s(msg, pwszSourceFile);
	wcscat_s(msg, str);
	LPCWSTR warn = msg;


	if (MessageBox(NULL, warn, TEXT("警告"), MB_YESNO) == 6) {
		whitelist.push_back(pwszSourceFile);
	}
	else {
		blacklist.push_back(pwszSourceFile);
		KillProcess(ProcID);
	}
	break;
	}
	}
	// Any hWVTStateData must be released by a call with close.
	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

	return true;
}
BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath)
{
	TCHAR            szDriveStr[500];
	TCHAR            szDrive[3];
	TCHAR            szDevName[100];
	INT                cchDevName;
	INT                i;

	//检查参数
	if (!pszDosPath || !pszNtPath)
		return FALSE;

	//获取本地磁盘字符串
	if (GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
	{
		for (i = 0; szDriveStr[i]; i += 4)
		{
			if (!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\")))
				continue;

			szDrive[0] = szDriveStr[i];
			szDrive[1] = szDriveStr[i + 1];
			szDrive[2] = '\0';
			if (!QueryDosDevice(szDrive, szDevName, 100))//查询 Dos 设备名
				return FALSE;

			cchDevName = lstrlen(szDevName);
			if (_tcsnicmp(pszDosPath, szDevName, cchDevName) == 0)//命中
			{
				lstrcpy(pszNtPath, szDrive);//复制驱动器
				lstrcat(pszNtPath, pszDosPath + cchDevName);//复制路径

				return TRUE;
			}
		}
	}

	lstrcpy(pszNtPath, pszDosPath);

	return FALSE;
}
//获取进程完整路径
BOOL GetProcessFullPath(DWORD dwPID, TCHAR pszFullPath[MAX_PATH])
{
	TCHAR        szImagePath[MAX_PATH];
	HANDLE        hProcess;
	if (!pszFullPath)
		return FALSE;

	pszFullPath[0] = '\0';
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPID);
	if (!hProcess)
		return FALSE;

	if (!GetProcessImageFileName(hProcess, szImagePath, MAX_PATH))
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	if (!DosPathToNtPath(szImagePath, pszFullPath))
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	CloseHandle(hProcess);
	
	int ir = std::count(blacklist.begin(), blacklist.end(), pszFullPath);
	if (ir)
	{
		printf(("进程%d已加入黑名单，直接终止该程序 \r\n"), dwPID);
		KillProcess(dwPID);
		return TRUE;

	}
	int iw = std::count(whitelist.begin(), whitelist.end(), pszFullPath);
	if (iw)
	{
		printf(("进程%d已加入白名单，因此直接跳过\r\n"), dwPID);
		return TRUE;

	}
	VerifyEmbeddedSignature(pszFullPath,dwPID);
	return TRUE;
}

int GetTime() {
	return clock()/CLOCKS_PER_SEC;
}

int _tmain()
{
	
	
	int i = 0;
	int lastTime = 0;
	while (60) {
		int now = GetTime();
		if (now - lastTime > 0) {
			++i;
			lastTime = now;

			HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (INVALID_HANDLE_VALUE == hSnapshot)
			{
				return NULL;
			}
			PROCESSENTRY32 pe = { 0 };
			pe.dwSize = sizeof(PROCESSENTRY32);

			BOOL fOk;
			for (fOk = Process32First(hSnapshot, &pe); fOk; fOk = Process32Next(hSnapshot, &pe))
			{
				TCHAR szProcessName[MAX_PATH] = { 0 };
				GetProcessFullPath(pe.th32ProcessID, szProcessName);
			}
		}

		
	}
	return 0;

}


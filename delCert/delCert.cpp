
// delcert.cpp : Defines the entry point for the console application.
//
// An app to make hiterto unsignable file(s) signable again.
//
// 8/10/2006 - Drew
// 7/19/2008 - deepred

//This is orginal work belongs to author 'deepred' https://forum.xda-developers.com/showthread.php?p=2508061#post2508061

//11/15/2017 -moogalm: Just migrated the code to VS2015, added function for error message.


#include "stdafx.h"


#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <imagehlp.h>
#include <malloc.h>
#include <tchar.h>

#define REGULARFILE(x) ((x) & ~(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_ENCRYPTED | FILE_ATTRIBUTE_VIRTUAL))

DWORD StripAuthenticode(LPTSTR);

int wmain(DWORD argc, LPTSTR argv[]) {
	WIN32_FIND_DATA FindFileData = { 0 };
	HANDLE hFindFile = INVALID_HANDLE_VALUE;
	DWORD dwResult = ERROR_SUCCESS;
	TCHAR lpBuffer[4096] = { 0 };
	LPTSTR lpPart = NULL;
	TCHAR pszFileDirectory[4096] = { 0 };
	TCHAR pszFileFullName[8192] = { 0 };

	_tprintf(_TEXT("\n"));
	if (2 != argc || 0 == _tcscmp(_TEXT("-?"), argv[1]) || 0 == _tcscmp(_TEXT("/?"), argv[1])) {
		_tprintf(_TEXT("%s takes one parameter - a file name to strip of its embedded Authenticode signature.\n\n"), argv[0]);
		return 0;
	}

	if (0 == GetFullPathName(argv[1], 4096, lpBuffer, &lpPart)) {
		_tprintf(_TEXT("Failed to GetFullPathName."));
		return 0;
	}
	if (_tcsstr(lpBuffer, lpPart)) {
		_tcsncpy_s(pszFileDirectory, lpBuffer, _tcslen(lpBuffer) - _tcslen(lpPart));
	}

	_tprintf(_TEXT("Target file(s): %s\n\n"), argv[1]);
	hFindFile = FindFirstFile(argv[1], &FindFileData);
	if (INVALID_HANDLE_VALUE == hFindFile) {
		dwResult = GetLastError();
		_tprintf(_TEXT("Invalid File Handle. GLE = 0x%08x\n"), dwResult);
	}
	else {
		if (REGULARFILE(FindFileData.dwFileAttributes)) {
			if (-1 == _stprintf_s(pszFileFullName, 8192, _TEXT("%s%s"), pszFileDirectory, FindFileData.cFileName)) {
				dwResult = GetLastError();
				_tprintf(_TEXT("Failed to copy pszFileName to string of chars. GLE == x0%08x\n"), dwResult);
				goto exit;
			}
			dwResult = StripAuthenticode(pszFileFullName);
		}
		while (TRUE) {
			if (FindNextFile(hFindFile, &FindFileData)) {
				if (REGULARFILE(FindFileData.dwFileAttributes)) {
					if (-1 == _stprintf_s(pszFileFullName, 8192, _TEXT("%s%s"), pszFileDirectory, FindFileData.cFileName)) {
						dwResult = GetLastError();
						_tprintf(_TEXT("Failed to copy pszFileName to string of chars. GLE == x0%08x\n"), dwResult);
						goto exit;
					}
					dwResult = StripAuthenticode(pszFileFullName);
				}
			}
			else {
				dwResult = GetLastError();
				break;
			}
		}
	}

exit:
	if (INVALID_HANDLE_VALUE != hFindFile) FindClose(hFindFile);
	return dwResult;
}

//Caller should deallocate the memory after use.
TCHAR* PrintErrorMSG(DWORD dwErr)
{

	WCHAR   wszMsgBuff[512];  // Buffer for text.

	DWORD   dwChars;  // Number of chars returned.

					  // Try to get the message from the system errors.
	dwChars = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dwErr,
		0,
		wszMsgBuff,
		512,
		NULL);

	if (0 == dwChars)
	{
		// The error code did not exist in the system errors.
		// Try Ntdsbmsg.dll for the error code.

		HINSTANCE hInst;

		// Load the library.
		hInst = LoadLibrary(L"Ntdsbmsg.dll");
		if (NULL == hInst)
		{
			return _T("cannot load Ntdsbmsg.dll\n");  // Could 'return' instead of 'exit'.
		}

		// Try getting message text from ntdsbmsg.
		dwChars = FormatMessage(FORMAT_MESSAGE_FROM_HMODULE |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			hInst,
			dwErr,
			0,
			wszMsgBuff,
			512,
			NULL);

		// Free the library.
		FreeLibrary(hInst);

	}

	// Display the error message, or generic text if not found.
	TCHAR* txtMsg = new TCHAR[512];
	swprintf(txtMsg, 512, _TEXT("Error value: %d Message: %ws\n"), dwErr, dwChars ? wszMsgBuff : L"Error message not found.");
	return txtMsg;

}
DWORD StripAuthenticode(LPTSTR pszFileName) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	LOADED_IMAGE image;
	DWORD dwResult = ERROR_SUCCESS;
	LPSTR lpszImageName = NULL;
	size_t cchImageName = 0;

	_tprintf(_TEXT("Stripping file: %s.\n"), pszFileName);
	hFile = CreateFile(pszFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (INVALID_HANDLE_VALUE == hFile) {
		dwResult = GetLastError();
		TCHAR* errorMSg = PrintErrorMSG(dwResult);
		_tprintf(errorMSg);
		delete[] errorMSg;
		goto cleanupAndExit;
	}

	if (ImageRemoveCertificate(hFile, 0)) {
		goto cleanupAndExit;
	}
	else {
		dwResult = GetLastError();
		TCHAR* errorMSg = PrintErrorMSG(dwResult);
		_tprintf(errorMSg);
		delete[] errorMSg;
		_tprintf(_TEXT("ImageRemoveCertificate failed with error 0x%08x\n"), dwResult);
		if (ERROR_INVALID_PARAMETER != dwResult) {
			goto cleanupAndExit;
		}
		else {
			_tprintf(_TEXT("This happens when there's a listing in IMAGE_DIRECTORY_SECURITY\nin the PE's header, but the actual Authenticode signature has been stripped.\nLet's fix that ...\n"));
			dwResult = ERROR_SUCCESS;
		}
	}

	if (CloseHandle(hFile)) hFile = INVALID_HANDLE_VALUE;
	// This is somewhat sloppy, but if we're here we've almost certainly found a PE with an
	// IMAGE_DIRECTORY_SECURITY that has nonzero SizeOfRawData and/or PointerToRawData,
	// but the actual signature (that raw data) has been removed.
	//
	// What causes this? IIRC, strong name signing something that's already been Authenticode-signed.
	//
	// The workaround is to crack open the PE and write zeros into the directory entry so that everything
	// that eventually calls through the Image*Certificate* APIs won't choke.

	cchImageName = _tcslen(pszFileName) + 1;
	lpszImageName = (LPSTR)malloc(cchImageName); // Yeah - so I'm all old-school mallocy!
	if (!lpszImageName) {
		dwResult = GetLastError();
		TCHAR* errorMSg = PrintErrorMSG(dwResult);
		_tprintf(errorMSg);
		delete[] errorMSg;
		_tprintf(_TEXT("Malloc failed. GLE == 0x%08x\n"), dwResult);
		goto cleanupAndExit;
	}

	if (-1 == sprintf_s(lpszImageName, cchImageName, "%S", pszFileName)) {
		dwResult = GetLastError();
		TCHAR* errorMSg = PrintErrorMSG(dwResult);
		_tprintf(errorMSg);
		delete[] errorMSg;
		_tprintf(_TEXT("Failed to copy pszFileName to string of chars. GLE == x0%08x\n"), dwResult);
		goto cleanupAndExit;
	}

	if (!MapAndLoad(lpszImageName, NULL, &image, FALSE, FALSE)) {
		dwResult = GetLastError();
		PrintErrorMSG(dwResult);
		_tprintf(_TEXT("MapAndLoad failed. GLE == 0x%08x"), dwResult);
		goto cleanupAndExit;
	}

	_tprintf(_TEXT("certificates->Size == 0x%08x\n"), image.FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
	_tprintf(_TEXT("certificates->VA == 0x%08x\n"), image.FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress);

	if (image.FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size ||
		image.FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress) {
		_tprintf(_TEXT("Setting both fields to zero ...\n"));
		image.FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
		image.FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
	}
	else {
		_tprintf(_TEXT("Fields are set to zero already. Skipping ...\n"));
	}

	if (!UnMapAndLoad(&image)) {
		dwResult = GetLastError();
		TCHAR* errorMSg = PrintErrorMSG(dwResult);
		_tprintf(errorMSg);
		delete[] errorMSg;
		_tprintf(_TEXT("Failed to UnMapAndLoad. GLE == 0x%08x\n"), dwResult);
		goto cleanupAndExit;
	}

cleanupAndExit:

	if (INVALID_HANDLE_VALUE != hFile) CloseHandle(hFile);
	if (lpszImageName) free(lpszImageName);
	if (ERROR_SUCCESS == dwResult) _tprintf(_TEXT("Succeeded.\n"));
	_tprintf(_TEXT("\n"));
	return dwResult;
}


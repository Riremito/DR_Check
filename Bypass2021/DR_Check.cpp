#include"Bypass.h"

//
// Define
//
NTSTATUS NTAPI NtGetContextThread_Hook(HANDLE hThread, PCONTEXT ct);

//
// Hook Function
//
bool CheapHook(DWORD dwAddress, DWORD dwHookFunction) {
	// 既にフックされている場合は無視
	if (*(BYTE *)dwAddress == 0xE9) {
		return false;
	}

	DWORD old;
	if (!VirtualProtect((void *)dwAddress, 0x05, PAGE_EXECUTE_READWRITE, &old)) {
		return false;
	}

	*(BYTE *)dwAddress = 0xE9;
	*(DWORD *)(dwAddress + 0x01) = (DWORD)dwHookFunction - dwAddress - 0x05;
	VirtualProtect((void *)dwAddress, 0x05, old, &old);
	return true;
}

bool HookNtGetContextThread(HMODULE hDll) {
	DWORD dwAddress = (DWORD)GetProcAddress(hDll, "NtGetContextThread");
	if (!dwAddress) {
		return false;
	}
	return CheapHook(dwAddress, (DWORD)NtGetContextThread_Hook);
}

bool HookCopyOfDll(HMODULE hDll, LPCSTR fn) {
	if (!hDll) {
		return false;
	}

	if (!fn) {
		return false;
	}

	std::string mn = fn;
	std::string ext = ".tmp";
	if (mn.compare(mn.size() - ext.size(), ext.size(), ext) != 0) {
		return false;
	}

	return HookNtGetContextThread(hDll);
}

bool IsTryingGettingDebugRegister(PCONTEXT ct) {
	if (ct->ContextFlags & CONTEXT_DEBUG_REGISTERS) {
		return true;
	}
	return false;
}

//
// API Hook
//
decltype(LoadLibraryA) *_LoadLibraryA = NULL;
HMODULE WINAPI LoadLibraryA_Hook(LPCSTR lpLibFileName) {
	HMODULE hDll = _LoadLibraryA(lpLibFileName);
	HookCopyOfDll(hDll, lpLibFileName);
	return hDll;
}

// この関数ポインタはオリジナルのntdll.dllの関数へのジャンプのほうが良いので上書きしないでください
NTSTATUS (NTAPI *_NtGetContextThread)(HANDLE, PCONTEXT) = NULL;
NTSTATUS NTAPI NtGetContextThread_Hook(HANDLE hThread, PCONTEXT ct) {
	// Debug Registerの取得を防止
	if (IsTryingGettingDebugRegister(ct)) {
		// 適当にエラーコードを設定
		return 0xC0000024;
	}
	return _NtGetContextThread(hThread, ct);
}

//
// Others
//
bool HookLoadedCopyOfDll() {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, GetCurrentProcessId());

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return false;
	}

	MODULEENTRY32W me = { sizeof(me) };
	if (!Module32FirstW(hSnapshot, &me)) {
		return false;
	}

	std::wstring ext = L".tmp";
	do {
		std::wstring wPath = me.szModule;
		//DEBUG(wPath);
		if (wPath.compare(wPath.size() - ext.size(), ext.size(), ext) == 0) {
			HookNtGetContextThread(me.hModule);
		}
	} while (Module32NextW(hSnapshot, &me));

	CloseHandle(hSnapshot);
	return true;
}

//
// Main
// 

bool DR_Check() {
	// ntdll.dllのコピーを検出
	TestHook(LoadLibraryA);
	// HardwareBreakPointの検出回避
	TestHookNT(ntdll.dll, NtGetContextThread);
	HookLoadedCopyOfDll();
	return true;
}
#include"Bypass.h"

//
// Define
//
NTSTATUS NTAPI NtGetContextThread_Hook(HANDLE hThread, PCONTEXT ct);

//
// Hook Function
//
bool CheapHook(DWORD dwAddress, DWORD dwHookFunction) {
	// ���Ƀt�b�N����Ă���ꍇ�͖���
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

// ���̊֐��|�C���^�̓I���W�i����ntdll.dll�̊֐��ւ̃W�����v�̂ق����ǂ��̂ŏ㏑�����Ȃ��ł�������
NTSTATUS (NTAPI *_NtGetContextThread)(HANDLE, PCONTEXT) = NULL;
NTSTATUS NTAPI NtGetContextThread_Hook(HANDLE hThread, PCONTEXT ct) {
	// Debug Register�̎擾��h�~
	if (IsTryingGettingDebugRegister(ct)) {
		// �K���ɃG���[�R�[�h��ݒ�
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
	// ntdll.dll�̃R�s�[�����o
	TestHook(LoadLibraryA);
	// HardwareBreakPoint�̌��o���
	TestHookNT(ntdll.dll, NtGetContextThread);
	HookLoadedCopyOfDll();
	return true;
}
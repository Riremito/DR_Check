#include"Bypass.h"

bool HideDLL(LPMODULEENTRY32W lpme) {
	static HMODULE hDll = NULL;

	if (!hDll) {
		hDll = GetModuleHandleW(NULL);
	}

	// ����DLL���B��
	if (lpme->hModule == hDll) {
		return true;
	}

	// ���̑��B��������DLL������ꍇ��true��Ԃ�

	return true;

	// �B���������Ȃ�DLL������ꍇ��false��Ԃ�
}

decltype(Module32NextW) *_Module32NextW = NULL;
BOOL WINAPI Module32NextW_Hook(HANDLE hSnapshot, LPMODULEENTRY32W lpme) {
	BOOL bRet = _Module32NextW(hSnapshot, lpme);
	if (bRet) {
		if (HideDLL(lpme)) {
			return Module32NextW(hSnapshot, lpme);
		}
	}
	return bRet;
}

bool DLL_Check() {
	TestHook(Module32NextW);
	return true;
}
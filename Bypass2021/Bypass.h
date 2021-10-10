#ifndef __BYPASS_H__
#define __BYPASS_H__

#include"../Lib/Hook.h"
#pragma comment(lib, "../Lib/Hook.lib")

#include<Windows.h>
#include<tlhelp32.h>
#include<string>


bool DR_Check();
bool DLL_Check();

//
// Debug
//
#define DEBUG(msg) \
{\
std::wstring wmsg = L"[Maple]";\
wmsg += msg;\
OutputDebugStringW(wmsg.c_str());\
}

#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <string>
#include <vector>

int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR arguments,int show) {
    std::vector<wchar_t> path(32768);
    DWORD size=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));
    if(!size||size>=path.size())return 1;
    std::wstring directory(path.data(),size);directory=directory.substr(0,directory.find_last_of(L"\\/"));
    std::wstring working=directory+L"\\app",target=working+L"\\ConWU.exe";
    SHELLEXECUTEINFOW launch{sizeof(launch)};launch.fMask=SEE_MASK_NOASYNC;launch.lpVerb=L"open";launch.lpFile=target.c_str();launch.lpParameters=arguments;launch.lpDirectory=working.c_str();launch.nShow=show;
    if(ShellExecuteExW(&launch))return 0;
    MessageBoxW(nullptr,L"无法启动 ConWU。请重新运行安装包并选择修复。",L"ConWU",MB_OK|MB_ICONERROR);
    return 1;
}

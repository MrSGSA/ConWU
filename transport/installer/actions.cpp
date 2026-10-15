#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <sddl.h>
#include <algorithm>
#include <string>
#include <vector>

namespace {
struct handle { HANDLE value=nullptr; ~handle(){if(value&&value!=INVALID_HANDLE_VALUE)CloseHandle(value);} };
struct service_handle { SC_HANDLE value=nullptr; ~service_handle(){if(value)CloseServiceHandle(value);} };
struct registry { HKEY value=nullptr; ~registry(){if(value)RegCloseKey(value);} };
struct context { std::wstring folder,service,attempt,transaction; bool validation=false; };
void log(MSIHANDLE install,const std::wstring &message,bool error=false){MSIHANDLE record=MsiCreateRecord(0);MsiRecordSetStringW(record,0,(L"StreamLink: "+message).c_str());MsiProcessMessage(install,error?INSTALLMESSAGE_ERROR:INSTALLMESSAGE_INFO,record);MsiCloseHandle(record);}
std::wstring property(MSIHANDLE h,const wchar_t *name){DWORD size=0;wchar_t empty=0;MsiGetPropertyW(h,name,&empty,&size);std::vector<wchar_t> text(size+1);++size;if(MsiGetPropertyW(h,name,text.data(),&size)!=ERROR_SUCCESS)return {};return text.data();}
bool under(std::wstring file,std::wstring root){std::transform(file.begin(),file.end(),file.begin(),towlower);std::transform(root.begin(),root.end(),root.begin(),towlower);while(!root.empty()&&(root.back()==L'\\'||root.back()==L'/'))root.pop_back();return file.size()>root.size()&&file.compare(0,root.size(),root)==0&&(file[root.size()]==L'\\'||file[root.size()]==L'/');}
context parameters(MSIHANDLE h){
    std::wstring raw=property(h,L"CustomActionData");std::vector<std::wstring> parts;size_t at=0,next;
    while((next=raw.find(L'|',at))!=std::wstring::npos){parts.push_back(raw.substr(at,next-at));at=next+1;}parts.push_back(raw.substr(at));
    if(parts.size()!=3||parts[0].empty()||parts[1].empty()||parts[2].size()!=38)throw std::wstring(L"安装参数无效。");
    context c{parts[0],parts[1],parts[2],L"",false};c.validation=c.service.rfind(L"StreamLink-Validation-",0)==0;
    std::vector<wchar_t> absolute(32768);DWORD length=GetFullPathNameW(c.folder.c_str(),static_cast<DWORD>(absolute.size()),absolute.data(),nullptr);
    if(!length||length>=absolute.size())throw std::wstring(L"安装目录无效。");
    c.folder.assign(absolute.data(),length);
    if(c.service!=L"StreamLink-PersonalFeature"&&(!c.validation||c.service.size()!=54))throw std::wstring(L"拒绝管理不属于本安装的服务。");
    for(wchar_t ch:c.attempt)if(!iswxdigit(ch)&&ch!=L'{'&&ch!=L'}'&&ch!=L'-')throw std::wstring(L"安装事务标识无效。");
    c.transaction=L"Software\\StreamLink\\InstallerTransactions\\"+c.attempt;
    PWSTR programs=nullptr;if(FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFiles,0,nullptr,&programs)))throw std::wstring(L"无法定位程序目录。");
    std::wstring root=std::wstring(programs)+(c.validation?L"\\StreamLink-Validation":L"\\StreamLink");CoTaskMemFree(programs);
    if(!under(c.folder,root))throw std::wstring(L"安装目录不在 StreamLink 的受管位置内。");
    std::wstring ancestor=c.folder;while(ancestor.size()>3){while(ancestor.size()>3&&(ancestor.back()==L'\\'||ancestor.back()==L'/'))ancestor.pop_back();DWORD attributes=GetFileAttributesW(ancestor.c_str());if(attributes!=INVALID_FILE_ATTRIBUTES&&(attributes&FILE_ATTRIBUTE_REPARSE_POINT))throw std::wstring(L"安装目录不能经过链接或重解析点。");auto slash=ancestor.find_last_of(L"\\/");if(slash==std::wstring::npos)break;ancestor.resize(slash);}
    return c;
}
std::wstring read_string(HKEY key,const wchar_t *name){DWORD bytes=0,type=0;if(RegQueryValueExW(key,name,nullptr,&type,nullptr,&bytes)!=ERROR_SUCCESS||type!=REG_SZ||bytes>65536)return {};std::vector<wchar_t> text(bytes/2+1);if(RegQueryValueExW(key,name,nullptr,nullptr,reinterpret_cast<BYTE*>(text.data()),&bytes)!=ERROR_SUCCESS)return {};return text.data();}
DWORD read_number(HKEY key,const wchar_t *name){DWORD value=0,bytes=sizeof(value);RegQueryValueExW(key,name,nullptr,nullptr,reinterpret_cast<BYTE*>(&value),&bytes);return value;}
void set_string(HKEY key,const wchar_t *name,const std::wstring &value){if(RegSetValueExW(key,name,0,REG_SZ,reinterpret_cast<const BYTE*>(value.c_str()),static_cast<DWORD>((value.size()+1)*2))!=ERROR_SUCCESS)throw std::wstring(L"无法记录安装恢复信息。");}
void set_number(HKEY key,const wchar_t *name,DWORD value){if(RegSetValueExW(key,name,0,REG_DWORD,reinterpret_cast<BYTE*>(&value),sizeof(value))!=ERROR_SUCCESS)throw std::wstring(L"无法记录安装恢复状态。");}
void set_binary(HKEY key,const wchar_t *name,const void *value,DWORD bytes){if(RegSetValueExW(key,name,0,REG_BINARY,static_cast<const BYTE*>(value),bytes)!=ERROR_SUCCESS)throw std::wstring(L"无法记录服务恢复数据。");}
std::vector<BYTE> query_config(SC_HANDLE service,DWORD level){DWORD size=0;QueryServiceConfig2W(service,level,nullptr,0,&size);if(!size||size>65536)throw std::wstring(L"服务附加配置大小无效。");std::vector<BYTE> bytes(size);if(!QueryServiceConfig2W(service,level,bytes.data(),size,&size))throw std::wstring(L"无法读取服务附加配置。");return bytes;}
void snapshot_policy(SC_HANDLE service,HKEY saved){
    auto bytes=query_config(service,SERVICE_CONFIG_FAILURE_ACTIONS);auto *policy=reinterpret_cast<SERVICE_FAILURE_ACTIONSW*>(bytes.data());
    set_number(saved,L"FailureReset",policy->dwResetPeriod);set_string(saved,L"FailureReboot",policy->lpRebootMsg?policy->lpRebootMsg:L"");set_string(saved,L"FailureCommand",policy->lpCommand?policy->lpCommand:L"");
    set_binary(saved,L"FailureActions",policy->lpsaActions,policy->cActions*sizeof(SC_ACTION));
    bytes=query_config(service,SERVICE_CONFIG_DESCRIPTION);auto *description=reinterpret_cast<SERVICE_DESCRIPTIONW*>(bytes.data());set_string(saved,L"Description",description->lpDescription?description->lpDescription:L"");
    bytes=query_config(service,SERVICE_CONFIG_FAILURE_ACTIONS_FLAG);set_number(saved,L"FailureNonCrash",reinterpret_cast<SERVICE_FAILURE_ACTIONS_FLAG*>(bytes.data())->fFailureActionsOnNonCrashFailures);
    bytes=query_config(service,SERVICE_CONFIG_DELAYED_AUTO_START_INFO);set_number(saved,L"DelayedAutoStart",reinterpret_cast<SERVICE_DELAYED_AUTO_START_INFO*>(bytes.data())->fDelayedAutostart);
}
void restore_policy(SC_HANDLE service,HKEY saved){
    DWORD size=0,type=0;if(RegQueryValueExW(saved,L"FailureActions",nullptr,&type,nullptr,&size)!=ERROR_SUCCESS||type!=REG_BINARY||size>65536||size%sizeof(SC_ACTION))throw std::wstring(L"服务失败动作恢复记录无效。");
    std::vector<SC_ACTION> actions(size/sizeof(SC_ACTION));if(RegQueryValueExW(saved,L"FailureActions",nullptr,nullptr,reinterpret_cast<BYTE*>(actions.data()),&size)!=ERROR_SUCCESS)throw std::wstring(L"无法读取原服务失败动作。");
    std::wstring reboot=read_string(saved,L"FailureReboot"),command=read_string(saved,L"FailureCommand"),description=read_string(saved,L"Description");
    SERVICE_FAILURE_ACTIONSW policy{read_number(saved,L"FailureReset"),reboot.data(),command.data(),static_cast<DWORD>(actions.size()),actions.data()};
    // An empty action array must be non-null to clear the new policy.
    SC_ACTION empty{};if(actions.empty())policy.lpsaActions=&empty;
    SERVICE_DESCRIPTIONW text{description.data()};SERVICE_FAILURE_ACTIONS_FLAG flag{static_cast<BOOL>(read_number(saved,L"FailureNonCrash"))};SERVICE_DELAYED_AUTO_START_INFO delayed{static_cast<BOOL>(read_number(saved,L"DelayedAutoStart"))};
    if(!ChangeServiceConfig2W(service,SERVICE_CONFIG_FAILURE_ACTIONS,&policy)||!ChangeServiceConfig2W(service,SERVICE_CONFIG_DESCRIPTION,&text)||!ChangeServiceConfig2W(service,SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,&flag)||!ChangeServiceConfig2W(service,SERVICE_CONFIG_DELAYED_AUTO_START_INFO,&delayed))throw std::wstring(L"恢复原服务附加配置失败。");
}
bool running(const wchar_t *name){service_handle manager{OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT)};service_handle service{manager.value?OpenServiceW(manager.value,name,SERVICE_QUERY_STATUS):nullptr};SERVICE_STATUS status{};return service.value&&QueryServiceStatus(service.value,&status)&&status.dwCurrentState!=SERVICE_STOPPED;}
bool has_legacy_service(){service_handle manager{OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT)};service_handle service{manager.value?OpenServiceW(manager.value,L"StreamLink",SERVICE_QUERY_STATUS):nullptr};return service.value!=nullptr;}
bool old_frontend(const std::wstring &file){DWORD ignored=0,size=GetFileVersionInfoSizeW(file.c_str(),&ignored);if(!size)return true;std::vector<BYTE> bytes(size);VS_FIXEDFILEINFO *info=nullptr;UINT count=0;if(!GetFileVersionInfoW(file.c_str(),0,size,bytes.data())||!VerQueryValueW(bytes.data(),L"\\",reinterpret_cast<void**>(&info),&count)||!info)return true;return HIWORD(info->dwFileVersionMS)==0;}
struct close_windows { DWORD pid; UINT message; };
BOOL CALLBACK close_window(HWND window,LPARAM parameter){auto &request=*reinterpret_cast<close_windows*>(parameter);DWORD pid=0;GetWindowThreadProcessId(window,&pid);if(pid==request.pid){DWORD_PTR ignored=0;SendMessageTimeoutW(window,request.message,0,0,SMTO_ABORTIFHUNG,300,&ignored);SendMessageTimeoutW(window,WM_CLOSE,0,0,SMTO_ABORTIFHUNG,300,&ignored);}return TRUE;}
void close_clients(MSIHANDLE h,const context &c,bool includeLegacy){
    PWSTR programs=nullptr;if(FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFiles,0,nullptr,&programs)))throw std::wstring(L"无法定位旧程序。");
    std::wstring legacy=std::wstring(programs)+L"\\StreamLink",personal=std::wstring(programs)+L"\\StreamLink-PersonalFeature";CoTaskMemFree(programs);
    UINT message=RegisterWindowMessageW(L"StreamLink.ExitUi.AQ1.v1");handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0)};if(snapshot.value==INVALID_HANDLE_VALUE)throw std::wstring(L"无法查询现有界面。");
    PROCESSENTRY32W entry{};entry.dwSize=sizeof(entry);if(!Process32FirstW(snapshot.value,&entry))return;
    do {
        bool web=_wcsicmp(entry.szExeFile,L"StreamLink.Web.exe")==0,desktop=_wcsicmp(entry.szExeFile,L"StreamLink.exe")==0;
        if(!web&&!desktop)continue;
        handle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE|PROCESS_TERMINATE,FALSE,entry.th32ProcessID)};if(!process.value)continue;
        std::vector<wchar_t> path(32768);DWORD length=static_cast<DWORD>(path.size());if(!QueryFullProcessImageNameW(process.value,0,path.data(),&length))continue;std::wstring file(path.data(),length);
        auto current=c.folder;while(!current.empty()&&(current.back()==L'\\'||current.back()==L'/'))current.pop_back();
        bool managed=under(file,current+L"\\app")||_wcsicmp(file.c_str(),(current+L"\\StreamLink.exe").c_str())==0;
        if(includeLegacy&&!c.validation)managed=managed||under(file,legacy)||under(file,personal);
        // Validation packages are confined to this instance, including its
        // earlier manual installer folder. They cannot close the daily UI.
        if(includeLegacy&&c.validation){auto split=current.find_last_of(L"\\/");managed=under(file,current.substr(0,split));}
        if(!managed)continue;
        if(desktop&&old_frontend(file)&&!has_legacy_service())throw std::wstring(L"旧版可能正在前台维持网络，请先在旧版停止网络并退出后再安装。旧服务和配置未修改。");
        log(h,L"Closing prior UI PID="+std::to_wstring(entry.th32ProcessID));
        if(desktop){close_windows request{entry.th32ProcessID,message};EnumWindows(close_window,reinterpret_cast<LPARAM>(&request));}
        if(WaitForSingleObject(process.value,2000)==WAIT_TIMEOUT){
            // Only identified UI/web executables in our installation paths;
            // StreamLink.Service and native/network workers are never killed.
            std::vector<wchar_t> check(32768);DWORD count=static_cast<DWORD>(check.size());
            if(!QueryFullProcessImageNameW(process.value,0,check.data(),&count)||std::wstring(check.data(),count)!=file)throw std::wstring(L"旧界面身份在更新期间改变。");
            if(!TerminateProcess(process.value,0)||WaitForSingleObject(process.value,5000)!=WAIT_OBJECT_0)throw std::wstring(L"旧界面未能退出，请退出后重新安装。");
        }
    } while(Process32NextW(snapshot.value,&entry));
}
void snapshot_service(const context &c){
    PSECURITY_DESCRIPTOR descriptor=nullptr;if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;KA;;;SY)(A;;KA;;;BA)",SDDL_REVISION_1,&descriptor,nullptr))throw std::wstring(L"无法保护安装恢复记录。");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),descriptor,FALSE};registry saved;DWORD disposition=0;
    LONG result=RegCreateKeyExW(HKEY_LOCAL_MACHINE,c.transaction.c_str(),0,nullptr,0,KEY_ALL_ACCESS|KEY_WOW64_64KEY,&attributes,&saved.value,&disposition);LocalFree(descriptor);
    if(result!=ERROR_SUCCESS||disposition!=REG_CREATED_NEW_KEY)throw std::wstring(L"安装恢复记录未能建立，或上次恢复尚待完成。");
    service_handle manager{OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT)};if(!manager.value)throw std::wstring(L"无法查询服务管理器。");
    service_handle service{OpenServiceW(manager.value,c.service.c_str(),SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS)};
    if(!service.value){if(GetLastError()!=ERROR_SERVICE_DOES_NOT_EXIST)throw std::wstring(L"无法读取原服务，安装已停止。");set_number(saved.value,L"Existed",0);set_number(saved.value,L"Complete",1);return;}
    DWORD size=0;QueryServiceConfigW(service.value,nullptr,0,&size);std::vector<BYTE> bytes(size);
    if(!QueryServiceConfigW(service.value,reinterpret_cast<QUERY_SERVICE_CONFIGW*>(bytes.data()),size,&size))throw std::wstring(L"原服务配置读取失败。");
    auto *config=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(bytes.data());
    if(_wcsicmp(config->lpServiceStartName,L"LocalSystem")!=0)throw std::wstring(L"现有个人服务使用了自定义账户，请保留原安装并手动处理。");
    set_number(saved.value,L"Existed",1);set_number(saved.value,L"Start",config->dwStartType);set_number(saved.value,L"Running",running(c.service.c_str())?1:0);set_string(saved.value,L"ImagePath",config->lpBinaryPathName);set_string(saved.value,L"Display",config->lpDisplayName);
    snapshot_policy(service.value,saved.value);
    set_number(saved.value,L"Complete",1);
}
void restore_service(const context &c){
    registry saved;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,c.transaction.c_str(),0,KEY_READ|KEY_WOW64_64KEY,&saved.value)!=ERROR_SUCCESS)return;
    if(!read_number(saved.value,L"Complete")||!read_number(saved.value,L"MutationPermitted"))return; // preparation failed before any service mutation
    service_handle manager{OpenSCManagerW(nullptr,nullptr,SC_MANAGER_ALL_ACCESS)};if(!manager.value)throw std::wstring(L"无法恢复服务管理状态。");
    service_handle service{OpenServiceW(manager.value,c.service.c_str(),SERVICE_ALL_ACCESS)};
    if(service.value){SERVICE_STATUS state{};if(QueryServiceStatus(service.value,&state)&&state.dwCurrentState!=SERVICE_STOPPED){ControlService(service.value,SERVICE_CONTROL_STOP,&state);ULONGLONG start=GetTickCount64();do{Sleep(100);if(!QueryServiceStatus(service.value,&state))break;}while(state.dwCurrentState!=SERVICE_STOPPED&&GetTickCount64()-start<50000);if(state.dwCurrentState!=SERVICE_STOPPED)throw std::wstring(L"新服务仍未停止，不能启动第二个资源所有者。");}}
    if(!read_number(saved.value,L"Existed")){if(service.value)DeleteService(service.value);return;}
    std::wstring image=read_string(saved.value,L"ImagePath"),display=read_string(saved.value,L"Display");if(image.empty())throw std::wstring(L"原服务恢复路径为空。");
    DWORD start=read_number(saved.value,L"Start");
    if(service.value){if(!ChangeServiceConfigW(service.value,SERVICE_NO_CHANGE,start,SERVICE_NO_CHANGE,image.c_str(),nullptr,nullptr,nullptr,nullptr,nullptr,display.c_str()))throw std::wstring(L"恢复原服务配置失败。");}
    else {service.value=CreateServiceW(manager.value,c.service.c_str(),display.c_str(),SERVICE_ALL_ACCESS,SERVICE_WIN32_OWN_PROCESS,start,SERVICE_ERROR_NORMAL,image.c_str(),nullptr,nullptr,nullptr,L"LocalSystem",nullptr);if(!service.value)throw std::wstring(L"重建原服务失败。");}
    restore_policy(service.value,saved.value);
    if(read_number(saved.value,L"Running")&&!StartServiceW(service.value,0,nullptr)&&GetLastError()!=ERROR_SERVICE_ALREADY_RUNNING)throw std::wstring(L"原服务配置已恢复，但启动失败。");
}
void remove_snapshot(const context &c){RegDeleteTreeW(HKEY_LOCAL_MACHINE,c.transaction.c_str());}
template<class F>UINT action(MSIHANDLE h,F operation){try{context c=parameters(h);operation(c);return ERROR_SUCCESS;}catch(const std::wstring &message){log(h,message,true);return ERROR_INSTALL_FAILURE;}catch(...){log(h,L"安装操作发生异常，正在按安装事务恢复。",true);return ERROR_INSTALL_FAILURE;}}
}
extern "C" __declspec(dllexport) UINT __stdcall NewTransaction(MSIHANDLE h){GUID id{};wchar_t text[40]{};if(FAILED(CoCreateGuid(&id))||!StringFromGUID2(id,text,40))return ERROR_INSTALL_FAILURE;return MsiSetPropertyW(h,L"STREAMLINK_TRANSACTION",text);}
extern "C" __declspec(dllexport) UINT __stdcall PrepareUpgrade(MSIHANDLE h){return action(h,[&](const context &c){snapshot_service(c);close_clients(h,c,true);registry saved;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,c.transaction.c_str(),0,KEY_SET_VALUE|KEY_WOW64_64KEY,&saved.value)!=ERROR_SUCCESS)throw std::wstring(L"安装恢复记录不可写。");set_number(saved.value,L"MutationPermitted",1);});}
extern "C" __declspec(dllexport) UINT __stdcall CloseClients(MSIHANDLE h){return action(h,[&](const context &c){close_clients(h,c,false);});}
extern "C" __declspec(dllexport) UINT __stdcall RollbackUpgrade(MSIHANDLE h){return action(h,[&](const context &c){restore_service(c);remove_snapshot(c);});}
extern "C" __declspec(dllexport) UINT __stdcall CommitUpgrade(MSIHANDLE h){return action(h,[&](const context &c){remove_snapshot(c);});}

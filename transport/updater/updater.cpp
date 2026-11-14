// Small, independent local MSI runner. No dependency on ConWU, its WebUI,
// virtual adapter, peer connection, or the files MSI is about to replace.
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <msi.h>
#include <bcrypt.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <sddl.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <stdexcept>

namespace fs=std::filesystem;
struct handle { HANDLE value=nullptr;~handle(){if(value&&value!=INVALID_HANDLE_VALUE)CloseHandle(value);} };
struct service { SC_HANDLE value=nullptr;~service(){if(value)CloseServiceHandle(value);} };
std::wstring ini(const fs::path &file,const wchar_t *section,const wchar_t *key){std::vector<wchar_t> value(32768);DWORD n=GetPrivateProfileStringW(section,key,L"",value.data(),static_cast<DWORD>(value.size()),file.c_str());if(n>=value.size()-1)throw std::runtime_error("INI field too large");return std::wstring(value.data(),n);}
std::string utf8(const std::wstring &text){int n=WideCharToMultiByte(CP_UTF8,0,text.data(),static_cast<int>(text.size()),nullptr,0,nullptr,nullptr);std::string out(n,0);WideCharToMultiByte(CP_UTF8,0,text.data(),static_cast<int>(text.size()),out.data(),n,nullptr,nullptr);return out;}
std::string quoted(const std::wstring &text){std::string out="\"";for(unsigned char c:utf8(text)){if(c=='"'||c=='\\')out+='\\';if(c>=32)out+=static_cast<char>(c);}return out+'"';}
void write_atomic(const fs::path &path,const std::string &bytes){auto temp=path;temp+=L".tmp";{std::ofstream out(temp,std::ios::binary|std::ios::trunc);out.write(bytes.data(),bytes.size());if(!out)throw std::runtime_error("Cannot write update state");}if(!MoveFileExW(temp.c_str(),path.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))throw std::runtime_error("Cannot commit update state");}
void status(const fs::path &folder,const std::wstring &ticket,const std::wstring &version,const wchar_t *state,const std::wstring &message,bool reboot=false){write_atomic(folder/L"status.json","{\"supported\":true,\"ticket\":"+quoted(ticket)+",\"version\":"+quoted(version)+",\"state\":"+quoted(state)+",\"message\":"+quoted(message)+",\"canInstall\":false,\"rebootRequired\":"+(reboot?"true":"false")+"}");}
bool hex_id(const std::wstring &value){return value.size()==32&&std::all_of(value.begin(),value.end(),[](wchar_t c){return c>='0'&&c<='9'||c>='a'&&c<='f';});}
void no_links(fs::path path){while(!path.empty()){DWORD attrs=GetFileAttributesW(path.c_str());if(attrs!=INVALID_FILE_ATTRIBUTES&&(attrs&FILE_ATTRIBUTE_REPARSE_POINT))throw std::runtime_error("Update path contains a link");auto parent=path.parent_path();if(parent==path)break;path=parent;}}
std::wstring digest(const fs::path &path){
 BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;
 if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)throw std::runtime_error("SHA256 provider failed");
 std::wstring result;try{
  DWORD size=0,used=0;BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&size),sizeof(size),&used,0);std::vector<BYTE> object(size);
  if(BCryptCreateHash(alg,&hash,object.data(),size,nullptr,0,0)<0)throw std::runtime_error("SHA256 initialization failed");
  std::ifstream input(path,std::ios::binary);if(!input)throw std::runtime_error("Installer unavailable");std::vector<char> bytes(131072);
  while(input){input.read(bytes.data(),bytes.size());if(input.gcount()>0&&BCryptHashData(hash,reinterpret_cast<PUCHAR>(bytes.data()),static_cast<ULONG>(input.gcount()),0)<0)throw std::runtime_error("SHA256 failed");}
  if(!input.eof())throw std::runtime_error("Installer read failed");BYTE output[32];if(BCryptFinishHash(hash,output,32,0)<0)throw std::runtime_error("SHA256 finish failed");
  const wchar_t *digits=L"0123456789ABCDEF";for(BYTE b:output){result+=digits[b>>4];result+=digits[b&15];}
 }catch(...){if(hash)BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(alg,0);throw;}
 if(hash)BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(alg,0);return result;
}
SERVICE_STATUS_PROCESS query(SC_HANDLE svc){SERVICE_STATUS_PROCESS value{};DWORD bytes=0;if(!QueryServiceStatusEx(svc,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&value),sizeof(value),&bytes))throw std::runtime_error("Service status unavailable");return value;}
void start(SC_HANDLE svc){auto state=query(svc);if(state.dwCurrentState==SERVICE_STOPPED&&!StartServiceW(svc,0,nullptr)&&GetLastError()!=ERROR_SERVICE_ALREADY_RUNNING)throw std::runtime_error("Cannot restart ConWU service");}
void stop(SC_HANDLE svc){
 auto before=query(svc);if(before.dwCurrentState==SERVICE_STOPPED)return;handle process{OpenProcess(SYNCHRONIZE,FALSE,before.dwProcessId)};
 SERVICE_STATUS ignored{};if(before.dwCurrentState!=SERVICE_STOP_PENDING&&!ControlService(svc,SERVICE_CONTROL_STOP,&ignored)&&GetLastError()!=ERROR_SERVICE_NOT_ACTIVE)throw std::runtime_error("Cannot stop ConWU service");
 ULONGLONG until=GetTickCount64()+90000;while(query(svc).dwCurrentState!=SERVICE_STOPPED){if(GetTickCount64()>until)throw std::runtime_error("ConWU service did not stop; installer was not started");Sleep(250);}
 if(process.value&&WaitForSingleObject(process.value,30000)!=WAIT_OBJECT_0)throw std::runtime_error("Previous backend still owns resources; installer was not started");
}
void backup(const fs::path &root,const fs::path &target){
 fs::create_directories(target);no_links(root);no_links(target);
 for(fs::recursive_directory_iterator it(root),end;it!=end;++it){
  auto rel=fs::relative(it->path(),root);auto name=it->path().filename().wstring();
  if(it->is_directory()&&(name==L"updates"||name==L"logs"||name==L"sessions")){it.disable_recursion_pending();continue;}
  if(it->is_symlink()||(GetFileAttributesW(it->path().c_str())&FILE_ATTRIBUTE_REPARSE_POINT))throw std::runtime_error("Configuration backup contains a link");
  if(it->is_regular_file()&&name!=L"runtime.lock"&&name!=L"install.lock"){
   auto dest=target/rel;fs::create_directories(dest.parent_path());fs::copy_file(it->path(),dest,fs::copy_options::overwrite_existing);
  }
 }
}
bool health(const fs::path &folder,const std::wstring &ticket,const std::wstring &version,DWORD pid,bool &connected){
 auto file=folder/L"health.ini";if(!fs::is_regular_file(file))return false;
 // The backend atomically replaces this file. Flush the profile API's cache
 // so a stale pre-restart PID can never confirm a new backend's recovery.
 WritePrivateProfileStringW(nullptr,nullptr,nullptr,file.c_str());
 if(ini(file,L"Health",L"Ticket")!=ticket||ini(file,L"Health",L"Version")!=version||ini(file,L"Health",L"Pid")!=std::to_wstring(pid)||ini(file,L"Health",L"Ready")!=L"1"||ini(file,L"Health",L"NetworksRestored")!=L"1")return false;
 connected=ini(file,L"Health",L"Connected")==ini(file,L"Health",L"ExpectedConnected");return true;
}
void resume_ui(SC_HANDLE svc,const std::wstring &sid){
 DWORD needed=0;QueryServiceConfigW(svc,nullptr,0,&needed);std::vector<BYTE> buffer(needed);auto config=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());if(!QueryServiceConfigW(svc,config,needed,&needed))return;
 std::wstring binary=config->lpBinaryPathName;if(binary.empty())return;binary=binary.front()=='"'?binary.substr(1,binary.find('"',1)-1):binary.substr(0,binary.find(' '));
 auto exe=fs::path(binary).parent_path()/L"ConWU.exe";if(!fs::is_regular_file(exe))return;
 PWTS_SESSION_INFOW sessions=nullptr;DWORD count=0;if(!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE,0,1,&sessions,&count))return;
 for(DWORD i=0;i<count;i++)if(sessions[i].State==WTSActive){
  handle token;if(!WTSQueryUserToken(sessions[i].SessionId,&token.value))continue;
  DWORD bytes=0;GetTokenInformation(token.value,TokenUser,nullptr,0,&bytes);std::vector<BYTE> user(bytes);if(!GetTokenInformation(token.value,TokenUser,user.data(),bytes,&bytes))continue;
  PWSTR actual=nullptr;if(!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid,&actual))continue;bool match=sid==actual;LocalFree(actual);if(!match)continue;
  // The UI deliberately refuses administrator tokens. WTS can return one on
  // machines with nonstandard UAC settings; restrict it to ordinary integrity.
  PSID admin=nullptr,medium=nullptr;
  if(!ConvertStringSidToSidW(L"S-1-5-32-544",&admin))continue;
  SID_AND_ATTRIBUTES deny{admin,0};handle ordinary;
  bool restricted=CreateRestrictedToken(token.value,DISABLE_MAX_PRIVILEGE,1,&deny,0,nullptr,0,nullptr,&ordinary.value)!=FALSE;LocalFree(admin);if(!restricted)continue;
  if(!ConvertStringSidToSidW(L"S-1-16-8192",&medium))continue;
  TOKEN_MANDATORY_LABEL label{{medium,SE_GROUP_INTEGRITY}};bool labeled=SetTokenInformation(ordinary.value,TokenIntegrityLevel,&label,sizeof(label)+GetLengthSid(medium))!=FALSE;LocalFree(medium);if(!labeled)continue;
  void *environment=nullptr;if(!CreateEnvironmentBlock(&environment,ordinary.value,FALSE))continue;
  std::wstring command=L"\""+exe.wstring()+L"\" --desktop";STARTUPINFOW startup{};startup.cb=sizeof(startup);startup.lpDesktop=const_cast<PWSTR>(L"winsta0\\default");PROCESS_INFORMATION process{};
  if(CreateProcessAsUserW(ordinary.value,exe.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_UNICODE_ENVIRONMENT|CREATE_NO_WINDOW|CREATE_BREAKAWAY_FROM_JOB,environment,exe.parent_path().c_str(),&startup,&process)){CloseHandle(process.hThread);CloseHandle(process.hProcess);}
  DestroyEnvironmentBlock(environment);break;
 }
 WTSFreeMemory(sessions);
}
int wmain(int argc,wchar_t **argv){
 // Standalone lifetime proof used by the private test: no service/MSI APIs.
 if(argc==4&&std::wstring(argv[1])==L"--probe-after-parent"){
  handle parent{OpenProcess(SYNCHRONIZE,FALSE,static_cast<DWORD>(std::stoul(argv[3])))};if(parent.value)WaitForSingleObject(parent.value,10000);
  if(parent.value&&WaitForSingleObject(parent.value,0)!=WAIT_OBJECT_0)return 4;
  write_atomic(argv[2],"{\"parentExited\":true}");return 0;
 }
 std::vector<wchar_t> module(32768);DWORD length=GetModuleFileNameW(nullptr,module.data(),static_cast<DWORD>(module.size()));fs::path folder=fs::path(std::wstring(module.data(),length)).parent_path();
 std::wstring ticket,version,serviceName;service manager,svc;bool stopped=false;
 try{
  no_links(folder);auto file=folder/L"job.ini";ticket=ini(file,L"Update",L"Ticket");version=ini(file,L"Update",L"Version");serviceName=ini(file,L"Update",L"Service");
  if(!hex_id(ticket)||folder.filename()!=ticket||version.empty()||version.size()>128||serviceName.empty()||serviceName.size()>100)throw std::runtime_error("Invalid local update job");
  fs::path profile=ini(file,L"Update",L"ProfileRoot");if(fs::weakly_canonical(profile/L"updates"/L"jobs"/ticket)!=fs::weakly_canonical(folder))throw std::runtime_error("Update job escaped protected profile");
  no_links(profile);auto package=folder/L"package.msi";no_links(package);
  if(fs::file_size(package)!=std::stoull(ini(file,L"Update",L"Bytes"))||digest(package)!=ini(file,L"Update",L"Sha256"))throw std::runtime_error("Installer integrity changed before execution");
  auto sid=ini(file,L"Update",L"UiSid");if(sid.size()>184||sid.rfind(L"S-1-5-21-",0)!=0||!std::all_of(sid.begin()+9,sid.end(),[](wchar_t c){return c>='0'&&c<='9'||c=='-';}))throw std::runtime_error("Invalid authorized update user");
  handle single{CreateMutexW(nullptr,TRUE,(L"Global\\"+serviceName+L"-LocalUpdate").c_str())};if(!single.value||GetLastError()==ERROR_ALREADY_EXISTS)throw std::runtime_error("Another local updater is running");
  manager.value=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);if(!manager.value)throw std::runtime_error("Cannot open service manager");
  svc.value=OpenServiceW(manager.value,serviceName.c_str(),SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS|SERVICE_START|SERVICE_STOP);if(!svc.value)throw std::runtime_error("Installed backend unavailable");
  status(folder,ticket,version,L"Installing",L"正在本机运行更新，远程连接中断不会取消安装");
  stop(svc.value);stopped=true;backup(profile,folder/L"previous-settings");
  // Do not retain a handle to the old service across RemoveExistingProducts.
  // Windows otherwise keeps it marked for deletion and rejects recreation.
  CloseServiceHandle(svc.value);svc.value=nullptr;
  MsiSetInternalUI(INSTALLUILEVEL_NONE,nullptr);MsiEnableLogW(INSTALLLOGMODE_VERBOSE,(folder/L"installer.log").c_str(),INSTALLLOGATTRIBUTES_APPEND);
  UINT result=ERROR_INSTALL_ALREADY_RUNNING;for(int attempt=0;attempt<12&&result==ERROR_INSTALL_ALREADY_RUNNING;attempt++){result=MsiInstallProductW(package.c_str(),L"REBOOT=ReallySuppress");if(result==ERROR_INSTALL_ALREADY_RUNNING)Sleep(5000);}
  // The MSI's deferred readiness check is inside Windows Installer's rollback
  // transaction. An unsuccessful install restores its prior files/service.
  svc.value=OpenServiceW(manager.value,serviceName.c_str(),SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS|SERVICE_START|SERVICE_STOP);
  if(!svc.value)throw std::runtime_error("MSI finished without an installed backend");
  start(svc.value);stopped=false;
  if(result!=ERROR_SUCCESS&&result!=ERROR_SUCCESS_REBOOT_REQUIRED){status(folder,ticket,version,L"Failed",L"MSI 更新未完成，已请求恢复原后台。错误码："+std::to_wstring(result));resume_ui(svc.value,sid);return 1;}
  status(folder,ticket,version,L"RestoringNetworks",L"安装已完成，正在恢复后台与原先启用的网络",result==ERROR_SUCCESS_REBOOT_REQUIRED);
  ULONGLONG until=GetTickCount64()+120000;bool local=false,connected=false;
  while(GetTickCount64()<until){auto state=query(svc.value);if(state.dwCurrentState==SERVICE_STOPPED){start(svc.value);Sleep(1000);continue;}
   local=state.dwCurrentState==SERVICE_RUNNING&&health(folder,ticket,version,state.dwProcessId,connected);if(local&&connected)break;Sleep(1000);
  }
  if(!local){status(folder,ticket,version,L"Failed",L"MSI 已安装，后台或网络配置恢复尚未确认；本机日志与上一份设置备份已保留",result==ERROR_SUCCESS_REBOOT_REQUIRED);return 2;}
  status(folder,ticket,version,connected?L"Completed":L"WaitingPeers",connected?L"更新完成，后台与原先连接的网络已恢复":L"更新完成，后台和网络配置已恢复，仍在等待部分对端上线",result==ERROR_SUCCESS_REBOOT_REQUIRED);
  resume_ui(svc.value,sid);return 0;
 }catch(const std::exception &error){
  if(stopped&&manager.value)try{if(!svc.value)svc.value=OpenServiceW(manager.value,serviceName.c_str(),SERVICE_QUERY_STATUS|SERVICE_START);if(svc.value)start(svc.value);}catch(...){}
  try{std::string text=error.what();status(folder,ticket,version,L"Failed",L"本机更新未完成："+std::wstring(text.begin(),text.end()));}catch(...){}
  return 3;
 }
}

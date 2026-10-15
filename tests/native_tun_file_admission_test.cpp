// Exact production admission helper, with host rundown/IRQL primitives.
// Tests submission ordering, not Windows CSQ, NDIS or kernel verification.
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <thread>
using LONG=int32_t; using BOOLEAN=bool; using VOID=void;
constexpr bool TRUE=true,FALSE=false;
thread_local int critical=0;
static void KeEnterCriticalRegion(){++critical;}
static void KeLeaveCriticalRegion(){if(--critical<0)std::abort();}
static LONG InterlockedExchange(volatile LONG* p,LONG n){return __sync_lock_test_and_set(p,n);}
static LONG InterlockedCompareExchange(volatile LONG* p,LONG n,LONG expected){return __sync_val_compare_and_swap(p,expected,n);}
struct EX_RUNDOWN_REF {std::mutex gate;std::condition_variable changed;int users=0;bool closed=false;};
static bool ExAcquireRundownProtection(EX_RUNDOWN_REF* r){std::lock_guard<std::mutex> held(r->gate);if(r->closed)return false;++r->users;return true;}
static void ExReleaseRundownProtection(EX_RUNDOWN_REF* r){std::lock_guard<std::mutex> held(r->gate);if(--r->users<0)std::abort();r->changed.notify_all();}
static void ExWaitForRundownProtectionRelease(EX_RUNDOWN_REF* r){if(critical==0)std::abort();std::unique_lock<std::mutex> held(r->gate);r->closed=true;r->changed.wait(held,[&]{return r->users==0;});}
struct SLT_ADAPTER {volatile LONG Opened=1;};
struct SLT_FILE {SLT_ADAPTER* Adapter;EX_RUNDOWN_REF Dispatch;volatile LONG Closing=0;};
#include "../drivers/StreamLink.Tun/file_admission.h"
static int checks=0;
static void check(bool p){if(!p)std::abort();++checks;}
int main(){
    for(int round=0;round<30;++round){
        SLT_ADAPTER adapter;SLT_FILE file{&adapter};std::atomic<bool> admitted{false};std::atomic<int> queued{0};
        std::thread read([&]{if(!SltEnterFile(&file))std::abort();admitted=true;
            while(InterlockedCompareExchange(&file.Closing,0,0)==0)std::this_thread::yield();
            ++queued;SltLeaveFile(&file);if(critical!=0)std::abort();});
        while(!admitted.load())std::this_thread::yield();
        SltBeginFileCleanup(&file);
        check(queued==1); // cleanup cannot drain before the admitted READ inserts
        queued=0;read.join();check(!SltEnterFile(&file));check(critical==0);
        check(adapter.Opened==2);check(InterlockedCompareExchange(&adapter.Opened,1,0)==2); // CREATE denied before CLOSE
        check(file.Dispatch.users==0);InterlockedExchange(&adapter.Opened,0);
        SLT_FILE next{&adapter};check(InterlockedCompareExchange(&adapter.Opened,1,0)==0);
        check(SltEnterFile(&next));SltLeaveFile(&next);SltBeginFileCleanup(&next);check(!SltEnterFile(&next));check(critical==0);
    }
    std::printf("TUN-FILE-ADMISSION %d checks; Pass; host model only, no kernel\n",checks);
}

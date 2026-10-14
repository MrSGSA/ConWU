// Host-side test of the exact once-only reservation helper used by driver.c.
// This deliberately does NOT emulate or claim to validate Windows CSQ/IRQL.
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <thread>
#include <vector>
#include <atomic>
#include <algorithm>
using LONG=int32_t;using PVOID=void*;using VOID=void;using BOOLEAN=bool;
#define TRUE true
#define FALSE false
#define NT_ASSERT(x) assert(x)
constexpr LONG SLT_PENDING_READS=16;
struct SLT_ADAPTER{volatile LONG PendingReads=0;};
struct IRP{struct{struct{void* DriverContext[4]{};}Overlay;}Tail;};using PIRP=IRP*;
static LONG InterlockedIncrement(volatile LONG* v){return __atomic_add_fetch(v,1,__ATOMIC_SEQ_CST);}
static LONG InterlockedDecrement(volatile LONG* v){return __atomic_sub_fetch(v,1,__ATOMIC_SEQ_CST);}
static PVOID InterlockedExchangePointer(PVOID volatile* p,PVOID v){return __atomic_exchange_n(p,v,__ATOMIC_SEQ_CST);}
#include "../drivers/StreamLink.Tun/read_reservation.h"
static int checks=0;
static void check(bool ok){++checks;assert(ok);}
int main(){
    SLT_ADAPTER a;
    // Pre-cancel: CSQ skips insertion/removal and invokes Cancel completion.
    for(int i=0;i<128;++i){IRP q;check(SltReserveRead(&a,&q));SltReleaseReadReservation(&a,&q);check(a.PendingReads==0);}
    // Queued cancel: Remove THEN CompleteCanceled; the second release is a no-op.
    for(int i=0;i<128;++i){IRP q;check(SltReserveRead(&a,&q));SltReleaseReadReservation(&a,&q);SltReleaseReadReservation(&a,&q);check(a.PendingReads==0);}
    IRP held[16],rejected;
    for(auto& q:held)check(SltReserveRead(&a,&q));
    check(a.PendingReads==16);check(!SltReserveRead(&a,&rejected));check(a.PendingReads==16);
    for(auto& q:held)SltReleaseReadReservation(&a,&q);
    check(a.PendingReads==0);check(SltReserveRead(&a,&rejected));SltReleaseReadReservation(&a,&rejected);
    // Two racing release paths cannot decrement twice, including before re-use.
    for(int i=0;i<200;++i){IRP q;check(SltReserveRead(&a,&q));
        std::thread one([&]{SltReleaseReadReservation(&a,&q);});
        std::thread two([&]{SltReleaseReadReservation(&a,&q);});one.join();two.join();check(a.PendingReads==0);}
    // Concurrent quota pressure. Each live reservation belongs to one IRP.
    std::atomic<int> completed{0};std::vector<std::thread> threads;
    for(int k=0;k<24;++k)threads.emplace_back([&]{for(int n=0;n<1000;++n){IRP q;
        if(SltReserveRead(&a,&q)){std::this_thread::yield();SltReleaseReadReservation(&a,&q);++completed;}}});
    for(auto& t:threads)t.join();check(a.PendingReads==0);check(completed>0);
    std::printf("{\"status\":\"Pass\",\"assertions\":%d,\"concurrentAcquires\":%d,\"kernelCsqExecuted\":false}\n",checks,completed.load());
}

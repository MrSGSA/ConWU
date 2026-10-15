#ifndef STREAMLINK_TUN_FILE_ADMISSION_H
#define STREAMLINK_TUN_FILE_ADMISSION_H
/* Per-file dispatch rundown only covers submission, NOT the lifetime of a
 * queued IRP. Cleanup rejects new dispatch, joins prior submissions, then
 * cancels the CSQ. I/O Manager keeps the FileObject alive through completion.
 * The lock order is file Dispatch -> adapter Writes. Cleanup never holds the
 * adapter rundown and cannot deadlock with miniport pause/halt. */
static BOOLEAN SltEnterFile(SLT_FILE *file)
{
    KeEnterCriticalRegion();
    if (!ExAcquireRundownProtection(&file->Dispatch)) { KeLeaveCriticalRegion(); return FALSE; }
    if (InterlockedCompareExchange(&file->Closing, 0, 0) != 0) {
        ExReleaseRundownProtection(&file->Dispatch);
        KeLeaveCriticalRegion();
        return FALSE;
    }
    return TRUE;
}
static VOID SltLeaveFile(SLT_FILE *file) { ExReleaseRundownProtection(&file->Dispatch); KeLeaveCriticalRegion(); }
static VOID SltBeginFileCleanup(SLT_FILE *file)
{
    InterlockedExchange(&file->Closing, 1);
    /* 0=unowned, 1=live, 2=closing. Closing blocks both NDIS enqueue and CREATE
     * until the FileObject CLOSE relinquishes the existing adapter reference. */
    InterlockedCompareExchange(&file->Adapter->Opened, 2, 1);
    KeEnterCriticalRegion();
    ExWaitForRundownProtectionRelease(&file->Dispatch);
    KeLeaveCriticalRegion();
}
#endif

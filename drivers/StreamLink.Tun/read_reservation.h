#ifndef STREAMLINK_TUN_READ_RESERVATION_H
#define STREAMLINK_TUN_READ_RESERVATION_H
/* PendingReads counts reservations, including the brief interval before CSQ
 * insertion. CSQ owns DriverContext[3]; our once-only reservation uses [0].
 * An already-cancelled IRP may bypass Insert/Remove altogether, so both Remove
 * and CompleteCanceled release through this helper. Never unconditionally
 * decrement in both callbacks. Host tests exercise this exact helper; they do
 * not replace Windows CSQ/IRQL/Verifier validation. */
static BOOLEAN SltReserveRead(SLT_ADAPTER *a, PIRP irp)
{
    irp->Tail.Overlay.DriverContext[0] = NULL;
    if (InterlockedIncrement(&a->PendingReads) > SLT_PENDING_READS) {
        InterlockedDecrement(&a->PendingReads);
        return FALSE;
    }
    irp->Tail.Overlay.DriverContext[0] = a;
    return TRUE;
}

static VOID SltReleaseReadReservation(SLT_ADAPTER *a, PIRP irp)
{
    PVOID held = InterlockedExchangePointer(
        (PVOID volatile *)&irp->Tail.Overlay.DriverContext[0], NULL);
    if (held != NULL) {
        NT_ASSERT(held == a);
        InterlockedDecrement(&a->PendingReads);
    }
}
#endif

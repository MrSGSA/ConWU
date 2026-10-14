// Original minimal raw-IP miniport research implementation. No NAT, crypto,
// packet capture, arbitrary memory IOCTL, Ethernet emulation or shared ring.
#include <ntddk.h>
#include <ndis.h>
#include <ntstrsafe.h>
#include "abi.h"
#define SLT_TAG 'nTLS'
typedef struct _SLT_PACKET { LIST_ENTRY Link; ULONG Length; UCHAR Data[SLT_MTU]; } SLT_PACKET;
typedef struct _SLT_ADAPTER SLT_ADAPTER;
typedef struct _SLT_EXTENSION { KSPIN_LOCK Gate; SLT_ADAPTER *Adapter; } SLT_EXTENSION;
struct _SLT_ADAPTER {
    NDIS_HANDLE Miniport,DeviceHandle,NblPool;
    PDEVICE_OBJECT Device;
    NET_LUID Luid; ULONG IfIndex;
    volatile LONG Refs,Opened,Stopped,Running,Paused,RundownClosed,DrainScheduled,PowerD0,Writers;
    EX_RUNDOWN_REF Writes;
    IO_CSQ ReadCsq; KSPIN_LOCK ReadLock; LIST_ENTRY Reads;
    KSPIN_LOCK PacketLock; LIST_ENTRY Packets;
    volatile LONG PendingReads,QueuedReads,Queued,PeakQueued;
    PIO_WORKITEM Work;
    volatile LONG64 OsOffered,OsQueued,OsDropped,UserReads,UserWrites,Malformed,Cancelled;
};
#include "read_reservation.h"
static NDIS_HANDLE SltDriverHandle;
DRIVER_INITIALIZE DriverEntry;
MINIPORT_INITIALIZE SltInitialize;
MINIPORT_HALT SltHalt;
MINIPORT_UNLOAD SltUnload;
MINIPORT_PAUSE SltPause;
MINIPORT_RESTART SltRestart;
MINIPORT_SEND_NET_BUFFER_LISTS SltSend;
MINIPORT_RETURN_NET_BUFFER_LISTS SltReturn;
MINIPORT_OID_REQUEST SltOid;
MINIPORT_CANCEL_OID_REQUEST SltCancelOid;
MINIPORT_CANCEL_SEND SltCancelSend;
MINIPORT_DEVICE_PNP_EVENT_NOTIFY SltPnp;
MINIPORT_SHUTDOWN SltShutdown;
MINIPORT_CHECK_FOR_HANG SltHang;
MINIPORT_RESET SltReset;
DRIVER_DISPATCH SltDispatch;

static VOID SltRef(SLT_ADAPTER *a){InterlockedIncrement(&a->Refs);}
static VOID SltRelease(SLT_ADAPTER *a){if(InterlockedDecrement(&a->Refs)==0){if(a->Work)IoFreeWorkItem(a->Work);ExFreePoolWithTag(a,SLT_TAG);}}
static NTSTATUS SltComplete(PIRP irp,NTSTATUS status,ULONG_PTR bytes){irp->IoStatus.Status=status;irp->IoStatus.Information=bytes;IoCompleteRequest(irp,IO_NO_INCREMENT);return status;}
static SLT_ADAPTER *SltFromCsq(PIO_CSQ csq){return CONTAINING_RECORD(csq,SLT_ADAPTER,ReadCsq);}
static VOID SltCsqInsert(PIO_CSQ csq,PIRP irp){SLT_ADAPTER *a=SltFromCsq(csq);InsertTailList(&a->Reads,&irp->Tail.Overlay.ListEntry);InterlockedIncrement(&a->QueuedReads);}
static VOID SltCsqRemove(PIO_CSQ csq,PIRP irp){SLT_ADAPTER *a=SltFromCsq(csq);RemoveEntryList(&irp->Tail.Overlay.ListEntry);InterlockedDecrement(&a->QueuedReads);SltReleaseReadReservation(a,irp);}
static PIRP SltCsqPeek(PIO_CSQ csq,PIRP irp,PVOID context){
    PLIST_ENTRY head=&SltFromCsq(csq)->Reads,e=irp?irp->Tail.Overlay.ListEntry.Flink:head->Flink;
    while(e!=head){PIRP next=CONTAINING_RECORD(e,IRP,Tail.Overlay.ListEntry);if(!context||IoGetCurrentIrpStackLocation(next)->FileObject==context)return next;e=e->Flink;}return NULL;
}
static VOID SltCsqAcquire(PIO_CSQ csq,PKIRQL irql){KeAcquireSpinLock(&SltFromCsq(csq)->ReadLock,irql);}
static VOID SltCsqRelease(PIO_CSQ csq,KIRQL irql){KeReleaseSpinLock(&SltFromCsq(csq)->ReadLock,irql);}
static VOID SltCsqCancelled(PIO_CSQ csq,PIRP irp){SltReleaseReadReservation(SltFromCsq(csq),irp);InterlockedIncrement64(&SltFromCsq(csq)->Cancelled);SltComplete(irp,STATUS_CANCELLED,0);}
static VOID SltCancelReads(SLT_ADAPTER *a,PFILE_OBJECT file,NTSTATUS status){PIRP irp;while((irp=IoCsqRemoveNextIrp(&a->ReadCsq,file))!=NULL){InterlockedIncrement64(&a->Cancelled);SltComplete(irp,status,0);}}
static SLT_PACKET *SltPop(SLT_ADAPTER *a){KIRQL level;SLT_PACKET *p=NULL;KeAcquireSpinLock(&a->PacketLock,&level);if(!IsListEmpty(&a->Packets)){p=CONTAINING_RECORD(RemoveHeadList(&a->Packets),SLT_PACKET,Link);InterlockedDecrement(&a->Queued);}KeReleaseSpinLock(&a->PacketLock,level);return p;}
static VOID SltClear(SLT_ADAPTER *a){SLT_PACKET *p;while((p=SltPop(a))!=NULL){InterlockedIncrement64(&a->OsDropped);ExFreePoolWithTag(p,SLT_TAG);}}
static VOID SltSchedule(SLT_ADAPTER *a);
static VOID SltDrain(PDEVICE_OBJECT device,PVOID context){
    SLT_ADAPTER *a=context;UNREFERENCED_PARAMETER(device);
    while(a->Running&&a->Queued>0){
        PIRP irp=IoCsqRemoveNextIrp(&a->ReadCsq,NULL);SLT_PACKET *p;if(!irp)break;
        p=SltPop(a);if(!p){SltComplete(irp,STATUS_DEVICE_NOT_READY,0);break;}
        if(!a->Running)SltComplete(irp,STATUS_DEVICE_NOT_READY,0);
        else if(IoGetCurrentIrpStackLocation(irp)->Parameters.Read.Length<p->Length)SltComplete(irp,STATUS_BUFFER_TOO_SMALL,0);
        else {RtlCopyMemory(irp->AssociatedIrp.SystemBuffer,p->Data,p->Length);InterlockedIncrement64(&a->UserReads);SltComplete(irp,STATUS_SUCCESS,p->Length);}
        ExFreePoolWithTag(p,SLT_TAG);
    }
    InterlockedExchange(&a->DrainScheduled,0);
    // A reservation may not have reached the CSQ yet (or was pre-cancelled).
    // Reschedule only for actual queued IRPs, not outstanding reservations.
    if(a->Running&&a->Queued>0&&a->QueuedReads>0)SltSchedule(a);
    SltRelease(a);
}
static VOID SltSchedule(SLT_ADAPTER *a){if(a->Running&&InterlockedCompareExchange(&a->DrainScheduled,1,0)==0){SltRef(a);IoQueueWorkItem(a->Work,SltDrain,DelayedWorkQueue,a);}}
static BOOLEAN SltIpv4(const UCHAR *p,ULONG n){ULONG h;if(n<20||n>SLT_MTU||(p[0]>>4)!=4)return FALSE;h=(p[0]&15)*4;return h>=20&&h<=n&&((ULONG)p[2]*256+p[3])==n;}
static VOID SltStopData(SLT_ADAPTER *a){InterlockedExchange(&a->Running,0);if(InterlockedExchange(&a->RundownClosed,1)==0)ExWaitForRundownProtectionRelease(&a->Writes);SltCancelReads(a,NULL,STATUS_DEVICE_NOT_READY);SltClear(a);}
static VOID SltStartData(SLT_ADAPTER *a){if(!a->Stopped&&!a->Paused&&a->PowerD0){if(InterlockedExchange(&a->RundownClosed,0)!=0)ExReInitializeRundownProtection(&a->Writes);InterlockedExchange(&a->Running,1);}}

NTSTATUS SltDispatch(PDEVICE_OBJECT device,PIRP irp){
    PIO_STACK_LOCATION stack=IoGetCurrentIrpStackLocation(irp);PFILE_OBJECT file=stack->FileObject;SLT_ADAPTER *a=file?file->FsContext:NULL;NTSTATUS status=STATUS_INVALID_DEVICE_REQUEST;ULONG_PTR used=0;
    if(stack->MajorFunction==IRP_MJ_CREATE){
        SLT_EXTENSION *ext=NdisGetDeviceReservedExtension(device);KIRQL level;KeAcquireSpinLock(&ext->Gate,&level);a=ext->Adapter;
        if(a&&!a->Stopped&&InterlockedCompareExchange(&a->Opened,1,0)==0){SltRef(a);file->FsContext=a;status=STATUS_SUCCESS;}else status=STATUS_DEVICE_NOT_READY;
        KeReleaseSpinLock(&ext->Gate,level);return SltComplete(irp,status,0);
    }
    if(!a)return SltComplete(irp,STATUS_ACCESS_DENIED,0);
    if(stack->MajorFunction==IRP_MJ_CLEANUP){SltCancelReads(a,file,STATUS_CANCELLED);SltClear(a);return SltComplete(irp,STATUS_SUCCESS,0);}
    if(stack->MajorFunction==IRP_MJ_CLOSE){file->FsContext=NULL;InterlockedExchange(&a->Opened,0);SltRelease(a);return SltComplete(irp,STATUS_SUCCESS,0);}
    if(a->Stopped)return SltComplete(irp,STATUS_DEVICE_REMOVED,0);
    if(stack->MajorFunction==IRP_MJ_DEVICE_CONTROL){
        ULONG code=stack->Parameters.DeviceIoControl.IoControlCode,length=stack->Parameters.DeviceIoControl.OutputBufferLength;
        if(code==SLT_IOCTL_INFO&&length>=sizeof(SLT_INFO)){
            SLT_INFO info={sizeof(SLT_INFO),SLT_ABI,SLT_MTU,SLT_QUEUE_PACKETS,0,0,1};info.Luid=a->Luid.Value;info.IfIndex=a->IfIndex;RtlCopyMemory(irp->AssociatedIrp.SystemBuffer,&info,sizeof(info));status=STATUS_SUCCESS;used=sizeof(info);
        }else if(code==SLT_IOCTL_STATS&&length>=sizeof(SLT_STATS)){
            SLT_STATS stats={0};stats.Size=sizeof(stats);stats.Abi=SLT_ABI;stats.OsOffered=a->OsOffered;stats.OsQueued=a->OsQueued;stats.OsDropped=a->OsDropped;stats.UserReads=a->UserReads;stats.UserWrites=a->UserWrites;stats.Malformed=a->Malformed;stats.Cancelled=a->Cancelled;stats.Queued=a->Queued;stats.PeakQueued=a->PeakQueued;stats.PendingReads=a->PendingReads;RtlCopyMemory(irp->AssociatedIrp.SystemBuffer,&stats,sizeof(stats));status=STATUS_SUCCESS;used=sizeof(stats);
        }else status=(code==SLT_IOCTL_INFO||code==SLT_IOCTL_STATS)?STATUS_BUFFER_TOO_SMALL:STATUS_INVALID_DEVICE_REQUEST;
    }else if(stack->MajorFunction==IRP_MJ_READ){
        if(stack->Parameters.Read.Length!=SLT_MTU)return SltComplete(irp,STATUS_INVALID_BUFFER_SIZE,0);
        if(!ExAcquireRundownProtection(&a->Writes))return SltComplete(irp,STATUS_DEVICE_NOT_READY,0);
        if(!a->Running){ExReleaseRundownProtection(&a->Writes);return SltComplete(irp,STATUS_DEVICE_NOT_READY,0);}
        if(!SltReserveRead(a,irp)){ExReleaseRundownProtection(&a->Writes);return SltComplete(irp,STATUS_INSUFFICIENT_RESOURCES,0);}
        IoMarkIrpPending(irp);IoCsqInsertIrp(&a->ReadCsq,irp,NULL);SltSchedule(a);ExReleaseRundownProtection(&a->Writes);return STATUS_PENDING;
    }else if(stack->MajorFunction==IRP_MJ_WRITE){
        ULONG n=stack->Parameters.Write.Length;UCHAR *p=irp->AssociatedIrp.SystemBuffer;PMDL mdl;PNET_BUFFER_LIST nbl;
        if(!p||!SltIpv4(p,n)){InterlockedIncrement64(&a->Malformed);return SltComplete(irp,STATUS_INVALID_PARAMETER,0);}
        if(!ExAcquireRundownProtection(&a->Writes))return SltComplete(irp,STATUS_DEVICE_NOT_READY,0);
        if(!a->Running){ExReleaseRundownProtection(&a->Writes);return SltComplete(irp,STATUS_DEVICE_NOT_READY,0);}
        if(InterlockedIncrement(&a->Writers)>16){InterlockedDecrement(&a->Writers);ExReleaseRundownProtection(&a->Writes);return SltComplete(irp,STATUS_INSUFFICIENT_RESOURCES,0);}
        mdl=IoAllocateMdl(p,n,FALSE,FALSE,NULL);nbl=NULL;if(mdl){MmBuildMdlForNonPagedPool(mdl);nbl=NdisAllocateNetBufferAndNetBufferList(a->NblPool,0,0,mdl,0,n);}
        if(!nbl){if(mdl)IoFreeMdl(mdl);status=STATUS_INSUFFICIENT_RESOURCES;}else{
            nbl->SourceHandle=a->Miniport;NdisSetNblFlag(nbl,NDIS_NBL_FLAGS_IS_IPV4);NET_BUFFER_LIST_INFO(nbl,NetBufferListFrameType)=(PVOID)(ULONG_PTR)RtlUshortByteSwap(0x0800);
            NdisMIndicateReceiveNetBufferLists(a->Miniport,nbl,0,1,NDIS_RECEIVE_FLAGS_RESOURCES);
            NdisFreeNetBufferList(nbl);IoFreeMdl(mdl);InterlockedIncrement64(&a->UserWrites);status=STATUS_SUCCESS;used=n;
        }InterlockedDecrement(&a->Writers);ExReleaseRundownProtection(&a->Writes);
    }
    return SltComplete(irp,status,used);
}

VOID SltSend(NDIS_HANDLE context,PNET_BUFFER_LIST lists,NDIS_PORT_NUMBER port,ULONG flags){
    SLT_ADAPTER *a=context;PNET_BUFFER_LIST nbl;UNREFERENCED_PARAMETER(port);
    for(nbl=lists;nbl;nbl=NET_BUFFER_LIST_NEXT_NBL(nbl)){
        PNET_BUFFER nb;NDIS_STATUS result=NDIS_STATUS_SUCCESS;
        for(nb=NET_BUFFER_LIST_FIRST_NB(nbl);nb;nb=NET_BUFFER_NEXT_NB(nb)){
            ULONG n=NET_BUFFER_DATA_LENGTH(nb);SLT_PACKET *packet;PUCHAR bytes;KIRQL level;BOOLEAN accepted=FALSE;
            InterlockedIncrement64(&a->OsOffered);
            if(!a->Running||!a->Opened||n>SLT_MTU||n<20){InterlockedIncrement64(&a->OsDropped);result=NDIS_STATUS_RESOURCES;continue;}
            packet=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*packet),SLT_TAG);
            if(!packet){InterlockedIncrement64(&a->OsDropped);result=NDIS_STATUS_RESOURCES;continue;}
            bytes=NdisGetDataBuffer(nb,n,packet->Data,1,0);
            if(!bytes||!SltIpv4(bytes,n)){InterlockedIncrement64(&a->Malformed);ExFreePoolWithTag(packet,SLT_TAG);result=NDIS_STATUS_INVALID_PACKET;continue;}
            if(bytes!=packet->Data)RtlCopyMemory(packet->Data,bytes,n);packet->Length=n;
            KeAcquireSpinLock(&a->PacketLock,&level);
            if(a->Running&&a->Opened&&a->Queued<SLT_QUEUE_PACKETS){InsertTailList(&a->Packets,&packet->Link);a->Queued++;if(a->Queued>a->PeakQueued)a->PeakQueued=a->Queued;accepted=TRUE;}
            KeReleaseSpinLock(&a->PacketLock,level);
            if(accepted){InterlockedIncrement64(&a->OsQueued);SltSchedule(a);}else{InterlockedIncrement64(&a->OsDropped);ExFreePoolWithTag(packet,SLT_TAG);result=NDIS_STATUS_RESOURCES;}
        }NET_BUFFER_LIST_STATUS(nbl)=result;
    }NdisMSendNetBufferListsComplete(a->Miniport,lists,(flags&NDIS_SEND_FLAGS_DISPATCH_LEVEL)?NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL:0);
}
VOID SltReturn(NDIS_HANDLE context,PNET_BUFFER_LIST lists,ULONG flags){UNREFERENCED_PARAMETER(context);UNREFERENCED_PARAMETER(lists);UNREFERENCED_PARAMETER(flags);NT_ASSERT(FALSE);/* receive indications are synchronous RESOURCES only */}

static const NDIS_OID SltOids[]={OID_GEN_SUPPORTED_LIST,OID_GEN_HARDWARE_STATUS,OID_GEN_MEDIA_SUPPORTED,OID_GEN_MEDIA_IN_USE,OID_GEN_MAXIMUM_FRAME_SIZE,OID_GEN_MAXIMUM_TOTAL_SIZE,OID_GEN_LINK_SPEED,OID_GEN_TRANSMIT_BUFFER_SPACE,OID_GEN_RECEIVE_BUFFER_SPACE,OID_GEN_TRANSMIT_BLOCK_SIZE,OID_GEN_RECEIVE_BLOCK_SIZE,OID_GEN_VENDOR_ID,OID_GEN_VENDOR_DESCRIPTION,OID_GEN_CURRENT_PACKET_FILTER,OID_GEN_CURRENT_LOOKAHEAD,OID_GEN_MAXIMUM_LOOKAHEAD,OID_GEN_MEDIA_CONNECT_STATUS,OID_GEN_XMIT_OK,OID_GEN_RCV_OK,OID_GEN_XMIT_ERROR,OID_GEN_RCV_ERROR,OID_GEN_RCV_NO_BUFFER,OID_PNP_CAPABILITIES,OID_PNP_QUERY_POWER,OID_PNP_SET_POWER};
NDIS_STATUS SltOid(NDIS_HANDLE context,PNDIS_OID_REQUEST request){
    SLT_ADAPTER *a=context;ULONG value=0;PVOID data=&value;ULONG bytes=sizeof(value);NDIS_OID oid;NDIS_PNP_CAPABILITIES capabilities={0};
    if(request->RequestType==NdisRequestSetInformation){
        oid=request->DATA.SET_INFORMATION.Oid;request->DATA.SET_INFORMATION.BytesRead=0;request->DATA.SET_INFORMATION.BytesNeeded=sizeof(ULONG);
        if(request->DATA.SET_INFORMATION.InformationBufferLength<sizeof(ULONG))return NDIS_STATUS_INVALID_LENGTH;
        if(oid==OID_PNP_SET_POWER){
            NDIS_DEVICE_POWER_STATE state=*(PNDIS_DEVICE_POWER_STATE)request->DATA.SET_INFORMATION.InformationBuffer;
            if(state<NdisDeviceStateD0||state>NdisDeviceStateD3)return NDIS_STATUS_INVALID_DATA;
            InterlockedExchange(&a->PowerD0,state==NdisDeviceStateD0);if(state==NdisDeviceStateD0)SltStartData(a);else SltStopData(a);
            request->DATA.SET_INFORMATION.BytesRead=sizeof(state);return NDIS_STATUS_SUCCESS;
        }
        if(oid!=OID_GEN_CURRENT_PACKET_FILTER&&oid!=OID_GEN_CURRENT_LOOKAHEAD)return NDIS_STATUS_NOT_SUPPORTED;
        request->DATA.SET_INFORMATION.BytesRead=sizeof(ULONG);return NDIS_STATUS_SUCCESS;
    }
    if(request->RequestType!=NdisRequestQueryInformation&&request->RequestType!=NdisRequestQueryStatistics)return NDIS_STATUS_NOT_SUPPORTED;
    oid=request->DATA.QUERY_INFORMATION.Oid;request->DATA.QUERY_INFORMATION.BytesWritten=0;
    switch(oid){
    case OID_PNP_QUERY_POWER:return request->DATA.QUERY_INFORMATION.InformationBufferLength>=sizeof(NDIS_DEVICE_POWER_STATE)?NDIS_STATUS_SUCCESS:NDIS_STATUS_INVALID_LENGTH;
    case OID_PNP_CAPABILITIES:data=&capabilities;bytes=sizeof(capabilities);break;
    case OID_GEN_SUPPORTED_LIST:data=(PVOID)SltOids;bytes=sizeof(SltOids);break;
    case OID_GEN_HARDWARE_STATUS:value=NdisHardwareStatusReady;break;
    case OID_GEN_MEDIA_SUPPORTED:case OID_GEN_MEDIA_IN_USE:value=NdisMediumIP;break;
    case OID_GEN_MAXIMUM_FRAME_SIZE:case OID_GEN_MAXIMUM_TOTAL_SIZE:case OID_GEN_TRANSMIT_BLOCK_SIZE:case OID_GEN_RECEIVE_BLOCK_SIZE:case OID_GEN_MAXIMUM_LOOKAHEAD:case OID_GEN_CURRENT_LOOKAHEAD:value=SLT_MTU;break;
    case OID_GEN_LINK_SPEED:value=10000000;break;
    case OID_GEN_TRANSMIT_BUFFER_SPACE:case OID_GEN_RECEIVE_BUFFER_SPACE:value=SLT_MTU*SLT_QUEUE_PACKETS;break;
    case OID_GEN_VENDOR_ID:value=0x00FFFFFF;break;
    case OID_GEN_VENDOR_DESCRIPTION:data="StreamLink raw IPv4 research miniport";bytes=sizeof("StreamLink raw IPv4 research miniport");break;
    case OID_GEN_MEDIA_CONNECT_STATUS:value=NdisMediaStateConnected;break;
    case OID_GEN_CURRENT_PACKET_FILTER:value=NDIS_PACKET_TYPE_DIRECTED;break;
    case OID_GEN_XMIT_OK:value=(ULONG)a->OsQueued;break;
    case OID_GEN_RCV_OK:value=(ULONG)a->UserWrites;break;
    case OID_GEN_XMIT_ERROR:case OID_GEN_RCV_NO_BUFFER:value=(ULONG)a->OsDropped;break;
    case OID_GEN_RCV_ERROR:value=(ULONG)a->Malformed;break;
    default:return NDIS_STATUS_NOT_SUPPORTED;
    }
    request->DATA.QUERY_INFORMATION.BytesNeeded=bytes;if(request->DATA.QUERY_INFORMATION.InformationBufferLength<bytes)return NDIS_STATUS_BUFFER_TOO_SHORT;
    RtlCopyMemory(request->DATA.QUERY_INFORMATION.InformationBuffer,data,bytes);request->DATA.QUERY_INFORMATION.BytesWritten=bytes;return NDIS_STATUS_SUCCESS;
}
VOID SltCancelOid(NDIS_HANDLE c,PVOID id){UNREFERENCED_PARAMETER(c);UNREFERENCED_PARAMETER(id);/* no pending OIDs */}
VOID SltCancelSend(NDIS_HANDLE c,PVOID id){UNREFERENCED_PARAMETER(c);UNREFERENCED_PARAMETER(id);/* NBL completion occurs before Send returns */}
VOID SltPnp(NDIS_HANDLE context,PNET_DEVICE_PNP_EVENT event){if(event->DevicePnPEvent==NdisDevicePnPEventSurpriseRemoved){SLT_ADAPTER *a=context;InterlockedExchange(&a->Stopped,1);SltStopData(a);}}
VOID SltShutdown(NDIS_HANDLE context,NDIS_SHUTDOWN_ACTION action){SLT_ADAPTER *a=context;UNREFERENCED_PARAMETER(action);InterlockedExchange(&a->Running,0);/* shutdown can run at high IRQL; no wait or pageable work */}
BOOLEAN SltHang(NDIS_HANDLE c){UNREFERENCED_PARAMETER(c);return FALSE;}
NDIS_STATUS SltReset(NDIS_HANDLE c,PBOOLEAN addressReset){UNREFERENCED_PARAMETER(c);*addressReset=FALSE;return NDIS_STATUS_SUCCESS;}
NDIS_STATUS SltPause(NDIS_HANDLE context,PNDIS_MINIPORT_PAUSE_PARAMETERS parameters){SLT_ADAPTER *a=context;UNREFERENCED_PARAMETER(parameters);InterlockedExchange(&a->Paused,1);SltStopData(a);return NDIS_STATUS_SUCCESS;}
NDIS_STATUS SltRestart(NDIS_HANDLE context,PNDIS_MINIPORT_RESTART_PARAMETERS parameters){SLT_ADAPTER *a=context;UNREFERENCED_PARAMETER(parameters);InterlockedExchange(&a->Paused,0);SltStartData(a);return NDIS_STATUS_SUCCESS;}
VOID SltHalt(NDIS_HANDLE context,NDIS_HALT_ACTION action){
    SLT_ADAPTER *a=context;UNREFERENCED_PARAMETER(action);InterlockedExchange(&a->Stopped,1);SltStopData(a);
    if(a->DeviceHandle){SLT_EXTENSION *ext=NdisGetDeviceReservedExtension(a->Device);KIRQL level;KeAcquireSpinLock(&ext->Gate,&level);ext->Adapter=NULL;KeReleaseSpinLock(&ext->Gate,level);NdisDeregisterDeviceEx(a->DeviceHandle);a->DeviceHandle=NULL;}
    if(a->NblPool){NdisFreeNetBufferListPool(a->NblPool);a->NblPool=NULL;}SltRelease(a);
}
NDIS_STATUS SltInitialize(NDIS_HANDLE miniport,NDIS_HANDLE driverContext,PNDIS_MINIPORT_INIT_PARAMETERS parameters){
    SLT_ADAPTER *a;NDIS_STATUS status;NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES reg={0};NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES general={0};NET_BUFFER_LIST_POOL_PARAMETERS pool={0};NDIS_DEVICE_OBJECT_ATTRIBUTES device={0};PDRIVER_DISPATCH dispatch[IRP_MJ_MAXIMUM_FUNCTION+1]={0};UNICODE_STRING name,symbol,sddl;WCHAR nameBuffer[80],symbolBuffer[80];ULONG i;
    UNREFERENCED_PARAMETER(driverContext);a=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*a),SLT_TAG);if(!a)return NDIS_STATUS_RESOURCES;
    a->Refs=1;a->Paused=1;a->PowerD0=1;a->Miniport=miniport;a->Luid=parameters->NetLuid;a->IfIndex=parameters->IfIndex;
    ExInitializeRundownProtection(&a->Writes);InitializeListHead(&a->Reads);InitializeListHead(&a->Packets);KeInitializeSpinLock(&a->ReadLock);KeInitializeSpinLock(&a->PacketLock);
    if(!NT_SUCCESS(IoCsqInitialize(&a->ReadCsq,SltCsqInsert,SltCsqRemove,SltCsqPeek,SltCsqAcquire,SltCsqRelease,SltCsqCancelled))){SltRelease(a);return NDIS_STATUS_RESOURCES;}
    reg.Header.Type=NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;reg.Header.Revision=NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;reg.Header.Size=NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;reg.MiniportAdapterContext=a;reg.AttributeFlags=NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND;reg.InterfaceType=NdisInterfaceInternal;
    status=NdisMSetMiniportAttributes(miniport,(PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&reg);if(status!=NDIS_STATUS_SUCCESS){SltRelease(a);return status;}
    general.Header.Type=NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;general.Header.Revision=NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;general.Header.Size=NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;
    general.MediaType=NdisMediumIP;general.PhysicalMediumType=NdisPhysicalMediumUnspecified;general.MtuSize=SLT_MTU;general.MaxXmitLinkSpeed=general.MaxRcvLinkSpeed=general.XmitLinkSpeed=general.RcvLinkSpeed=1000000000;general.MediaConnectState=MediaConnectStateConnected;general.MediaDuplexState=MediaDuplexStateFull;general.LookaheadSize=SLT_MTU;general.SupportedPacketFilters=NDIS_PACKET_TYPE_DIRECTED;general.IfType=IF_TYPE_PROP_VIRTUAL;general.IfConnectorPresent=FALSE;general.AccessType=NET_IF_ACCESS_POINT_TO_POINT;general.DirectionType=NET_IF_DIRECTION_SENDRECEIVE;general.ConnectionType=NET_IF_CONNECTION_DEDICATED;general.SupportedOidList=(PNDIS_OID)SltOids;general.SupportedOidListLength=sizeof(SltOids);general.AutoNegotiationFlags=NDIS_LINK_STATE_XMIT_LINK_SPEED_AUTO_NEGOTIATED|NDIS_LINK_STATE_RCV_LINK_SPEED_AUTO_NEGOTIATED;
    status=NdisMSetMiniportAttributes(miniport,(PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&general);if(status!=NDIS_STATUS_SUCCESS){SltHalt(a,NdisHaltDeviceInitializationFailed);return status;}
    pool.Header.Type=NDIS_OBJECT_TYPE_DEFAULT;pool.Header.Revision=NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;pool.Header.Size=NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;pool.ProtocolId=NDIS_PROTOCOL_ID_DEFAULT;pool.fAllocateNetBuffer=TRUE;pool.PoolTag=SLT_TAG;a->NblPool=NdisAllocateNetBufferListPool(miniport,&pool);
    if(!a->NblPool){SltHalt(a,NdisHaltDeviceInitializationFailed);return NDIS_STATUS_RESOURCES;}
    RtlStringCchPrintfW(nameBuffer,RTL_NUMBER_OF(nameBuffer),L"\\Device\\StreamLinkTun-%lu",a->IfIndex);RtlStringCchPrintfW(symbolBuffer,RTL_NUMBER_OF(symbolBuffer),L"\\DosDevices\\StreamLinkTun-%lu",a->IfIndex);RtlInitUnicodeString(&name,nameBuffer);RtlInitUnicodeString(&symbol,symbolBuffer);RtlInitUnicodeString(&sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    for(i=0;i<=IRP_MJ_MAXIMUM_FUNCTION;i++)dispatch[i]=SltDispatch;
    device.Header.Type=NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;device.Header.Revision=NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;device.Header.Size=NDIS_SIZEOF_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;device.DeviceName=&name;device.SymbolicName=&symbol;device.MajorFunctions=dispatch;device.ExtensionSize=sizeof(SLT_EXTENSION);device.DefaultSDDLString=&sddl;
    status=NdisRegisterDeviceEx(SltDriverHandle,&device,&a->Device,&a->DeviceHandle);if(status!=NDIS_STATUS_SUCCESS){SltHalt(a,NdisHaltDeviceInitializationFailed);return status;}
    {SLT_EXTENSION *ext=NdisGetDeviceReservedExtension(a->Device);KeInitializeSpinLock(&ext->Gate);ext->Adapter=a;}
    a->Device->Flags|=DO_BUFFERED_IO;a->Work=IoAllocateWorkItem(a->Device);if(!a->Work){SltHalt(a,NdisHaltDeviceInitializationFailed);return NDIS_STATUS_RESOURCES;}
    return NDIS_STATUS_SUCCESS;
}
VOID SltUnload(PDRIVER_OBJECT driver){UNREFERENCED_PARAMETER(driver);NdisMDeregisterMiniportDriver(SltDriverHandle);}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING path){
    NDIS_MINIPORT_DRIVER_CHARACTERISTICS c={0};c.Header.Type=NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS;c.Header.Revision=NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;c.Header.Size=NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;c.MajorNdisVersion=6;c.MinorNdisVersion=30;c.MajorDriverVersion=1;
    c.InitializeHandlerEx=SltInitialize;c.HaltHandlerEx=SltHalt;c.UnloadHandler=SltUnload;c.PauseHandler=SltPause;c.RestartHandler=SltRestart;c.SendNetBufferListsHandler=SltSend;c.ReturnNetBufferListsHandler=SltReturn;c.OidRequestHandler=SltOid;c.CancelOidRequestHandler=SltCancelOid;c.CancelSendHandler=SltCancelSend;c.DevicePnPEventNotifyHandler=SltPnp;c.ShutdownHandlerEx=SltShutdown;c.CheckForHangHandlerEx=SltHang;c.ResetHandlerEx=SltReset;
    return NdisMRegisterMiniportDriver(driver,path,NULL,&c,&SltDriverHandle);
}

// Limited WFP research: authorized-tuple observations, explicit injection-state
// recognition and controller-loss cleanup. No packet block or RST suppression.
#include <ntddk.h>
#include <initguid.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <wdmsec.h>
#include <ntstrsafe.h>
DEFINE_GUID(SltCaptureDevice,0x53e73cbd,0x5e86,0x432c,0xa1,0xcf,0xc9,0xd5,0x17,0xa3,0x5b,0x69);
DEFINE_GUID(SltCaptureSubLayer,0x548ab691,0x2c61,0x4a98,0xb7,0xe4,0xa6,0x82,0x77,0x2b,0x81,0x4c);
DEFINE_GUID(SltCaptureInbound,0x24c39de1,0x0a64,0x4183,0x9d,0x6a,0x90,0x2f,0xa6,0xde,0x54,0x9b);
DEFINE_GUID(SltCaptureOutbound,0x93249065,0xc94c,0x4492,0xba,0x55,0x8a,0xa0,0x37,0x42,0x5a,0x6e);
#define SLCP_TAG 'cTLS'
#define SLCP_TUPLE CTL_CODE(FILE_DEVICE_NETWORK,0x911,METHOD_BUFFERED,FILE_WRITE_ACCESS)
#define SLCP_CLEAR CTL_CODE(FILE_DEVICE_NETWORK,0x912,METHOD_BUFFERED,FILE_WRITE_ACCESS)
#define SLCP_STATS CTL_CODE(FILE_DEVICE_NETWORK,0x913,METHOD_BUFFERED,FILE_READ_ACCESS)
typedef struct _SLCP_RULE { ULONG Size,Abi; ULONGLONG Generation; ULONG LocalIp,RemoteIp; USHORT LocalPort,RemotePort; ULONG Reserved; } SLCP_RULE;
typedef struct _SLCP_COUNTERS { ULONGLONG Matched,SelfInjected,OtherInjected; ULONG Rules,Abi; } SLCP_COUNTERS;
static PDEVICE_OBJECT Device;
static HANDLE Engine,Injection;
static UINT32 Callouts[2];static UINT64 Filters[2];
static KSPIN_LOCK RulesLock;static KMUTEX ControlLock;
static SLCP_RULE Rules[32];static ULONG RuleCount;
static PFILE_OBJECT Controller;
static volatile LONG64 Matched,SelfInjected,OtherInjected;
static UNICODE_STRING Symbol;
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD SltCaptureUnload;
DRIVER_DISPATCH SltCaptureDispatch;
static VOID ClearRules(VOID){KIRQL irql;KeAcquireSpinLock(&RulesLock,&irql);RtlZeroMemory(Rules,sizeof(Rules));RuleCount=0;KeReleaseSpinLock(&RulesLock,irql);}
static VOID RemoveFilters(VOID){ULONG i;for(i=0;i<2;i++)if(Filters[i]){FwpmFilterDeleteById0(Engine,Filters[i]);Filters[i]=0;}}
static NTSTATUS AddFilters(VOID){
    ULONG i;NTSTATUS status=FwpmTransactionBegin0(Engine,0);if(!NT_SUCCESS(status))return status;
    for(i=0;i<2;i++){
        FWPM_FILTER0 filter={0};FWPM_FILTER_CONDITION0 condition={0};filter.displayData.name=L"StreamLink authorized tuple observation (research)";filter.layerKey=i?FWPM_LAYER_OUTBOUND_TRANSPORT_V4:FWPM_LAYER_INBOUND_TRANSPORT_V4;filter.subLayerKey=SltCaptureSubLayer;filter.action.type=FWP_ACTION_CALLOUT_INSPECTION;filter.action.calloutKey=i?SltCaptureOutbound:SltCaptureInbound;
        condition.fieldKey=FWPM_CONDITION_IP_PROTOCOL;condition.matchType=FWP_MATCH_EQUAL;condition.conditionValue.type=FWP_UINT8;condition.conditionValue.uint8=6;filter.numFilterConditions=1;filter.filterCondition=&condition;
        status=FwpmFilterAdd0(Engine,&filter,NULL,&Filters[i]);if(!NT_SUCCESS(status)){FwpmTransactionAbort0(Engine);Filters[0]=Filters[1]=0;return status;}
    }status=FwpmTransactionCommit0(Engine);if(!NT_SUCCESS(status)){FwpmTransactionAbort0(Engine);Filters[0]=Filters[1]=0;}return status;
}
static NTSTATUS SltNotify(FWPS_CALLOUT_NOTIFY_TYPE type,const GUID *key,const FWPS_FILTER0 *filter){UNREFERENCED_PARAMETER(type);UNREFERENCED_PARAMETER(key);UNREFERENCED_PARAMETER(filter);return STATUS_SUCCESS;}
static VOID SltClassify(const FWPS_INCOMING_VALUES0 *values,const FWPS_INCOMING_METADATA_VALUES0 *metadata,PVOID data,const FWPS_FILTER0 *filter,UINT64 flow,FWPS_CLASSIFY_OUT0 *out){
    ULONG local,remote,localPort,remotePort,i;KIRQL irql;BOOLEAN authorized=FALSE;FWPS_PACKET_INJECTION_STATE state;
    UNREFERENCED_PARAMETER(metadata);UNREFERENCED_PARAMETER(filter);UNREFERENCED_PARAMETER(flow);
    if(out->rights&FWPS_RIGHT_ACTION_WRITE)out->actionType=FWP_ACTION_CONTINUE;
    if(values->layerId==FWPS_LAYER_OUTBOUND_TRANSPORT_V4){
        local=values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;remote=values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;localPort=values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;remotePort=values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
    }else if(values->layerId==FWPS_LAYER_INBOUND_TRANSPORT_V4){
        local=values->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;remote=values->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;localPort=values->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;remotePort=values->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
    }else return;
    KeAcquireSpinLock(&RulesLock,&irql);for(i=0;i<RuleCount;i++)if(Rules[i].LocalIp==local&&Rules[i].RemoteIp==remote&&Rules[i].LocalPort==localPort&&Rules[i].RemotePort==remotePort){authorized=TRUE;break;}KeReleaseSpinLock(&RulesLock,irql);
    if(!authorized||!data)return;
    state=FwpsQueryPacketInjectionState0(Injection,data,NULL);
    if(state==FWPS_PACKET_INJECTED_BY_SELF||state==FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF){InterlockedIncrement64(&SelfInjected);return;}
    if(state==FWPS_PACKET_INJECTED_BY_OTHER)InterlockedIncrement64(&OtherInjected);
    InterlockedIncrement64(&Matched);
}
static NTSTATUS Complete(PIRP irp,NTSTATUS status,ULONG length){irp->IoStatus.Status=status;irp->IoStatus.Information=length;IoCompleteRequest(irp,IO_NO_INCREMENT);return status;}
NTSTATUS SltCaptureDispatch(PDEVICE_OBJECT device,PIRP irp){
    PIO_STACK_LOCATION s=IoGetCurrentIrpStackLocation(irp);NTSTATUS status=STATUS_INVALID_DEVICE_REQUEST;ULONG length=0;UNREFERENCED_PARAMETER(device);
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return Complete(irp,STATUS_INVALID_DEVICE_STATE,0);
    KeWaitForSingleObject(&ControlLock,Executive,KernelMode,FALSE,NULL);
    if(s->MajorFunction==IRP_MJ_CREATE){if(!Controller){status=AddFilters();if(NT_SUCCESS(status))Controller=s->FileObject;}else status=STATUS_SHARING_VIOLATION;}
    else if(s->MajorFunction==IRP_MJ_CLEANUP||s->MajorFunction==IRP_MJ_CLOSE){if(Controller==s->FileObject){ClearRules();RemoveFilters();Controller=NULL;}status=STATUS_SUCCESS;}
    else if(Controller!=s->FileObject)status=STATUS_ACCESS_DENIED;
    else if(s->MajorFunction==IRP_MJ_DEVICE_CONTROL){
        ULONG code=s->Parameters.DeviceIoControl.IoControlCode;
        if(code==SLCP_CLEAR){ClearRules();status=STATUS_SUCCESS;}
        else if(code==SLCP_TUPLE&&s->Parameters.DeviceIoControl.InputBufferLength==sizeof(SLCP_RULE)){
            SLCP_RULE *rule=irp->AssociatedIrp.SystemBuffer;KIRQL irql;ULONG i;
            if(rule->Size!=sizeof(*rule)||rule->Abi!=1||rule->Generation==0||!rule->LocalIp||!rule->RemoteIp||!rule->LocalPort||!rule->RemotePort||rule->Reserved)status=STATUS_INVALID_PARAMETER;
            else{KeAcquireSpinLock(&RulesLock,&irql);for(i=0;i<RuleCount;i++)if(Rules[i].LocalIp==rule->LocalIp&&Rules[i].RemoteIp==rule->RemoteIp&&Rules[i].LocalPort==rule->LocalPort&&Rules[i].RemotePort==rule->RemotePort)break;
                if(i<RuleCount)status=Rules[i].Generation==rule->Generation?STATUS_SUCCESS:STATUS_OBJECT_NAME_COLLISION;
                else if(RuleCount<RTL_NUMBER_OF(Rules)){Rules[RuleCount++]=*rule;status=STATUS_SUCCESS;}else status=STATUS_INSUFFICIENT_RESOURCES;
                KeReleaseSpinLock(&RulesLock,irql);}
        }else if(code==SLCP_STATS&&s->Parameters.DeviceIoControl.OutputBufferLength>=sizeof(SLCP_COUNTERS)){
            SLCP_COUNTERS c={0};KIRQL irql;c.Matched=Matched;c.SelfInjected=SelfInjected;c.OtherInjected=OtherInjected;c.Abi=1;KeAcquireSpinLock(&RulesLock,&irql);c.Rules=RuleCount;KeReleaseSpinLock(&RulesLock,irql);RtlCopyMemory(irp->AssociatedIrp.SystemBuffer,&c,sizeof(c));length=sizeof(c);status=STATUS_SUCCESS;
        }
    }KeReleaseMutex(&ControlLock,FALSE);return Complete(irp,status,length);
}
VOID SltCaptureUnload(PDRIVER_OBJECT driver){ULONG i;UNREFERENCED_PARAMETER(driver);ClearRules();RemoveFilters();if(Engine){FwpmEngineClose0(Engine);Engine=NULL;}for(i=0;i<2;i++)if(Callouts[i]){FwpsCalloutUnregisterById0(Callouts[i]);Callouts[i]=0;}if(Injection){FwpsInjectionHandleDestroy0(Injection);Injection=NULL;}IoDeleteSymbolicLink(&Symbol);if(Device){IoDeleteDevice(Device);Device=NULL;}}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING registry){
    UNICODE_STRING name,sddl;FWPM_SESSION0 session={0};FWPM_SUBLAYER0 sublayer={0};NTSTATUS status;ULONG i;UNREFERENCED_PARAMETER(registry);
    KeInitializeSpinLock(&RulesLock);KeInitializeMutex(&ControlLock,0);RtlInitUnicodeString(&name,L"\\Device\\StreamLinkCaptureResearch");RtlInitUnicodeString(&Symbol,L"\\DosDevices\\StreamLinkCaptureResearch");RtlInitUnicodeString(&sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    status=IoCreateDeviceSecure(driver,0,&name,FILE_DEVICE_NETWORK,FILE_DEVICE_SECURE_OPEN,FALSE,&sddl,&SltCaptureDevice,&Device);if(!NT_SUCCESS(status))return status;
    Device->Flags|=DO_BUFFERED_IO;
    for(i=0;i<=IRP_MJ_MAXIMUM_FUNCTION;i++)driver->MajorFunction[i]=SltCaptureDispatch;driver->DriverUnload=SltCaptureUnload;
    status=IoCreateSymbolicLink(&Symbol,&name);if(!NT_SUCCESS(status))goto fail;
    status=FwpsInjectionHandleCreate0(AF_INET,FWPS_INJECTION_TYPE_TRANSPORT,&Injection);if(!NT_SUCCESS(status))goto fail;
    session.flags=FWPM_SESSION_FLAG_DYNAMIC;status=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,&session,&Engine);if(!NT_SUCCESS(status))goto fail;
    sublayer.subLayerKey=SltCaptureSubLayer;sublayer.displayData.name=L"StreamLink capture research";sublayer.weight=0x100;status=FwpmSubLayerAdd0(Engine,&sublayer,NULL);if(!NT_SUCCESS(status))goto fail;
    for(i=0;i<2;i++){
        FWPS_CALLOUT0 kernel={0};FWPM_CALLOUT0 callout={0};kernel.calloutKey=i?SltCaptureOutbound:SltCaptureInbound;kernel.classifyFn=SltClassify;kernel.notifyFn=SltNotify;
        status=FwpsCalloutRegister0(Device,&kernel,&Callouts[i]);if(!NT_SUCCESS(status))goto fail;
        callout.calloutKey=kernel.calloutKey;callout.displayData.name=L"StreamLink authorized TCP tuple observer";callout.applicableLayer=i?FWPM_LAYER_OUTBOUND_TRANSPORT_V4:FWPM_LAYER_INBOUND_TRANSPORT_V4;status=FwpmCalloutAdd0(Engine,&callout,NULL,NULL);if(!NT_SUCCESS(status))goto fail;
    }
    Device->Flags&=~DO_DEVICE_INITIALIZING;return STATUS_SUCCESS;
fail:SltCaptureUnload(driver);return status;
}

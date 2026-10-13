#pragma once
// Versioned, pointer-free buffered ABI. IPv4 only in the research backend.
#define SLT_ABI 1u
#define SLT_MTU 1280u
#define SLT_QUEUE_PACKETS 64u
#define SLT_PENDING_READS 16u
#define SLT_IOCTL_INFO CTL_CODE(FILE_DEVICE_NETWORK,0x901,METHOD_BUFFERED,FILE_READ_ACCESS)
#define SLT_IOCTL_STATS CTL_CODE(FILE_DEVICE_NETWORK,0x902,METHOD_BUFFERED,FILE_READ_ACCESS)
#pragma pack(push,8)
typedef struct _SLT_INFO { unsigned int Size,Abi,Mtu,QueuePackets; unsigned long long Luid; unsigned int IfIndex,Flags; } SLT_INFO;
typedef struct _SLT_STATS { unsigned int Size,Abi; unsigned long long OsOffered,OsQueued,OsDropped,UserReads,UserWrites,Malformed,Cancelled; unsigned int Queued,PeakQueued,PendingReads,Reserved; } SLT_STATS;
#pragma pack(pop)

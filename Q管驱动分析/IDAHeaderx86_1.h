typedef LONG KPRIORITY;


typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION,*PPROCESS_BASIC_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG   TitleIndex;
    ULONG   Type;
    ULONG   DataLength;
    UCHAR   Data[1];            // Variable size
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
    ULONG   TitleIndex;
    ULONG   Type;
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable size
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;                 // Not filled in
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[ 256 ];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[ 1 ];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _OBJECT_TYPE_INITIALIZER {
    USHORT Length;
    BOOLEAN UseDefaultObject;
    BOOLEAN CaseInsensitive;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    BOOLEAN MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    FARPROC DumpProcedure;
    FARPROC OpenProcedure;
    FARPROC CloseProcedure;
    FARPROC DeleteProcedure;
    FARPROC ParseProcedure;
    FARPROC SecurityProcedure;
    FARPROC QueryNameProcedure;
    FARPROC OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE {
    ERESOURCE Mutex;
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;            // Copy from object header for convenience
    PVOID DefaultObject;
    ULONG Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER TypeInfo;
    ERESOURCE ObjectLocks[ 4 ];
} OBJECT_TYPE, *POBJECT_TYPE;

typedef struct _OBJECT_HEADER {
    LONG_PTR PointerCount;
    union {
        LONG_PTR HandleCount;
        PVOID NextToFree;
    };
    POBJECT_TYPE Type;
    UCHAR NameInfoOffset;
    UCHAR HandleInfoOffset;
    UCHAR QuotaInfoOffset;
    UCHAR Flags;

    union {
        PVOID QuotaBlockCharged;
    };

    PSECURITY_DESCRIPTOR SecurityDescriptor;
    QUAD Body;
} OBJECT_HEADER, *POBJECT_HEADER;

typedef struct _DUMMY_FILE_OBJECT {
    OBJECT_HEADER ObjectHeader;
    CHAR FileObjectBody[ sizeof( FILE_OBJECT ) ];
} DUMMY_FILE_OBJECT, *PDUMMY_FILE_OBJECT;

typedef struct _PS_CREATE_NOTIFY_INFO {
    SIZE_T Size;
    union {
        ULONG Flags;
        struct {
            ULONG FileOpenNameAvailable : 1;
            ULONG Reserved : 31;
        };
    };
    HANDLE ParentProcessId;
    CLIENT_ID CreatingThreadId;
    struct _FILE_OBJECT *FileObject;
    PCUNICODE_STRING ImageFileName;
    PCUNICODE_STRING CommandLine;
    NTSTATUS CreationStatus;
} PS_CREATE_NOTIFY_INFO, *PPS_CREATE_NOTIFY_INFO;

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PULONG_PTR Base;
    PULONG Count;
    ULONG Limit;
    PUCHAR Number;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[MaximumMode];
    struct _KPROCESS *Process;
    BOOLEAN KernelApcInProgress;
    BOOLEAN KernelApcPending;
    BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
    ULONG AllocatedAttributes;
    ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;



  typedef USHORT FLT_CONTEXT_REGISTRATION_FLAGS;
  typedef USHORT FLT_CONTEXT_TYPE;
  typedef ULONG FLT_REGISTRATION_FLAGS;
  typedef ULONG FLT_OPERATION_REGISTRATION_FLAGS;
  
  typedef struct _FLT_CONTEXT_REGISTRATION 
  {
    FLT_CONTEXT_TYPE ContextType;
    FLT_CONTEXT_REGISTRATION_FLAGS Flags;
    FARPROC ContextCleanupCallback;
    SIZE_T Size;
    ULONG PoolTag;
    FARPROC ContextAllocateCallback;
    FARPROC ContextFreeCallback;
    PVOID Reserved1;
} FLT_CONTEXT_REGISTRATION, *PFLT_CONTEXT_REGISTRATION;
  
  typedef struct _FLT_OPERATION_REGISTRATION 
  {
    UCHAR MajorFunction;
    FLT_OPERATION_REGISTRATION_FLAGS Flags;
    FARPROC PreOperation;
    FARPROC PostOperation;
    PVOID Reserved1;
} FLT_OPERATION_REGISTRATION, *PFLT_OPERATION_REGISTRATION;
  
  typedef struct _FLT_REGISTRATION 
  {
    USHORT Size;
    USHORT Version;
    FLT_REGISTRATION_FLAGS Flags;
    FLT_CONTEXT_REGISTRATION *ContextRegistration;
    FLT_OPERATION_REGISTRATION *OperationRegistration;
    FARPROC FilterUnloadCallback;
    FARPROC InstanceSetupCallback;
    FARPROC InstanceQueryTeardownCallback;
    FARPROC InstanceTeardownStartCallback;
    FARPROC InstanceTeardownCompleteCallback;
    FARPROC GenerateFileNameCallback;
    FARPROC NormalizeNameComponentCallback;
    FARPROC NormalizeContextCleanupCallback;

} FLT_REGISTRATION, *PFLT_REGISTRATION;
  
  typedef PVOID PFLT_FILTER;
 NTSTATUS __stdcall FltRegisterFilter (PDRIVER_OBJECT Driver,FLT_REGISTRATION *Registration,PFLT_FILTER *RetFilter); 
 NTSTATUS __stdcall FltGetDeviceObject (PVOID Volume,PDEVICE_OBJECT *DeviceObject);
 
 typedef ULONG FLT_CALLBACK_DATA_FLAGS;
 typedef struct _FLT_TAG_DATA_BUFFER {
    ULONG FileTag;
    USHORT TagDataLength;
    USHORT UnparsedNameLength;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;

        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;

        struct {
            UCHAR  DataBuffer[1];
        } GenericReparseBuffer;

        //
        //  Used for non-Microsoft reparse points
        //

        struct {
            GUID TagGuid;
            UCHAR DataBuffer[1];
        } GenericGUIDReparseBuffer;
    };
} FLT_TAG_DATA_BUFFER, *PFLT_TAG_DATA_BUFFER;

 typedef struct _FLT_CALLBACK_DATA 
 {
    FLT_CALLBACK_DATA_FLAGS Flags;
    PETHREAD Thread;
    PVOID Iopb;
    IO_STATUS_BLOCK IoStatus;
    struct _FLT_TAG_DATA_BUFFER *TagData;
    union 
	{
        struct 
		{
            LIST_ENTRY QueueLinks;
            PVOID QueueContext[2];
        };
        PVOID FilterContext[4];
    };
    KPROCESSOR_MODE RequestorMode;
} FLT_CALLBACK_DATA, *PFLT_CALLBACK_DATA;
 NTSTATUS __stdcall FltGetRequestorProcess (PFLT_CALLBACK_DATA CallbackData);
 NTSTATUS __stdcall FltSetInformationFile (PVOID Instance,PFILE_OBJECT FileObject,PVOID FileInformation,
    ULONG Length,FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS __stdcall FltCancelFileOpen (PVOID Instance, PFILE_OBJECT FileObject);
typedef ULONG FLT_FILE_NAME_OPTIONS;
typedef USHORT FLT_FILE_NAME_PARSED_FLAGS;
typedef ULONG FLT_FILE_NAME_OPTIONS;
typedef struct _FLT_FILE_NAME_INFORMATION 
{
    USHORT Size;
    FLT_FILE_NAME_PARSED_FLAGS NamesParsed;
    FLT_FILE_NAME_OPTIONS Format;
    UNICODE_STRING Name;
    UNICODE_STRING Volume;
    UNICODE_STRING Share;
    UNICODE_STRING Extension;
    UNICODE_STRING Stream;
    UNICODE_STRING FinalComponent;
    UNICODE_STRING ParentDir;
} FLT_FILE_NAME_INFORMATION, *PFLT_FILE_NAME_INFORMATION;

NTSTATUS __stdcall FltGetDestinationFileNameInformation (PVOID Instance,PFILE_OBJECT FileObject,
    HANDLE RootDirectory,PWSTR FileName,ULONG FileNameLength,FLT_FILE_NAME_OPTIONS NameOptions,
    PFLT_FILE_NAME_INFORMATION *RetFileNameInformation);
NTSTATUS __stdcall FltGetFileNameInformation (PFLT_CALLBACK_DATA CallbackData,FLT_FILE_NAME_OPTIONS NameOptions,
    PFLT_FILE_NAME_INFORMATION *FileNameInformation);
NTSTATUS __stdcall FltParseFileNameInformation (PFLT_FILE_NAME_INFORMATION FileNameInformation);
NTSTATUS __stdcall FltReleaseFileNameInformation (PFLT_FILE_NAME_INFORMATION FileNameInformation);
NTSTATUS __stdcall FltFsControlFile (PVOID Instance,PFILE_OBJECT FileObject,ULONG FsControlCode,
	PVOID InputBuffer,ULONG InputBufferLength,PVOID OutputBuffer,ULONG OutputBufferLength,PULONG LengthReturned);
NTSTATUS __stdcall FltCreateFile (PFLT_FILTER Filter,PVOID Instance,PHANDLE   FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,ULONG ShareAccess,ULONG CreateDisposition,ULONG CreateOptions,PVOID EaBuffer,
    ULONG EaLength,ULONG Flags
    );

typedef PVOID PFLT_VOLUME;
typedef PVOID PFLT_INSTANCE;
typedef PVOID PFLT_PORT;
typedef PVOID PFLT_CONTEXT;
typedef PVOID FLT_SET_CONTEXT_OPERATION;
typedef PVOID PFLT_CONNECT_NOTIFY;
typedef PVOID PFLT_DISCONNECT_NOTIFY;
typedef PVOID PFLT_MESSAGE_NOTIFY;
#define void void
#define PEX_PUSH_LOCK PULONG_PTR
NTSTATUS __stdcall FltGetVolumeInstanceFromName(PFLT_FILTER Filter,PFLT_VOLUME Volume,PCUNICODE_STRING InstanceName,PFLT_INSTANCE *RetInstance);
void __stdcall FltObjectDereference (PVOID FltObject);
void __stdcall FltAcquirePushLockShared(PEX_PUSH_LOCK PushLock);
void __stdcall FltAcquirePushLockExclusive(PEX_PUSH_LOCK PushLock);
void __stdcall FltReleasePushLock(PEX_PUSH_LOCK PushLock);
void __stdcall FltDeletePushLock(PEX_PUSH_LOCK PushLock);
void __stdcall FltInitializePushLock(PEX_PUSH_LOCK PushLock);
NTSTATUS __stdcall FltGetFileNameInformationUnsafe (PFILE_OBJECT FileObject,PFLT_INSTANCE Instance,FLT_FILE_NAME_OPTIONS NameOptions,PFLT_FILE_NAME_INFORMATION *FileNameInformation );
void __stdcall FltReferenceFileNameInformation (PFLT_FILE_NAME_INFORMATION FileNameInformation );
NTSTATUS __stdcall FltSendMessage (PFLT_FILTER Filter,PFLT_PORT *ClientPort,PVOID SenderBuffer,ULONG SenderBufferLength,PVOID ReplyBuffer, PULONG ReplyLength,PLARGE_INTEGER Timeout);
NTSTATUS __stdcall FltGetStreamHandleContext (PFLT_INSTANCE Instance,PFILE_OBJECT FileObject,PFLT_CONTEXT *Context );
NTSTATUS __stdcall FltAllocateCallbackData (PFLT_INSTANCE Instance,PFILE_OBJECT FileObject,PFLT_CALLBACK_DATA *RetNewCallbackData );
void __stdcall FltPerformSynchronousIo (PFLT_CALLBACK_DATA CallbackData );
void __stdcall FltFreeCallbackData(PFLT_CALLBACK_DATA CallbackData );
PVOID __stdcall FltGetRoutineAddress (PCSTR FltMgrRoutineName );
NTSTATUS __stdcall FltGetVolumeName (PFLT_VOLUME Volume,PUNICODE_STRING VolumeName,PULONG BufferSizeNeeded );
NTSTATUS __stdcall FltQueryVolumeInformation( PFLT_INSTANCE Instance,PIO_STATUS_BLOCK Iosb,PVOID FsInformation,ULONG Length,FS_INFORMATION_CLASS FsInformationClass );
NTSTATUS __stdcall FltSetStreamContext (PFLT_INSTANCE Instance,PFILE_OBJECT FileObject, FLT_SET_CONTEXT_OPERATION Operation, PFLT_CONTEXT NewContext, PFLT_CONTEXT *OldContext );
NTSTATUS __stdcall FltParseFileNameInformation ( PFLT_FILE_NAME_INFORMATION FileNameInformation );
NTSTATUS __stdcall FltAllocateContext (PFLT_FILTER Filter, FLT_CONTEXT_TYPE ContextType,SIZE_T ContextSize,POOL_TYPE PoolType,PFLT_CONTEXT *ReturnedContext );
NTSTATUS __stdcall FltCreateFile ( PFLT_FILTER Filter, PFLT_INSTANCE Instance, PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,ULONG ShareAccess,ULONG CreateDisposition,
ULONG CreateOptions,PVOID EaBuffer,ULONG EaLength,ULONG Flags);
NTSTATUS __stdcall FltClose(HANDLE FileHandle );
NTSTATUS __stdcall FltSetStreamHandleContext (PFLT_INSTANCE Instance,PFILE_OBJECT FileObject,FLT_SET_CONTEXT_OPERATION Operation,PFLT_CONTEXT NewContext, PFLT_CONTEXT *OldContext );
void __stdcall FltCancelFileOpen (PFLT_INSTANCE Instance, PFILE_OBJECT FileObject );
NTSTATUS __stdcall FltRegisterFilter (PDRIVER_OBJECT Driver,FLT_REGISTRATION *Registration,PFLT_FILTER *RetFilter );
NTSTATUS __stdcall FltBuildDefaultSecurityDescriptor(PSECURITY_DESCRIPTOR *SecurityDescriptor,ACCESS_MASK DesiredAccess );
NTSTATUS __stdcall FltCreateCommunicationPort (PFLT_FILTER Filter, PFLT_PORT *ServerPort,POBJECT_ATTRIBUTES ObjectAttributes,PVOID ServerPortCookie, PFLT_CONNECT_NOTIFY ConnectNotifyCallback,PFLT_DISCONNECT_NOTIFY DisconnectNotifyCallback,PFLT_MESSAGE_NOTIFY MessageNotifyCallback,LONG MaxConnections);
NTSTATUS __stdcall FltStartFiltering (PFLT_FILTER Filter );
void __stdcall FltFreeSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor );
void __stdcall FltCloseCommunicationPort (PFLT_PORT ServerPort );
void __stdcall FltUnregisterFilter (PFLT_FILTER Filter );
NTSTATUS __stdcall FltGetFileNameInformation (PFLT_CALLBACK_DATA CallbackData,FLT_FILE_NAME_OPTIONS NameOptions, PFLT_FILE_NAME_INFORMATION *FileNameInformation );
NTSTATUS __stdcall FltIsDirectory (PFILE_OBJECT FileObject,PFLT_INSTANCE Instance,PBOOLEAN IsDirectory );
void __stdcall FltReleaseFileNameInformation (PFLT_FILE_NAME_INFORMATION FileNameInformation );
NTSTATUS __stdcall FltGetStreamContext (PFLT_INSTANCE Instance,PFILE_OBJECT FileObject, PFLT_CONTEXT *Context );
PEPROCESS __stdcall FltGetRequestorProcess (PFLT_CALLBACK_DATA CallbackData );
NTSTATUS __stdcall FltGetInstanceContext (PFLT_INSTANCE Instance, PFLT_CONTEXT *Context );
ULONG __stdcall FltGetRequestorProcessId ( PFLT_CALLBACK_DATA CallbackData );
NTSTATUS __stdcall FltGetDiskDeviceObject(PFLT_VOLUME Volume, PDEVICE_OBJECT *DiskDeviceObject );
void __stdcall FltReleaseContext (PFLT_CONTEXT Context );
NTSTATUS __stdcall FltSetInstanceContext (PFLT_INSTANCE Instance, FLT_SET_CONTEXT_OPERATION Operation, PFLT_CONTEXT NewContext,PFLT_CONTEXT *OldContext );
void __stdcall FltReferenceContext ( PFLT_CONTEXT Context );
void __stdcall FltCloseClientPort (PFLT_FILTER Filter,PFLT_PORT *ClientPort );
NTSTATUS __stdcall FltGetVolumeFromFileObject (PFLT_FILTER Filter, PFILE_OBJECT FileObject,PFLT_VOLUME *RetVolume );
	
typedef struct _FLT_RELATED_OBJECTS {

    USHORT Size;
    USHORT TransactionContext;            //TxF mini-version
    PVOID Filter;
    PVOID Volume;
    PVOID Instance;
    PFILE_OBJECT FileObject;
    PVOID Transaction;

} FLT_RELATED_OBJECTS, *PFLT_RELATED_OBJECTS;

typedef struct _FLT_RELATED_OBJECTS *PCFLT_RELATED_OBJECTS;	
	typedef ULONG FLT_INSTANCE_SETUP_FLAGS;
	typedef unsigned long ULONG;
	typedef enum _FLT_FILESYSTEM_TYPE {

    FLT_FSTYPE_UNKNOWN,         //an UNKNOWN file system type
    FLT_FSTYPE_RAW,             //Microsoft's RAW file system       (\FileSystem\RAW)
    FLT_FSTYPE_NTFS,            //Microsoft's NTFS file system      (\FileSystem\Ntfs)
    FLT_FSTYPE_FAT,             //Microsoft's FAT file system       (\FileSystem\Fastfat)
    FLT_FSTYPE_CDFS,            //Microsoft's CDFS file system      (\FileSystem\Cdfs)
    FLT_FSTYPE_UDFS,            //Microsoft's UDFS file system      (\FileSystem\Udfs)
    FLT_FSTYPE_LANMAN,          //Microsoft's LanMan Redirector     (\FileSystem\MRxSmb)
    FLT_FSTYPE_WEBDAV,          //Microsoft's WebDav redirector     (\FileSystem\MRxDav)
    FLT_FSTYPE_RDPDR,           //Microsoft's Terminal Server redirector    (\Driver\rdpdr)
    FLT_FSTYPE_NFS,             //Microsoft's NFS file system       (\FileSystem\NfsRdr)
    FLT_FSTYPE_MS_NETWARE,      //Microsoft's NetWare redirector    (\FileSystem\nwrdr)
    FLT_FSTYPE_NETWARE,         //Novell's NetWare redirector
    FLT_FSTYPE_BSUDF,           //The BsUDF CD-ROM driver           (\FileSystem\BsUDF)
    FLT_FSTYPE_MUP,             //Microsoft's Mup redirector        (\FileSystem\Mup)
    FLT_FSTYPE_RSFX,            //Microsoft's WinFS redirector      (\FileSystem\RsFxDrv)
    FLT_FSTYPE_ROXIO_UDF1,      //Roxio's UDF writeable file system (\FileSystem\cdudf_xp)
    FLT_FSTYPE_ROXIO_UDF2,      //Roxio's UDF readable file system  (\FileSystem\UdfReadr_xp)
    FLT_FSTYPE_ROXIO_UDF3,      //Roxio's DVD file system           (\FileSystem\DVDVRRdr_xp)
    FLT_FSTYPE_TACIT,           //Tacit FileSystem                  (\Device\TCFSPSE)
    FLT_FSTYPE_FS_REC,          //Microsoft's File system recognizer (\FileSystem\Fs_rec)
    FLT_FSTYPE_INCD,            //Nero's InCD file system           (\FileSystem\InCDfs)
    FLT_FSTYPE_INCD_FAT,        //Nero's InCD FAT file system       (\FileSystem\InCDFat)
    FLT_FSTYPE_EXFAT,           //Microsoft's EXFat FILE SYSTEM     (\FileSystem\exfat)
    FLT_FSTYPE_PSFS,            //PolyServ's file system            (\FileSystem\psfs)
    FLT_FSTYPE_GPFS             //IBM General Parallel File System  (\FileSystem\gpfs)
} FLT_FILESYSTEM_TYPE, *PFLT_FILESYSTEM_TYPE;
	
typedef union _FLT_PARAMETERS 
{
    struct 
	{
        PIO_SECURITY_CONTEXT SecurityContext;
        ULONG Options;
        USHORT FileAttributes;
        USHORT ShareAccess;
        ULONG  EaLength;
        PVOID EaBuffer;                 //Not in IO_STACK_LOCATION parameters list
        LARGE_INTEGER AllocationSize;   //Not in IO_STACK_LOCATION parameters list
    } Create;
    struct 
	{
        PIO_SECURITY_CONTEXT SecurityContext;
        ULONG Options;
        USHORT  Reserved;
        USHORT ShareAccess;
        PVOID Parameters; // PNAMED_PIPE_CREATE_PARAMETERS
    } CreatePipe;
    struct 
	{
        PIO_SECURITY_CONTEXT SecurityContext;
        ULONG Options;
        USHORT  Reserved;
        USHORT ShareAccess;
        PVOID Parameters; // PMAILSLOT_CREATE_PARAMETERS
    } CreateMailslot;
    struct 
	{
        ULONG Length;                   //Length of transfer
        ULONG  Key;
        LARGE_INTEGER ByteOffset;       //Offset to read from
        PVOID ReadBuffer;       //Not in IO_STACK_LOCATION parameters list
        PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
    } Read;
    struct 
	{
        ULONG Length;                   //Length of transfer
        ULONG  Key;
        LARGE_INTEGER ByteOffset;       //Offset to write to
        PVOID WriteBuffer;      //Not in IO_STACK_LOCATION parameters list
        PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
    } Write;
    struct 
	{
        ULONG Length;           //Length of buffer
        FILE_INFORMATION_CLASS  FileInformationClass; //Class of information to query
        PVOID InfoBuffer;       //Not in IO_STACK_LOCATION parameters list
    } QueryFileInformation;
    struct 
	{
        ULONG Length;
        FILE_INFORMATION_CLASS  FileInformationClass;
        PFILE_OBJECT ParentOfTarget;
        union 
		{
            struct 
			{
                BOOLEAN ReplaceIfExists;
                BOOLEAN AdvanceOnly;
            };
            ULONG ClusterCount;
            HANDLE DeleteHandle;
        };
        PVOID InfoBuffer;       //Not in IO_STACK_LOCATION parameters list
    } SetFileInformation;
    struct 
	{
        ULONG Length;
        PVOID EaList;
        ULONG EaListLength;
        ULONG  EaIndex;
        PVOID EaBuffer;         //Not in IO_STACK_LOCATION parameters list
        PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
    } QueryEa;
    struct 
	{
        ULONG Length;
        PVOID EaBuffer;         //Not in IO_STACK_LOCATION parameters list
        PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
    } SetEa;
    struct 
	{
        ULONG Length;
        FS_INFORMATION_CLASS  FsInformationClass;

        PVOID VolumeBuffer;     //Not in IO_STACK_LOCATION parameters list
    } QueryVolumeInformation;
    struct 
	{
        ULONG Length;
        FS_INFORMATION_CLASS  FsInformationClass;
        PVOID VolumeBuffer;     //Not in IO_STACK_LOCATION parameters list
    } SetVolumeInformation;
    union 
	{
        struct 
		{
            ULONG Length;
            PUNICODE_STRING FileName;
            FILE_INFORMATION_CLASS FileInformationClass;
            ULONG  FileIndex;
            PVOID DirectoryBuffer;  //Not in IO_STACK_LOCATION parameters list
            PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
        } QueryDirectory;
        struct 
		{
            ULONG Length;
            ULONG  CompletionFilter;
            ULONG  Spare1;
            ULONG  Spare2;
            PVOID DirectoryBuffer;  //Not in IO_STACK_LOCATION parameters list
            PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
        } NotifyDirectory;
    } DirectoryControl;
    union 
	{
        struct 
		{
            PVOID Vpb;
            PDEVICE_OBJECT DeviceObject;
        } VerifyVolume;
        struct {
            ULONG OutputBufferLength;
            ULONG  InputBufferLength;
            ULONG  FsControlCode;
        } Common;
        struct 
		{
            ULONG OutputBufferLength;
            ULONG  InputBufferLength;
            ULONG  FsControlCode;
            PVOID InputBuffer;
            PVOID OutputBuffer;
            PMDL OutputMdlAddress;
        } Neither;
        struct 
		{
            ULONG OutputBufferLength;
            ULONG  InputBufferLength;
            ULONG  FsControlCode;
            PVOID SystemBuffer;
        } Buffered;
        struct 
		{
            ULONG OutputBufferLength;
            ULONG  InputBufferLength;
            ULONG  FsControlCode;
            PVOID InputSystemBuffer;
            PVOID OutputBuffer;
            PMDL OutputMdlAddress;
        } Direct;
    } FileSystemControl;
    union 
	{
        struct 
		{
            ULONG OutputBufferLength;
            ULONG  InputBufferLength;
            ULONG  IoControlCode;
        } Common;
        struct 
		{
            ULONG OutputBufferLength;
            ULONG  InputBufferLength;
            ULONG  IoControlCode;
            PVOID InputBuffer;
            PVOID OutputBuffer;
            PMDL OutputMdlAddress;
        } Neither;
        struct 
		{
            ULONG OutputBufferLength;
            ULONG  InputBufferLength;
            ULONG  IoControlCode;
            PVOID SystemBuffer;
        } Buffered;
        struct 
		{
            ULONG OutputBufferLength;
            ULONG  InputBufferLength;
            ULONG  IoControlCode;
            PVOID InputSystemBuffer;
            PVOID OutputBuffer;
            PMDL OutputMdlAddress;
        } Direct;
        struct 
		{
            ULONG OutputBufferLength;
            ULONG  InputBufferLength;
            ULONG  IoControlCode;
            PVOID InputBuffer;
            PVOID OutputBuffer;
        } FastIo;
    } DeviceIoControl;
    struct 
	{
        PLARGE_INTEGER Length;
        ULONG  Key;
        LARGE_INTEGER ByteOffset;

        PEPROCESS ProcessId;        //  Only meaningful for FastIo locking operations.
        BOOLEAN FailImmediately;    //  Only meaningful for FastIo locking operations.
        BOOLEAN ExclusiveLock;      //  Only meaningful for FastIo locking operations.
    } LockControl;
    struct 
	{
        SECURITY_INFORMATION SecurityInformation;
        ULONG  Length;
        PVOID SecurityBuffer;   //Not in IO_STACK_LOCATION parameters list
        PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
    } QuerySecurity;
    struct 
	{
        SECURITY_INFORMATION SecurityInformation;
        PSECURITY_DESCRIPTOR SecurityDescriptor;
    } SetSecurity;
    struct 
	{
        ULONG_PTR ProviderId;
        PVOID DataPath;
        ULONG BufferSize;
        PVOID Buffer;
    } WMI;
    struct 
	{
        ULONG Length;
        PSID StartSid;
        PVOID SidList;
        ULONG SidListLength;
        PVOID QuotaBuffer;      //Not in IO_STACK_LOCATION parameters list
        PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
    } QueryQuota;
    struct 
	{
        ULONG Length;
        PVOID QuotaBuffer;      //Not in IO_STACK_LOCATION parameters list
        PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
    } SetQuota;
    union 
	{
        struct 
		{
            PCM_RESOURCE_LIST AllocatedResources;
            PCM_RESOURCE_LIST AllocatedResourcesTranslated;
        } StartDevice;
        struct 
		{
            DEVICE_RELATION_TYPE Type;
        } QueryDeviceRelations;
        struct 
		{
             GUID *InterfaceType;
            USHORT Size;
            USHORT Version;
            PINTERFACE Interface;
            PVOID InterfaceSpecificData;
        } QueryInterface;
        struct 
		{
            PDEVICE_CAPABILITIES Capabilities;
        } DeviceCapabilities;
        struct 
		{
            PIO_RESOURCE_REQUIREMENTS_LIST IoResourceRequirementList;
        } FilterResourceRequirements;
        struct 
		{
            ULONG WhichSpace;
            PVOID Buffer;
            ULONG Offset;
            ULONG  Length;
        } ReadWriteConfig;
        struct 
		{
            BOOLEAN Lock;
        } SetLock;
        struct 
		{
            BUS_QUERY_ID_TYPE IdType;
        } QueryId;
        struct 
		{
            DEVICE_TEXT_TYPE DeviceTextType;
            LCID  LocaleId;
        } QueryDeviceText;
        struct 
		{
            BOOLEAN InPath;
            BOOLEAN Reserved[3];
            DEVICE_USAGE_NOTIFICATION_TYPE  Type;
        } UsageNotification;

    } Pnp;
    struct 
	{
        ULONG SyncType;
        ULONG PageProtection;
    } AcquireForSectionSynchronization;
    struct 
	{
        PLARGE_INTEGER EndingOffset;
        PERESOURCE *ResourceToRelease;
    } AcquireForModifiedPageWriter;
    struct 
	{
        PERESOURCE ResourceToRelease;
    } ReleaseForModifiedPageWriter;
    struct 
	{
        LARGE_INTEGER FileOffset;
        ULONG Length;
        ULONG  LockKey;
        BOOLEAN  CheckForReadOperation;
    } FastIoCheckIfPossible;
    struct 
	{
        PIRP Irp;
        PFILE_NETWORK_OPEN_INFORMATION NetworkInformation;
    } NetworkQueryOpen;
    struct 
	{
        LARGE_INTEGER FileOffset;
        ULONG  Length;
        ULONG  Key;
        PMDL *MdlChain;
    } MdlRead;
    struct 
	{
        PMDL MdlChain;
    } MdlReadComplete;
    struct 
	{
        LARGE_INTEGER FileOffset;
        ULONG  Length;
        ULONG  Key;
        PMDL *MdlChain;
    } PrepareMdlWrite;
    struct 
	{
        LARGE_INTEGER FileOffset;
        PMDL MdlChain;
    } MdlWriteComplete;
    struct 
	{
        ULONG DeviceType;
    } MountVolume;
    struct 
	{
        PVOID Argument1;
        PVOID Argument2;
        PVOID Argument3;
        PVOID Argument4;
        PVOID Argument5;
        LARGE_INTEGER Argument6;
    } Others;
} FLT_PARAMETERS, *PFLT_PARAMETERS;
	
typedef struct _FLT_IO_PARAMETER_BLOCK 
{
    ULONG IrpFlags;
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    UCHAR OperationFlags;
    UCHAR Reserved;
    PFILE_OBJECT TargetFileObject;
    PVOID TargetInstance;
    FLT_PARAMETERS Parameters;
} FLT_IO_PARAMETER_BLOCK, *PFLT_IO_PARAMETER_BLOCK;

typedef struct _DISPATCHER_HEADER 
{
    union 
	{
        struct 
		{
            UCHAR Type;                 // All (accessible via KOBJECT_TYPE)
            union 
			{
                union 
				{                 // Timer
                    UCHAR TimerControlFlags;
                    struct 
					{
                        UCHAR Absolute              : 1;
                        UCHAR Coalescable           : 1;
                        UCHAR KeepShifting          : 1;    // Periodic timer
                        UCHAR EncodedTolerableDelay : 5;    // Periodic timer
                    } DUMMYSTRUCTNAME;
                } ;
                UCHAR Abandoned;        // Queue
                BOOLEAN Signalling;     // Gate/Events
            } ;
            union 
			{
                union 
				{
                    UCHAR ThreadControlFlags;  // Thread
                    struct 
					{
                        UCHAR CpuThrottled      : 1;
                        UCHAR CycleProfiling    : 1;
                        UCHAR CounterProfiling  : 1;
                        UCHAR Reserved          : 5;
                    } DUMMYSTRUCTNAME;
                } ;
                UCHAR Hand;             // Timer
                UCHAR Size;             // All other objects
            };
            union 
			{
                union 
				{                 // Timer
                    UCHAR TimerMiscFlags;
                    struct 
					{
                        UCHAR Index             : 1;
                        UCHAR Processor         : 5;
                        UCHAR Inserted          : 1;
                        volatile UCHAR Expired  : 1;
                    } DUMMYSTRUCTNAME;
                } ;
                union 
				{                 // Thread
                    BOOLEAN DebugActive;
                    struct 
					{
                        BOOLEAN ActiveDR7       : 1;
                        BOOLEAN Instrumented    : 1;
                        BOOLEAN Reserved2       : 4;
                        BOOLEAN UmsScheduled    : 1;
                        BOOLEAN UmsPrimary      : 1;
                    } DUMMYSTRUCTNAME;
                } ;
                BOOLEAN DpcActive;      // Mutant
            } ;
        } DUMMYSTRUCTNAME;
        volatile LONG Lock;             // Interlocked
    } ;
    LONG SignalState;                   // Object lock
    LIST_ENTRY WaitListHead;            // Object lock
} DISPATCHER_HEADER;

typedef struct _KQUEUE {
    DISPATCHER_HEADER Header;
    LIST_ENTRY EntryListHead;       // Object lock
    volatile ULONG CurrentCount;    // Interlocked
    ULONG MaximumCount;
    LIST_ENTRY ThreadListHead;      // Object lock
} KQUEUE, *PKQUEUE, *PRKQUEUE;

typedef struct _COMPRESSED_DATA_INFO 
{
    USHORT CompressionFormatAndEngine;
    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved;
    USHORT NumberOfChunks;
    ULONG CompressedChunkSizes[1];
} COMPRESSED_DATA_INFO;
typedef COMPRESSED_DATA_INFO *PCOMPRESSED_DATA_INFO;

typedef struct _FS_FILTER_CALLBACKS 
{
    ULONG SizeOfFsFilterCallbacks;
    ULONG Reserved; //  For alignment
    FARPROC PreAcquireForSectionSynchronization;
    FARPROC PostAcquireForSectionSynchronization;
    FARPROC PreReleaseForSectionSynchronization;
    FARPROC PostReleaseForSectionSynchronization;
    FARPROC PreAcquireForCcFlush;
    FARPROC PostAcquireForCcFlush;
    FARPROC PreReleaseForCcFlush;
    FARPROC PostReleaseForCcFlush;
    FARPROC PreAcquireForModifiedPageWriter;
    FARPROC PostAcquireForModifiedPageWriter;
    FARPROC PreReleaseForModifiedPageWriter;
    FARPROC PostReleaseForModifiedPageWriter;
} FS_FILTER_CALLBACKS, *PFS_FILTER_CALLBACKS;

typedef struct _REG_DELETE_KEY_INFORMATION 
{
    PVOID    Object;                      // IN
    PVOID    CallContext;  // new to Windows Vista
    PVOID    ObjectContext;// new to Windows Vista
    PVOID    Reserved;     // new to Windows Vista
} REG_DELETE_KEY_INFORMATION, *PREG_DELETE_KEY_INFORMATION;

typedef struct _REG_SET_VALUE_KEY_INFORMATION 
{
    PVOID               Object;                         // IN
    PUNICODE_STRING     ValueName;                      // IN
    ULONG               TitleIndex;                     // IN
    ULONG               Type;                           // IN
    PVOID               Data;                           // IN
    ULONG               DataSize;                       // IN
    PVOID               CallContext;  // new to Windows Vista
    PVOID               ObjectContext;// new to Windows Vista
    PVOID               Reserved;     // new to Windows Vista
} REG_SET_VALUE_KEY_INFORMATION, *PREG_SET_VALUE_KEY_INFORMATION;

typedef struct _REG_DELETE_VALUE_KEY_INFORMATION 
{
    PVOID               Object;                         // IN
    PUNICODE_STRING     ValueName;                      // IN
    PVOID               CallContext;  // new to Windows Vista
    PVOID               ObjectContext;// new to Windows Vista
    PVOID               Reserved;     // new to Windows Vista
} REG_DELETE_VALUE_KEY_INFORMATION, *PREG_DELETE_VALUE_KEY_INFORMATION;

typedef struct _REG_SET_INFORMATION_KEY_INFORMATION 
{
    PVOID                       Object;                 // IN
    KEY_SET_INFORMATION_CLASS   KeySetInformationClass; // IN
    PVOID                       KeySetInformation;      // IN
    ULONG                       KeySetInformationLength;// IN
    PVOID                       CallContext;  // new to Windows Vista
    PVOID                       ObjectContext;// new to Windows Vista
    PVOID                       Reserved;     // new to Windows Vista
} REG_SET_INFORMATION_KEY_INFORMATION, *PREG_SET_INFORMATION_KEY_INFORMATION;

typedef struct _REG_ENUMERATE_KEY_INFORMATION 
{
    PVOID                       Object;                 // IN
    ULONG                       Index;                  // IN
    KEY_INFORMATION_CLASS       KeyInformationClass;    // IN
    PVOID                       KeyInformation;         // IN
    ULONG                       Length;                 // IN
    PULONG                      ResultLength;           // OUT
    PVOID                       CallContext;  // new to Windows Vista
    PVOID                       ObjectContext;// new to Windows Vista
    PVOID                       Reserved;     // new to Windows Vista
} REG_ENUMERATE_KEY_INFORMATION, *PREG_ENUMERATE_KEY_INFORMATION;

typedef struct _REG_ENUMERATE_VALUE_KEY_INFORMATION 
{
    PVOID                           Object;                     // IN
    ULONG                           Index;                      // IN
    KEY_VALUE_INFORMATION_CLASS     KeyValueInformationClass;   // IN
    PVOID                           KeyValueInformation;        // IN
    ULONG                           Length;                     // IN
    PULONG                          ResultLength;               // OUT
    PVOID                           CallContext;  // new to Windows Vista
    PVOID                           ObjectContext;// new to Windows Vista
    PVOID                           Reserved;     // new to Windows Vista
} REG_ENUMERATE_VALUE_KEY_INFORMATION, *PREG_ENUMERATE_VALUE_KEY_INFORMATION;

typedef struct _REG_QUERY_KEY_INFORMATION 
{
    PVOID                       Object;                 // IN
    KEY_INFORMATION_CLASS       KeyInformationClass;    // IN
    PVOID                       KeyInformation;         // IN
    ULONG                       Length;                 // IN
    PULONG                      ResultLength;           // OUT
    PVOID                       CallContext;  // new to Windows Vista
    PVOID                       ObjectContext;// new to Windows Vista
    PVOID                       Reserved;     // new to Windows Vista
} REG_QUERY_KEY_INFORMATION, *PREG_QUERY_KEY_INFORMATION;

typedef struct _REG_QUERY_VALUE_KEY_INFORMATION 
{
    PVOID                           Object;                     // IN
    PUNICODE_STRING                 ValueName;                  // IN
    KEY_VALUE_INFORMATION_CLASS     KeyValueInformationClass;   // IN
    PVOID                           KeyValueInformation;        // IN
    ULONG                           Length;                     // IN
    PULONG                          ResultLength;               // OUT
    PVOID                           CallContext;  // new to Windows Vista
    PVOID                           ObjectContext;// new to Windows Vista
    PVOID                           Reserved;     // new to Windows Vista
} REG_QUERY_VALUE_KEY_INFORMATION, *PREG_QUERY_VALUE_KEY_INFORMATION;

typedef struct _REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION 
{
    PVOID               Object;                 // IN
    PKEY_VALUE_ENTRY    ValueEntries;           // IN
    ULONG               EntryCount;             // IN
    PVOID               ValueBuffer;            // IN
    PULONG              BufferLength;           // IN OUT
    PULONG              RequiredBufferLength;   // OUT
    PVOID               CallContext;  // new to Windows Vista
    PVOID               ObjectContext;// new to Windows Vista
    PVOID 	            Reserved;     // new to Windows Vista
} REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION, *PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION;

typedef struct _REG_RENAME_KEY_INFORMATION 
{
    PVOID            Object;    // IN
    PUNICODE_STRING  NewName;   // IN
    PVOID            CallContext;  // new to Windows Vista
    PVOID            ObjectContext;// new to Windows Vista
    PVOID            Reserved;     // new to Windows Vista
} REG_RENAME_KEY_INFORMATION, *PREG_RENAME_KEY_INFORMATION;


typedef struct _REG_KEY_HANDLE_CLOSE_INFORMATION 
{
    PVOID               Object;         // IN
    PVOID               CallContext;  // new to Windows Vista
    PVOID               ObjectContext;// new to Windows Vista
    PVOID               Reserved;     // new to Windows Vista
} REG_KEY_HANDLE_CLOSE_INFORMATION, *PREG_KEY_HANDLE_CLOSE_INFORMATION;

typedef struct _REG_CREATE_KEY_INFORMATION 
{
    PUNICODE_STRING     CompleteName; // IN
    PVOID               RootObject;   // IN
    PVOID               ObjectType;   // new to Windows Vista
    ULONG               CreateOptions;// new to Windows Vista
    PUNICODE_STRING     Class;        // new to Windows Vista
    PVOID               SecurityDescriptor;// new to Windows Vista
    PVOID               SecurityQualityOfService;// new to Windows Vista
    ACCESS_MASK         DesiredAccess;// new to Windows Vista
    ACCESS_MASK         GrantedAccess;// new to Windows Vista
    PULONG              Disposition;  // new to Windows Vista
    PVOID               *ResultObject;// new to Windows Vista
    PVOID               CallContext;  // new to Windows Vista
    PVOID               RootObjectContext;  // new to Windows Vista
    PVOID               Transaction;  // new to Windows Vista
    PVOID               Reserved;     // new to Windows Vista
} REG_CREATE_KEY_INFORMATION, REG_OPEN_KEY_INFORMATION,*PREG_CREATE_KEY_INFORMATION, *PREG_OPEN_KEY_INFORMATION;

typedef struct _REG_CREATE_KEY_INFORMATION_V1 
{
    PUNICODE_STRING     CompleteName; // IN
    PVOID               RootObject;   // IN
    PVOID               ObjectType;   // new to Windows Vista
    ULONG               Options;      // new to Windows Vista
    PUNICODE_STRING     Class;        // new to Windows Vista
    PVOID               SecurityDescriptor;// new to Windows Vista
    PVOID               SecurityQualityOfService;// new to Windows Vista
    ACCESS_MASK         DesiredAccess;// new to Windows Vista
    ACCESS_MASK         GrantedAccess;// new to Windows Vista
    PULONG              Disposition;  // new to Windows Vista
    PVOID               *ResultObject;// new to Windows Vista
    PVOID               CallContext;  // new to Windows Vista
    PVOID               RootObjectContext;  // new to Windows Vista
    PVOID               Transaction;  // new to Windows Vista
    ULONG_PTR           Version;      // following is new to Windows 7
    PUNICODE_STRING     RemainingName;// the true path left to parse
    ULONG               Wow64Flags;   // Wow64 specific flags gotten from DesiredAccess input
    ULONG               Attributes;   // ObjectAttributes->Attributes
    KPROCESSOR_MODE     CheckAccessMode;  // mode used for the securiry checks 
} REG_CREATE_KEY_INFORMATION_V1, REG_OPEN_KEY_INFORMATION_V1,*PREG_CREATE_KEY_INFORMATION_V1, *PREG_OPEN_KEY_INFORMATION_V1;

typedef struct _REG_POST_OPERATION_INFORMATION 
{
    PVOID               Object;         // IN
    NTSTATUS            Status;         // IN
    PVOID               PreInformation; // new to Windows Vista; identical with the pre information that was sent
    NTSTATUS            ReturnStatus;   // new to Windows Vista; callback can now change the outcome of the operation
    PVOID               CallContext;    // new to Windows Vista
    PVOID               ObjectContext;  // new to Windows Vista
    PVOID               Reserved;       // new to Windows Vista
} REG_POST_OPERATION_INFORMATION,*PREG_POST_OPERATION_INFORMATION;
/* XP only */
typedef struct _REG_PRE_CREATE_KEY_INFORMATION 
{
    PUNICODE_STRING     CompleteName;   // IN
} REG_PRE_CREATE_KEY_INFORMATION, REG_PRE_OPEN_KEY_INFORMATION,*PREG_PRE_CREATE_KEY_INFORMATION, *PREG_PRE_OPEN_KEY_INFORMATION;;

typedef struct _REG_POST_CREATE_KEY_INFORMATION 
{
    PUNICODE_STRING     CompleteName;   // IN
    PVOID               Object;         // IN
    NTSTATUS            Status;         // IN
} REG_POST_CREATE_KEY_INFORMATION,REG_POST_OPEN_KEY_INFORMATION, *PREG_POST_CREATE_KEY_INFORMATION, *PREG_POST_OPEN_KEY_INFORMATION;
/* end XP only */
typedef struct _REG_LOAD_KEY_INFORMATION 
{
    PVOID               Object;
    PUNICODE_STRING     KeyName;
    PUNICODE_STRING     SourceFile;
	ULONG				Flags;
    PVOID               TrustClassObject;
	PVOID               UserEvent;
	ACCESS_MASK         DesiredAccess;
    PHANDLE             RootHandle;
    PVOID               CallContext;  
    PVOID               ObjectContext;
    PVOID               Reserved;     
} REG_LOAD_KEY_INFORMATION, *PREG_LOAD_KEY_INFORMATION;

typedef struct _REG_UNLOAD_KEY_INFORMATION 
{
    PVOID    Object;                      
    PVOID	 UserEvent;
    PVOID    CallContext;  
    PVOID    ObjectContext;
    PVOID    Reserved;     
} REG_UNLOAD_KEY_INFORMATION, *PREG_UNLOAD_KEY_INFORMATION;

typedef struct _REG_CALLBACK_CONTEXT_CLEANUP_INFORMATION 
{
    PVOID   Object;
    PVOID   ObjectContext;  
    PVOID   Reserved;     
} REG_CALLBACK_CONTEXT_CLEANUP_INFORMATION, *PREG_CALLBACK_CONTEXT_CLEANUP_INFORMATION;

typedef struct _REG_QUERY_KEY_SECURITY_INFORMATION 
{
    PVOID                   Object;
    PSECURITY_INFORMATION   SecurityInformation;  // IN
    PSECURITY_DESCRIPTOR    SecurityDescriptor;   // INOUT  
    PULONG                  Length;               // INOUT  
    PVOID                   CallContext;  
    PVOID                   ObjectContext;
    PVOID                   Reserved;     
} REG_QUERY_KEY_SECURITY_INFORMATION, *PREG_QUERY_KEY_SECURITY_INFORMATION;

typedef struct _REG_SET_KEY_SECURITY_INFORMATION 
{
    PVOID                   Object;
    PSECURITY_INFORMATION   SecurityInformation;  // IN
    PSECURITY_DESCRIPTOR    SecurityDescriptor;   // IN
    PVOID                   CallContext;  
    PVOID                   ObjectContext;
    PVOID                   Reserved;     
} REG_SET_KEY_SECURITY_INFORMATION, *PREG_SET_KEY_SECURITY_INFORMATION;

typedef struct _REG_RESTORE_KEY_INFORMATION 
{
    PVOID               Object;
    HANDLE              FileHandle;
    ULONG				Flags;
    PVOID               CallContext;  
    PVOID               ObjectContext;
    PVOID               Reserved;     
} REG_RESTORE_KEY_INFORMATION, *PREG_RESTORE_KEY_INFORMATION;

typedef struct _REG_SAVE_KEY_INFORMATION 
{
    PVOID               Object;
    HANDLE              FileHandle;
    ULONG               Format;
    PVOID               CallContext;  
    PVOID               ObjectContext;
    PVOID               Reserved;     
} REG_SAVE_KEY_INFORMATION, *PREG_SAVE_KEY_INFORMATION;

typedef struct _REG_REPLACE_KEY_INFORMATION 
{
    PVOID               Object;
    PUNICODE_STRING     OldFileName;
    PUNICODE_STRING     NewFileName;
    PVOID               CallContext;  
    PVOID               ObjectContext;
    PVOID               Reserved;     
} REG_REPLACE_KEY_INFORMATION, *PREG_REPLACE_KEY_INFORMATION;

typedef enum _KAPC_ENVIRONMENT 
{
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef enum _PROCESSINFOCLASS 
{
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,          // Note: this is kernel mode only
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessTlsInformation,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    ProcessGroupInformation,
    ProcessTokenVirtualizationEnabled,
    ProcessConsoleHostProcess,
    ProcessWindowInformation,
    MaxProcessInfoClass             // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;

typedef struct _FLT_IO_PARAMETER_BLOCK 
{
    ULONG IrpFlags;
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    UCHAR OperationFlags;
    UCHAR Reserved;
    PFILE_OBJECT TargetFileObject;
    PFLT_INSTANCE TargetInstance;
    FLT_PARAMETERS Parameters;
} FLT_IO_PARAMETER_BLOCK, *PFLT_IO_PARAMETER_BLOCK;

#define DEVICE_TYPE ULONG

typedef enum _OBJECT_INFORMATION_CLASS 
{
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectTypesInformation,
    ObjectHandleFlagInformation,
    ObjectSessionInformation,
    MaxObjectInfoClass  // MaxObjectInfoClass should always be the last enum
} OBJECT_INFORMATION_CLASS;

typedef struct _IMAGE_INFO 
{
    union 
	{
        ULONG Properties;
        struct 
		{
            ULONG ImageAddressingMode  : 8;  // code addressing mode
            ULONG SystemModeImage      : 1;  // system mode image
            ULONG ImageMappedToAllPids : 1;  // image mapped into all processes
            ULONG Reserved             : 22;
        };
    };
    PVOID       ImageBase;
    ULONG       ImageSelector;
    SIZE_T      ImageSize;
    ULONG       ImageSectionNumber;
} IMAGE_INFO, *PIMAGE_INFO;

typedef struct _LUID 
{
    ULONG LowPart;
    LONG HighPart;
} LUID, *PLUID;

typedef struct _OSVERSIONINFOW 
{
    ULONG dwOSVersionInfoSize;
    ULONG dwMajorVersion;
    ULONG dwMinorVersion;
    ULONG dwBuildNumber;
    ULONG dwPlatformId;
    WCHAR  szCSDVersion[ 128 ];     // Maintenance string for PSS usage
} OSVERSIONINFOW, *POSVERSIONINFOW, *LPOSVERSIONINFOW, RTL_OSVERSIONINFOW, *PRTL_OSVERSIONINFOW;

typedef struct _GENERIC_MAPPING 
{
    ACCESS_MASK GenericRead;
    ACCESS_MASK GenericWrite;
    ACCESS_MASK GenericExecute;
    ACCESS_MASK GenericAll;
} GENERIC_MAPPING;
typedef GENERIC_MAPPING *PGENERIC_MAPPING;

typedef struct _ACCESS_STATE
{
   LUID OperationID;                // Currently unused, replaced by TransactionId in AUX_ACCESS_DATA
   BOOLEAN SecurityEvaluated;
   BOOLEAN GenerateAudit;
   BOOLEAN GenerateOnClose;
   BOOLEAN PrivilegesAllocated;
   ULONG Flags;
   ACCESS_MASK RemainingDesiredAccess;
   ACCESS_MASK PreviouslyGrantedAccess;
   ACCESS_MASK OriginalDesiredAccess;
   SECURITY_SUBJECT_CONTEXT SubjectSecurityContext;
   PSECURITY_DESCRIPTOR SecurityDescriptor; // it stores SD supplied by caller when creating a new object.
   PVOID AuxData;
   union 
   {
      INITIAL_PRIVILEGE_SET InitialPrivilegeSet;
      PRIVILEGE_SET PrivilegeSet;
    } Privileges;
   BOOLEAN AuditPrivileges;
   UNICODE_STRING ObjectName;
   UNICODE_STRING ObjectTypeName;
}ACCESS_STATE, *PACCESS_STATE;

typedef enum _SYSTEM_INFORMATION_CLASS {  
	SystemBasicInformation=0,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation, 
	SystemModuleInformation,
	SystemLocksInformation, 
	SystemStackTraceInformation,
	SystemPagedPoolInformation, 
	SystemNonPagedPoolInformation,  
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation, 
	SystemSummaryMemoryInformation, 
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemPowerInformation2,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation
}SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids,
    TokenSessionId,
    TokenGroupsAndPrivileges,
    TokenSessionReference,
    TokenSandBoxInert,
    TokenAuditPolicy,
    TokenOrigin,
    TokenElevationType,
    TokenLinkedToken,
    TokenElevation,
    TokenHasRestrictions,
    TokenAccessInformation,
    TokenVirtualizationAllowed,
    TokenVirtualizationEnabled,
    TokenIntegrityLevel,
    TokenUIAccess,
    TokenMandatoryPolicy,
    TokenLogonSid,
    MaxTokenInfoClass  // MaxTokenInfoClass should always be the last enum
} TOKEN_INFORMATION_CLASS, *PTOKEN_INFORMATION_CLASS;

typedef PVOID PRKPROCESS;
typedef GUID UUID;

typedef struct _KEY_BASIC_INFORMATION 
{
    LARGE_INTEGER LastWriteTime;
    ULONG   TitleIndex;
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable length string
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef struct _KEY_NODE_INFORMATION
 {
    LARGE_INTEGER LastWriteTime;
    ULONG   TitleIndex;
    ULONG   ClassOffset;
    ULONG   ClassLength;
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable length string
//          Class[1];           // Variable length string not declared
} KEY_NODE_INFORMATION, *PKEY_NODE_INFORMATION;

typedef struct _KEY_FULL_INFORMATION 
{
    LARGE_INTEGER LastWriteTime;
    ULONG   TitleIndex;
    ULONG   ClassOffset;
    ULONG   ClassLength;
    ULONG   SubKeys;
    ULONG   MaxNameLen;
    ULONG   MaxClassLen;
    ULONG   Values;
    ULONG   MaxValueNameLen;
    ULONG   MaxValueDataLen;
    WCHAR   Class[1];           // Variable length
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;

typedef enum _KEY_INFORMATION_CLASS
 {
    KeyNameInformation=3,
    KeyCachedInformation,
    KeyFlagsInformation,
    KeyVirtualizationInformation,
    KeyHandleTagsInformation,
    MaxKeyInfoClass  // MaxKeyInfoClass should always be the last enum
} KEY_INFORMATION_CLASS;

typedef struct _OBJECT_DUMP_CONTROL
{
    PVOID Stream;
    ULONG Detail;
} OB_DUMP_CONTROL, *POB_DUMP_CONTROL;

typedef void (__stdcall *OB_DUMP_METHOD)(PVOID Object,POB_DUMP_CONTROL Control);
typedef enum _OB_OPEN_REASON 
{
    ObCreateHandle,
    ObOpenHandle,
    ObDuplicateHandle,
    ObInheritHandle,
    ObMaxOpenReason
} OB_OPEN_REASON;

typedef struct _PORT_DATA_ENTRY 
{
    PVOID Base;
    ULONG Size;
} PORT_DATA_ENTRY, *PPORT_DATA_ENTRY;

typedef struct _PORT_DATA_INFORMATION 
{
    ULONG CountDataEntries;
    PORT_DATA_ENTRY DataEntries[1];
} PORT_DATA_INFORMATION, *PPORT_DATA_INFORMATION;

typedef struct _LPCP_NONPAGED_PORT_QUEUE 
{
    KSEMAPHORE Semaphore;
    struct _LPCP_PORT_OBJECT *BackPointer;
} LPCP_NONPAGED_PORT_QUEUE, *PLPCP_NONPAGED_PORT_QUEUE;

typedef struct _LPCP_PORT_QUEUE 
{
    PLPCP_NONPAGED_PORT_QUEUE NonPagedPortQueue;
    PKSEMAPHORE Semaphore;
    LIST_ENTRY ReceiveHead;     // list of messages to receive
} LPCP_PORT_QUEUE, *PLPCP_PORT_QUEUE;

typedef struct _SECURITY_CLIENT_CONTEXT 
{
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    PACCESS_TOKEN ClientToken;
    BOOLEAN DirectlyAccessClientToken;
    BOOLEAN DirectAccessEffectiveOnly;
    BOOLEAN ServerIsRemote;
    TOKEN_CONTROL ClientTokenControl;
    } SECURITY_CLIENT_CONTEXT, *PSECURITY_CLIENT_CONTEXT;

typedef struct _LPCP_PORT_OBJECT 
{
    struct _LPCP_PORT_OBJECT *ConnectionPort;
    struct _LPCP_PORT_OBJECT *ConnectedPort;
    LPCP_PORT_QUEUE MsgQueue;
    CLIENT_ID Creator;
    PVOID ClientSectionBase;
    PVOID ServerSectionBase;
    PVOID PortContext;
    PETHREAD ClientThread;                  // only SERVER_COMMUNICATION_PORT
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SECURITY_CLIENT_CONTEXT StaticSecurity;
    LIST_ENTRY LpcReplyChainHead;           // Only in _COMMUNICATION ports
    LIST_ENTRY LpcDataInfoChainHead;        // Only in _COMMUNICATION ports
    union {
        PEPROCESS ServerProcess;                // Only in SERVER_CONNECTION ports
        PEPROCESS MappingProcess;               // Only in _COMMUNICATION    ports
    };
    USHORT MaxMessageLength;
    USHORT MaxConnectionInfoLength;
    ULONG Flags;
    KEVENT WaitEvent;                          // Object is truncated for non-waitable ports
} LPCP_PORT_OBJECT, *PLPCP_PORT_OBJECT;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    PVOID GpValue;
    PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Unused5;
    PVOID SectionPointer;
    ULONG CheckSum;
    PVOID LoadedImports;
    PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

typedef struct _SHUTDOWN_PACKET 
{
    LIST_ENTRY ListEntry;
    PDEVICE_OBJECT DeviceObject;
} SHUTDOWN_PACKET, *PSHUTDOWN_PACKET;

#pragma pack(push)
#pragma pack(8)
typedef struct _IRP 
{
    CSHORT Type;
    USHORT Size;
    PMDL MdlAddress;
    ULONG Flags;
    union 
	{
        struct _IRP *MasterIrp;
        LONG IrpCount;
        PVOID SystemBuffer;
    } AssociatedIrp;
    LIST_ENTRY ThreadListEntry;
    IO_STATUS_BLOCK IoStatus;
    KPROCESSOR_MODE RequestorMode;
    BOOLEAN PendingReturned;
    CHAR StackCount;
    CHAR CurrentLocation;
    BOOLEAN Cancel;
    KIRQL CancelIrql;
    CCHAR ApcEnvironment;
    UCHAR AllocationFlags;
    PIO_STATUS_BLOCK UserIosb;
    PKEVENT UserEvent;
    union 
	{
        struct 
		{
            union 
			{
                PIO_APC_ROUTINE UserApcRoutine;
                PVOID IssuingProcess;
            };
            PVOID UserApcContext;
        } AsynchronousParameters;
        LARGE_INTEGER AllocationSize;
    } Overlay;
    __volatile PDRIVER_CANCEL CancelRoutine;
    PVOID UserBuffer;
    union 
	{
        struct 
		{
            union 
			{
                KDEVICE_QUEUE_ENTRY DeviceQueueEntry;
                struct 
				{
                    PVOID DriverContext[4];
                } ;
            } ;
            PETHREAD Thread;
            PCHAR AuxiliaryBuffer;
            struct 
			{
                LIST_ENTRY ListEntry;
                union 
				{
                    struct _IO_STACK_LOCATION *CurrentStackLocation;
                    ULONG PacketType;
                };
            };
            PFILE_OBJECT OriginalFileObject;
        } Overlay;
        KAPC Apc;
        PVOID CompletionKey;
    } Tail;
} IRP;
#pragma pack(pop)

typedef NTSTATUS (__stdcall *OB_OPEN_METHOD)(OB_OPEN_REASON OpenReason,PEPROCESS Process,PVOID Object,ACCESS_MASK GrantedAccess,ULONG HandleCount);
typedef BOOLEAN (__stdcall *OB_OKAYTOCLOSE_METHOD)(PEPROCESS Process,PVOID Object,HANDLE Handle,KPROCESSOR_MODE PreviousMode);
typedef void (__stdcall *OB_CLOSE_METHOD)(PEPROCESS Process,PVOID Object,ACCESS_MASK GrantedAccess,ULONG_PTR ProcessHandleCount,ULONG_PTR SystemHandleCount);
typedef void (__stdcall *OB_DELETE_METHOD)(PVOID   Object);
typedef NTSTATUS (__stdcall *OB_PARSE_METHOD)(PVOID ParseObject,PVOID ObjectType,PACCESS_STATE AccessState,KPROCESSOR_MODE AccessMode,ULONG Attributes,PUNICODE_STRING CompleteName,PUNICODE_STRING RemainingName,PVOID Context,PSECURITY_QUALITY_OF_SERVICE SecurityQos,PVOID *Object);
typedef NTSTATUS (__stdcall *OB_SECURITY_METHOD)(PVOID Object,SECURITY_OPERATION_CODE OperationCode,PSECURITY_INFORMATION SecurityInformation,PSECURITY_DESCRIPTOR SecurityDescriptor,PULONG CapturedLength,PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,POOL_TYPE PoolType,PGENERIC_MAPPING GenericMapping);
typedef NTSTATUS (__stdcall *OB_QUERYNAME_METHOD)(PVOID Object,BOOLEAN HasObjectName,POBJECT_NAME_INFORMATION ObjectNameInfo,ULONG Length,PULONG ReturnLength,KPROCESSOR_MODE Mode);

typedef union _FS_FILTER_PARAMETERS 
{
    struct 
	{
        PLARGE_INTEGER EndingOffset;
        PVOID *ResourceToRelease;
    } AcquireForModifiedPageWriter;
    struct 
	{
        PVOID ResourceToRelease;
    } ReleaseForModifiedPageWriter;
    struct 
	{
        DWORD SyncType;
        ULONG PageProtection;
    } AcquireForSectionSynchronization;
    struct 
	{
        DWORD NotificationType;
        BOOLEAN SafeToRecurse;
    } NotifyStreamFileObject;
    struct 
	{
        PVOID Argument1;
        PVOID Argument2;
        PVOID Argument3;
        PVOID Argument4;
        PVOID Argument5;
    } Others;
} FS_FILTER_PARAMETERS, *PFS_FILTER_PARAMETERS;

typedef struct _FS_FILTER_CALLBACK_DATA 
{
    ULONG SizeOfFsFilterCallbackData;
    UCHAR Operation;
    UCHAR Reserved;
    struct _DEVICE_OBJECT *DeviceObject;
    struct _FILE_OBJECT *FileObject;
    FS_FILTER_PARAMETERS Parameters;
} FS_FILTER_CALLBACK_DATA, *PFS_FILTER_CALLBACK_DATA;

typedef struct _FILTER_REPLY_HEADER 
{
  NTSTATUS  Status;
  ULONGLONG MessageId;
} FILTER_REPLY_HEADER, *PFILTER_REPLY_HEADER;

typedef struct _FILTER_MESSAGE_HEADER 
{
  ULONG     ReplyLength;
  ULONGLONG MessageId;
} FILTER_MESSAGE_HEADER, *PFILTER_MESSAGE_HEADER;

HRESULT __stdcall FilterReplyMessage(HANDLE hPort,PFILTER_REPLY_HEADER lpReplyBuffer,DWORD dwReplyBufferSize);
HRESULT __stdcall FilterSendMessage(HANDLE hPort,LPVOID lpInBuffer,DWORD dwInBufferSize,LPVOID lpOutBuffer,DWORD dwOutBufferSize,LPDWORD lpBytesReturned);
HRESULT __stdcall FilterGetMessage(HANDLE hPort,PFILTER_MESSAGE_HEADER lpMessageBuffer,DWORD dwMessageBufferSize,LPOVERLAPPED lpOverlapped);
HRESULT __stdcall FilterLoad(LPCWSTR lpFilterName);
HRESULT __stdcall FilterUnload(LPCWSTR lpFilterName);
HRESULT __stdcall FilterConnectCommunicationPort(LPCWSTR lpPortName,DWORD dwOptions,LPCVOID lpContext,WORD dwSizeOfContext,LPSECURITY_ATTRIBUTES lpSecurityAttributes,HANDLE *hPort);

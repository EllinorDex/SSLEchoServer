#include <Windows.h>
#include <Process.h>
#include <Malloc.h>
#include <SChannel.h>
#include <WinCrypt.h>
#include <shlwapi.h>
//#include "Resource.h"

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")

#define  SECURITY_WIN32
#include <Security.h>
#include "transport.h"

#define HANDLE_WM_USER_CONNECT(hwnd, wParam, lParam, fn) ((fn) (hwnd), 0L)
#define HANDLE_WM_USER_DISCONNECT(hwnd, wParam, lParam, fn) ((fn) (hwnd), 0L)

#define MSG(Text)             MessageBox(NULL, Text, TEXT("SSLChat"), MB_OK)

#define WM_USER_CONNECT       (WM_USER + 5150)
#define WM_USER_DISCONNECT    (WM_USER + 5151)

#define GUI_STATE_READY       1
#define GUI_STATE_CONNECTING  2
#define GUI_STATE_CONNECTED   3


typedef struct _SSLChatState
{
    _SSLChatState();

    ~_SSLChatState();

    // Dialog and layout state
    HWND        m_hwndDialog;

    // "Output" state
    HWND        m_hwndScript;
    HWND        m_hwndInfo;

    // Server and client info
    BOOL        m_fServer;
    BOOL        m_fRunAsSystem;
    TCHAR       m_szRemoteUserName[1024];
    TCHAR       m_szLocalUserName[1024];

    // SSL info
    CtxtHandle  m_hContext;
    CredHandle  m_hCredentials;
    CredHandle  m_hCertCredentials;
    BOOL        m_fMutualAuth;
    TCHAR       m_szSrvActName[1024];
    ULONG       m_lExtraData;

    // Communication info
    CTransport* m_pTransport;
    PBYTE       m_pbReadBuffer;
    ULONG       m_lReadBufferLen;

    // Threads and thread sync
    HANDLE      m_hReadThread;
    CRITICAL_SECTION m_CriticalSec;

} SSLChatState, *PSSLChatState;


void ReportSSLError(PTSTR szAPI, SECURITY_STATUS ss);

static void PrintHexDump(PSSLChatState pscState, PTSTR pszTitle, PBYTE buffer, ULONG length);

inline BOOL SSLClientHandshakeAuth(
    PSSLChatState pscState,
    PCredHandle phCredentials,
    PCredHandle phCertCredentials,
    PULONG plAttributes,
    PCtxtHandle phContext,
    PTSTR pszServer,
    PBYTE pbExtraData,
    PULONG pcbExtraData,
    ULONG lSizeExtraDataBuf);

BOOL GetAnonymousCredentials(PCredHandle phCredentials);

BOOL GetCertCredentials(PCredHandle phCredentials, PTSTR pszName, BOOL fRunAsSystem, ULONG lCredUse);

BOOL GetCertNameFromContext(PCtxtHandle phContext, PTSTR pszName, ULONG lBufSize);

BOOL InitializeSecureConnection(PSSLChatState pscState, BOOL fServer, PTSTR szServer);

BOOL SendEncryptedMessage(
    PSSLChatState pscState,
    PCtxtHandle phContext,
    PVOID pvData,
    ULONG lSize);

PVOID GetEncryptedMessage(
    PSSLChatState pscState,
    PCtxtHandle phContext,
    PULONG plSize,
    PBYTE ppbExtraData,
    PULONG pcbExtraData,
    ULONG lSizeExtraDataBuf,
    PBOOL pfReneg);

DWORD WINAPI ConnectAndReadThread(PVOID lpParam);
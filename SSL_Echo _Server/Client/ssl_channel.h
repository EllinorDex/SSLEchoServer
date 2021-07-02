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

#define MSG(Text) MessageBox(NULL, Text, TEXT("SSLChat"), MB_OK)

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

} SSLChatState, * PSSLChatState;


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
    ULONG lSizeExtraDataBuf)
{

    BOOL fSuccess = FALSE;

    try {
        {
            // Setup our own copy of the credentials handle
            CredHandle credsUse;
            CopyMemory(&credsUse, phCredentials, sizeof(credsUse));

            // Setup buffer interms of local variables for readability
            ULONG lEndBufIndex = *pcbExtraData;
            ULONG lBufMaxSize = lSizeExtraDataBuf;
            PBYTE pbData = pbExtraData;

            // Declare in and out buffers
            SecBuffer secBufferOut;
            SecBufferDesc secBufDescriptorOut;

            SecBuffer secBufferIn[2];
            SecBufferDesc secBufDescriptorIn;

            // Setup loop state information
            BOOL fFirstPass = TRUE;
            SECURITY_STATUS ss = SEC_I_CONTINUE_NEEDED;
            while ((ss == SEC_I_CONTINUE_NEEDED) || (ss == SEC_E_INCOMPLETE_MESSAGE))
            {

                // How much data can we read per pass
                ULONG lReadBuffSize;

                // Reset if we are not doing an "incomplete" loop
                if (ss != SEC_E_INCOMPLETE_MESSAGE)
                {

                    // Reset state for another blob exchange
                    lEndBufIndex = 0;
                    lReadBuffSize = lBufMaxSize;
                }

                // Some stuff we only due after the first pass
                if (!fFirstPass)
                {

                    // Receive as much data as we can
                    if (pscState->m_pTransport->ReceiveData(pbData + lEndBufIndex, &lReadBuffSize))
                        PrintHexDump(pscState, PTSTR(LR"(<IN: Auth-blob from Server>)"), pbData + lEndBufIndex, lReadBuffSize);
                    else
                        goto leave;

                    // This is how much data we have so far
                    lEndBufIndex += lReadBuffSize;

                    // Setup in buffer with our current data
                    secBufferIn[0].BufferType = SECBUFFER_TOKEN;
                    secBufferIn[0].cbBuffer = lEndBufIndex;
                    secBufferIn[0].pvBuffer = pbData;

                    // This becomes a SECBUFFER_EXTRA buffer to let us
                    // know if we have extra data afterward
                    secBufferIn[1].BufferType = SECBUFFER_EMPTY;
                    secBufferIn[1].cbBuffer = 0;
                    secBufferIn[1].pvBuffer = NULL;

                    // Setup in buffer descriptor
                    secBufDescriptorIn.cBuffers = 2;
                    secBufDescriptorIn.pBuffers = secBufferIn;
                    secBufDescriptorIn.ulVersion = SECBUFFER_VERSION;
                }

                // Setup out buffer (allocated by SSPI)
                secBufferOut.BufferType = SECBUFFER_TOKEN;
                secBufferOut.cbBuffer = 0;
                secBufferOut.pvBuffer = NULL;

                // Setup out buffer descriptor
                secBufDescriptorOut.cBuffers = 1;
                secBufDescriptorOut.pBuffers = &secBufferOut;
                secBufDescriptorOut.ulVersion = SECBUFFER_VERSION;

                // This inner loop handles the "continue case" where there is
                // no blob data to be sent.  In this case, there are still more
                // "sections" in our last blob entry that must be processed
                BOOL fNoOutBuffer;
                do
                {

                    fNoOutBuffer = FALSE;

                    // Blob processing
                    ss = InitializeSecurityContext(
                        &credsUse,
                        fFirstPass ? NULL : phContext,
                        fFirstPass ? pszServer : NULL,
                        *plAttributes | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM,
                        0,
                        SECURITY_NATIVE_DREP,
                        fFirstPass ? NULL : &secBufDescriptorIn,
                        0,
                        phContext,
                        &secBufDescriptorOut,
                        plAttributes,
                        NULL);

                    // Are there more sections to process?
                    if ((ss == SEC_I_CONTINUE_NEEDED) && (secBufferOut.cbBuffer == 0))
                    {

                        fNoOutBuffer = TRUE; // Set state to loop

                                             // Here is how much data was left over
                        ULONG lExtraData = secBufferIn[1].cbBuffer;

                        // We want to move this data back to the beginning of our buffer
                        MoveMemory(pbData, pbData + (lEndBufIndex - lExtraData), lExtraData);

                        // Now we have a new lendbufindex
                        lEndBufIndex = lExtraData;

                        // Lets reset input buffers
                        secBufferIn[0].BufferType = SECBUFFER_TOKEN;
                        secBufferIn[0].cbBuffer = lEndBufIndex;
                        secBufferIn[0].pvBuffer = pbData;

                        secBufferIn[1].BufferType = SECBUFFER_EMPTY;
                        secBufferIn[1].cbBuffer = 0;
                        secBufferIn[1].pvBuffer = NULL;
                    }

                    if (ss == SEC_I_INCOMPLETE_CREDENTIALS)
                    {

                        // Server requested credentials.  Copy credentials with cert.
                        // Normally, we would call AcquireCredentialsHandle here
                        // to pick up new credentials... However, we have already passed
                        // in cert credentials in this sample function.
                        CopyMemory(&credsUse, phCertCredentials, sizeof(credsUse));

                        // No input needed this pass
                        secBufDescriptorIn.cBuffers = 0;

                        // Keep on truckin
                        fNoOutBuffer = TRUE; // Set state to loop
                    }

                } while (fNoOutBuffer);

                // This is how much data our next read from the wire
                // can bring in without overflowing our buffer
                lReadBuffSize = lBufMaxSize - lEndBufIndex;

                // Was there data to be sent?
                if (secBufferOut.cbBuffer != 0)
                {

                    // Send it then
                    ULONG lOut = secBufferOut.cbBuffer;
                    if (pscState->m_pTransport->SendData(secBufferOut.pvBuffer, &lOut))
                        PrintHexDump(pscState, PTSTR(R"(<OUT: Auth-blob to Server>)"), (PBYTE)secBufferOut.pvBuffer, lOut);
                    else
                        goto leave;

                    // And free up that out buffer
                    FreeContextBuffer(secBufferOut.pvBuffer);
                }

                if (ss != SEC_E_INCOMPLETE_MESSAGE)
                    fFirstPass = FALSE;
            }

            if (ss == SEC_E_OK) {

                int nIndex = 1;
                while (secBufferIn[nIndex].BufferType != SECBUFFER_EXTRA && (nIndex-- != 0));

                if ((nIndex != -1) && (secBufferIn[nIndex].cbBuffer != 0))
                {

                    *pcbExtraData = secBufferIn[nIndex].cbBuffer;
                    PBYTE pbTempBuf = pbData;
                    pbTempBuf += (lEndBufIndex - *pcbExtraData);
                    MoveMemory(pbExtraData, pbTempBuf, *pcbExtraData);
                }
                else
                    *pcbExtraData = 0;

                fSuccess = TRUE;
            }

        } leave:;
    }
    catch (...) {}

    return(fSuccess);
}


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
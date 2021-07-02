#include "transport.h"

#define SOCKETPORT 2112


DWORD APIDbgMsg(PTSTR pszAPI, DWORD dwError)
{

    if (dwError == 0)
        dwError = GetLastError();

    PVOID pvMessageBuffer;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (PTSTR)&pvMessageBuffer, 0, NULL);

    TCHAR szErrMsgBuffer[500];
    wsprintf(szErrMsgBuffer,
        TEXT("ERROR: API = %s.\n")
        TEXT("ERROR CODE = %d.\nMESSAGE = %s.\n"),
        pszAPI, dwError, (PTSTR)pvMessageBuffer);

    std::cout << szErrMsgBuffer;
    LocalFree(pvMessageBuffer);
    return (dwError);
}

BOOL CTransport::SendMsg(PBYTE pBuf, DWORD cbBuf)
{
    BOOL fSuccess = FALSE;

    try
    {
        if (cbBuf == 0)
            return TRUE;

        ULONG lSize = sizeof(cbBuf);
        if (!SendData((PBYTE)&cbBuf, &lSize))
            return FALSE;

        lSize = cbBuf;
        if (!SendData(pBuf, &lSize) || lSize == 0)
            return FALSE;

        fSuccess = TRUE;
    }
    catch (...) {}

    return fSuccess;
}


BOOL CTransport::ReceiveDataUntil(PVOID pData, ULONG lBytes)
{
    BOOL fSuccess = FALSE;

    try
    {
        PBYTE pbTemp = (PBYTE)pData;
        ULONG cbBufSize = lBytes;

        do
        {
            ULONG cbAttempt = cbBufSize;
            if (!ReceiveData(pbTemp, &cbAttempt))
                return FALSE;

            pbTemp += cbAttempt;
            cbBufSize -= cbAttempt;
        } while (cbBufSize > 0);

        fSuccess = TRUE;
    }
    catch (...) {}

    return fSuccess;
}


PBYTE CTransport::ReceiveMsg(PDWORD pcbRead) {

    PBYTE pbRet = NULL;

    try
    {
        ULONG cbData;
        if (!ReceiveDataUntil(&cbData, sizeof(cbData)))
            return NULL;

        pbRet = (PBYTE)LocalAlloc(LPTR, cbData + sizeof(TCHAR));
        if (pbRet == NULL)
            return NULL;

        ZeroMemory(pbRet + cbData, sizeof(TCHAR));

        if (!ReceiveDataUntil(pbRet, cbData))
        {
            LocalFree(pbRet);
            return NULL;
        }

        if (pcbRead != NULL)
            *pcbRead = cbData;
    }
    catch (...) {}

    return pbRet;
}


CSocketTransport::CSocketTransport()
{

    int     nRes;
    WSADATA wsaData;
    WORD    wVerRequested = 0x0101;

    nRes = WSAStartup(wVerRequested, &wsaData);
    if (nRes != 0)
    {
        TCHAR szErrMsg[128];
        wsprintf(szErrMsg, TEXT("Couldn't init winsock: %d\n"), nRes);
        MessageBox(NULL, szErrMsg, TEXT("ERROR"), MB_OK);
    }

    ResetInstance(TRUE);
}


void CSocketTransport::ResetInstance(BOOL fConstructing)
{

    m_lAddress = 0;
    if (!fConstructing)
    {
        if (m_Socket != INVALID_SOCKET)
            closesocket(m_Socket);
    }

    m_Socket = INVALID_SOCKET;
}


BOOL CSocketTransport::SendData(PVOID pData, PULONG plBytes)
{
    ULONG cbRemaining = *plBytes;
    ULONG cbToSend = *plBytes;
    *plBytes = 0;

    try
    {

        PBYTE pTemp = (PBYTE)pData;
        while (cbRemaining != 0)
        {

            ULONG cbSent = send(m_Socket, (char*)pTemp, cbRemaining, 0);
            if (cbSent == SOCKET_ERROR)
            {
                APIDbgMsg(PTSTR(LR"(send)"), WSAGetLastError());
                return cbToSend == *plBytes;
            }

            pTemp += cbSent;
            cbRemaining -= cbSent;
            *plBytes += cbSent;
        }

    }
    catch (...) {}

    return cbToSend == *plBytes;
}


BOOL CSocketTransport::ReceiveData(PVOID pData, PULONG plBytes)
{
    BOOL fSuccess = FALSE;
    int cbRead = *plBytes;
    *plBytes = 0;

    try
    {
        *plBytes = recv(m_Socket, (char*)pData, cbRead, 0);
        if (*plBytes == SOCKET_ERROR)
        {
            if (WSAGetLastError() != WSAECONNRESET && WSAGetLastError() != WSAECONNABORTED)
                APIDbgMsg(PTSTR(LR"("recv")"), WSAGetLastError());

            *plBytes = 0;
            return FALSE;
        }

        fSuccess = (*plBytes != 0);
    }
    catch (...) {}

    return (fSuccess);
}


BOOL CSocketTransport::InitializeConversation(PTSTR szServerNameOrIP)
{
    BOOL fSuccess = FALSE;

    try
    {
        if (szServerNameOrIP == NULL)
        {  // Server

            SOCKADDR_IN sin;
            int nRes;

            // Create listening socket
            m_Socket = socket(PF_INET, SOCK_STREAM, 0);
            if (m_Socket == INVALID_SOCKET)
            {
                APIDbgMsg(PTSTR(LR"(socket)"), WSAGetLastError());
                ResetInstance();
                return FALSE;
            }

            // Bind to local port
            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = 0;
            sin.sin_port = htons(SOCKETPORT);

            nRes = bind(m_Socket, (PSOCKADDR)&sin, sizeof(sin));
            if (nRes == SOCKET_ERROR)
            {
                APIDbgMsg(PTSTR(LR"(bind)"), WSAGetLastError());
                ResetInstance();
                return FALSE;
            }

            // Listen for client
            nRes = listen(m_Socket, 1);
            if (nRes == SOCKET_ERROR)
            {
                APIDbgMsg(PTSTR(LR"(listen)"), WSAGetLastError());
                ResetInstance();
                return FALSE;
            }

        }
        else
        { // Client

            struct hostent* pHost;
            SOCKADDR_IN sin;
            PSTR pszSvr;

            pszSvr = (PCHAR)szServerNameOrIP;

            // Lookup the address for the server name
            m_lAddress = inet_addr(pszSvr);
            if (INADDR_NONE == m_lAddress)
            {
                pHost = gethostbyname(pszSvr);
                if (pHost == NULL)
                {
                    APIDbgMsg(PTSTR(LR"(gethostbyname)"), WSAGetLastError());
                    ResetInstance();
                    return FALSE;
                }

                memcpy((char FAR*) & m_lAddress, pHost->h_addr, pHost->h_length);
            }

            // Create the socket
            m_Socket = socket(PF_INET, SOCK_STREAM, 0);
            if (m_Socket == INVALID_SOCKET)
            {
                APIDbgMsg(PTSTR(LR"(socket)"), WSAGetLastError());
                ResetInstance();
                return FALSE;
            }

            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = m_lAddress;
            sin.sin_port = htons(SOCKETPORT);
        }

        fSuccess = TRUE;
    }
    catch (...) {}

    if (!fSuccess)
        ResetInstance();

    return fSuccess;
}


BOOL CSocketTransport::WaitForConversation()
{

    BOOL fSuccess = FALSE;
    SOCKET ListenSocket = INVALID_SOCKET;

    try
    {
        if (m_lAddress == 0)
        { // Server

            ListenSocket = m_Socket;

            // Accept client
            m_Socket = accept(ListenSocket, NULL, NULL);
            if (m_Socket == INVALID_SOCKET)
            {
                APIDbgMsg(PTSTR(LR"(accept)"), WSAGetLastError());
                if (ListenSocket != INVALID_SOCKET)
                    closesocket(ListenSocket);
                return FALSE;
            }

            Beep(500, 250);
        }
        else
        {
            SOCKADDR_IN sin;

            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = m_lAddress;
            sin.sin_port = htons(SOCKETPORT);

            // Connect to remote endpoint
            if (connect(m_Socket, (PSOCKADDR)&sin, sizeof(sin)) == SOCKET_ERROR)
            {
                APIDbgMsg(PTSTR(LR"(connect)"), WSAGetLastError());
                closesocket(m_Socket);
                m_Socket = INVALID_SOCKET;
                closesocket(ListenSocket);
                return FALSE;
            };
        }
        fSuccess = TRUE;
    }
    catch (...) {}

    if (ListenSocket != INVALID_SOCKET)
        closesocket(ListenSocket);

    return (fSuccess);
}


void CSocketTransport::CloseConversation()
{

    ResetInstance();
}

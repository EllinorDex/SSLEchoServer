//  SspiExample.h
#include "stdafx.h"
#include "SSL_SSP.h"

BOOL SendMsg(SOCKET s, PBYTE pBuf, DWORD cbBuf)
{
    return true;
}

BOOL ReceiveMsg(SOCKET s, PBYTE pBuf, DWORD cbBuf, DWORD* pcbRead)
{
    return true;
}

BOOL SendBytes(SOCKET s, PBYTE pBuf, DWORD cbBuf)
{
    return true;
}

BOOL ReceiveBytes(SOCKET s, PBYTE pBuf, DWORD cbBuf, DWORD* pcbRead)
{
    return true;
}

void cleanup()
{

}

BOOL GenClientContext(
    BYTE* pIn,
    DWORD cbIn,
    BYTE* pOut,
    DWORD* pcbOut,
    BOOL* pfDone,
    CHAR* pszTarget,
    CredHandle* hCred,
    struct _SecHandle* hcText
)
{
    return true;
}


BOOL GenServerContext(
    BYTE* pIn,
    DWORD cbIn,
    BYTE* pOut,
    DWORD* pcbOut,
    BOOL* pfDone,
    BOOL  fNewCredential
)
{
    return true;
}


BOOL EncryptThis(
    PBYTE pMessage,
    ULONG cbMessage,
    BYTE** ppOutput,
    LPDWORD pcbOutput,
    ULONG securityTrailer
)
{
    return true;
}


PBYTE DecryptThis(
    PBYTE achData,
    LPDWORD pcbMessage,
    struct _SecHandle* hCtxt,
    ULONG   cbSecurityTrailer
)
{
    PBYTE q = 0;
    return q;
}

BOOL SignThis(
    PBYTE pMessage,
    ULONG cbMessage,
    BYTE** ppOutput,
    LPDWORD pcbOutput
)
{
    return true;
}

PBYTE VerifyThis(
    PBYTE pBuffer,
    LPDWORD pcbMessage,
    struct _SecHandle* hCtxt,
    ULONG   cbMaxSignature
)
{
    PBYTE q = 0;
    return q;
}

void PrintHexDump(DWORD length, PBYTE buffer)
{

}

BOOL ConnectAuthSocket(
    SOCKET* s,
    CredHandle* hCred,
    struct _SecHandle* hcText
)
{
    return true;
}

BOOL CloseAuthSocket(SOCKET s)
{
    return true;
}

BOOL DoAuthentication(SOCKET s)
{
    return true;
}

void MyHandleError(char* s)
{

}


int main()
{
    std::cout << "Hello World!\n";
}

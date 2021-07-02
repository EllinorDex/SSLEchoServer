#pragma once

#include <Windows.h>
#include <TChar.h>
#include <iostream>


DWORD APIDbgMsg(PTSTR pszAPI, DWORD dwError);


class CTransport {
public:
    virtual ~CTransport() {};

public:
    BOOL SendMsg(PBYTE pBuf, DWORD cbBuf);
    PBYTE ReceiveMsg(PDWORD pcbRead);

    virtual BOOL SendData(PVOID pData, PULONG plBytes) = 0;
    virtual BOOL ReceiveData(PVOID pData, PULONG plBytes) = 0;
    virtual BOOL InitializeConversation(PTSTR szServerNameOrIP) = 0;
    virtual BOOL WaitForConversation() = 0;
    virtual void CloseConversation() = 0;

private:
    BOOL ReceiveDataUntil(PVOID pData, ULONG lBytes);

};


class CSocketTransport :public CTransport {
public:
    CSocketTransport();
    ~CSocketTransport() { ResetInstance(); WSACleanup(); };

public:
    virtual BOOL SendData(PVOID pData, PULONG lBytes);
    virtual BOOL ReceiveData(PVOID pData, PULONG plBytes);
    virtual BOOL InitializeConversation(PTSTR szServerNameOrIP);
    virtual BOOL WaitForConversation();
    virtual void CloseConversation();

private:
    SOCKET   m_Socket;
    ULONG    m_lAddress;

    void ResetInstance(BOOL fConstructing = FALSE);
};

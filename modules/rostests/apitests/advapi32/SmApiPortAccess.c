/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test that connecting to a port by name checks the port's security
 * COPYRIGHT:   Copyright 2026 Emrul Islam <emrul@emrul.com>
 */

#include "precomp.h"

typedef struct
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} SMP_UNICODE_STRING;

typedef LONG (NTAPI *PNT_CONNECT_PORT)(PHANDLE, PVOID, PVOID, PVOID, PVOID, PULONG, PVOID, PULONG);

static LONG
ConnectSmApiPort(PNT_CONNECT_PORT Connect)
{
    static WCHAR PortName[] = L"\\SmApiPort";
    SECURITY_QUALITY_OF_SERVICE Qos = { sizeof(Qos), SecurityIdentification, SECURITY_DYNAMIC_TRACKING, FALSE };
    SMP_UNICODE_STRING Name;
    HANDLE Port = NULL;
    LONG Status;

    Name.Length = (USHORT)(wcslen(PortName) * sizeof(WCHAR));
    Name.MaximumLength = Name.Length + sizeof(WCHAR);
    Name.Buffer = PortName;
    Status = Connect(&Port, &Name, &Qos, NULL, NULL, NULL, NULL, NULL);
    if (Port)
        CloseHandle(Port);
    return Status;
}

START_TEST(SmApiPortAccess)
{
    PNT_CONNECT_PORT Connect = (PNT_CONNECT_PORT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtConnectPort");
    BYTE AdminsBuffer[SECURITY_MAX_SID_SIZE];
    SID_AND_ATTRIBUTES Disable;
    HANDLE Token = NULL, Restricted = NULL;
    DWORD Size = sizeof(AdminsBuffer);
    BOOL IsAdmin = FALSE;
    LONG Status;

    ok(Connect != NULL, "NtConnectPort is not exported\n");
    if (!Connect)
        return;

    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, AdminsBuffer, &Size) ||
        !CheckTokenMembership(NULL, AdminsBuffer, &IsAdmin) || !IsAdmin)
    {
        skip("The test needs an elevated administrator\n");
        return;
    }

    Status = ConnectSmApiPort(Connect);
    ok(Status == 0, "an administrator could not connect to \\SmApiPort: 0x%lx\n", Status);

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &Token),
       "OpenProcessToken failed with %lu\n", GetLastError());
    Disable.Sid = AdminsBuffer;
    Disable.Attributes = 0;
    ok(CreateRestrictedToken(Token, 0, 1, &Disable, 0, NULL, 0, NULL, &Restricted),
       "CreateRestrictedToken failed with %lu\n", GetLastError());
    if (Restricted && ImpersonateLoggedOnUser(Restricted))
    {
        Status = ConnectSmApiPort(Connect);
        ok(Status == (LONG)0xC0000022, "without Administrators, connecting to \\SmApiPort returned 0x%lx\n", Status);
        ok(RevertToSelf(), "RevertToSelf failed with %lu\n", GetLastError());
    }
    else
    {
        ok(0, "ImpersonateLoggedOnUser failed with %lu\n", GetLastError());
    }

    if (Restricted)
        CloseHandle(Restricted);
    if (Token)
        CloseHandle(Token);
}

/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test that a DOS device defined in one logon session is not seen from another
 * COPYRIGHT:   Copyright 2026 Emrul Islam <emrul@emrul.com>
 */

#include "precomp.h"

static BOOL
FindFreeLetter(PWSTR Device)
{
    WCHAR Target[MAX_PATH];
    WCHAR Letter;

    for (Letter = L'Q'; Letter <= L'Z'; ++Letter)
    {
        Device[0] = Letter;
        Device[1] = L':';
        Device[2] = 0;
        if (!QueryDosDeviceW(Device, Target, ARRAYSIZE(Target)) && GetLastError() == ERROR_FILE_NOT_FOUND)
            return TRUE;
    }
    return FALSE;
}

START_TEST(DosDeviceLogonSession)
{
    WCHAR Device[3], Target[MAX_PATH];
    DWORD Length, Error;
    BOOL Impersonating;

    if (!FindFreeLetter(Device))
    {
        skip("No free drive letter\n");
        return;
    }

    ok(DefineDosDeviceW(0, Device, L"C:\\LiberNTDosDeviceTest"), "DefineDosDeviceW(%ls) failed with %lu\n", Device, GetLastError());
    Length = QueryDosDeviceW(Device, Target, ARRAYSIZE(Target));
    ok(Length != 0, "the defining logon session does not see %ls: %lu\n", Device, GetLastError());

    Impersonating = ImpersonateAnonymousToken(GetCurrentThread());
    ok(Impersonating, "ImpersonateAnonymousToken failed with %lu\n", GetLastError());
    if (Impersonating)
    {
        SetLastError(0xdeadbeef);
        Length = QueryDosDeviceW(Device, Target, ARRAYSIZE(Target));
        Error = GetLastError();
        ok(Length == 0 && Error == ERROR_FILE_NOT_FOUND, "the anonymous logon session sees %ls: length %lu error %lu\n", Device, Length, Error);

        SetLastError(0xdeadbeef);
        Length = QueryDosDeviceW(L"C:", Target, ARRAYSIZE(Target));
        Error = GetLastError();
        ok(Length == 0 && Error == ERROR_ACCESS_DENIED, "the global C: from the anonymous logon session: length %lu error %lu\n", Length, Error);
        ok(RevertToSelf(), "RevertToSelf failed with %lu\n", GetLastError());
    }

    Length = QueryDosDeviceW(Device, Target, ARRAYSIZE(Target));
    ok(Length != 0, "the defining logon session lost %ls after reverting: %lu\n", Device, GetLastError());
    ok(DefineDosDeviceW(DDD_REMOVE_DEFINITION, Device, NULL), "removing %ls failed with %lu\n", Device, GetLastError());
    SetLastError(0xdeadbeef);
    Length = QueryDosDeviceW(Device, Target, ARRAYSIZE(Target));
    ok(Length == 0 && GetLastError() == ERROR_FILE_NOT_FOUND, "%ls is still defined: length %lu error %lu\n", Device, Length, GetLastError());
}

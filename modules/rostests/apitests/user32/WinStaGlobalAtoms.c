/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test that window stations of one session share the global atom table
 * COPYRIGHT:   Copyright 2026 Emrul Islam <emrul@emrul.com>
 */

#include "precomp.h"

START_TEST(WinStaGlobalAtoms)
{
    WCHAR StationName[64], InsideName[64], OutsideName[64];
    HWINSTA Original, Station;
    ATOM Inside = 0, Outside, Found;

    wsprintfW(StationName, L"LiberNTAtomTest%lu", GetCurrentProcessId());
    wsprintfW(InsideName, L"LiberNTAtomInside%lu", GetCurrentProcessId());
    wsprintfW(OutsideName, L"LiberNTAtomOutside%lu", GetCurrentProcessId());

    Original = GetProcessWindowStation();
    ok(Original != NULL, "GetProcessWindowStation failed with %lu\n", GetLastError());

    Outside = GlobalAddAtomW(OutsideName);
    ok(Outside != 0, "GlobalAddAtomW in the original station failed with %lu\n", GetLastError());

    Station = CreateWindowStationW(StationName, 0, WINSTA_ALL_ACCESS, NULL);
    ok(Station != NULL, "CreateWindowStationW failed with %lu\n", GetLastError());
    if (!Station || !Original)
        goto Cleanup;

    ok(SetProcessWindowStation(Station), "SetProcessWindowStation(new) failed with %lu\n", GetLastError());
    Found = GlobalFindAtomW(OutsideName);
    ok(Found == Outside, "the original station's atom is %x in the new station, expected %x\n", Found, Outside);
    Inside = GlobalAddAtomW(InsideName);
    ok(Inside != 0, "GlobalAddAtomW in the new station failed with %lu\n", GetLastError());
    ok(GlobalFindAtomW(InsideName) == Inside, "the new station's atom is not found in its own station\n");

    ok(SetProcessWindowStation(Original), "SetProcessWindowStation(original) failed with %lu\n", GetLastError());
    Found = GlobalFindAtomW(InsideName);
    ok(Found == Inside, "the new station's atom is %x in the original station, expected %x\n", Found, Inside);
    ok(GlobalFindAtomW(OutsideName) == Outside, "the original station's atom is not found after switching back\n");

    ok(SetProcessWindowStation(Station), "SetProcessWindowStation(new) failed with %lu\n", GetLastError());
    if (Inside)
        GlobalDeleteAtom(Inside);
    ok(SetProcessWindowStation(Original), "SetProcessWindowStation(original) failed with %lu\n", GetLastError());

    {
        WCHAR MessageName[64];
        UINT Message;
        wsprintfW(MessageName, L"LiberNTAtomMessage%lu", GetCurrentProcessId());
        Message = RegisterWindowMessageW(MessageName);
        Found = GlobalFindAtomW(MessageName);
        ok(Message != 0, "RegisterWindowMessageW failed with %lu\n", GetLastError());
        ok(Found == 0, "a registered window message name is global atom %x (message %x)\n", Found, Message);
    }

Cleanup:
    if (Outside)
        GlobalDeleteAtom(Outside);
    if (Station)
        CloseWindowStation(Station);
}

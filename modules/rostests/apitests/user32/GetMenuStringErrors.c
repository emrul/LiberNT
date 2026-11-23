/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test the results and last errors of GetMenuString for invalid menus and items
 * COPYRIGHT:   Copyright 2026 Emrul Islam <emrul@emrul.com>
 */

#include "precomp.h"

START_TEST(GetMenuStringErrors)
{
    WCHAR Text[32];
    HMENU Menu, Destroyed;
    DWORD Error;
    int Result;

    Menu = CreateMenu();
    ok(Menu != NULL, "CreateMenu failed with %lu\n", GetLastError());
    if (!Menu)
        return;
    ok(AppendMenuW(Menu, MF_STRING, 7, L"item"), "AppendMenuW failed with %lu\n", GetLastError());

    Destroyed = CreateMenu();
    ok(DestroyMenu(Destroyed), "DestroyMenu failed with %lu\n", GetLastError());

    SetLastError(0xdeadbeef);
    Text[0] = L'x';
    Result = GetMenuStringW(Destroyed, 0, Text, ARRAYSIZE(Text), MF_BYPOSITION);
    Error = GetLastError();
    ok(Result == 0, "destroyed menu: GetMenuStringW returned %d\n", Result);
    ok(Error == ERROR_INVALID_PARAMETER, "destroyed menu: error %lu\n", Error);
    ok(Text[0] == 0, "destroyed menu: buffer was not cleared\n");

    SetLastError(0xdeadbeef);
    Result = GetMenuStringW(Menu, 5, Text, ARRAYSIZE(Text), MF_BYPOSITION);
    Error = GetLastError();
    ok(Result == 0, "missing position: GetMenuStringW returned %d\n", Result);
    ok(Error == ERROR_MENU_ITEM_NOT_FOUND, "missing position: error %lu\n", Error);

    SetLastError(0xdeadbeef);
    Result = GetMenuStringW(Menu, 99, Text, ARRAYSIZE(Text), MF_BYCOMMAND);
    Error = GetLastError();
    ok(Result == 0, "missing command: GetMenuStringW returned %d\n", Result);
    ok(Error == ERROR_MENU_ITEM_NOT_FOUND, "missing command: error %lu\n", Error);

    SetLastError(0xdeadbeef);
    Result = GetMenuStringW(Menu, 0, Text, ARRAYSIZE(Text), MF_BYPOSITION);
    Error = GetLastError();
    ok(Result == 4 && !lstrcmpW(Text, L"item"), "valid item: GetMenuStringW returned %d \"%ls\"\n", Result, Text);
    ok(Error == 0xdeadbeef, "valid item: error %lu\n", Error);

    DestroyMenu(Menu);
}

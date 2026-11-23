/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test that BOOL window APIs return exactly FALSE for invalid window handles
 * COPYRIGHT:   Copyright 2026 Emrul Islam <emrul@emrul.com>
 */

#include "precomp.h"

static HWND
DestroyedWindow(void)
{
    HWND Window = CreateWindowExW(0, L"STATIC", L"", WS_POPUP, 0, 0, 1, 1, NULL, NULL, NULL, NULL);

    ok(Window != NULL, "CreateWindowExW failed with %lu\n", GetLastError());
    if (Window)
        ok(DestroyWindow(Window) == TRUE, "DestroyWindow of a valid window did not return TRUE\n");
    return Window;
}

START_TEST(InvalidWindowReturn)
{
    HWND Invalid[3];
    TITLEBARINFO Info;
    BOOL Result;
    DWORD Error;
    int i, Round;

    Invalid[0] = DestroyedWindow();
    Invalid[1] = (HWND)(ULONG_PTR)0x7ffe;
    Invalid[2] = (HWND)(ULONG_PTR)0x4006a;

    for (Round = 0; Round < 8; ++Round)
    {
        for (i = 0; i < ARRAYSIZE(Invalid); ++i)
        {
            if (IsWindow(Invalid[i]))
                continue;

            SetLastError(0xdeadbeef);
            Result = DestroyWindow(Invalid[i]);
            Error = GetLastError();
            ok(Result == FALSE, "round %d handle %p: DestroyWindow returned %d\n", Round, Invalid[i], Result);
            ok(Error == ERROR_INVALID_WINDOW_HANDLE, "round %d handle %p: DestroyWindow error %lu\n", Round, Invalid[i], Error);

            ZeroMemory(&Info, sizeof(Info));
            Info.cbSize = sizeof(Info);
            SetLastError(0xdeadbeef);
            Result = GetTitleBarInfo(Invalid[i], &Info);
            Error = GetLastError();
            ok(Result == FALSE, "round %d handle %p: GetTitleBarInfo returned %d\n", Round, Invalid[i], Result);
            ok(Error == ERROR_INVALID_WINDOW_HANDLE, "round %d handle %p: GetTitleBarInfo error %lu\n", Round, Invalid[i], Error);
        }
    }
}

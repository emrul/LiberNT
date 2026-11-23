/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test that DeleteProfile removes a profile found from its SID
 * COPYRIGHT:   Copyright 2026 Emrul Islam <emrul@emrul.com>
 */

#include <apitest.h>
#include <winreg.h>
#include <sddl.h>
#include <userenv.h>
#include <lm.h>
#include <strsafe.h>

#define TEST_USER L"LntDelProfile"
#define TEST_PASSWORD L"Lnt!DelProf#2026q"

START_TEST(DeleteProfile)
{
    union
    {
        TOKEN_USER User;
        BYTE Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    } Identity;
    USER_INFO_1 User = {0};
    PROFILEINFOW Profile = {0};
    WCHAR Directory[MAX_PATH], KeyPath[MAX_PATH];
    LPWSTR SidString = NULL;
    HANDLE hToken = NULL;
    NET_API_STATUS Status;
    HKEY hKey;
    DWORD Length;
    BOOL Ret;

    SetLastError(0xdeadbeef);
    ok(!DeleteProfileW(NULL, NULL, NULL), "DeleteProfileW(NULL) succeeded\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "DeleteProfileW(NULL) error %lu\n", GetLastError());

    NetUserDel(NULL, TEST_USER);
    User.usri1_name = TEST_USER;
    User.usri1_password = TEST_PASSWORD;
    User.usri1_priv = USER_PRIV_USER;
    User.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    Status = NetUserAdd(NULL, 1, (LPBYTE)&User, NULL);
    if (Status != NERR_Success)
    {
        skip("Making the test user needs administrator rights: %lu\n", Status);
        return;
    }

    if (!LogonUserW(TEST_USER, L".", TEST_PASSWORD, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken))
    {
        ok(0, "LogonUserW failed %lu\n", GetLastError());
        goto Cleanup;
    }

    Profile.dwSize = sizeof(Profile);
    Profile.lpUserName = TEST_USER;
    Profile.dwFlags = PI_NOUI;
    ok(LoadUserProfileW(hToken, &Profile), "LoadUserProfileW failed %lu\n", GetLastError());
    if (Profile.hProfile == NULL)
        goto Cleanup;

    Length = ARRAYSIZE(Directory);
    ok(GetUserProfileDirectoryW(hToken, Directory, &Length), "GetUserProfileDirectoryW failed %lu\n", GetLastError());
    ok(UnloadUserProfile(hToken, Profile.hProfile), "UnloadUserProfile failed %lu\n", GetLastError());

    ok(GetTokenInformation(hToken, TokenUser, &Identity, sizeof(Identity), &Length),
       "GetTokenInformation failed %lu\n", GetLastError());
    ok(ConvertSidToStringSidW(Identity.User.User.Sid, &SidString), "ConvertSidToStringSidW failed %lu\n", GetLastError());
    if (SidString == NULL)
        goto Cleanup;

    StringCchPrintfW(KeyPath, ARRAYSIZE(KeyPath),
                     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%s", SidString);
    ok(GetFileAttributesW(Directory) != INVALID_FILE_ATTRIBUTES, "%ls does not exist before the delete\n", Directory);
    ok(RegOpenKeyExW(HKEY_LOCAL_MACHINE, KeyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS,
       "the profile list entry is missing before the delete\n");
    RegCloseKey(hKey);

    SetLastError(0xdeadbeef);
    Ret = DeleteProfileW(SidString, NULL, NULL);
    ok(Ret, "DeleteProfileW failed %lu\n", GetLastError());

    SetLastError(0xdeadbeef);
    ok(GetFileAttributesW(Directory) == INVALID_FILE_ATTRIBUTES, "%ls is still there\n", Directory);
    ok(GetLastError() == ERROR_FILE_NOT_FOUND, "GetFileAttributesW error %lu\n", GetLastError());
    ok(RegOpenKeyExW(HKEY_LOCAL_MACHINE, KeyPath, 0, KEY_READ, &hKey) == ERROR_FILE_NOT_FOUND,
       "the profile list entry is still there\n");

    SetLastError(0xdeadbeef);
    ok(!DeleteProfileW(SidString, NULL, NULL), "a second DeleteProfileW succeeded\n");
    ok(GetLastError() == ERROR_FILE_NOT_FOUND, "a second DeleteProfileW error %lu\n", GetLastError());

Cleanup:
    if (SidString)
        LocalFree(SidString);
    if (hToken)
        CloseHandle(hToken);
    NetUserDel(NULL, TEST_USER);
}

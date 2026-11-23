/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test the default security descriptor of a named pipe created without one
 * COPYRIGHT:   Copyright 2026 Emrul Islam <emrul@emrul.com>
 */

#include "precomp.h"
#include <aclapi.h>
#include <sddl.h>

static ACCESS_MASK
FindAllowed(PACL Dacl, WELL_KNOWN_SID_TYPE Type, PSID Explicit, PULONG Count)
{
    BYTE Buffer[SECURITY_MAX_SID_SIZE];
    PSID Sid = Explicit;
    DWORD Size = sizeof(Buffer);
    ACCESS_MASK Mask = 0;
    ACCESS_ALLOWED_ACE *Ace;
    WORD i;

    *Count = 0;
    if (!Sid)
    {
        if (!CreateWellKnownSid(Type, NULL, Buffer, &Size))
            return 0;
        Sid = Buffer;
    }
    for (i = 0; i < Dacl->AceCount; ++i)
    {
        if (!GetAce(Dacl, i, (LPVOID *)&Ace))
            continue;
        if (Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && EqualSid(&Ace->SidStart, Sid))
        {
            Mask |= Ace->Mask;
            ++*Count;
        }
    }
    return Mask;
}

START_TEST(NamedPipeDefaultSecurity)
{
    WCHAR Name[64];
    HANDLE Pipe, Token;
    PSECURITY_DESCRIPTOR Descriptor = NULL;
    PACL Dacl = NULL;
    PSID Owner = NULL;
    BYTE UserBuffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    PTOKEN_USER User = (PTOKEN_USER)UserBuffer;
    DWORD Size, Error;
    ULONG Count;
    ACCESS_MASK Mask;
    LPWSTR Sddl = NULL;
    BOOL OwnerIsAdministrators;

    wsprintfW(Name, L"\\\\.\\pipe\\LiberNTDefaultSecurity%lu", GetCurrentProcessId());
    Pipe = CreateNamedPipeW(Name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 1, 512, 512, 0, NULL);
    ok(Pipe != INVALID_HANDLE_VALUE, "CreateNamedPipeW failed with %lu\n", GetLastError());
    if (Pipe == INVALID_HANDLE_VALUE)
        return;

    Error = GetSecurityInfo(Pipe, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                            &Owner, NULL, &Dacl, NULL, &Descriptor);
    ok(Error == ERROR_SUCCESS && Dacl != NULL, "GetSecurityInfo failed with %lu\n", Error);
    if (Error != ERROR_SUCCESS || !Dacl)
        goto Cleanup;

    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(Descriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &Sddl, NULL))
    {
        trace("default pipe DACL %ls\n", Sddl);
        LocalFree(Sddl);
    }

    Mask = FindAllowed(Dacl, WinLocalSystemSid, NULL, &Count);
    ok(Count == 1 && Mask == FILE_ALL_ACCESS, "LocalSystem: %lu ACEs mask %lx\n", Count, Mask);
    OwnerIsAdministrators = IsWellKnownSid(Owner, WinBuiltinAdministratorsSid);
    Mask = FindAllowed(Dacl, WinBuiltinAdministratorsSid, NULL, &Count);
    ok(Count == (OwnerIsAdministrators ? 2u : 1u) && Mask == FILE_ALL_ACCESS, "Administrators: %lu ACEs mask %lx\n", Count, Mask);
    Mask = FindAllowed(Dacl, WinWorldSid, NULL, &Count);
    ok(Count == 1 && Mask == FILE_GENERIC_READ, "Everyone: %lu ACEs mask %lx\n", Count, Mask);
    Mask = FindAllowed(Dacl, WinAnonymousSid, NULL, &Count);
    ok(Count == 1 && Mask == FILE_GENERIC_READ, "Anonymous: %lu ACEs mask %lx\n", Count, Mask);

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
    {
        if (GetTokenInformation(Token, TokenUser, User, sizeof(UserBuffer), &Size))
        {
            Mask = FindAllowed(Dacl, 0, Owner, &Count);
            ok(Count == (OwnerIsAdministrators ? 2u : 1u) && Mask == FILE_ALL_ACCESS, "owner: %lu ACEs mask %lx\n", Count, Mask);
        }
        CloseHandle(Token);
    }
    ok(Dacl->AceCount == 5, "DACL has %u ACEs\n", Dacl->AceCount);

Cleanup:
    if (Descriptor)
        LocalFree(Descriptor);
    CloseHandle(Pipe);
}

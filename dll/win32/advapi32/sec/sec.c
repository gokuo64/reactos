/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            lib/advapi32/sec/sec.c
 * PURPOSE:         Security descriptor functions
 * PROGRAMMER:      Ariadne ( ariadne@xs4all.nl)
 *                  Steven Edwards ( Steven_Ed4153@yahoo.com )
 *                  Andrew Greenwood ( silverblade_uk@hotmail.com )
 * UPDATE HISTORY:
 *                  Created 01/11/98
 */

#include <advapi32.h>
WINE_DEFAULT_DEBUG_CHANNEL(advapi);

/*
 * @implemented
 */
BOOL
WINAPI
GetSecurityDescriptorControl(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                             PSECURITY_DESCRIPTOR_CONTROL pControl,
                             LPDWORD lpdwRevision)
{
    NTSTATUS Status;

    Status = RtlGetControlSecurityDescriptor(pSecurityDescriptor,
                                             pControl,
                                             (PULONG)lpdwRevision);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL
WINAPI
GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                          LPBOOL lpbDaclPresent,
                          PACL *pDacl,
                          LPBOOL lpbDaclDefaulted)
{
    BOOLEAN DaclPresent;
    BOOLEAN DaclDefaulted;
    NTSTATUS Status;

    Status = RtlGetDaclSecurityDescriptor(pSecurityDescriptor,
                                          &DaclPresent,
                                          pDacl,
                                          &DaclDefaulted);
    *lpbDaclPresent = (BOOL)DaclPresent;
    *lpbDaclDefaulted = (BOOL)DaclDefaulted;

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL
WINAPI
GetSecurityDescriptorGroup(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                           PSID *pGroup,
                           LPBOOL lpbGroupDefaulted)
{
    BOOLEAN GroupDefaulted;
    NTSTATUS Status;

    Status = RtlGetGroupSecurityDescriptor(pSecurityDescriptor,
                                           pGroup,
                                           &GroupDefaulted);
    *lpbGroupDefaulted = (BOOL)GroupDefaulted;

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL
WINAPI
GetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                           PSID *pOwner,
                           LPBOOL lpbOwnerDefaulted)
{
    BOOLEAN OwnerDefaulted;
    NTSTATUS Status;

    Status = RtlGetOwnerSecurityDescriptor(pSecurityDescriptor,
                                           pOwner,
                                           &OwnerDefaulted);
    *lpbOwnerDefaulted = (BOOL)OwnerDefaulted;

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
DWORD
WINAPI
GetSecurityDescriptorRMControl(PSECURITY_DESCRIPTOR SecurityDescriptor,
                               PUCHAR RMControl)
{
    if (!RtlGetSecurityDescriptorRMControl(SecurityDescriptor,
                                           RMControl))
        return ERROR_INVALID_DATA;

    return ERROR_SUCCESS;
}


/*
 * @implemented
 */
BOOL
WINAPI
GetSecurityDescriptorSacl(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                          LPBOOL lpbSaclPresent,
                          PACL *pSacl,
                          LPBOOL lpbSaclDefaulted)
{
    BOOLEAN SaclPresent;
    BOOLEAN SaclDefaulted;
    NTSTATUS Status;

    Status = RtlGetSaclSecurityDescriptor(pSecurityDescriptor,
                                          &SaclPresent,
                                          pSacl,
                                          &SaclDefaulted);
    *lpbSaclPresent = (BOOL)SaclPresent;
    *lpbSaclDefaulted = (BOOL)SaclDefaulted;

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
IsValidSecurityDescriptor(PSECURITY_DESCRIPTOR pSecurityDescriptor)
{
    BOOLEAN Result;

    Result = RtlValidSecurityDescriptor (pSecurityDescriptor);
    if (Result == FALSE)
        SetLastError(RtlNtStatusToDosError(STATUS_INVALID_SECURITY_DESCR));

    return (BOOL)Result;
}

/*
 * @implemented
 */
BOOL
WINAPI
MakeAbsoluteSD2(IN OUT PSECURITY_DESCRIPTOR pSelfRelativeSecurityDescriptor,
                OUT LPDWORD lpdwBufferSize)
{
    NTSTATUS Status;

    Status = RtlSelfRelativeToAbsoluteSD2(pSelfRelativeSecurityDescriptor,
                                          lpdwBufferSize);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL
WINAPI
MakeSelfRelativeSD(PSECURITY_DESCRIPTOR pAbsoluteSecurityDescriptor,
                   PSECURITY_DESCRIPTOR pSelfRelativeSecurityDescriptor,
                   LPDWORD lpdwBufferLength)
{
    NTSTATUS Status;

    Status = RtlAbsoluteToSelfRelativeSD(pAbsoluteSecurityDescriptor,
                                         pSelfRelativeSecurityDescriptor,
                                         (PULONG)lpdwBufferLength);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL
WINAPI
SetSecurityDescriptorControl(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                             SECURITY_DESCRIPTOR_CONTROL ControlBitsOfInterest,
                             SECURITY_DESCRIPTOR_CONTROL ControlBitsToSet)
{
    NTSTATUS Status;

    Status = RtlSetControlSecurityDescriptor(pSecurityDescriptor,
                                             ControlBitsOfInterest,
                                             ControlBitsToSet);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL
WINAPI
SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                          BOOL bDaclPresent,
                          PACL pDacl,
                          BOOL bDaclDefaulted)
{
    NTSTATUS Status;

    Status = RtlSetDaclSecurityDescriptor(pSecurityDescriptor,
                                          bDaclPresent,
                                          pDacl,
                                          bDaclDefaulted);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL
WINAPI
SetSecurityDescriptorGroup(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                           PSID pGroup,
                           BOOL bGroupDefaulted)
{
    NTSTATUS Status;

    Status = RtlSetGroupSecurityDescriptor(pSecurityDescriptor,
                                           pGroup,
                                           bGroupDefaulted);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL
WINAPI
SetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                           PSID pOwner,
                           BOOL bOwnerDefaulted)
{
    NTSTATUS Status;

    Status = RtlSetOwnerSecurityDescriptor(pSecurityDescriptor,
                                           pOwner,
                                           bOwnerDefaulted);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
DWORD
WINAPI
SetSecurityDescriptorRMControl(PSECURITY_DESCRIPTOR SecurityDescriptor,
                               PUCHAR RMControl)
{
    RtlSetSecurityDescriptorRMControl(SecurityDescriptor,
                                      RMControl);

    return ERROR_SUCCESS;
}


/*
 * @implemented
 */
BOOL
WINAPI
SetSecurityDescriptorSacl(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                          BOOL bSaclPresent,
                          PACL pSacl,
                          BOOL bSaclDefaulted)
{
    NTSTATUS Status;

    Status = RtlSetSaclSecurityDescriptor(pSecurityDescriptor,
                                          bSaclPresent,
                                          pSacl,
                                          bSaclDefaulted);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
VOID
WINAPI
QuerySecurityAccessMask(IN SECURITY_INFORMATION SecurityInformation,
                        OUT LPDWORD DesiredAccess)
{
    *DesiredAccess = 0;

    if (SecurityInformation & (OWNER_SECURITY_INFORMATION |
                               GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION))
    {
        *DesiredAccess |= READ_CONTROL;
    }

    if (SecurityInformation & SACL_SECURITY_INFORMATION)
        *DesiredAccess |= ACCESS_SYSTEM_SECURITY;
}


/*
 * @implemented
 */
VOID
WINAPI
SetSecurityAccessMask(IN SECURITY_INFORMATION SecurityInformation,
                      OUT LPDWORD DesiredAccess)
{
    *DesiredAccess = 0;

    if (SecurityInformation & (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION))
        *DesiredAccess |= WRITE_OWNER;

    if (SecurityInformation & DACL_SECURITY_INFORMATION)
        *DesiredAccess |= WRITE_DAC;

    if (SecurityInformation & SACL_SECURITY_INFORMATION)
        *DesiredAccess |= ACCESS_SYSTEM_SECURITY;
}


/*
 * @unimplemented
 */
BOOL
WINAPI
ConvertToAutoInheritPrivateObjectSecurity(IN PSECURITY_DESCRIPTOR ParentDescriptor,
                                          IN PSECURITY_DESCRIPTOR CurrentSecurityDescriptor,
                                          OUT PSECURITY_DESCRIPTOR* NewSecurityDescriptor,
                                          IN GUID* ObjectType,
                                          IN BOOLEAN IsDirectoryObject,
                                          IN PGENERIC_MAPPING GenericMapping)
{
    UNIMPLEMENTED;
    return FALSE;
}


static DWORD
InternalTrusteeToSidW(IN PTRUSTEE_W pTrustee OPTIONAL,
                      OUT PSID *ppSid,
                      OUT PBOOL pbAllocated)
{
    DWORD cbSid = 0, cchDomain = 0;
    SID_NAME_USE peUse;
    LPWSTR lpDomain = NULL;
    PSID pSid = NULL;
    HANDLE hToken = NULL;

    *ppSid = NULL;
    *pbAllocated = FALSE;

    if (!pTrustee)
        return ERROR_SUCCESS;

    if (pTrustee->TrusteeForm == TRUSTEE_IS_SID)
    {
        *ppSid = (PSID)pTrustee->ptstrName;
        return ERROR_SUCCESS;
    }

    if ((pTrustee->TrusteeForm == TRUSTEE_IS_NAME) && pTrustee->ptstrName)
    {
        /* Check for special CURRENT_USER trustee */
        if (_wcsicmp(pTrustee->ptstrName, L"CURRENT_USER") == 0)
        {
            if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken))
            {
                if (GetLastError() == ERROR_NO_TOKEN)
                    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
            }

            if (hToken)
            {
                UCHAR Buffer[sizeof(TOKEN_USER) + sizeof(SID) +
                             sizeof(ULONG) * SID_MAX_SUB_AUTHORITIES];
                DWORD cbLength = sizeof(Buffer);

                if (GetTokenInformation(hToken, TokenUser, Buffer, cbLength, &cbLength))
                {
                    PTOKEN_USER pUser = (PTOKEN_USER)Buffer;
                    DWORD dwLen = GetLengthSid(pUser->User.Sid);

                    pSid = LocalAlloc(LMEM_FIXED, dwLen);
                    if (pSid && CopySid(dwLen, pSid, pUser->User.Sid))
                    {
                        *ppSid = pSid;
                        *pbAllocated = TRUE;
                        CloseHandle(hToken);
                        return ERROR_SUCCESS;
                    }
                    if (pSid) LocalFree(pSid);
                }
                CloseHandle(hToken);
            }
        }

        LookupAccountNameW(NULL, pTrustee->ptstrName, NULL, &cbSid, NULL, &cchDomain, &peUse);
        if (cbSid == 0)
            return GetLastError();

        pSid = LocalAlloc(LMEM_FIXED, cbSid);
        if (!pSid)
            return ERROR_NOT_ENOUGH_MEMORY;

        lpDomain = HeapAlloc(GetProcessHeap(), 0, cchDomain * sizeof(WCHAR));
        if (!lpDomain)
        {
            LocalFree(pSid);
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        if (LookupAccountNameW(NULL, pTrustee->ptstrName, pSid, &cbSid,
                               lpDomain, &cchDomain, &peUse))
        {
            *ppSid = pSid;
            *pbAllocated = TRUE;
            HeapFree(GetProcessHeap(), 0, lpDomain);
            return ERROR_SUCCESS;
        }

        LocalFree(pSid);
        HeapFree(GetProcessHeap(), 0, lpDomain);
        return GetLastError();
    }

    return ERROR_INVALID_PARAMETER;
}

/*
 * @implemented
 */
DWORD
WINAPI
BuildSecurityDescriptorW(IN PTRUSTEE_W pOwner  OPTIONAL,
                         IN PTRUSTEE_W pGroup  OPTIONAL,
                         IN ULONG cCountOfAccessEntries,
                         IN PEXPLICIT_ACCESS_W pListOfAccessEntries  OPTIONAL,
                         IN ULONG cCountOfAuditEntries,
                         IN PEXPLICIT_ACCESS_W pListOfAuditEntries  OPTIONAL,
                         IN PSECURITY_DESCRIPTOR pOldSD  OPTIONAL,
                         OUT PULONG pSizeNewSD,
                         OUT PSECURITY_DESCRIPTOR* pNewSD)
{
    DWORD dwError = ERROR_SUCCESS;
    PACL pOldDacl = NULL, pOldSacl = NULL;
    PSID pOldOwner = NULL, pOldGroup = NULL;
    PACL pNewDacl = NULL, pNewSacl = NULL;
    PSID pNewOwner = NULL, pNewGroup = NULL;
    BOOL bDaclPresent = FALSE, bDaclDefaulted = FALSE;
    BOOL bSaclPresent = FALSE, bSaclDefaulted = FALSE;
    BOOL bOwnerDefaulted = FALSE, bGroupDefaulted = FALSE;
    BOOL bAllocOwner = FALSE, bAllocGroup = FALSE;
    SECURITY_DESCRIPTOR AbsSD;
    DWORD dwBufferSize = 0;
    PSECURITY_DESCRIPTOR pRelSD = NULL;

    if (!pNewSD || !pSizeNewSD)
        return ERROR_INVALID_PARAMETER;

    *pNewSD = NULL;
    *pSizeNewSD = 0;

    /* Extract components from old security descriptor if provided */
    if (pOldSD)
    {
        if (!IsValidSecurityDescriptor(pOldSD))
            return ERROR_INVALID_SECURITY_DESCR;

        GetSecurityDescriptorDacl(pOldSD, &bDaclPresent, &pOldDacl, &bDaclDefaulted);
        GetSecurityDescriptorSacl(pOldSD, &bSaclPresent, &pOldSacl, &bSaclDefaulted);
        GetSecurityDescriptorOwner(pOldSD, &pOldOwner, &bOwnerDefaulted);
        GetSecurityDescriptorGroup(pOldSD, &pOldGroup, &bGroupDefaulted);
    }

    /* Build the new DACL */
    if (cCountOfAccessEntries > 0 && pListOfAccessEntries)
    {
        dwError = SetEntriesInAclW(cCountOfAccessEntries,
                                   pListOfAccessEntries,
                                   (bDaclPresent ? pOldDacl : NULL),
                                   &pNewDacl);
        if (dwError != ERROR_SUCCESS)
            goto Cleanup;
    }
    else if (bDaclPresent)
    {
        pNewDacl = pOldDacl;
    }

    /* Build the new SACL */
    if (cCountOfAuditEntries > 0 && pListOfAuditEntries)
    {
        dwError = SetEntriesInAclW(cCountOfAuditEntries,
                                   pListOfAuditEntries,
                                   (bSaclPresent ? pOldSacl : NULL),
                                   &pNewSacl);
        if (dwError != ERROR_SUCCESS)
            goto Cleanup;
    }
    else if (bSaclPresent)
    {
        pNewSacl = pOldSacl;
    }

    /* Resolve owner SID */
    if (pOwner)
    {
        dwError = InternalTrusteeToSidW(pOwner, &pNewOwner, &bAllocOwner);
        if (dwError != ERROR_SUCCESS)
            goto Cleanup;
    }
    else
    {
        pNewOwner = pOldOwner;
    }

    /* Resolve group SID */
    if (pGroup)
    {
        dwError = InternalTrusteeToSidW(pGroup, &pNewGroup, &bAllocGroup);
        if (dwError != ERROR_SUCCESS)
            goto Cleanup;
    }
    else
    {
        pNewGroup = pOldGroup;
    }

    /* Initialize absolute security descriptor */
    if (!InitializeSecurityDescriptor(&AbsSD, SECURITY_DESCRIPTOR_REVISION))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    if (pNewOwner)
        SetSecurityDescriptorOwner(&AbsSD, pNewOwner, FALSE);

    if (pNewGroup)
        SetSecurityDescriptorGroup(&AbsSD, pNewGroup, FALSE);

    if (pNewDacl || bDaclPresent || (cCountOfAccessEntries > 0))
        SetSecurityDescriptorDacl(&AbsSD, TRUE, pNewDacl, FALSE);

    if (pNewSacl || bSaclPresent || (cCountOfAuditEntries > 0))
        SetSecurityDescriptorSacl(&AbsSD, TRUE, pNewSacl, FALSE);

    /* Determine size needed for self-relative security descriptor */
    MakeSelfRelativeSD(&AbsSD, NULL, &dwBufferSize);
    if (dwBufferSize == 0)
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    pRelSD = LocalAlloc(LPTR, dwBufferSize);
    if (!pRelSD)
    {
        dwError = ERROR_NOT_ENOUGH_MEMORY;
        goto Cleanup;
    }

    if (!MakeSelfRelativeSD(&AbsSD, pRelSD, &dwBufferSize))
    {
        dwError = GetLastError();
        LocalFree(pRelSD);
        pRelSD = NULL;
        goto Cleanup;
    }

    *pNewSD = pRelSD;
    *pSizeNewSD = dwBufferSize;
    dwError = ERROR_SUCCESS;

Cleanup:
    if (pNewDacl && (pNewDacl != pOldDacl))
        LocalFree(pNewDacl);

    if (pNewSacl && (pNewSacl != pOldSacl))
        LocalFree(pNewSacl);

    if (bAllocOwner && pNewOwner)
        LocalFree(pNewOwner);

    if (bAllocGroup && pNewGroup)
        LocalFree(pNewGroup);

    return dwError;
}

/*
 * @unimplemented
 */
DWORD
WINAPI
BuildSecurityDescriptorA(IN PTRUSTEE_A pOwner  OPTIONAL,
                         IN PTRUSTEE_A pGroup  OPTIONAL,
                         IN ULONG cCountOfAccessEntries,
                         IN PEXPLICIT_ACCESS_A pListOfAccessEntries  OPTIONAL,
                         IN ULONG cCountOfAuditEntries,
                         IN PEXPLICIT_ACCESS_A pListOfAuditEntries  OPTIONAL,
                         IN PSECURITY_DESCRIPTOR pOldSD  OPTIONAL,
                         OUT PULONG pSizeNewSD,
                         OUT PSECURITY_DESCRIPTOR* pNewSD)
{
    UNIMPLEMENTED;
    return ERROR_CALL_NOT_IMPLEMENTED;
}

/* EOF */

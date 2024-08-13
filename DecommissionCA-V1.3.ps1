<#PSScriptInfo
 
.VERSION 1.3
 
.GUID 4ffb77b7-00d7-4f55-88a4-4926feea41e8
 
.AUTHOR scaron@pcevolution.com
 
.COMPANYNAME PC-Évolution enr.
 
.COPYRIGHT Copyright (c) 2019-2024 PC-Évolution enr. This code is licensed under the GNU General Public License (GPL).
 
.TAGS decommission CA SBS 2008 SBS 2011 Windows Server 2012 R2 Essentials Windows Server 2016 R2 Essentials
 
#.LICENSEURI = 'https://www.gnu.org/licenses/gpl-3.0.en.html'
 
#.PROJECTURI = 'https://github.com/SergeCaron/Decommission-CA'
 
#.ICONURI
 
.EXTERNALMODULEDEPENDENCIES PSPKI,Windows Management Framework 5.1
 
.REQUIREDSCRIPTS
 
.EXTERNALSCRIPTDEPENDENCIES
 
.RELEASENOTES
This script is an aid in decommissioning a Certification Authority (CA).
It allows to save the CA Root Certificate and Key to a location of your choice, including a full backup of the CA databse. All active certificates are revoked and a Certificate Revocation List (CRL) is published with an expiration date later than the expiration date of any certificate published by this CA.
Dependencies: you must install PSPKI (also available on the PowerShell Gallery).
Caution: In theory, this script can be executed against a remote CA. This has not been tested and saving the CA Root Certificate is restricted to the local machine.
 
#>

<#
 
.DESCRIPTION
 Aid in decommissionning a Certification Authority
 
#> 
Param()


##******************************************************************
## Revision date: 2024.08.12
##
## Copyright (c) 2019-2024 PC-�volution enr.
## This code is licensed under the GNU General Public License (GPL).
##
## THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
## ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
## IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
## PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
##
##******************************************************************

## Do we have a toolset?
Try {
    Write-Host "Please wait..."
    Import-Module pspki -ErrorAction Stop
}
Catch {
    Write-Host ""
    Write-Host "Error: Please install the PowerShell PKI Module from PKI Solutions inc."
    Write-Host "       (https://www.pkisolutions.com/tools/pspki/)"
    Write-Host "       You may also have to install Windows Management Framework 5.1."
    Write-Host ""
    Exit 911
}

## Enumerate all Certification Authorities and display their status
Try {
    [System.Object[]] $CAs = Get-CertificationAuthority -ErrorAction Stop
    $CAs | Get-EnterprisePKIHealthStatus | Format-Table *
}
Catch {
    Write-Host "There are no Certification Authority active on this network."
    Exit 911
}

## Get the retiring Certification Authority
If ($CAs.Count -eq 1) {
    $RetiringCA = $CAs[0]
}
Else {
    Do { $Candidate = Read-Host "Please enter 0-based index of retiring Certification Authority" }
    While ($Candidate -lt 0 -or $Candidate -ge $CAs.Count)
    $RetiringCA = $CAs[$Candidate]
}

## Get access to the Root Certificate on the Certification Authority server
$LocalMachine = ([System.Net.Dns]::GetHostByName(($env:computerName))).HostName
If ($RetiringCA.ComputerName -eq $LocalMachine) {
    $CertToExport = Get-ChildItem -Path cert:\LocalMachine\My | Where-Object { $_.SerialNumber -eq $RetiringCA.Certificate.SerialNumber }
    If ($CertToExport.Count -eq 1) {
        ## Get destination folder
        [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
        $FolderName = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderName.Description = "Select folder to export Root Certification Authority Certificate and Key "
        $FolderName.rootfolder = "MyComputer"

        ## Warn the user if we are not saving the root certificate and key
        if ($FolderName.ShowDialog() -eq "OK") {

            ## Create the full path for this certificate
            $CertOutputFileName = $CertToExport.DnsNameList[0].Unicode
            $CertFullPath = Join-Path -Path $FolderName.SelectedPath -ChildPath "Export-$CertOutputFileName.pfx"

            ## Get a confirmed password (or die!)
            DO {
                $SecurePassword = Read-Host -Prompt "Enter password for $CertFullPath" -AsSecureString
                $ConfirmationPassword = Read-Host -Prompt "Confirm password" -AsSecureString
            } While ( [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)) `
                    -cne [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmationPassword)) )

            # Export PFX certificate along with private key
            Export-PfxCertificate -Cert $CertToExport -FilePath $CertFullPath -Password $SecurePassword -Verbose
			
            Backup-CARoleService -Path $FolderName.SelectedPath -Force -Password $SecurePassword
            Write-Warning "A backup of the CA was also stored in the destination folder using the same password."

        }
        Else {
            Write-Host "Caution: You have elected not to save the Root Certificate and Key."
            Write-Host "         Proceed at your own risk."
        }
    }
    Else {
        Write-Host "Caution: Unable to export $RetiringCA Root Certificate and Key"
        Write-Host "         Proceed at your own risk."
    }
}
Else {
    Write-Host "Caution: $RetiringCA is a remote system. Proceed at your risk."
}

## Get explicit confirmation from the user
Write-Host
Write-Host "Caution: This script irreversibly revokes everything issued by this Certification Authority."
Write-Host "         This includes Disaster Recovery Agents and other critical roles."
Write-Host "         Upon successfull execution, local operations are still enabled on the CA: if need be,"
Write-Host "         you can rerun this script locally."
Write-Host
If ( (Read-Host "Please confirm retirement of" $RetiringCA.DisplayName "[Enter IDO, anything else exits]") -ne "IDO")
{ Exit 911 }

## Set a timestamp for this run
$RevocationDate = Get-Date

## Freeze the retiring CA operations
$RetiringCA | Get-InterfaceFlag | Enable-InterfaceFlag -Flag "NoRemoteICertRequest", "NoLocalICertRequest", "NoRPCICertRequest" -RestartCA
Start-Sleep -s 15

## Deny pending request
[System.Object[]] $PendingCertificates = $RetiringCA | Get-PendingRequest
If ($PendingCertificates.Count -ge 1) {
    $PendingCertificates | Deny-CertificateRequest
    Write-Host "Notice: some pending certificate requests denied."
}

## Get oldest expiration date of revoked certificates
[System.Object[]] $RevokedCertificates = $RetiringCA | Get-RevokedRequest -Property NotAfter
If ($RevokedCertificates.Count -ge 1) {
    $TargetExpirationDate = ($RevokedCertificates | Measure-Object -Property NotAfter -Maximum).Maximum
}
Else {
    $TargetExpirationDate = $RevocationDate
}

## Revoke all outstanding certificates
[System.Object[]] $ActiveCertificates = $RetiringCA | Get-IssuedRequest
If ($ActiveCertificates.Count -ge 1) {
    $ExpirationDate = ($ActiveCertificates | Measure-Object -Property NotAfter -Maximum).Maximum
    If ($ExpirationDate -lt $RevocationDate) {
        Write-Host "Notice: All outstanding certificates are already expired."
        $ExpirationDate = $RevocationDate
    }
    $ActiveCertificates | Revoke-Certificate -Reason "CeaseOfOperation" -RevocationDate $RevocationDate
}
else {
    Write-Host "Notice: There are no outstanding certificates."
    $ExpirationDate = $RevocationDate
}

## Compute a lifetime for the next Certificate Revocation List
If ($TargetExpirationDate -gt $ExpirationDate) {
    $Duration = ($TargetExpirationDate - $RevocationDate).Days + 1
}
Else {
    $Duration = ($ExpirationDate - $RevocationDate).Days + 1
}

## Update the Certification Authority
Set-CRLValidityPeriod -InputObject (Get-CRLValidityPeriod -CertificationAuthority $RetiringCA) -BaseCRL "$Duration days" -BaseCRLOverlap "2 days" -RestartCA
Start-Sleep -s 15

## Publish a new authoritative CRL
$RetiringCA | Publish-CRL

## Thaw local operations the retiring CA 
$RetiringCA | Get-InterfaceFlag | Disable-InterfaceFlag -Flag "NoLocalICertRequest" -RestartCA
Start-Sleep -s 15

Write-Host
Write-Host "It's done. Check the CRL Distribution Points (CDPs). Local operations are still allowed on the retiring CA."
Write-Host


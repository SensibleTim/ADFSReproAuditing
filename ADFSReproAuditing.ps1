PARAM ($KeepAuditing = $false)
#************************************************
# ADFSReproAuditing.ps1
# Version 1.0
# Date: 6-1-2016
# Author: Tim Springston
# Description: This script will enable ADFS auditing and tracing on an ADFS server and start a network
#  capture. Once enabled a problem with ADFS authentication can be reproduced and then the 
#  tracing can be stopped.
#************************************************
cls
$cs = get-wmiobject -class win32_computersystem
$DomainRole = $cs.domainrole
$OSVersion = gwmi win32_operatingsystem
$DateRaw = Get-Date
$Date = ($DateRaw.Month.ToString()) + '-' + ($DateRaw.Day.ToString()) + "-" + ($DateRaw.Year.ToString())
$AuthReproDataPath = $env:SystemRoot + '\temp\AuthRepro' + $Date
If (!(Test-Path $AuthReproDataPath)) {md  $AuthReproDataPath}

$ReproDoc = $AuthReproDataPath + "\ProblemReproDetails.txt"
"Problem Repro Details" | Out-File -FilePath  $ReproDoc -Encoding UTF8
"**********************" | Out-File -FilePath  $ReproDoc -Encoding UTF8 -Append
"Computer Name: " + $CS.DNSHostName  | Out-File -FilePath  $ReproDoc -Encoding UTF8 -Append
"Computer Domain: " + $CS.Domain  | Out-File -FilePath  $ReproDoc -Encoding UTF8 -Append
"Computer OS: " + ($OSVersion.Name).Split("|")[0] | Out-File -FilePath  $ReproDoc -Encoding UTF8 -Append
"Repro Start Time: $DateRaw"  | Out-File -FilePath  $ReproDoc -Encoding UTF8 -Append


#Check and add service account to auditing user right if needed
$ADFSService = GWMI Win32_Service -Filter "name = 'adfssrv'"
$ADFSServiceAccount = $ADFSService.StartName
$objUser = New-Object System.Security.Principal.NTAccount($ADFSServiceAccount) 
$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]) 
$SvcAcctSID = $strSID.Value 
$SecPolPath = $AuthReproDataPath + "\secpol.cfg"
secedit /export /cfg $SecPolPath
$OldSeSecPriv = Select-string -path $SecPolPath -pattern "SeSecurityPrivilege"
$OldSeSecPriv = $OldSeSecPriv.Line
$NewSeSecPriv = $OldSeSecPriv  + ",*" + $SvcAcctSID
(gc $SecPolPath).replace($OldSeSecPriv,$NewSeSecPriv) | Out-File $SecPolPath 
secedit /configure /db c:\windows\security\local.sdb /cfg $SecPolPath /areas SECURITYPOLICY
rm -force $SecPolPath -confirm:$false -ErrorAction SilentlyContinue
gpupdate /force

#Enable ADFS Tracing log
$ADFSTraceLogName = "AD FS Tracing/Debug"
$ADFSTraceLog = New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration $ADFSTraceLogName
$ADFSTraceLog.IsEnabled = $true
$ADFSTraceLog.SaveChanges()

#Enable security auditing from ADFS
switch ($OSVersion.Buildnumber)
				{
				'6000'{Add-PsSnapin Microsoft.Adfs.Powershell -ErrorAction SilentlyContinue}
				'6001'{Add-PsSnapin Microsoft.Adfs.Powershell -ErrorAction SilentlyContinue}
				'6002'{Add-PsSnapin Microsoft.Adfs.Powershell -ErrorAction SilentlyContinue}
				'7600'{Add-PsSnapin Microsoft.Adfs.Powershell -ErrorAction SilentlyContinue}
				'7601'{Add-PsSnapin Microsoft.Adfs.Powershell -ErrorAction SilentlyContinue}
				'9200'{Import-Module ADFS -ErrorAction SilentlyContinue}
				'9600'{Import-Module ADFS -ErrorAction SilentlyContinue}	
				}
Set-ADFSProperties -LogLevel  @("Warnings", "FailureAudits","Information","SuccessAudits")
auditpol.exe /set /subcategory:"Application Generated" /failure:enable /success:enable

#Start Tracing
$NetCapFile = $AuthReproDataPath + '\netcap.etl'
$StartNetCap = "netsh trace start traceFile=" + $NetCapFile  + " capture=yes"
if ($OSVersion.Buildnumber -ge 7600)
	{ cmd /c $StartNetCap }

Write-Host "Tracing has started. Please reproduce the problem now." -ForegroundColor Yellow
Read-Host -Prompt "Press any key to stop tracing once the problem has been reproduced"

#Stop Tracing
$StopTime = Get-Date
"Repro Stop Time: $StopTime"  | Out-File -FilePath  $ReproDoc -Encoding UTF8 -Append
$StopNetCap = 'netsh trace stop'
if ($OSVersion.Buildnumber -ge 7600)
	{ cmd /c $StopNetCap }
if ($KeepAuditing -eq $false)
	{
	$ADFSTraceLog.IsEnabled = $false
	$ADFSTraceLog.SaveChanges()
	auditpol.exe /set /subcategory:"Application Generated" /failure:disable /success:disable
	Set-ADFSProperties -LogLevel  @("Warnings", "Information")
	}
	
#Collect event log data
$SecurityEvents = Get-WinEvent -FilterHashTable @{ LogName= "Security"; StartTime = $DateRaw} -ErrorAction SilentlyContinue
if ($OSVersion.Buildnumber -le 9200) {$ADFSAdminEvents = Get-WinEvent -FilterHashTable @{ LogName= "AD FS 2.0/Admin"; StartTime = $date}  -ErrorAction SilentlyContinue}
	else {$ADFSAdminEvents = Get-WinEvent -FilterHashTable @{ LogName= "AD FS/Admin"; StartTime = $DateRaw} -ErrorAction SilentlyContinue }
$ADFSTracingEvents = Get-WinEvent -LogName "AD FS Tracing/Debug" -Oldest -ErrorAction SilentlyContinue

#Copy data to repro folder for collection
$SecurityEvents | Export-Csv -Path ($AuthReproDataPath + "\SecurityEvents.csv") -NoTypeInformation -Force
$ADFSAdminEvents | Export-Csv -Path ($AuthReproDataPath + "\ADFSAdminEvents.csv") -NoTypeInformation -Force
$ADFSTracingEvents | Export-Csv -Path ($AuthReproDataPath + "\ADFSTracingEvents.csv") -NoTypeInformation -Force

Write-Host "Tracing has stopped. Files can be found at $AuthReproDataPath`."

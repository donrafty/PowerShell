PARAM
(
    [Parameter(Mandatory=$true)]
    [string]$From,
    [Parameter(Mandatory=$true)]
    [string]$To,
    [Parameter(Mandatory=$true)]
    [string]$Smtp,
    [string]$ClientPath,
    [string]$ReportPath = $env:TEMP
)

<# README.md  
 .DESCRIPTION  
 Send a mail with a .csv and the current pending reboot and pending windows update status of registered clients in WSUS.  
 .NOTES  
 Author: Raphael Koller (@0x3e4)  
 .REQUIRES
 PSWindowsUpdate module: https://www.powershellgallery.com/packages/PSWindowsUpdate/2.1.1.2
 .PARAMETER -From  
 Mail address of the sender. It's a mandatory parameter.  
 .PARAMETER -To  
 Mail address of the recipient. It's a mandatory parameter.  
 .PARAMETER -Smtp  
 IP or DNS of the mail server. It's a mandatory parameter. 
 .PARAMETER -ClientPath  
 Path of a .csv file with an own list of clients to query. Column name needs to be "Clients" and entries are the FQDN of the clients. If you don't use this parameter then every client registered in the WSUS console will be queried.  
 .PARAMETER -ReportPath  
 Folder for the .csv files. Default Path: "$env:TEMP"  
 .EXAMPLE without a client path file  
 PS> .\Get-WUClientStatus.ps1 -From "bot@contoso.com" -To "human@contoso.com" -Smtp "mail.contoso.com"  
 .EXAMPLE with a client path file  
 PS> .\Get-WUClientStatus.ps1 -From "bot@contoso.com" -To "human@contoso.com" -Smtp "mail.contoso.com" -ClientPath "C:\tmp\clients.csv"  
#>  

$ReportSummary = $ReportPath + "\$(Get-Date -format ddMMyyyy_HHmmss)_Get-WUClientStatus_$env:USERDNSDOMAIN.csv"

[reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")

$WSUS = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer();
$computerscope = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
$updatescope = New-Object Microsoft.UpdateServices.Administration.UpdateScope

if (!$ClientPath) {
    $wsus.GetSummariesPerComputerTarget($updatescope,$computerscope) | % {

        $FQDN = $(($WSUS.GetComputerTarget([guid]$_.ComputerTargetId)).FullDomainName)

        try{
            $PendingReboot = if([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $FQDN).OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")){$?}else{"False"}
            $PendingUpdate = Get-WUList -ComputerName $FQDN

            $PendingUpdateKBstring = try {$([string]::join(",", $($PendingUpdate.KB)))} catch {$null}

            New-Object PSObject -Property @{
                FQDN = $FQDN
                PendingRebootWU = $PendingReboot
                PendingUpdateKB = $PendingUpdateKBstring
            } | Select-Object FQDN,PendingRebootWU,PendingUpdateKB
        }
        catch{
            $FQDN + " connection not possible."
        }

    } | Export-Csv $ReportSummary -NoTypeInformation
}
else {
    Import-Csv $ClientPath | % {

        $FQDN = $_.Clients

        try{
            $PendingReboot = if([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $FQDN).OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")){$?}else{"False"}
            $PendingUpdate = Get-WUList -ComputerName $FQDN

            $PendingUpdateKBstring = try {$([string]::join(",", $($PendingUpdate.KB)))} catch {$null}

            New-Object PSObject -Property @{
                FQDN = $FQDN
                PendingRebootWU = $PendingReboot
                PendingUpdateKB = $PendingUpdateKBstring
            } | Select-Object FQDN,PendingRebootWU,PendingUpdateKB
        }
        catch{
            $FQDN + " connection not possible."
        }

    } | Export-Csv $ReportSummary -NoTypeInformation
}

$CountNoReboot = (Get-Content -Path $ReportSummary | Where-Object { $_ -match "False" }).count
$CountPendingReboot = (Get-Content -Path $ReportSummary | Where-Object { $_ -match "True" }).count

$Body = "<html><head><meta http-equiv=""Content-Type"" content=""text/html"" /></head>"
$Body += "<body style=""font-family: Calibri; color: #000000;""><P>"
$Body += "Dear administrator,<p>"
$Body += "following a list of Windows Server in the $env:USERDNSDOMAIN Domain with potential pending updates and reboots:"
$Body += "<ul style=""list-style-position: inside;""><li><i>Pending Reboot/s: $CountPendingReboot</i>"
$Body += "<li><i>No Reboot/s: $CountNoReboot</i></ul><p>"
$Body += "Detailed list in the attachment.<p>"
$Body += "Get-WUClientStatus.ps1 is a scheduled task on $env:COMPUTERNAME."

Send-MailMessage -From $From -To $To -Subject "Pending Windows Updates and needed reboots | $env:USERDNSDOMAIN" -BodyAsHtml -Body $Body -SmtpServer $Smtp -Attachments $ReportSummary
PARAM
(
    [Parameter(Mandatory=$true)]
    [string]$From,
    [Parameter(Mandatory=$true)]
    [string]$To,
    [Parameter(Mandatory=$true)]
    [string]$Smtp,
    [Parameter(Mandatory=$true)]
    [string]$Domain,
    [string]$Report = "$env:TEMP\$(Get-Date -format ddMMyyyy_HHmmss)_Get-WSUSStatus"
)
  

####################################################################

[reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")

$WSUS = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer();
$ComputerScope = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
$UpdateScope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
$UpdateScope.IncludedInstallationStates = 'Downloaded','NotInstalled'

$WSUS.GetSummariesPerComputerTarget($UpdateScope,$ComputerScope) | Select @{L='Computername';E={($WSUS.GetComputerTarget([guid]$_.ComputerTargetId)).FullDomainName}},`
    @{L='NeededCount';E={($_.DownloadedCount + $_.NotInstalledCount)}},DownloadedCount,NotInstalledCount,InstalledCount,FailedCount,LastUpdated, `
    @{L='NeededUpdate';E={(($WSUS.getcomputertarget([guid]$_.ComputerTargetId)).GetUpdateInstallationInfoPerUpdate($UpdateScope) | % {"KB" + $_.GetUpdate().KnowledgebaseArticles})}} `
    | Export-CSV $Report + ".csv" -NoTypeInformation -Encoding UTF8

$WSUS.GetComputerTargets($ComputerScope) | % {
        $Computername = $_.fulldomainname
        $_.GetUpdateInstallationInfoPerUpdate($UpdateScope) | % {
            $Update = $_.GetUpdate()
            [pscustomobject]@{
                Computername = $Computername
                UpdateTitle = $Update.Title 
                IsApproved = $Update.IsApproved
            }
    }
} | Export-CSV $Report + "_detailed.csv" -NoTypeInformation -Encoding UTF8

$body = "<html><head><meta http-equiv=""Content-Type"" content=""text/html"" /></head>"
$body += "<body style=""font-family: Calibri; color: #000000;""><P>"
$body += "Dear administrator,<p>"
$body += "find the current weekly report of the $Domain WSUS environment in the mail attachment.<br>"
$body += "Get-WSUSStatus.ps1 is a scheduled task on $env:COMPUTERNAME.<p>"

Send-MailMessage -From $From -To $To -Bcc $Bcc -Subject "WSUS Client Status | $Domain" -bodyashtml -body $body -SmtpServer $Smtp -Attachments "C:\SRVADM\LOG\Get-WSUSStatus\$(Get-Date -format ddMMyyyy)_$env:USERDOMAIN.csv", "C:\SRVADM\LOG\Get-WSUSStatus\$(Get-Date -format ddMMyyyy)_$($env:USERDOMAIN)_detailed.csv"

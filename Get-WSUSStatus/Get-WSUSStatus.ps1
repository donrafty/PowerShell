if(!(Get-ChildItem "C:\SRVADM\LOG\Get-WSUSStatus")){New-Item -Path "C:\SRVADM\LOG\Get-WSUSStatus" -ItemType directory -ErrorAction SilentlyContinue}

####################################################################

$MailConfig = Import-LocalizedData -BaseDirectory "C:\SRVADM\CFG\WindowsUpdate\" -FileName "MailConfig.psd1"

$From = $MailConfig.From
$To = "DCS_Windows_Server@snt.at", "csm@snt.at", "security@snt.at"
$Bcc = $MailConfig.Bcc
$Smtp = $MailConfig.Smtp
$Domain = $MailConfig.Domain
$Scriptserver = $env:COMPUTERNAME + "." + $domain

####################################################################

[reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")

$WSUS = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer();
$ComputerScope = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
$UpdateScope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
$UpdateScope.IncludedInstallationStates = 'Downloaded','NotInstalled'

$WSUS.GetSummariesPerComputerTarget($UpdateScope,$ComputerScope) | Select @{L='Computername';E={($WSUS.GetComputerTarget([guid]$_.ComputerTargetId)).FullDomainName}},`
    @{L='NeededCount';E={($_.DownloadedCount + $_.NotInstalledCount)}},DownloadedCount,NotInstalledCount,InstalledCount,FailedCount,LastUpdated, `
    @{L='NeededUpdate';E={(($WSUS.getcomputertarget([guid]$_.ComputerTargetId)).GetUpdateInstallationInfoPerUpdate($UpdateScope) | % {"KB" + $_.GetUpdate().KnowledgebaseArticles})}} `
    | Export-CSV "C:\SRVADM\LOG\Get-WSUSStatus\$(Get-Date -format ddMMyyyy)_$env:USERDOMAIN.csv" -NoTypeInformation -Encoding UTF8

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
} | Export-CSV "C:\SRVADM\LOG\Get-WSUSStatus\$(Get-Date -format ddMMyyyy)_$($env:USERDOMAIN)_detailed.csv" -NoTypeInformation -Encoding UTF8

$body = "<html><head><meta http-equiv=""Content-Type"" content=""text/html"" /></head>"
$body += "<body style=""font-family: Calibri; color: #000000;""><P>"
$body += "Dear administrator,<p>"
$body += "find the current weekly report of the $Domain WSUS environment in the mail attachment.<br>"
$body += "Get-WSUSStatus.ps1 is a scheduled task on $Scriptserver.<p>"

Send-MailMessage -From $From -To $To -Bcc $Bcc -Subject "WSUS Client Status | $Domain" -bodyashtml -body $body -SmtpServer $Smtp -Attachments "C:\SRVADM\LOG\Get-WSUSStatus\$(Get-Date -format ddMMyyyy)_$env:USERDOMAIN.csv", "C:\SRVADM\LOG\Get-WSUSStatus\$(Get-Date -format ddMMyyyy)_$($env:USERDOMAIN)_detailed.csv"
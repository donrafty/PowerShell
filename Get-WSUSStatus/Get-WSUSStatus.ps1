PARAM
(
    [Parameter(Mandatory=$true)]
    [string]$From,
    [Parameter(Mandatory=$true)]
    [string]$To,
    [Parameter(Mandatory=$true)]
    [string]$Smtp,
    [string]$ReportPath = $env:TEMP
)

<# README.md  
 .DESCRIPTION  
 Get a .csv with the current status of the WSUS server. Detailed view of the clients and approved updates in a sperate .csv included too.  
 .NOTES  
 Author: Raphael Koller (@0x3e4)  
 .PARAMETER -From  
 Mail address of the sender. It's a mandatory parameter.  
 .PARAMETER -To  
 Mail address of the recipient. It's a mandatory parameter.  
 .PARAMETER -Smtp  
 IP or DNS of the mail server. It's a mandatory parameter. 
 .PARAMETER -ReportPath  
 Folder for the .csv files. Default Path: "$env:TEMP"  
 .EXAMPLE 
 PS> .\Get-WSUSStatus.ps1 -From "bot@contoso.com" -To "human@contos.com" -Smtp "mail.contoso.com"
#>  

$ReportSummary = $ReportPath + "\$(Get-Date -format ddMMyyyy_HHmmss)_Get-WSUSStatus_summary.csv"
$ReportDetailed = $ReportPath + "\$(Get-Date -format ddMMyyyy_HHmmss)_Get-WSUSStatus_detailed.csv"

[reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")

$WSUS = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer();
$ComputerScope = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
$UpdateScope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
$UpdateScope.IncludedInstallationStates = 'Downloaded','NotInstalled'

$WSUS.GetSummariesPerComputerTarget($UpdateScope,$ComputerScope) | Select @{L='Computername';E={($WSUS.GetComputerTarget([guid]$_.ComputerTargetId)).FullDomainName}},`
    @{L='NeededCount';E={($_.DownloadedCount + $_.NotInstalledCount)}},DownloadedCount,NotInstalledCount,InstalledCount,FailedCount,LastUpdated, `
    @{L='NeededUpdate';E={(($WSUS.getcomputertarget([guid]$_.ComputerTargetId)).GetUpdateInstallationInfoPerUpdate($UpdateScope) | % {"KB" + $_.GetUpdate().KnowledgebaseArticles})}} `
    | Export-CSV $ReportSummary -NoTypeInformation -Encoding UTF8

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
} | Export-CSV $ReportDetailed -NoTypeInformation -Encoding UTF8

$body = "<html><head><meta http-equiv=""Content-Type"" content=""text/html"" /></head>"
$body += "<body style=""font-family: Calibri; color: #000000;""><P>"
$body += "Dear administrator,<p>"
$body += "find the current weekly report of the $env:USERDNSDOMAIN WSUS environment in the mail attachment.<br>"
$body += "Get-WSUSStatus.ps1 is a scheduled task on $env:COMPUTERNAME.<p>"

Send-MailMessage -From $From -To $To -Subject "WSUS Client Status | $env:USERDNSDOMAIN" -bodyashtml -body $body -SmtpServer $Smtp -Attachments $ReportSummary, $ReportDetailed

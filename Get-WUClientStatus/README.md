# Get-WUClientStatus.ps1

**.DESCRIPTION**  
Send a mail with a .csv and the current pending reboot and pending windows update status of registered clients in WSUS.  
**.NOTES**  
Author: Raphael Koller (@0x3e4)  
**.REQUIRES**  
PSWindowsUpdate module: https://www.powershellgallery.com/packages/PSWindowsUpdate/2.1.1.2  
**.PARAMETER -From**  
Mail address of the sender. It's a mandatory parameter.  
**.PARAMETER -To**  
Mail address of the recipient. It's a mandatory parameter.  
**.PARAMETER -Smtp**  
IP or DNS of the mail server. It's a mandatory parameter.  
**.PARAMETER -ClientPath**  
Path of a .csv file with an own list of clients to query. Column name needs to be "Clients" and entries are the FQDN of the clients. If you don't use this parameter then every client registered in the WSUS console will be queried.  
**.PARAMETER -ReportPath**  
Folder for the .csv files. Default Path: "$env:TEMP"  
**.EXAMPLE without a client path file**  
```PS> .\Get-WUClientStatus.ps1 -From "bot@contoso.com" -To "human@contoso.com" -Smtp "mail.contoso.com"```  
**.EXAMPLE with a client path file**  
```PS> .\Get-WUClientStatus.ps1 -From "bot@contoso.com" -To "human@contoso.com" -Smtp "mail.contoso.com" -ClientPath "C:\tmp\Clients.csv"```  

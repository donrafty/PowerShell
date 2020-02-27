# Get-WSUSStatus.ps1

**.DESCRIPTION**  
Get a .csv with the current status of the WSUS server. Detailed view of the clients and approved updates in a sperate .csv included too.  
**.NOTES**  
Author: Raphael Koller (@0x3e4)  
**.PARAMETER -From**  
Mail address of the sender. It's a mandatory parameter.  
**.PARAMETER -To**  
Mail address of the recipient. It's a mandatory parameter.  
**.PARAMETER -Smtp**  
IP or DNS of the mail server. It's a mandatory parameter.  
**.PARAMETER -ReportPath**  
Folder for the .csv files. Default Path: "$env:TEMP"  
**.EXAMPLE**  
```PS> .\Get-WSUSStatus.ps1 -From "bot@contoso.com" -To "human@contoso.com" -Smtp "mail.contoso.com"```

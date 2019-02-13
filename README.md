# Test-ConnectionPort

**.DESCRIPTION**  
TCP port ping to a target. One time or in a loop. Logging function integrated.  
**.NOTES**  
Author: Raphael Koller (@koll0x3e7)  
**.PARAMETER -IP**  
IP or FQDN of the target server. It's a mandatory parameter.  
**.PARAMETER -Port**  
Port to ping on the target server. It's a mandatory parameter.  
**.PARAMETER -Loop**  
Switch parameter for an one time or a loop port ping test.  
**.PARAMETER -Log**  
Logging enable or disable. Path: ```$env:TEMP\$(Get-Date -format ddMMyyyy_HHmmss)_$($IP)_$($Port)_ConnectionPort.log```  
**.EXAMPLE without loop**  
```PS> .\Test-ConnectionPort.ps1 -IP 1.1.1.1 -Port 53```  
**.EXAMPLE with loop**  
```PS> .\Test-ConnectionPort.ps1 -IP 1.1.1.1 -Port 53 -Loop:$true```  
**.EXAMPLE with logging to the default path**  
```PS> .\Test-ConnectionPort.ps1 -IP 1.1.1.1 -Port 53 -Loop:$true -Log:$true```  

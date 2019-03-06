PARAM
(
    [Parameter(Mandatory=$true)]
    [string]$IP,
    [Parameter(Mandatory=$true)]
    [string]$Port,
    [switch]$Loop,
    [switch]$Log
)

<# README.md  
 .DESCRIPTION  
 TCP port ping to a target. One time or in a loop. Logging function integrated.  
 .NOTES  
 Author: Raphael Koller (@0x3e4)  
 .PARAMETER -IP  
 IP or FQDN of the target server. It's a mandatory parameter.  
 .PARAMETER -Port  
 Port to ping on the target server. It's a mandatory parameter.  
 .PARAMETER -Loop  
 Switch parameter for an one time or a loop port ping test.  
 .PARAMETER -Log  
 Logging enable or disable. Path: "$env:TEMP\$(Get-Date -format ddMMyyyy_HHmmss)_$($IP)_$($Port)_ConnectionPort.log"  
 .EXAMPLE without loop  
 PS> .\Test-ConnectionPort.ps1 -IP 1.1.1.1 -Port 53  
 .EXAMPLE with loop  
 PS> .\Test-ConnectionPort.ps1 -IP 1.1.1.1 -Port 53 -Loop:$true  
 .EXAMPLE with logging to the default path  
 PS> .\Test-ConnectionPort.ps1 -IP 1.1.1.1 -Port 53 -Loop:$true -Log:$true  
#>  

if(($IP -as [ipaddress]) -or ([System.Net.Dns]::GetHostEntry($IP))){
    if($Log -eq $true){
        Start-Transcript -Path "$env:TEMP\$(Get-Date -format ddMMyyyy_HHmmss)_$($IP)_$($Port)_ConnectionPort.log"
    }

    if($Loop -eq $true){
        while($true){
            try{
                $Socket = New-Object System.Net.Sockets.TcpClient($IP,$Port)
                if($Socket.Connected) {
	                Write-Output "$(get-date) :: Successfully connected to $($IP):$($Port)"
                }
            }
            catch{
                Write-Error "$(get-date) :: Failed to connect to $($IP):$($Port)"
            }
            sleep -Seconds 1
        }
    }
    else{
        try{
            $Socket = New-Object System.Net.Sockets.TcpClient($IP,$Port)
            if($Socket.Connected) {
	            Write-Output "$(get-date) :: Successfully connected to $($IP):$($Port)"
            }
        }
        catch{
            Write-Error "$(get-date) :: Failed to connect to $($IP):$($Port)"
        }
    }
}
else{
    Write-Error -Message $_.Exception
}

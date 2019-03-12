PARAM
(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Check","BestPractice","Strict")][string]$Purpose,
    [Parameter()]
    [string]$ComputerName
)

# Configuration
$DefaultHive = [Microsoft.Win32.RegistryHive]::LocalMachine
if($ComputerName){
    
    $env:COMPUTERNAME = $ComputerName.ToUpper()

}

$DefaultHivePath = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
$DefaultPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
$DefaultHivePathCipherSuites = "SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$DefaultPathCipherSuites = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"

# Which registry will be checked or modified
Write-Output "`r"
Write-Host -BackgroundColor Black -ForegroundColor Black $env:COMPUTERNAME$env:COMPUTERNAME$env:COMPUTERNAME$env:COMPUTERNAME$env:COMPUTERNAME
Write-Host -BackgroundColor Black -ForegroundColor Black $env:COMPUTERNAME$env:COMPUTERNAME -NoNewline
Write-Host -BackgroundColor Black -ForegroundColor White $env:COMPUTERNAME -NoNewline
Write-Host -BackgroundColor Black -ForegroundColor Black $env:COMPUTERNAME$env:COMPUTERNAME
Write-Host -BackgroundColor Black -ForegroundColor Black $env:COMPUTERNAME$env:COMPUTERNAME$env:COMPUTERNAME$env:COMPUTERNAME$env:COMPUTERNAME

if($ComputerName){

    try{

        Write-Output "`r"
        Write-Output "Testing SMB & RPC TCP connections.."

        # Test RPC Connection
        $SocketTCP135 = New-Object Net.Sockets.TcpClient
        $SocketTCP135.Connect($env:COMPUTERNAME, 135)
        # Test SMB Connection
        $SocketTCP445 = New-Object Net.Sockets.TcpClient
        $SocketTCP445.Connect($env:COMPUTERNAME, 445)

        Write-Host -ForegroundColor Gray "Connection to $($env:COMPUTERNAME) via TCP/135 & TCP/445 is possible."

    }
    catch{

        if((!$SocketTCP135.Connected) -and (!$SocketTCP445.Connected)){

            $SocketTCP135.Dispose()
            $SocketTCP445.Dispose()
            Write-Host -ForegroundColor Red "No connection to $($env:COMPUTERNAME) via TCP/135 & TCP/445 possible."

        }
        else{

            if(!$SocketTCP445.Connected){

                $SocketTCP445.Dispose()
                Write-Host -ForegroundColor Red "No connection to $($env:COMPUTERNAME) via TCP/445 possible."

            }
            if(!$SocketTCP135.Connected){

                $SocketTCP135.Dispose()
                Write-Host -ForegroundColor Red "No connection to $($env:COMPUTERNAME) via TCP/135 possible."

            }

        }

    }

}

try{

    [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($DefaultHive, $env:COMPUTERNAME) | Out-Null

    if((!$ComputerName) -or (($SocketTCP135.Connected) -and ($SocketTCP445.Connected))){

        $SocketTCP135.Close()
        $SocketTCP445.Close()

        if($Purpose -ne "Check"){

            if($Purpose -eq "BestPractice"){

                $Ciphers0 = "DES 56/56", "NULL", "RC2 128/128", "RC2 40/128", "RC2 56/128", "RC4 128/128", "RC4 40/128", "RC4 56/128", "RC4 64/128"
                $Ciphers1 = "AES 128/128", "AES 256/256", "Triple DES 168"
                $Hashes1 = "MD5", "SHA", "SHA256", "SHA384", "SHA512"
                $KeyExchangeAlgorithms = "Diffie-Hellman", "ECDH", "PKCS"
                $Protocols0 = "Multi-Protocol Unified Hello", "PCT 1.0", "SSL 2.0", "SSL 3.0"
                $Protocols1 = "TLS 1.0", "TLS 1.1", "TLS 1.2"
                $ProtocolsOperator = "Client", "Server"
                $CipherSuites = @(
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521",
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384",
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256",
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521",
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384",
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256",
                    #"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                    #"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_RSA_WITH_AES_256_CBC_SHA256",
                    "TLS_RSA_WITH_AES_128_CBC_SHA256",
                    "TLS_RSA_WITH_AES_256_CBC_SHA",
                    "TLS_RSA_WITH_AES_128_CBC_SHA"
                )

            }

            if($Purpose -eq "Strict"){

                $Ciphers0 = "DES 56/56", "NULL", "RC2 128/128", "RC2 40/128", "RC2 56/128", "RC4 128/128", "RC4 40/128", "RC4 56/128", "RC4 64/128", "Triple DES 168"
                $Ciphers1 = "AES 128/128", "AES 256/256"
                $Hashes0 = "MD5"
                $Hashes1 = "SHA", "SHA256", "SHA384", "SHA512"
                $KeyExchangeAlgorithms = "Diffie-Hellman", "ECDH", "PKCS"
                $Protocols0 = "Multi-Protocol Unified Hello", "PCT 1.0", "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"
                $Protocols1 = "TLS 1.2"
                $ProtocolsOperator = "Client", "Server"
                $CipherSuites = @(
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521",
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384",
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256",
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521",
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384",
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256"
                )

            }

            # Ciphers BestPractice/Strict Settings
            Write-Output "`r"
            Write-Output "Checking Ciphers.."

            $Ciphers0 | ForEach-Object {

                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($DefaultHive, $env:COMPUTERNAME)

                if($($Reg.OpenSubKey("$DefaultHivePath\Ciphers\$_")) -eq $null){
        
                    $OpenSubKey = $Reg.OpenSubKey("$DefaultHivePath\Ciphers", $true)
                    $OpenSubKey.CreateSubKey($_) | Out-Null
                    $Ciphers0Output = Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $DefaultPath\Ciphers\$_ Key has been created."
                    $Ciphers0Output

                }

                $Ciphers0Path = $Reg.OpenSubKey("$DefaultHivePath\Ciphers\$_", $true)

                if(($Ciphers0Path.GetValue("Enabled") -eq $null) -or ($Ciphers0Path.GetValue("Enabled") -ne 0) -or (($Ciphers0Path.GetValueKind("Enabled")) -ne "DWord")){

                    if($Ciphers0Path.GetValue("Enabled") -eq $null){

                        $Ciphers0Path.SetValue("Enabled", 0, [Microsoft.Win32.RegistryValueKind]::DWORD)
                        $Ciphers0Output + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $_ has been created and disabled.")
                        $Ciphers0Output + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: Enabled Value contains: $($Ciphers0Path.GetValue("Enabled")) ($($Ciphers0Path.GetValueKind("Enabled")))")

                    }

                    if(($Ciphers0Path.GetValue("Enabled") -ne 0) -or (($Ciphers0Path.GetValueKind("Enabled")) -ne "DWord")){
            
                        $Ciphers0OldValue = $Ciphers0Path.GetValue("Enabled")
                        $Ciphers0OldValueKind = $Ciphers0Path.GetValueKind("Enabled")
                        $Ciphers0Path.SetValue("Enabled", 0, [Microsoft.Win32.RegistryValueKind]::DWORD)
                        $Ciphers0Output + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: $_ has been modified and disabled.")
                        $Ciphers0Output + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: Enabled Value contains: $($Ciphers0Path.GetValue("Enabled")) ($($Ciphers0Path.GetValueKind("Enabled"))) (Old: $Ciphers0OldValue ($Ciphers0OldValueKind))")

                    }

                }
                else{

                    Write-Host -ForegroundColor Green "$_ is already disabled. Enabled Value contains: $($Ciphers0Path.GetValue("Enabled")) ($($Ciphers0Path.GetValueKind("Enabled")))"

                }
    
            }

            $Ciphers1 | ForEach-Object {

                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($DefaultHive, $env:COMPUTERNAME)

                if($($Reg.OpenSubKey("$DefaultHivePath\Ciphers\$_")) -eq $null){
        
                    $OpenSubKey = $Reg.OpenSubKey("$DefaultHivePath\Ciphers", $true)
                    $OpenSubKey.CreateSubKey($_) | Out-Null
                    $Ciphers1Output = Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $DefaultPath\Ciphers\$_ Key has been created."
                    $Ciphers1Output

                }

                $Ciphers1Path = $Reg.OpenSubKey("$DefaultHivePath\Ciphers\$_", $true)

                if(($Ciphers1Path.GetValue("Enabled") -eq $null) -or ($Ciphers1Path.GetValue("Enabled") -ne -1) -or (($Ciphers1Path.GetValueKind("Enabled")) -ne "DWord")){

                    if($Ciphers1Path.GetValue("Enabled") -eq $null){

                        $Ciphers1Path.SetValue("Enabled", -1, [Microsoft.Win32.RegistryValueKind]::DWORD)
                        $Ciphers1Output + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $_ has been created and enabled.")
                        $Ciphers1Output + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: Enabled Value contains: $($Ciphers1Path.GetValue("Enabled")) ($($Ciphers1Path.GetValueKind("Enabled")))")

                    }

                    if(($Ciphers1Path.GetValue("Enabled") -ne -1) -or (($Ciphers1Path.GetValueKind("Enabled")) -ne "DWord")){
            
                        $Ciphers1OldValue = $Ciphers0Path.GetValue("Enabled")
                        $Ciphers1OldValueKind = $Ciphers0Path.GetValueKind("Enabled")
                        $Ciphers1Path.SetValue("Enabled", -1, [Microsoft.Win32.RegistryValueKind]::DWORD)
                        $Ciphers1Output + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: $_ has been modified and enabled.")
                        $Ciphers1Output + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: Enabled Value contains: $($Ciphers1Path.GetValue("Enabled")) ($($Ciphers1Path.GetValueKind("Enabled"))) (Old: $Ciphers1OldValue ($Ciphers1OldValueKind))")

                    }

                }
                else{

                    Write-Host -ForegroundColor Green "$_ is already enabled. Enabled Value contains: $($Ciphers1Path.GetValue("Enabled")) ($($Ciphers1Path.GetValueKind("Enabled")))"

                }
    
            }

            # Hashes BestPractice/Strict Settings
            Write-Output "`r"
            Write-Output "Checking Hashes.."

            if($Hashes0 -ne $null){
                $Hashes0 | ForEach-Object {

                    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($DefaultHive, $env:COMPUTERNAME)

                    if($($Reg.OpenSubKey("$DefaultHivePath\Hashes\$_")) -eq $null){
        
                        $OpenSubKey = $Reg.OpenSubKey("$DefaultHivePath\Hashes", $true)
                        $OpenSubKey.CreateSubKey($_) | Out-Null
                        $Hashes0Output = Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $DefaultPath\Hashes\$_ Key has been created."
                        $Hashes0Output
                
                    }

                    $Hashes0Path = $Reg.OpenSubKey("$DefaultHivePath\Hashes\$_", $true)

                    if(($Hashes0Path.GetValue("Enabled") -eq $null) -or ($Hashes0Path.GetValue("Enabled") -ne 0) -or (($Hashes0Path.GetValueKind("Enabled")) -ne "DWord")){

                        if($Hashes0Path.GetValue("Enabled") -eq $null){

                            $Hashes0Path.SetValue("Enabled", 0, [Microsoft.Win32.RegistryValueKind]::DWORD)
                            $Hashes0Output + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $_ has been created and disabled.")
                            $Hashes0Output + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: Enabled Value contains: $($Hashes0Path.GetValue("Enabled")) ($($Hashes0Path.GetValueKind("Enabled")))")

                        }

                        if(($Hashes0Path.GetValue("Enabled") -ne 0) -or (($Hashes0Path.GetValueKind("Enabled")) -ne "DWord")){
            
                            $Hashes0OldValue = $Hashes0Path.GetValue("Enabled")
                            $Hashes0OldValueKind = $Hashes0Path.GetValueKind("Enabled")
                            $Hashes0Path.SetValue("Enabled", 0, [Microsoft.Win32.RegistryValueKind]::DWORD)
                            $Hashes0Output + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: $_ has been modified and disabled.")
                            $Hashes0Output + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: Enabled Value contains: $($Hashes0Path.GetValue("Enabled")) ($($Hashes0Path.GetValueKind("Enabled"))) (Old: $Hashes0OldValue ($Hashes0OldValueKind))")

                        }

                    }
                    else{

                        Write-Host -ForegroundColor Green "$_ is already disabled. Enabled Value contains: $($Hashes0Path.GetValue("Enabled")) ($($Hashes0Path.GetValueKind("Enabled")))"

                    }

                }
            }

            $Hashes1 | ForEach-Object {

                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($DefaultHive, $env:COMPUTERNAME)

                if($($Reg.OpenSubKey("$DefaultHivePath\Hashes\$_")) -eq $null){
        
                    $OpenSubKey = $Reg.OpenSubKey("$DefaultHivePath\Hashes", $true)
                    $OpenSubKey.CreateSubKey($_) | Out-Null
                    $Hashes1Output = Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $DefaultPath\Hashes\$_ Key has been created."
                    $Hashes1Output

                }

                $Hashes1Path = $Reg.OpenSubKey("$DefaultHivePath\Hashes\$_", $true)

                if(($Hashes1Path.GetValue("Enabled") -eq $null) -or ($Hashes1Path.GetValue("Enabled") -ne -1) -or (($Hashes1Path.GetValueKind("Enabled")) -ne "DWord")){

                    if($Hashes1Path.GetValue("Enabled") -eq $null){

                        $Hashes1Path.SetValue("Enabled", -1, [Microsoft.Win32.RegistryValueKind]::DWORD)
                        $Hashes1Output + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $_ has been created and enabled.")
                        $Hashes1Output + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: Enabled Value contains: $($Hashes1Path.GetValue("Enabled")) ($($Hashes1Path.GetValueKind("Enabled")))")

                    }

                    if(($Hashes1Path.GetValue("Enabled") -ne -1) -or (($Hashes1Path.GetValueKind("Enabled")) -ne "DWord")){
            
                        $Hashes1OldValue = $Hashes1Path.GetValue("Enabled")
                        $Hashes1OldValueKind = $Hashes1Path.GetValueKind("Enabled")
                        $Hashes1Path.SetValue("Enabled", -1, [Microsoft.Win32.RegistryValueKind]::DWORD)
                        $Hashes1Output + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: $_ has been modified and enabled.")
                        $Hashes1Output + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: Enabled Value contains: $($Hashes1Path.GetValue("Enabled")) ($($Hashes1Path.GetValueKind("Enabled"))) (Old: $Hashes1OldValue ($Hashes1OldValueKind))")

                    }

                }
                else{

                    Write-Host -ForegroundColor Green "$_ is already enabled. Enabled Value contains: $($Hashes1Path.GetValue("Enabled")) ($($Hashes1Path.GetValueKind("Enabled")))"

                }

            }

            # Key Exchange Alogrithms BestPractice/Strict Settings
            Write-Output "`r"
            Write-Output "Checking Key Exchange Algorithms.."

            $KeyExchangeAlgorithms | ForEach-Object {

                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($DefaultHive, $env:COMPUTERNAME)

                if($($Reg.OpenSubKey("$DefaultHivePath\KeyExchangeAlgorithms\$_")) -eq $null){
        
                    $OpenSubKey = $Reg.OpenSubKey("$DefaultHivePath\KeyExchangeAlgorithms", $true)
                    $OpenSubKey.CreateSubKey($_) | Out-Null
                    $KeyExchangeAlgorithmsOutput = Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $DefaultPath\KeyExchangeAlgorithms\$_ Key has been created."
                    $KeyExchangeAlgorithmsOutput

                }

                $KeyExchangeAlgorithmsPath = $Reg.OpenSubKey("$DefaultHivePath\KeyExchangeAlgorithms\$_", $true)

                if(($KeyExchangeAlgorithmsPath.GetValue("Enabled") -eq $null) -or ($KeyExchangeAlgorithmsPath.GetValue("Enabled") -ne -1) -or (($KeyExchangeAlgorithmsPath.GetValueKind("Enabled")) -ne "DWord")){

                    if($KeyExchangeAlgorithmsPath.GetValue("Enabled") -eq $null){

                        $KeyExchangeAlgorithmsPath.SetValue("Enabled", -1, [Microsoft.Win32.RegistryValueKind]::DWORD)
                        $KeyExchangeAlgorithmsOutput + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $_ has been created and enabled.")
                        $KeyExchangeAlgorithmsOutput + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: Enabled Value contains: $($KeyExchangeAlgorithmsPath.GetValue("Enabled")) ($($KeyExchangeAlgorithmsPath.GetValueKind("Enabled")))")

                    }

                    if(($KeyExchangeAlgorithmsPath.GetValue("Enabled") -ne -1) -or (($KeyExchangeAlgorithmsPath.GetValueKind("Enabled")) -ne "DWord")){
            
                        $KeyExchangeAlgorithmsOldValue = $KeyExchangeAlgorithmsPath.GetValue("Enabled")
                        $KeyExchangeAlgorithmsOldValueKind = $KeyExchangeAlgorithmsPath.GetValueKind("Enabled")
                        $KeyExchangeAlgorithmsPath.SetValue("Enabled", -1, [Microsoft.Win32.RegistryValueKind]::DWORD)
                        $KeyExchangeAlgorithmsOutput + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: $_ has been modified and enabled.")
                        $KeyExchangeAlgorithmsOutput + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: Enabled Value contains: $($KeyExchangeAlgorithmsPath.GetValue("Enabled")) ($($KeyExchangeAlgorithmsPath.GetValueKind("Enabled"))) (Old: $KeyExchangeAlgorithmsOldValue ($KeyExchangeAlgorithmsOldValueKind))")

                    }

                }
                else{

                    Write-Host -ForegroundColor Green "$_ is already enabled. Enabled Value contains: $($KeyExchangeAlgorithmsPath.GetValue("Enabled")) ($($KeyExchangeAlgorithmsPath.GetValueKind("Enabled")))"

                }

                if($_ -eq "Diffie-Hellman"){
    
                    if(($KeyExchangeAlgorithmsPath.GetValue("ServerMinKeyBitLength") -eq $null) -or ($KeyExchangeAlgorithmsPath.GetValue("ServerMinKeyBitLength") -ne 2048) -or (($KeyExchangeAlgorithmsPath.GetValueKind("ServerMinKeyBitLength")) -ne "DWord")){

                        if($KeyExchangeAlgorithmsPath.GetValue("ServerMinKeyBitLength") -eq $null){

                            $KeyExchangeAlgorithmsPath.SetValue("ServerMinKeyBitLength", 2048, [Microsoft.Win32.RegistryValueKind]::DWORD)
                            $KeyExchangeAlgorithmsOutput + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: ServerMinKeyBitLength has been created.")
                            $KeyExchangeAlgorithmsOutput + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: ServerMinKeyBitLength Value contains: $($KeyExchangeAlgorithmsPath.GetValue("ServerMinKeyBitLength")) ($($KeyExchangeAlgorithmsPath.GetValueKind("ServerMinKeyBitLength")))")

                        }

                        if(($KeyExchangeAlgorithmsPath.GetValue("ServerMinKeyBitLength") -ne 2048) -or (($KeyExchangeAlgorithmsPath.GetValueKind("ServerMinKeyBitLength")) -ne "DWord")){

                            $KeyExchangeAlgorithmsOldValue = $KeyExchangeAlgorithmsPath.GetValue("ServerMinKeyBitLength")
                            $KeyExchangeAlgorithmsOldValueKind = $KeyExchangeAlgorithmsPath.GetValueKind("ServerMinKeyBitLength")
                            $KeyExchangeAlgorithmsPath.SetValue("ServerMinKeyBitLength", 2048, [Microsoft.Win32.RegistryValueKind]::DWORD)
                            $KeyExchangeAlgorithmsOutput + $(Write-Host -ForegroundColor Cyan "`t[Modified]`t:: ServerMinKeyBitLength has been modified.")
                            $KeyExchangeAlgorithmsOutput + $(Write-Host -ForegroundColor Cyan "`t[Modified]`t:: ServerMinKeyBitLength Value contains: $($KeyExchangeAlgorithmsPath.GetValue("ServerMinKeyBitLength")) ($($KeyExchangeAlgorithmsPath.GetValueKind("ServerMinKeyBitLength"))) (Old: $KeyExchangeAlgorithmsOldValue ($KeyExchangeAlgorithmsOldValueKind))")

                        }

                    }
                    else{

                        Write-Host -ForegroundColor Green "+ ServerMinKeyBitLength is already set. ServerMinKeyBitLength Value contains: $($KeyExchangeAlgorithmsPath.GetValue("ServerMinKeyBitLength")) ($($KeyExchangeAlgorithmsPath.GetValueKind("ServerMinKeyBitLength")))"

                    }

                }
    
            }
    
            # Protocols BestPractice/Strict Settings
            Write-Output "`r"
            Write-Output "Checking Protocols.."

            ForEach($Protocol in $Protocols0){

                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($DefaultHive, $env:COMPUTERNAME)

	            if($($Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocol")) -eq $null){
	
		            $OpenSubKey = $Reg.OpenSubKey("$DefaultHivePath\Protocols", $true)
		            $OpenSubKey.CreateSubKey($Protocol) | Out-Null
		            $Protocols0Output = Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $DefaultPath\Protocols\$Protocol Key has been created."
		            $Protocols0Output

	            }

                if(($($Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocol\Client")) -eq $null) -or ($($Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocol\Server")) -eq $null)){

                    if($($Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocol\Client")) -eq $null){

                        $OpenSubKey = $Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocol", $true)        
                        $OpenSubKey.CreateSubKey("Client") | Out-Null
                        $Protocols0Output = Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $DefaultPath\Protocols\$Protocol\Client Key has been created."
                        $Protocols0Output

                    }

                    if($($Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocol\Server")) -eq $null){

                        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($DefaultHive, $env:COMPUTERNAME)
                        $OpenSubKey = $Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocol", $true)        
                        $OpenSubKey.CreateSubKey("Server") | Out-Null
                        $Protocols0Output = Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $DefaultPath\Protocols\$Protocol\Server Key has been created."
                        $Protocols0Output

                    }

                }

                $ProtocolsOperator | ForEach-Object {

                     $Protocols0Path = $Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocol\$_", $true)

                    if((($Protocols0Path.GetValue("Enabled") -eq $null)) -or ($Protocols0Path.GetValue("Enabled") -ne 0) -or (($Protocols0Path.GetValueKind("Enabled")) -ne "DWord")){

                        if($Protocols0Path.GetValue("Enabled") -eq $null){

                            $Protocols0Path.SetValue("Enabled", 0, [Microsoft.Win32.RegistryValueKind]::DWORD)
                            $Protocols0Output + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $Protocol $_ has been created and disabled.")
                            $Protocols0Output + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: Enabled Value contains: $($Protocols0Path.GetValue("Enabled")) ($($Protocols0Path.GetValueKind("Enabled"))")

                        }

                        if(($Protocols0Path.GetValue("Enabled") -ne 0) -or (($Protocols0Path.GetValueKind("Enabled")) -ne "DWord")){

			                $Protocols0OldValue = $Protocols0Path.GetValue("Enabled")
			                $Protocols0OldValueKind = $Protocols0Path.GetValueKind("Enabled")
                            $Protocols0Path.SetValue("Enabled", 0, [Microsoft.Win32.RegistryValueKind]::DWORD)
                            $Protocols0Output + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: $Protocol $_ has been modified and disabled.")
                            $Protocols0Output + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: Enabled Value contains: $($Protocols0Path.GetValue("Enabled")) ($($Protocols0Path.GetValueKind("Enabled"))) (Old: $Protocols0OldValue ($Protocols0OldValueKind))")

                        }

                    }
                    else{

                        $Protocols0Output = Write-Host -ForegroundColor Green -NoNewline "$Protocol $_ is already disabled. Enabled Value contains: $($Protocols0Path.GetValue("Enabled")) ($($Protocols0Path.GetValueKind("Enabled"))). "

                    }

                    if((($Protocols0Path.GetValue("DisabledByDefault") -eq $null)) -or ($Protocols0Path.GetValue("DisabledByDefault") -ne 1) -or (($Protocols0Path.GetValueKind("DisabledByDefault")) -ne "DWord")){

                        if(($Protocols0Path.GetValue("DisabledByDefault") -eq $null)){

                            $Protocols0Path.SetValue("DisabledByDefault", 1, [Microsoft.Win32.RegistryValueKind]::DWORD)
                            $Protocols0Output + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: DisabledByDefault Value has been created and contains: $($Protocols0Path.GetValue("DisabledByDefault")) ($($Protocols0Path.GetValueKind("DisabledByDefault"))")

                        }

                        if(($Protocols0Path.GetValue("DisabledByDefault") -ne 1) -or (($Protocols0Path.GetValueKind("DisabledByDefault")) -ne "DWord")){

			                $Protocols0OldValue = $Protocols0Path.GetValue("DisabledByDefault")
			                $Protocols0OldValueKind = $Protocols0Path.GetValueKind("DisabledByDefault")
                            $Protocols0Path.SetValue("DisabledByDefault", 1, [Microsoft.Win32.RegistryValueKind]::DWORD)
                            $Protocols0Output + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: DisabledByDefault Value has been modified and contains: $($Protocols0Path.GetValue("DisabledByDefault")) ($($Protocols0Path.GetValueKind("DisabledByDefault"))) (Old: $Protocols0OldValue ($Protocols0OldValueKind))")

                        }

                    }
                    else{

                        $Protocols0Output + $(Write-Host -ForegroundColor Green "DisabledByDefault Value contains: $($Protocols0Path.GetValue("DisabledByDefault")) ($($Protocols0Path.GetValueKind("DisabledByDefault")))")

                    }

                }
    
            }

            ForEach($Protocol in $Protocols1){

                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($DefaultHive, $env:COMPUTERNAME)

	            if($($Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocol")) -eq $null){
	
		            $OpenSubKey = $Reg.OpenSubKey("$DefaultHivePath\Protocols", $true)
		            $OpenSubKey.CreateSubKey($Protocol) | Out-Null
		            $Protocols1Output = Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $DefaultPath\Protocols\$Protocol Key has been created."
		            $Protocols1Output

	            }

                if(($($Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocol\Client")) -eq $null) -or ($($Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocol\Server")) -eq $null)){

                    if($($Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocol\Client")) -eq $null){

                        $OpenSubKey = $Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocol", $true)        
                        $OpenSubKey.CreateSubKey("Client") | Out-Null
                        $Protocols1Output = Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $DefaultPath\Protocols\$Protocol\Client Key has been created."
                        $Protocols1Output

                    }

                    if($($Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocol\Server")) -eq $null){

                        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($DefaultHive, $env:COMPUTERNAME)
                        $OpenSubKey = $Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocol", $true)        
                        $OpenSubKey.CreateSubKey("Server") | Out-Null
                        $Protocols1Output = Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $DefaultPath\Protocols\$Protocol\Server Key has been created."
                        $Protocols1Output

                    }

                }

                $ProtocolsOperator | ForEach-Object {

                     $Protocols1Path = $Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocol\$_", $true)

                    if((($Protocols1Path.GetValue("Enabled") -eq $null)) -or ($Protocols1Path.GetValue("Enabled") -ne -1) -or (($Protocols1Path.GetValueKind("Enabled")) -ne "DWord")){

                        if($Protocols1Path.GetValue("Enabled") -eq $null){

                            $Protocols1Path.SetValue("Enabled", -1, [Microsoft.Win32.RegistryValueKind]::DWORD)
                            $Protocols1Output + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: $Protocol $_ has been created and enabled.")
                            $Protocols1Output + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: Enabled Value contains: $($Protocols1Path.GetValue("Enabled")) ($($Protocols1Path.GetValueKind("Enabled"))")

                        }

                        if(($Protocols1Path.GetValue("Enabled") -ne -1) -or (($Protocols1Path.GetValueKind("Enabled")) -ne "DWord")){

			                $Protocols1OldValue = $Protocols1Path.GetValue("Enabled")
			                $Protocols1OldValueKind = $Protocols1Path.GetValueKind("Enabled")
                            $Protocols1Path.SetValue("Enabled", -1, [Microsoft.Win32.RegistryValueKind]::DWORD)
                            $Protocols1Output + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: $Protocol $_ has been modified and enabled.")
                            $Protocols1Output + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: Enabled Value contains: $($Protocols1Path.GetValue("Enabled")) ($($Protocols1Path.GetValueKind("Enabled"))) (Old: $Protocols1OldValue ($Protocols1OldValueKind))")

                        }

                    }
                    else{

                        $Protocols1Output = Write-Host -ForegroundColor Green -NoNewline "$Protocol $_ is already enabled. Enabled Value contains: $($Protocols1Path.GetValue("Enabled")) ($($Protocols1Path.GetValueKind("Enabled"))). "

                    }

                    if((($Protocols1Path.GetValue("DisabledByDefault") -eq $null)) -or ($Protocols1Path.GetValue("DisabledByDefault") -ne 0) -or (($Protocols1Path.GetValueKind("DisabledByDefault")) -ne "DWord")){

                        if(($Protocols1Path.GetValue("DisabledByDefault") -eq $null)){

                            $Protocols1Path.SetValue("DisabledByDefault", 0, [Microsoft.Win32.RegistryValueKind]::DWORD)
                            $Protocols1Output + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: DisabledByDefault Value has been created and contains: $($Protocols1Path.GetValue("DisabledByDefault")) ($($Protocols1Path.GetValueKind("DisabledByDefault"))")

                        }

                        if(($Protocols1Path.GetValue("DisabledByDefault") -ne 0) -or (($Protocols1Path.GetValueKind("DisabledByDefault")) -ne "DWord")){

			                $Protocols1OldValue = $Protocols1Path.GetValue("DisabledByDefault")
			                $Protocols1OldValueKind = $Protocols1Path.GetValueKind("DisabledByDefault")
                            $Protocols1Path.SetValue("DisabledByDefault", 0, [Microsoft.Win32.RegistryValueKind]::DWORD)
                            $Protocols1Output + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: DisabledByDefault Value has been modified and contains: $($Protocols1Path.GetValue("DisabledByDefault")) ($($Protocols1Path.GetValueKind("DisabledByDefault"))) (Old: $Protocols1OldValue ($Protocols1OldValueKind))")

                        }

                    }
                    else{

                        $Protocols1Output + $(Write-Host -ForegroundColor Green "DisabledByDefault Value contains: $($Protocols1Path.GetValue("DisabledByDefault")) ($($Protocols1Path.GetValueKind("DisabledByDefault")))")

                    }

                }
    
            }

            # Cipher Suites BestPractice/Strict Settings
            Write-Output "`r"
            Write-Output "Checking Cipher Suites.."

            $CipherSuites = [string]::join(",", $CipherSuites)

            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($DefaultHive, $env:COMPUTERNAME)
            $CipherSuitesPath = $Reg.OpenSubKey($DefaultHivePathCipherSuites, $true)

            if(($CipherSuitesPath.GetValue("Functions") -eq $null) -or ($CipherSuitesPath.GetValue("Functions") -ne $CipherSuites) -or (($CipherSuitesPath.GetValueKind("Functions")) -ne "String")){

                if($CipherSuitesPath.GetValue("Functions") -eq $null){

                    $CipherSuitesPath.SetValue("Functions", $CipherSuites, [Microsoft.Win32.RegistryValueKind]::String)
                    $CipherSuitesSplit = ($CipherSuitesPath.GetValue("Functions") -split ",")
                    $CipherSuitesOutput + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: Cipher Suites has been created and configured.")
                    $CipherSuitesOutput + $(Write-Host -ForegroundColor Yellow "`t[CREATED]`t:: Functions Value contains:")
                    $CipherSuitesOutput + $(Write-Host -ForegroundColor Yellow ($CipherSuitesSplit | Out-String))
                    $CipherSuitesOutput + $(Write-Host -ForegroundColor Yellow "($($CipherSuitesPath.GetValueKind("Functions")))")

                }

                if(($CipherSuitesPath.GetValue("Functions") -ne $CipherSuites) -or (($CipherSuitesPath.GetValueKind("Functions")) -ne "String")){

                    $CipherSuitesOldValue = $CipherSuitesPath.GetValue("Functions")
                    $CipherSuitesOldValueKind = $CipherSuitesPath.GetValueKind("Functions")
                    $CipherSuitesPath.SetValue("Functions", $CipherSuites, [Microsoft.Win32.RegistryValueKind]::String)
                    $CipherSuitesSplit = ($CipherSuitesPath.GetValue("Functions") -split ",")
                    $CipherSuitesOutput + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: Cipher Suites has been modified and configured.")
                    $CipherSuitesOutput + $(Write-Host -ForegroundColor Cyan "`t[MODIFIED]`t:: Functions Value contains:")
                    $CipherSuitesOutput + $(Write-Host -ForegroundColor Cyan ($CipherSuitesSplit | Out-String))
                    $CipherSuitesOutput + $(Write-Host -ForegroundColor Cyan "($($CipherSuitesPath.GetValueKind("Functions")))")

                }

            }
            else{

                $CipherSuitesSplit = ($CipherSuitesPath.GetValue("Functions") -split ",")
                Write-Host -ForegroundColor Green "Cipher Suites is already configured. Functions Value contains:"
                Write-Host -ForegroundColor Green ($CipherSuitesSplit | Out-String)
                Write-Host -ForegroundColor Green "($((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002").Functions.GetType().Name))"

            }

        }
        else{

            $Ciphers = "DES 56/56", "NULL", "RC2 128/128", "RC2 40/128", "RC2 56/128", "RC4 128/128", "RC4 40/128", "RC4 56/128", "RC4 64/128", "AES 128/128", "AES 256/256", "Triple DES 168"
            $Hashes = "MD5", "SHA", "SHA256", "SHA384", "SHA512"
            $KeyExchangeAlgorithms = "Diffie-Hellman", "ECDH", "PKCS"
            $Protocols = "Multi-Protocol Unified Hello", "PCT 1.0", "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2"
            $ProtocolsOperator = "Client", "Server"

            # Ciphers Settings
            Write-Output "`r"
            Write-Output "Checking Ciphers.."

            $Ciphers | ForEach-Object {

                $Cipher = $_
                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($DefaultHive, $env:COMPUTERNAME)
                $CiphersPath = $Reg.OpenSubKey("$DefaultHivePath\Ciphers\$_", $true)

                try{
            
                    Write-Host -ForegroundColor Gray "$Cipher | Enabled Value contains: $($CiphersPath.GetValue("Enabled")) ($($CiphersPath.GetValueKind("Enabled")))"

                }
                catch{

                    Write-Host -ForegroundColor Red "$Cipher | Enabled Value is not available!"

                }

            }

            # Hashes Settings
            Write-Output "`r"
            Write-Output "Checking Hashes.."

            $Hashes | ForEach-Object {

                $Hash = $_
                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($DefaultHive, $env:COMPUTERNAME)
                $HashesPath = $Reg.OpenSubKey("$DefaultHivePath\Hashes\$_", $true)

                try{
           
                    Write-Host -ForegroundColor Gray "$Hash | Enabled Value contains: $($HashesPath.GetValue("Enabled")) ($($HashesPath.GetValueKind("Enabled")))"
                }
                catch{

                    Write-Host -ForegroundColor Red "$Hash | Enabled Value is not available!"

                }

            }

            # Key Exchange Alogrithms Settings
            Write-Output "`r"
            Write-Output "Checking Key Exchange Algorithms.."

            $KeyExchangeAlgorithms | ForEach-Object {

                $KeyExchangeAlgorithm = $_
                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($DefaultHive, $env:COMPUTERNAME)
                $KeyExchangeAlgorithmsPath = $Reg.OpenSubKey("$DefaultHivePath\KeyExchangeAlgorithms\$_", $true)

                try{
        
                    Write-Host -ForegroundColor Gray "$KeyExchangeAlgorithm | Enabled Value contains: $($KeyExchangeAlgorithmsPath.GetValue("Enabled")) ($($KeyExchangeAlgorithmsPath.GetValueKind("Enabled")))"
        
                }
                catch{

                    Write-Host -ForegroundColor Red "$KeyExchangeAlgorithm | Enabled Value is not available!"

                }

                if($_ -eq "Diffie-Hellman"){

                    try{
        
                        Write-Host -ForegroundColor Gray "+ ServerMinKeyBitLength Value contains: $($KeyExchangeAlgorithmsPath.GetValue("ServerMinKeyBitLength")) ($($KeyExchangeAlgorithmsPath.GetValueKind("ServerMinKeyBitLength")))"
        
                    }
                    catch{

                        Write-Host -ForegroundColor Red "+ ServerMinKeyBitLength Value is not available!"

                    }

                }

            }

            # Protocols Settings
            Write-Output "`r"
            Write-Output "Checking Protocols.."

            $Protocols | ForEach-Object {

                $Protocols = $_
                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($DefaultHive, $env:COMPUTERNAME)

                $ProtocolsOperator | ForEach-Object {

                    $ProtocolsPath = $Reg.OpenSubKey("$DefaultHivePath\Protocols\$Protocols\$_", $true)

                    try{
           
                        Write-Host -ForegroundColor Gray "$Protocols | Enabled Value contains: $($ProtocolsPath.GetValue("Enabled")) ($($ProtocolsPath.GetValueKind("Enabled")))"
                    }
                    catch{

                        Write-Host -ForegroundColor Red "$Protocols | Enabled Value is not available!"

                    }
                    try{
           
                        Write-Host -ForegroundColor Gray "$Protocols | DisabledByDefault Value contains: $($ProtocolsPath.GetValue("DisabledByDefault")) ($($ProtocolsPath.GetValueKind("DisabledByDefault")))"
                    }
                    catch{

                        Write-Host -ForegroundColor Red "$Protocols | DisabledByDefault Value is not available!"

                    }

                }

            }

            # Cipher Suites Settings
            Write-Output "`r"
            Write-Output "Checking Cipher Suites.."

            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($DefaultHive, $env:COMPUTERNAME)
            $CipherSuitesPath = $Reg.OpenSubKey($DefaultHivePathCipherSuites, $true)
            $CipherSuitesSplit = ($CipherSuitesPath.GetValue("Functions") -split ",")

            try{
        
                $CipherSuitesPath.GetValueKind("Functions") | Out-Null
                Write-Host -ForegroundColor Gray "Cipher Suites is already configured. Functions Value contains:"
                Write-Host -ForegroundColor Gray ($CipherSuitesSplit | Out-String)
                Write-Host -ForegroundColor Gray "($($CipherSuitesPath.GetValueKind("Functions")))"
        
            }
            catch{

                Write-Host -ForegroundColor Red "Cipher Suites Value is not available!"

            }

        }

    }

}
catch{

    Write-Output "`r"
    Write-Host -ForegroundColor Red "Cant access to registry.."
    Write-Host -ForegroundColor Red $_.Exception.Message

}
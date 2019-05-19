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


### Drivers

I usually download my drivers from [Station-Drivers](https://www.station-drivers.com/) or [Win-RAID](https://www.win-raid.com/). Except BIOS, Keyboard/mouse & GPU driver updates, because (MSI/Corsair/nVidia usually lists them faster on their website(s) - _Yes, I'm an MSI/Corsair "fanboy" [I simply like their products]_)


__Reasons__
- Fast(er) updates
- Some drivers are modified or are smaller in size (driver only packages)
- RSS feed
- Easier access to drivers might require you to login into the website to download a driver


## Root CAs

I remove all the [Trusted Root Certificates](https://www.thewindowsclub.com/manage-trusted-root-certificates-windows) which I don't need (certmgr.msc), there is no utility for it because it is depending on several factors like your ISP/Region etc. I did it with the [trial & error](https://en.wikipedia.org/wiki/Trial_and_error) method to see which websites might break or which certificates I truly need. I do not uninstall those certificates, I put them into the "untrusted" folder because Windows stores those certificates maybe under a temporarily folder/storage, to prevent this just put them into untrusted and mark them as "untrusted".

[RCC](https://www.trustprobe.com/fs1/apps.html) is a program which "inspects"/lists unknown or dangerous certificates which makes your decisions a little bit easier.


## Browser Configuration & Flags

Soon.


### Malware Testing

I do test malware when I have some free time, I typically use VMWare Pro & Sandboxie for this. Both programs are not freeware or open source but I believe that I can trust them.


## Encryption

I use [VeraCrypt](https://en.wikipedia.org/wiki/VeraCrypt) to migrate several attack factors like cold boot, data extraction etc. The [performance](https://en.wikipedia.org/wiki/VeraCrypt#Performance) is [lower than you think](https://github.com/veracrypt/VeraCrypt/issues/136) on "modern hardware", benchmark wise I could not find any difference, however the [loading times from Games/application are a bit slower](https://superuser.com/questions/992587/does-full-disk-encryption-using-veracrypt-on-a-home-pc-affect-my-gaming-performa).

Keep in mind that whenever you use FDE you might need to remove/disable it during an in-place upgrade to avoid possible problems. As a workaround you could restore the original bootloader configuration before you do an upgrade.


### Other tools

Do I need other tools like [O&O shit'sup](https://www.oo-software.com/en/shutup10), [HardenTools](https://github.com/securitywithoutborders/hardentools) [_-insert 5000 other well-known tools here-_]?

The answer is **NO**, if you have done everything correctly you do not need them because due to the fact that we:
- Already integrated the registry tweaks & stuff via NTLite/MSGM ToolKit
- Used GPO's to control Windows "features" & settings
- The firewall takes care of the rest (aka out-(incoming traffic)


Checking everything with GPO (gpedit.msc) is maybe redundant but there is a reason behind why you should do it anyway after each major Windows Update. There could be new stuff which you might want to control do not blindly copy some tweaks, sometimes Windows removes old stuff, other tweaks aren't working anymore etc. there could be multiple reasons.


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




### Guide Updates

This guide will constantly receive updates. Because I'm never satisfied & Windows 10 + my own preferences might change over the time.


Last updated:
* `15.09.2019`


Status:
* `ALPHA 1 (draft)`

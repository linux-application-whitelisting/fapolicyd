# How to Set Up IMA (Integrity Measurement Architecture)

## Step-by-Step Guide

### 1. Ensure `securityfs` is mounted:
```bash
mount -l | grep securityfs
```
Example output:
```
# mount -l | grep securityfs
securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)
```
### 2. Confirm IMA kernel options are configured:
```bash
grep -e IMA -e INTEGRITY /boot/config-$(uname -r)
```
Example output:
```
$ grep -e IMA -e INTEGRITY /boot/config-4.18.0-80.11.2.e18_0.x86_64
CONFIG BLK _DEV_INTEGRIT’

CONFIG _KEXEC_BZIMAGE_VERIFY_SIG=-y

# CONFIG WIMAX is not set

CONFIG _DM_INTEGRITY=m

CONFIG _MLXSW_MINIMAL=m
CONFIG_FB_CFB_IMAGEBLIT=y
CONFIG_FB_SYS_IMAGEBLIT=m
CONFIG_FRAMEBUFFER_CONSOLE_DETECT_PRIMARY=y
CONFIG_HID_PRIMAX=m

CONFIG_INTEGRITY=y
CONFIG_INTEGRITY_SIGNATURE=y

CONFIG INTEGRITY ASYMMETRIC KEYS=y
CONFIG_INTEGRITY_TRUSTED_KEYRING=y
CONFIG INTEGRITY PLATFORM KEYRING=y
CONFIG_INTEGRITY_AUDIT=y

CONFIG_IMA=y
CONFIG_IMA_MEASURE_PCR_IDX=10
CONFIG_IMA_LSM RULES-y_

# CONFIG INA TEMPLATE is not set
CONFIG_IMA_NG_TEMPLATE=y

# CONFIG INA SIG TEMPLATE is not set
CONFIG_IMA_DEFAULT_TEMPLATE="ima-ng”
CONFIG _IMA DEFAULT HASH SHAL=y

# CONFIG_IMA_DEFAULT_HASH_SHA2S6 is not set
CONFIG _IMA_DEFAULT_HASH="shal"

# CONFIG_IMA WRITE POLICY is not set

# CONFIG_IMA READ POLICY is not set
CONFIG_IMA_APPRAISE=y
CONFIG_IMA_APPRAISE_BOOTPARAM=y
CONFIG_IMA_TRUSTED_KEYRING=y

# CONFIG IMA BLACKLIST KEYRING is not set
# CONFIG IMA LOAD _XS09 is not set
```
### 3. Ensure the file system supports `i_version`:

- `ext4` has `i_version` enabled by default.

- Other filesystems like XFS and ext3 require it to be explicitly enabled in `/etc/fstab`.

Example `/etc/fstab` entry:

```
[shearerd@awc-devel fapolicyd]$ cat /etc/fstab

/etc/fstab
Created by anaconda on Wed Apr 22 11:31:17 2020

See man pages fstab(5), findfs(8), mount(8) and/or blkid(8) for more info

After editing this file, run ‘systemctl daemon-reload' to update systemd

#
#
#
#
# Accessible filesystems, by reference, are maintained under '/dev/disk/'
#
#
#
# units generated from this file.

#
/dev/mapper/cl_awc--devel-root / ext4 defaults, iversion ai
UUID=f26b7db8 -4935-4507-9722-79ad9eb5c55b /boot ext4 defaults 12

/dev/mapper/cl_awc--devel-swap swap swap defaults 00
```
Check if `i_version` is enabled:

```bash
mount -l | grep version
```
Example output:
```
[shearerd@awc-devel fapolicyd]$ mount -l | grep version
/dev/mapper/cl_awc--devel-root on / type ext4 (rw,relatime,seclabel,i version)
[shearerd@awc-devel fapolicyd]$ |
```
### 4. Enable IMA in appraise fix mode:

**a.** Backup the grub config:

```bash
cp /etc/default/grub /etc/default/grub.orig
```
**b.** Edit `/etc/default/grub` to include IMA settings:

```
3_TIMEOUT=5
GRUB_DISTRIBUTOR="5 (sed
GRUB_DEFAULT=2aved
GRUB_DISABLE_SUBMENU-true

GRUB_TERMINAL_OUTPUT="console”

GRUB_CMDLINE_EINUX="crashkernel=auto ima_policy=tcb ima_appraise_tcb ima_appraise=fix ima_hash=sha256 ima_audit=1 resume=/dev/mapper/cl-swap rd.ivm.lv=cl/root rd.ivm.iv=cl/swap rhgb quiet”

GRUB_DISABLE_RECOVERY="true"
GRUB_ENABLE_BLSCFG=true

release .*5,,g" /etc/system-release)”
```
**c.** Rebuild grub:

- BIOS-based machines:
  ```bash
grub2-mkconfig -o /boot/grub2/grub.cfg
```
- UEFI-based machines:
  ```bash
grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
```
**d.** Reboot machine:

```bash
reboot
```
**e.** Confirm that the IMA directory structure is present:

```bash
ls /sys/kernel/security/ima
```
**f.** Label files:

```bash
find / -fstype ext4 -type f -uid 0 -exec dd if='{}' of=/dev/null count=0 status=none \;
```
**g.** [OPTIONAL] View measurements:

```bash
tail -f /sys/kernel/security/ima/ascii_runtime_measurements
```
### 5. View contents of security labels:

```bash
# getfattr -m ^security --dump -e hex /bin/bash
getfattr: Removing leading '/' from absolute path names

# file: bin/bash

security.ima=0x040420557151302622baSc281893436a62164538C77bd43452267fa2da6c3cf23ed8
security.selinux=0x73797374656d5£753a6£626a6563745£723a7368656CEcS£E657865635£743a733000

```
### 6. Install fapolicyd
```bash
# dnf install fapolicyd
```

### 7. Set IMA in fapolicyd.conf
```bash
# vim /etc/fapolicyd/fapolicyd.conf
...
integrity = ima
...
```

### 7. Start fapolicyd
```bash
# fapolicyd --debug-deny
```

If no errors, you are good to go.

If following appears hashes are not present in extended attributes.
```bash
10/28/24 06:13:21 [ ERROR ]: IMA integrity checking selected, but the extended attributes can't be read
10/28/24 06:13:21 [ ERROR ]: Exiting due to bad configuration
```

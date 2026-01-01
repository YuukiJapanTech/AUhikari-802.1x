# AUhikari-802.1x
This project analyzes the 802.1x authentication credentials used by au Hikari HGWs and enables obtaining a global IP address without using the HGW.

> [!CAUTION]
> Use of this content is at your own risk!
> * This content is maintained by reverse engineering by enthusiasts.
> * If ISP service is suspended due to 3rd party system connected, you may be subject to punishment under the laws of your country.
> * The creator of this content assumes no responsibility for any problems that may arise from this content.

# Background
## KDDI au Hikari Home
au Hikari Home, provided by KDDI, is an FTTH service that uses optical fiber infrastructure provided by Tokyo Electric Power Company and is delivered over DPoE/CTC-based EPON.

The provided equipment consists of:
* an NEC-manufactured ONU (Broadcom-based) that terminates the EPON line, and
* an NEC-manufactured HGW that provides telephone and Internet services.

The line uses 802.1x authentication, where the HGW’s WAN interface acts as the supplicant. As a result, the service normally cannot be used unless traffic passes through the HGW.
```
[ NNI ] --- [ OLT ] --- [ ONU ] --802.1x-- [ HGW ] --- [ UNI ]
```
Once 802.1x authentication succeeds, a global IPv4 address and an IPv6-PD prefix are assigned to the HGW’s WAN interface. However, since the HGW does not provide a true bridge function, it cannot directly expose the global IP address, and all traffic is routed through the HGW.

For relatively advanced network setups, routing all traffic through the HGW is undesirable. Therefore, as described in this article, methods to communicate without passing through the HGW are often explored.

## Handling of Authentication Credentials in the Past
It has been reported that older HGWs, such as the _Ateam BL170HV_, stored 802.1x authentication credentials in plaintext within internal configuration files.

However, in current HGWs such as the _Ateam BL1000HW_ and _Ateam BL3000HM_, authentication credentials are no longer stored in configuration files.

# Analysis Steps
## Packet Capture
By capturing packets between the ONU and the HGW and examining the 802.1x authentication traffic, the identity and authentication method can be observed.

* Authentication method: MD5 (Identity / Password)
* MAC Address: WAN interface MAC address
* Identity: HGW serial number
* Password: Unknown (hashed)

![HGW Packet](/Files/HGW_Packet.png)

Additionally, the packet source address matches the OLT PON interface MAC address obtained through ONU analysis. This indicates that 802.1x authentication is performed on the OLT side in conjunction with ONU registration.

```
TK2000 APP 3.29 Mar 23 2017 19:30:57  Chip: 4701 B2110816
Mode: App Normal

2000/mpcp/>oltmac
000DB6230001
2000/mpcp/>
```

## Analysis of Ateam BL3000HM
In another project, **[CA8271x](https://github.com/YuukiJapanTech/CA8271x)** analysis of the _Ateam BL3000HM—an integrated ONU + HGW device—revealed_ an interesting ELF file with supplicant in its name.
(The BL3000HM uses an AES-encrypted rootfs. Methods for obtaining the rootfs and shell access are not disclosed here.)
```
root@ATERM-001122:~# m
mail-lock              mke2fs.e2fsprogs       mlg
mail-touchlock         mkexfatfs              modinfo
mail-unlock            mkfifo                 modprobe
make_8021x_wired_conf  mkfs                   more
mcookie                mkfs.cramfs            more.util-linux
md5sum                 mkfs.exfat             mount
mdio-read              mkfs.ext2              mount.util-linux
mdio-read-iros         mkfs.ext2.e2fsprogs    mount_root
mdio-write             mkfs.ext3              mountpoint
mdio-write-iros        mkfs.ext4              mountpoint.util-linux
memtester              mkfs.ubifs             mpicalc
mesg                   mkfwbin                mpstat
mesg.util-linux        mklost+found           mtd_debug
microcom               mknod                  mtd_name2dev.sh
mii-tool               mkpasswd               mtdinfo
mii-tool.net-tools     mkswap                 mtdpart
mkdir                  mkswap.util-linux      mv
mke2fs                 mktemp
root@ATERM-001122:~# which make_8021x_wired_conf
/usr/bin/make_8021x_wired_conf
root@ATERM-001122:~#
```
Although the filename includes `wpa`, it is labeled as a wired supplicant, clearly suggesting 802.1x functionality.
When this ELF file was executed, it generated a configuration file named `wpa_supplicant_wired.conf` under `/etc/`.

## Contents of wpa_supplicant_wired.conf
Inspecting the generated `wpa_supplicant_wired.conf` revealed content that appears to be 802.1x authentication information for a specific interface.
```
ctrl_interface=/var/run/wpa_supplicant_wired
eapol_version=1
wired_11x_kddispec=1
network={
     key_mgmt=IEEE8021X
     eap=MD5
     identity="H03HGxxxxxxx"
     password="1de37849e1abe1f"
}
```
Since the only wired interface on the HGW that performs 802.1x authentication is the WAN interface, it is evident that this configuration corresponds to 802.1x authentication between the OLT and the HGW.

## Analysis of wpa_supplicant_wired.conf
The `wpa_supplicant_wired.conf` file was extracted from the HGW and analyzed using Ghidra.
The Ateam BL3000HM uses a CORTINA CA8289 SoC, with an AARCH64 v8A-LE (64-bit) architecture.
Searching for references to `wpa_supplicant_wired.conf` in the analysis results revealed a single function.

![Analysis of wpa_supplicant_wired.conf](/Files/ghidra.png)

This function performs MD5 calculation and exports `wpa_supplicant_wired.conf`, strongly indicating that it generates the 802.1x authentication credentials.

The function also calls two external functions:
* `pfmg_read_serial_number`
* `pfmg_read_main_macaddr`
This shows that the authentication credentials are derived from the serial number and the MAC address of some interface.
The HGW chassis label lists both the serial number and the WAN interface MAC address, so `pfmg_read_main_macaddr` is very likely returning the WAN interface MAC address.

The relevant function appears to wrap the value obtained from `pfmg_read_main_macaddr` with the string `"HITU2%sSEIRA"`.
```
  pfmg_read_main_macaddr(auStack_c8);
  lVar2 = 0xd;
  puVar5 = auStack_c8;
  puVar6 = auStack_c0;
  do {
    lVar3 = lVar2 + -2;
    __snprintf_chk(puVar6,lVar2,1,0xffffffffffffffff,&DAT_00100eb0,*puVar5);
    lVar2 = lVar3;
    puVar5 = puVar5 + 1;
    puVar6 = puVar6 + 2;
  } while (lVar3 != 1);
  __snprintf_chk(auStack_a0,0x17,1,0x17,"HITU2%sSEIRA",auStack_c0);
```
After that, it calculates an MD5 hash and extracts only the last 15 characters, which are then exported to `wpa_supplicant_wired.conf` as the password.
```
  sVar1 = strlen(acStack_48);
  snprintf(acStack_68,0x20,"%s",acStack_48 + (sVar1 - 0xf));
~
    __fprintf_chk(__stream,1,"     password=\"%s\"\n",acStack_68);
```

From this, it can be concluded that the 802.1x password is:
> The last 15 characters of the MD5 hash of
> `"HITU2[WAN-IF MAC address in lowercase]SEIRA"`

## Verification
Based on the analysis, the 802.1x password can be generated using the following Linux command:
```
$ echo -n "HITU2[WAN-IF MAC-Address Lowercase]SEIRA" | md5sum | cut -c 18-32
```
Example:
```
MAC address: AA:BB:CC:00:11:22

$ echo -n "HITU2aabbcc001122SEIRA" | md5sum | cut -c 18-32
1de37849e1abe1f
```
The authentication parameters are therefore:

* Authentication method: MD5 (Identity / Password)
* MAC Address: WAN interface MAC address
* Identity: HGW serial number
* Password : `$ echo -n "HITU2[WAN-IF MAC-Address]SEIRA" | md5sum | cut -c 18-32`

Using these credentials, 802.1x authentication was attempted.

![Verification PASS Packet](/Files/VerificationPacket.png)
![Verification PASS](/Files/VerificationIP.png)

Success! Authentication succeeded without using the HGW, and an IP address was successfully assigned.
Next, authentication was attempted again after changing the MAC address.

![Fail](/Files/MAC_Failed.png)

An unconditional EAP Failure was returned. This indicates that the MAC address is also being validated.
Therefore, it is not possible to obtain multiple IPv4 addresses.

## Notes / Warnings
KDDI monitors HGWs using TR-069.
As a result, if the HGW is not used with this method, there is a possibility that KDDI may contact you for confirmation.

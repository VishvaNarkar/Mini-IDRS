# 🛡️ Mini IDRS Lab — Cisco Router Configuration

This configuration is designed for the Mini Intrusion Detection & Response System (IDRS) lab.  
⚠️ **Replace all `<PLACEHOLDERS>` before deploying on any router.**

---

## 📌 Router Configuration


Mini IDRS lab router configuration  
Replace any `<PLACEHOLDERS>` before deployment


#### Basic device identity & convenience
```bash
enable
configure terminal
hostname IDRS-RTR
no ip domain-lookup
service timestamps log datetime msec localtime
no ip http server
no ip http secure-server
```

#### Set domain for SSH key generation (change as you like)
```bash
ip domain-name lab.local
```

#### Local admin user — REPLACE secret before publishing/deploying
```bash
username admin privilege 15 secret <REPLACE_WITH_ADMIN_SECRET>
```

#### Enable secret for privileged mode — REPLACE
```bash
enable secret <REPLACE_WITH_ENABLE_SECRET>
```

#### Generate RSA keys for SSH (run once in console if required)
```bash
crypto key generate rsa modulus 2048
```

#### SSH config:
```bash
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
```

#### Logging
```bash
logging buffered 8192 debugging
no logging console
service password-encryption

```

! ---------------------------  
! Interfaces
! --------------------------- !

#### Internal lab interface (connected to VMnet2 / hub)
```bash
interface FastEthernet0/0
 description INTERNAL-LAB-SEGMENT
 ip address 192.168.10.1 255.255.255.0
 no shutdown
 ip nat inside
 ip access-group IDS_BLOCK_LIST in

```

#### External interface (connected to VMnet8 / NAT for Internet)
```bash
interface FastEthernet0/1
 description EXTERNAL-TO-VMNET8-NAT
 ip address dhcp
 no shutdown
 ip nat outside
```

! ---------------------------
! DHCP for lab hosts (internal network)
! --------------------------- !

#### Exclude network device addresses from DHCP allocation
```bash
ip dhcp excluded-address 192.168.10.1 192.168.10.9
ip dhcp pool LAB_POOL
 network 192.168.10.0 255.255.255.0
 default-router 192.168.10.1
 dns-server 8.8.8.8
 lease 7
```

! --------------------------- 
! NAT/PAT configuration 
! --------------------------- !

#### Create access-list for inside (lab) networks to be NATed
```bash
access-list 100 permit 192.168.10.0 0.0.0.255 any
```

#### NAT overload (PAT) using the external interface
```bash
ip nat inside source list 100 interface FastEthernet0/1 overload
```
! --------------------------- 
! IDS ACL (pre-created named ACL) 
! --------------------------- !

```bash
ip access-list extended IDS_BLOCK_LIST
 remark IDS dynamic block list - script will insert deny entries with sequence numbers
 permit ip any any
exit
```

! --------------------------- 
! VTY / console 
! ---------------------------!
```bash
line vty 0 4
 transport input ssh
 login local
 exec-timeout 10 0
 logging synchronous
```

#### Save config at end in console
```bash
write memory  
```
-------------------------------------------------------------------

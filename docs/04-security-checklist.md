# BÁO CÁO NGHIÊN CỨU – BƯỚC 4
## Xác định các hạng mục kiểm tra bảo mật cho từng loại thành phần ứng dụng Desktop trên Linux

**Phạm vi:** Linux Desktop Application  
**Giai đoạn:** Bước 4 – Security Check Definition & Mapping  
**Mục tiêu tài liệu:** Xác định các hạng mục security cần kiểm tra cho từng loại component đã được phân loại ở Bước 3, trước khi lựa chọn tool ở Bước 5.

---

# 1. Tóm tắt dành cho Lead

Bước 4 nhằm trả lời câu hỏi:

> **Với từng loại thành phần đã được xác định ở Bước 3, cần kiểm tra những nội dung bảo mật nào?**

Bước này chưa chọn tool cụ thể.

Mục tiêu của Bước 4 là xây một lớp trung gian:

```text
Component
    ↓
Security Check
    ↓
Expected Secure State
    ↓
Evidence Required
    ↓
Finding Condition
```

Kết quả của Bước 4 giúp đảm bảo:

- Không bỏ sót nhóm kiểm tra quan trọng.
- Không chạy tool theo kiểu “có tool gì thì scan tool đó”.
- Mỗi component chỉ được đưa vào đúng nhóm kiểm tra phù hợp.
- Có thể chuẩn hóa finding ở các bước sau.
- Có nền tảng rõ ràng để chọn tool ở Bước 5.

---

# 2. Vị trí của Bước 4 trong toàn bộ quy trình

```text
Bước 1
Nhận diện ứng dụng
       ↓
Bước 2
Extract / Unpack
       ↓
Bước 3
Phân loại component
       ↓
Bước 4
Xác định Security Checklist
       ↓
Bước 5
Chọn Tool
```

Bước 4 không trả lời:

```text
Tool nào chạy check này?
```

Bước 4 chỉ trả lời:

```text
Check cái gì?
Expected state là gì?
Evidence nào cần lấy?
Khi nào được coi là finding?
```

---

# 3. Các nhóm checklist chính

Đề xuất 18 nhóm kiểm tra:

| ID | Hạng mục |
|---|---|
| CHK-01 | Application Information |
| CHK-02 | Package / Metadata / Manifest |
| CHK-03 | Permission / Privilege |
| CHK-04 | Entry Point / Handler |
| CHK-05 | Native Binary Hardening |
| CHK-06 | OS/API Capability |
| CHK-07 | Code Security |
| CHK-08 | Secret / Hardcoded Sensitive Data |
| CHK-09 | Network Security |
| CHK-10 | Certificate / Key Material |
| CHK-11 | Local Storage / Database |
| CHK-12 | Dependency / Library / SBOM |
| CHK-13 | Sensitive File Exposure |
| CHK-14 | Service / Startup Security |
| CHK-15 | IPC / D-Bus |
| CHK-16 | Update Mechanism |
| CHK-17 | Malware / Suspicious Capability |
| CHK-18 | Domain / IP / Port / IOC Inventory |

---

# 4. CHK-01 – Application Information

Áp dụng cho:

```text
Package
Executable
Application Metadata
```

## Thông tin cần thu thập

```text
Application Name
Package ID
Version
Build
Architecture
Package Type
Runtime
Framework
Primary Executable
SHA256
Build ID
Entry Point
Bundled Runtime
```

Đây chủ yếu là inventory, không phải vulnerability.

---

# 5. CHK-02 – Package / Manifest / Metadata Analysis

Áp dụng cho:

```text
DEB
RPM
Snap
Flatpak
AppImage
.desktop
package.json
MANIFEST.MF
```

## Nội dung cần kiểm tra

```text
Application ID
Version
Architecture
Entry Command
Declared Dependency
Installation Location
Maintainer Scripts
Package Hooks
Runtime Requirement
Environment Variables
Application Handlers
```

Linux không có một manifest duy nhất giống Android.

Metadata có thể nằm ở:

```text
DEBIAN/control
meta/snap.yaml
Flatpak metadata
.desktop
RPM metadata
package.json
MANIFEST.MF
```

---

# 6. CHK-03 – Permission / Privilege Analysis

Đây là Linux equivalent của Application Permission.

## Nội dung cần kiểm tra

```text
SetUID
SetGID
Linux Capabilities
File Ownership
File Permission
World-writable File
Privileged Helper
sudoers
Polkit
systemd Service User
AppArmor
SELinux
Snap Confinement
Flatpak Permissions
```

## Các câu hỏi cần trả lời

```text
Binary nào chạy với quyền root?
File nào có SetUID?
Binary nào có capability đặc biệt?
App có quyền filesystem quá rộng không?
Flatpak có quyền filesystem host không?
Snap có dùng classic confinement không?
```

---

# 7. CHK-04 – Entry Point / Handler

Đây là Linux equivalent gần nhất với Browsable Activity.

## Nội dung cần kiểm tra

```text
.desktop Exec
URL Scheme Handler
MIME Handler
File Handler
Command-line Parameter
D-Bus Activation
Autostart
Custom URI Scheme
```

Ví dụ:

```text
x-scheme-handler/product
```

Cần xem:

```text
URI input được truyền vào command thế nào?
Có shell interpretation không?
Có validate input không?
```

---

# 8. CHK-05 – Native Binary Hardening

Áp dụng cho:

```text
ELF Executable
Shared Object
Native Plugin
.node
JNI Library
```

## Checklist

```text
RELRO
Stack Canary
NX
PIE
FORTIFY
RPATH
RUNPATH
Executable Stack
RWX Segment
Stripped Symbols
Debug Symbols
Build ID
Static/Dynamic Linkage
DT_NEEDED
Interpreter
SONAME
```

---

# 9. RPATH / RUNPATH

Cần đánh giá:

```text
Absolute Path
Relative Path
Current Directory
/tmp
/home/...
World-writable Path
User-controlled Path
```

Ví dụ:

```text
RPATH=/tmp/lib
RUNPATH=.
```

có thể liên quan library hijacking tùy context.

Không kết luận vulnerability chỉ vì tồn tại RPATH/RUNPATH.

---

# 10. Executable Stack / RWX

Cần kiểm tra:

```text
Executable Stack
Writable + Executable Segment
RWX Mapping
```

Đây là hardening indicator.

Severity thực tế sẽ được đánh giá ở Bước 6.

---

# 11. CHK-06 – OS/API Capability Analysis

Đây là equivalent của việc xem application sử dụng API hệ điều hành nào.

Nguồn phân tích có thể gồm:

```text
Imported Function
Symbol
Library Dependency
Syscall Wrapper
```

## Command Execution

```text
system
popen
execve
execvp
execl
posix_spawn
```

## Process

```text
fork
clone
kill
ptrace
```

## Filesystem

```text
open
openat
fopen
unlink
chmod
chown
rename
```

## Network

```text
socket
connect
bind
listen
accept
send
recv
getaddrinfo
```

## Dynamic Loading

```text
dlopen
dlsym
```

## Environment

```text
getenv
setenv
```

## Privilege

```text
setuid
setgid
setresuid
capset
```

## Memory

```text
mmap
mprotect
```

## Crypto/TLS

```text
EVP_*
AES_*
RSA_*
SSL_*
TLS_*
```

---

# 12. API Presence không đồng nghĩa Vulnerability

Ví dụ phát hiện:

```text
system()
```

chỉ cho thấy application có khả năng gọi shell command.

Không được kết luận ngay:

```text
Command Injection
```

Finding cần thêm context, ví dụ:

```text
Untrusted Input
      ↓
system()
```

---

# 13. CHK-07 – Code Security Analysis

Áp dụng cho:

```text
JavaScript
TypeScript
Python
Shell
Java
C/C++ source nếu có
.NET
```

## Các hạng mục cần kiểm tra

```text
Command Injection
Path Traversal
Unsafe File Operation
Unsafe Deserialization
SQL Injection
XSS
SSRF
Weak Random
Temporary File Issue
Insecure Permission
TLS Verification Bypass
Unsafe Dynamic Loading
Sensitive Logging
Debug Functionality
Credential Handling
```

---

# 14. Electron Security Checklist

Nếu component là Electron:

```text
nodeIntegration
contextIsolation
sandbox
webSecurity
allowRunningInsecureContent
preload
IPC
remote module
webview
CSP
navigation
external URL handling
shell.openExternal
certificate verification
```

Các vùng cần xem riêng:

```text
Main Process
Renderer Process
preload.js
IPC Bridge
```

---

# 15. Electron IPC

Cần kiểm tra:

```text
ipcMain.handle
ipcMain.on
ipcRenderer.invoke
ipcRenderer.send
contextBridge
```

Các câu hỏi:

```text
Renderer có gọi được function nguy hiểm không?
IPC handler có validate input không?
Có expose filesystem không?
Có expose shell command không?
Có expose credential không?
```

---

# 16. Shell Script Checklist

Đối với `.sh`:

```text
eval
sh -c
bash -c
Unquoted Variable
Unsafe Temporary File
curl | sh
wget | sh
chmod 777
sudo
User-controlled Command Argument
```

---

# 17. Python Checklist

Kiểm tra:

```text
os.system
subprocess
shell=True
eval
exec
pickle
unsafe yaml load
tempfile misuse
TLS verify=False
hardcoded secret
```

---

# 18. Java Checklist

Kiểm tra:

```text
Runtime.exec
ProcessBuilder
ObjectInputStream
XML Parser
SQL Query Construction
TLS Validation
Weak Crypto
Temporary File
Logging
```

---

# 19. CHK-08 – Hardcoded Secret / Sensitive Data

Áp dụng gần như toàn bộ:

```text
Source
JS Bundle
Config
Binary String
Database
Script
Certificate Container
```

## Nội dung cần tìm

```text
Password
API Key
Access Token
Refresh Token
Private Key
JWT
AWS Key
Cloud Credential
Database Credential
Encryption Key
OAuth Secret
SSH Key
```

Cần phân biệt:

```text
Actual Secret
Test Credential
Placeholder
Public Identifier
False Positive
```

---

# 20. Hardcoded Crypto Material

Cần chú ý:

```text
Static AES Key
Static IV
Hardcoded RSA Private Key
Hardcoded HMAC Key
Embedded Client Secret
```

Ví dụ:

```text
KEY = "1234567890abcdef"
IV  = "0000000000000000"
```

---

# 21. CHK-09 – Network Security

Cần inventory protocol:

```text
http://
https://
ws://
wss://
ftp://
tcp
udp
mqtt
grpc
```

## Nội dung kiểm tra

```text
Plain HTTP
Plain WebSocket
TLS Verification Disabled
Certificate Validation Bypass
Hostname Verification Disabled
Custom CA
Certificate Pinning
Weak TLS Version
Weak Cipher Configuration
Proxy Bypass
Hardcoded Endpoint
```

---

# 22. HTTP / HTTPS Classification

Không phải mọi `http://` đều là vulnerability.

Cần phân biệt:

```text
Loopback
Private Network
Production External
Development
Documentation / Reference
```

---

# 23. WebSocket

Kiểm tra:

```text
ws://
wss://
```

Ngoài transport còn cần xem:

```text
Authentication
Origin Validation
Token Handling
```

nếu code/context cho phép.

---

# 24. CHK-10 – Certificate / Key Analysis

Áp dụng:

```text
.pem
.crt
.cer
.der
.p12
.pfx
.jks
.key
```

## Checklist

```text
Certificate Type
Subject
Issuer
Expiration
Signature Algorithm
Key Length
CA Flag
Self-signed
Private Key Presence
Private Key Encryption
Keystore Password Exposure
Certificate Pinning Material
```

Đặc biệt cần chú ý:

```text
Private Key Bundled in Application
```

---

# 25. CA Certificate

Bundled CA không mặc định là issue.

Cần phân biệt:

```text
Public CA
Internal CA
Self-signed CA
Client-specific Trust Anchor
```

---

# 26. CHK-11 – Database / Local Storage

Áp dụng:

```text
SQLite
LevelDB
IndexedDB
JSON Storage
Cache
Local File
```

## Nội dung cần kiểm tra

```text
Password
Token
Session
Cookie
API Key
PII
Internal Endpoint
Sensitive Document
Encryption Status
Plaintext Credential
```

---

# 27. Electron Storage

Có thể gặp:

```text
Cookies
Local Storage
IndexedDB
Session Storage
LevelDB
```

Cần kiểm tra:

```text
Authentication Token Stored Plaintext?
Refresh Token?
Cookie?
Sensitive User Data?
Encryption?
```

---

# 28. CHK-12 – Dependency / Library / SBOM

Đây là nhóm kiểm tra library version/dependency.

## Inventory

```text
Component Name
Version
Package Ecosystem
Source
Bundled/System
License
```

## Security

```text
Known CVE
End-of-life
Unsupported Version
Duplicate Version
Known Vulnerable Transitive Dependency
```

Nguồn dependency có thể đến từ:

```text
.so
package.json
package-lock.json
JAR
MANIFEST
Python Metadata
Go Build Info
Rust Metadata
.NET deps
```

---

# 29. Bundled vs System Dependency

Cần phân biệt.

Ví dụ application bundle có:

```text
libssl.so.1.1
```

→ Bundled Dependency.

Trong khi DEB chỉ khai báo:

```text
Depends: libssl3
```

→ System Dependency.

Điều này ảnh hưởng đến remediation sau này.

---

# 30. CHK-13 – Sensitive File Analysis

Các file đáng chú ý:

```text
.env
*.key
*.pem
*.pfx
*.p12
id_rsa
credentials
database
backup
.bak
.old
production config
debug file
source map
log
core dump
```

Phải kiểm tra content/type chứ không chỉ filename.

---

# 31. Debug / Source Artifact

Các artifact như:

```text
*.map
*.debug
source code
symbol file
```

có thể làm lộ:

```text
Source Path
Function Name
Internal API
Comment
Source Code
Build Path
Developer Username
```

---

# 32. CHK-14 – Service / Startup Security

Áp dụng:

```text
systemd service
systemd timer
init script
autostart
cron
```

## Checklist

```text
User=
Group=
ExecStart=
Environment=
EnvironmentFile=
WorkingDirectory=
Permission
Writable Executable
Writable Service File
Relative Executable Path
Root Service
Shell Command
Capabilities
Restart Behavior
```

---

# 33. systemd Hardening

Có thể đánh giá:

```text
NoNewPrivileges
PrivateTmp
ProtectSystem
ProtectHome
CapabilityBoundingSet
RestrictAddressFamilies
ProtectKernelTunables
ProtectControlGroups
PrivateDevices
```

Thiếu một hardening option không tự động là vulnerability.

Đây là hardening assessment.

---

# 34. CHK-15 – Polkit / Authorization / IPC

## Polkit

Kiểm tra:

```text
Action
Default Authorization
allow_any
allow_inactive
allow_active
Authentication Requirement
Associated Helper
Input Validation
```

Ví dụ cần review kỹ:

```text
allow_any=yes
```

khi action có quyền cao.

---

# 35. D-Bus / IPC Security

Áp dụng:

```text
D-Bus
Unix Socket
Named Pipe
Local TCP
Shared Memory
```

## Checklist

```text
Service Name
Bus Type
Activation
Authorization
Caller Validation
Input Validation
Privileged Method
Filesystem Access
Command Execution
```

Boundary quan trọng:

```text
Unprivileged User
      ↓
D-Bus
      ↓
Root Service
```

---

# 36. Unix Socket

Nếu application sử dụng:

```text
/run/product.sock
/tmp/product.sock
```

cần kiểm tra:

```text
File Permission
Owner
Authentication
Input Validation
Predictable Location
World-writable Access
```

---

# 37. CHK-16 – Update Mechanism

Desktop app thường có updater.

## Checklist

```text
Update URL
HTTP/HTTPS
Signature Validation
Hash Validation
Certificate Validation
Download Location
Temporary File Handling
Update Package Validation
Rollback Protection
Privilege Boundary
```

Đặc biệt flow:

```text
Download Update
      ↓
Execute Installer
```

cần review kỹ.

---

# 38. Electron Auto-update

Nếu dùng Electron:

```text
electron-updater
Squirrel
custom updater
```

cần kiểm tra:

```text
latest.yml
app-update.yml
Provider URL
Signature Mechanism
TLS
Update Channel
```

---

# 39. CHK-17 – Malware / Suspicious Capability

Bước 4 chỉ xác định hạng mục, chưa chọn scanner.

Cần đánh giá:

```text
Known Malware Signature
Suspicious Binary
Packed/Obfuscated Artifact
Suspicious Command Execution
Persistence
Credential Access
Process Injection
Downloader
Reverse Connection
Crypto Mining Behavior
```

---

# 40. CHK-18 – Domain / IP / Port / IOC Inventory

Cần extract:

```text
Domain
URL
IPv4
IPv6
Port
Email
URI
WebSocket URL
```

Sau đó classify:

```text
Production
Development
Staging
Internal
Loopback
Third-party
Telemetry
Update
API
Authentication
```

IOC inventory không tự động là vulnerability.

---

# 41. Logging

Theo yêu cầu ban đầu cần kiểm tra:

```text
Logging Framework
Log Location
Log Level
Debug Mode
Credential Logged
Token Logged
Request/Response Logged
PII Logged
Internal Path
Stack Trace Exposure
```

---

# 42. Crypto

Cần xác định:

```text
Crypto Library
Algorithm
Mode
Key Length
Hash Algorithm
Random Generation
Static Key
Static IV
ECB
Deprecated Algorithm
Custom Crypto
Password Hashing
TLS Config
```

Các yếu tố cần review:

```text
DES
3DES
RC4
MD5
SHA-1 Security Usage
AES-ECB
Static IV
Hardcoded Key
```

Cần xét usage context trước khi tạo finding.

---

# 43. File Permission

Bước 2 giữ metadata, Bước 4 đánh giá:

```text
World-writable
World-readable Sensitive File
SetUID
SetGID
Sensitive File Readable by All
Private Key Permission
Config Writable by Low-privilege User
Executable Writable by Low-privilege User
```

Combination đáng chú ý:

```text
Root Service
+
Writable Executable
```

---

# 44. Plugin / Extension Security

Nếu có plugin/extension/module:

```text
Plugin Discovery Path
Plugin Signature
Plugin Validation
Writable Plugin Directory
Arbitrary Plugin Loading
Dynamic Library Loading
Search Order
Extension Permission
```

---

# 45. Dynamic Library Loading

Cần kiểm tra:

```text
dlopen()
LD_LIBRARY_PATH
LD_PRELOAD
RPATH
RUNPATH
Plugin Directory
Current Working Directory
User-writable Library Path
```

Có thể liên quan đến:

```text
Shared Library Hijacking
```

trên Linux.

---

# 46. Temporary Files

Cần chú ý:

```text
/tmp
/var/tmp
XDG_RUNTIME_DIR
```

## Checklist

```text
Predictable Filename
Symlink Attack
World-writable Temp File
Insecure Permission
Race Condition
TOCTOU
```

---

# 47. Environment Variables

Các biến cần chú ý:

```text
PATH
LD_LIBRARY_PATH
LD_PRELOAD
HOME
TMPDIR
XDG_*
Proxy Environment
Credential Environment
```

Đặc biệt nếu privileged process tin tưởng environment từ user.

---

# 48. Mapping 14 yêu cầu ban đầu sang Linux

| Yêu cầu ban đầu | Equivalent trong Bước 4 |
|---|---|
| App Information | CHK-01 |
| Signer Certificate | Certificate / Package Signing |
| Application Permission | CHK-03 |
| Android APIs | CHK-06 OS/API Capability |
| Browsable Activities | CHK-04 Entry Point / Handler |
| Network Security | CHK-09 |
| Manifest Analysis | CHK-02 |
| Code Analysis | CHK-07 |
| Shared Library | CHK-05 + CHK-12 |
| File Analysis | CHK-13 |
| Malware | CHK-17 |
| Domain/IP/Port/Email | CHK-18 |
| Hardcoded Secret | CHK-08 |
| Library Version | CHK-12 |

Như vậy toàn bộ yêu cầu mẫu ban đầu đã có equivalent trên Linux.

---

# 49. Routing từ Bước 3 sang Bước 4

## ELF Executable

```text
ELF Executable
     ↓
CHK-05 Hardening
CHK-06 API Capability
CHK-12 Dependency
CHK-17 Suspicious Capability
```

## Shared Object

```text
Shared Object
     ↓
CHK-05 Hardening
CHK-06 API
CHK-12 Dependency
```

## JavaScript / Source

```text
JavaScript
     ↓
CHK-07 Code
CHK-08 Secret
CHK-09 Network
CHK-17 Suspicious Code
```

## Config

```text
Config
     ↓
CHK-08 Secret
CHK-09 Network
CHK-10 Certificate
CHK-18 IOC
```

## systemd Service

```text
systemd service
     ↓
CHK-03 Privilege
CHK-14 Service Security
```

## D-Bus Service

```text
D-Bus Service
     ↓
CHK-03 Privilege
CHK-15 IPC
```

## Private Key

```text
Private Key
     ↓
CHK-08 Secret
CHK-10 Certificate / Key
CHK-13 Sensitive File
```

Một component có thể đi vào nhiều checklist.

---

# 50. Checklist Matrix tổng hợp

| Component | Security Checks |
|---|---|
| ELF Executable | Hardening, API, Dependency, Privilege |
| Shared Object | Hardening, Dependency, Symbol, Loading |
| JavaScript | Code, Secret, Network, Crypto |
| Python | Code, Secret, Command Execution |
| Shell | Command Execution, Permission, Temp File |
| Java | Code, Crypto, Deserialization, Dependency |
| Config | Secret, Network, Debug, Crypto |
| Certificate | Trust, Expiry, Key, Algorithm |
| Private Key | Exposure, Protection, Reuse |
| SQLite | Sensitive Storage |
| `.desktop` | Handler, URI, Command Argument |
| systemd | Privilege, Execution, Hardening |
| Polkit | Authorization |
| D-Bus | IPC / Privilege Boundary |
| Plugin | Loading / Permission / Validation |
| Updater | Integrity / Signature / Transport |
| Dependency Metadata | SBOM / CVE |
| Source Map | Source Disclosure |
| Log Config | Sensitive Logging |
| Network Config | Protocol / TLS / Endpoint |
| Unknown Binary | Identification / Suspicious Analysis |

---

# 51. Severity chưa thuộc trọng tâm Bước 4

Bước 4 không nên gán ngay:

```text
Critical
High
Medium
Low
```

Ví dụ:

```text
No PIE
```

là một hardening issue candidate.

Trong khi:

```text
Reusable Private Key Bundled
```

có thể nghiêm trọng hơn rất nhiều.

Severity thực tế thuộc:

> **Bước 6 – Đánh giá kết quả kiểm tra**

---

# 52. Data Model Checklist đề xuất

Mỗi check có thể được mô tả theo dạng:

```json
{
  "id": "ELF-RELRO-001",
  "component": "elf",
  "category": "binary_hardening",
  "check": "RELRO",
  "expected": "Full RELRO",
  "evidence": [
    "ELF program headers",
    "dynamic section"
  ],
  "finding_condition": "No RELRO or Partial RELRO",
  "severity": "defer_to_step6"
}
```

Ví dụ network:

```json
{
  "id": "NET-HTTP-001",
  "component": "network_endpoint",
  "category": "network_security",
  "check": "Plain HTTP endpoint",
  "expected": "HTTPS for sensitive remote communication",
  "evidence": [
    "URL",
    "source file",
    "usage context"
  ]
}
```

---

# 53. Mỗi Check cần tối thiểu 4 trường

```text
Check
Expected Secure State
Evidence
Finding Condition
```

Ví dụ:

```text
Check:
Private Key Bundled

Expected:
Không phân phối reusable private credential trong client

Evidence:
File path + key type + fingerprint

Finding:
Private key thực sự được bundle và sử dụng như shared/reusable credential
```

Không nên chỉ ghi:

```text
Check Private Key
```

---

# 54. Priority của Check

Có thể chia:

```text
Mandatory
Recommended
Context-dependent
```

## Mandatory

```text
Secret
Binary Hardening
Dependency Inventory
Sensitive File
Network Endpoint
Privilege
```

## Context-dependent

```text
D-Bus
Polkit
systemd
Electron
Java
```

chỉ áp dụng khi component tồn tại.

---

# 55. Tiêu chí hoàn thành Bước 4

Bước 4 được xem là hoàn thành khi:

1. Mỗi component ở Bước 3 có ít nhất một nhóm kiểm tra hoặc được đánh dấu `No Security Check Required`.
2. Mỗi check có:
   - mục tiêu,
   - expected secure state,
   - evidence cần lấy,
   - finding condition.
3. Các hạng mục Linux-specific được phủ:
   - ELF,
   - systemd,
   - Polkit,
   - D-Bus,
   - `.desktop`,
   - package permission,
   - shared library.
4. Các hạng mục cross-platform được phủ:
   - secret,
   - network,
   - crypto,
   - dependency,
   - storage,
   - malware,
   - code.
5. Chưa phụ thuộc vào scanner/tool cụ thể.

---

# 56. Tình hình đã hoàn thành ở Bước 4

Đến thời điểm hiện tại đã xác định được:

## Nhóm checklist chính

- Application Information.
- Package / Metadata.
- Permission / Privilege.
- Entry Point / Handler.
- Native Binary Hardening.
- OS/API Capability.
- Code Security.
- Secret / Hardcoded Sensitive Data.
- Network Security.
- Certificate / Key.
- Local Storage.
- Dependency / SBOM.
- Sensitive File.
- Service / Startup.
- IPC / D-Bus.
- Update Mechanism.
- Malware / Suspicious Capability.
- Domain / IP / Port / IOC.

## Linux-specific checks đã đưa vào scope

- ELF hardening.
- RPATH/RUNPATH.
- SetUID/SetGID.
- Linux capabilities.
- systemd.
- Polkit.
- D-Bus.
- Unix socket.
- `.desktop` handlers.
- Shared library loading.
- AppArmor/SELinux-related configuration.
- Snap/Flatpak permission model.

## Framework-specific checks đã đưa vào scope

- Electron.
- Java.
- Python.
- Shell script.
- Native addon/plugin.

---

# 57. Kết luận

Nếu:

```text
Bước 1:
Tôi đang cầm cái gì?

Bước 2:
Tôi bung được gì?

Bước 3:
Những thứ bung ra là gì?
```

thì Bước 4 trả lời:

> **Với từng thứ đó, về security phải kiểm tra những gì?**

Output chính của Bước 4 là:

```text
Component
   ↓
Security Checklist
   ↓
Expected Secure State
   ↓
Evidence Required
   ↓
Finding Condition
```

Bước 4 là baseline quan trọng trước khi lựa chọn công cụ.

---

# 58. Phạm vi chuyển tiếp sang Bước 5

Bước 5 sẽ tập trung vào:

> **Tìm và đánh giá các tool có thể thực hiện từng hạng mục kiểm tra đã được xác định ở Bước 4.**

Ví dụ:

```text
Security Check
      ↓
Candidate Tools
      ↓
Coverage
      ↓
Output Format
      ↓
False-positive Risk
      ↓
Automation Capability
      ↓
DefectDojo Compatibility
```

Bước 5 mới map từng hạng mục sang các tool phù hợp.

# BÁO CÁO NGHIÊN CỨU – BƯỚC 3
## Phân tích và phân loại các thành phần sau khi Extract ứng dụng Desktop trên Linux

**Phạm vi:** Linux Desktop Application  
**Giai đoạn:** Bước 3 – Component Analysis & Classification  
**Mục tiêu tài liệu:** Phân tích toàn bộ artifact thu được sau Bước 2, xác định loại thành phần, vai trò, nguồn gốc, mức độ ưu tiên và nhóm kiểm tra tương ứng để chuẩn bị cho Bước 4.

---

# 1. Tóm tắt dành cho Lead

Bước 3 nhằm trả lời câu hỏi:

> **Sau khi ứng dụng đã được extract/unpack, bên trong có những thành phần nào, mỗi thành phần có vai trò gì trong ứng dụng và cần được chuyển sang nhóm kiểm tra nào ở bước tiếp theo?**

Đây là bước **phân loại và hiểu cấu trúc ứng dụng**, chưa thực hiện kiểm tra lỗ hổng.

Kết quả Bước 3 cần cho biết:

- Có bao nhiêu executable, shared library, script, config, certificate, database, plugin...
- Thành phần nào là application code.
- Thành phần nào thuộc runtime/framework.
- Thành phần nào là third-party dependency.
- Thành phần nào có liên quan đến privilege, service, IPC, updater, network, storage...
- Thành phần nào cần được ưu tiên kiểm tra.
- Thành phần nào sẽ được chuyển sang nhóm kiểm tra nào ở Bước 4.

Bước 3 tạo ra:

```text
Component Inventory
+
Component Tree
+
Analysis Routing Map
```

---

# 2. Input của Bước 3

Input của Bước 3 là artifact tree được tạo từ Bước 2.

Ví dụ:

```text
application/
├── AppRun
├── application.desktop
├── usr/
│   ├── bin/
│   │   └── application
│   ├── lib/
│   │   ├── libabc.so
│   │   └── libssl.so.3
│   └── share/
├── resources/
│   ├── app.asar
│   ├── config.json
│   └── cert.pem
└── plugins/
    └── plugin.so
```

Bước 3 phải biến cấu trúc trên thành các nhóm có ý nghĩa:

```text
Executable
Shared Library
Application Metadata
Configuration
Certificate
Embedded Application
Plugin
Resource
...
```

---

# 3. Mục tiêu chính

Bước 3 có 5 mục tiêu:

1. **Xác định file/component type**
2. **Xác định role của component**
3. **Xác định nguồn gốc component**
4. **Xác định priority phân tích**
5. **Routing sang nhóm kiểm tra ở Bước 4**

Bước 3 chưa đánh giá:

- Vulnerability.
- CVE.
- Secret.
- Malware.
- Hardening.
- Code weakness.

---

# 4. Output mong đợi

Ví dụ:

```text
Component Inventory
────────────────────────────────────

Native Executables     : 5
Shared Libraries       : 126
Scripts                : 7
JavaScript Files       : 183
Config Files           : 14
Certificates           : 3
Databases              : 2
Desktop Entries        : 1
Systemd Units          : 2
Polkit Components      : 1
JAR Files              : 4
Unknown Binaries       : 3
```

Với từng artifact quan trọng:

```text
Path:
usr/bin/application

Type:
ELF Executable

Role:
Primary Application Binary

Architecture:
x86_64

Origin:
ABC.AppImage

Next Analysis Group:
Native Binary
```

---

# 5. Taxonomy đề xuất

| ID | Nhóm thành phần |
|---|---|
| CMP-01 | Native Executable |
| CMP-02 | Shared Library |
| CMP-03 | Script / Source Code |
| CMP-04 | Application Framework / Embedded App |
| CMP-05 | Configuration |
| CMP-06 | Application Metadata |
| CMP-07 | Certificate / Key Material |
| CMP-08 | Database / Local Storage |
| CMP-09 | Dependency / Package Metadata |
| CMP-10 | Service / Startup Components |
| CMP-11 | Privilege / Authorization Components |
| CMP-12 | Plugin / Extension |
| CMP-13 | Network-related Configuration |
| CMP-14 | Resource / Asset |
| CMP-15 | Nested Container |
| CMP-16 | Unknown / Unclassified |

---

# 6. CMP-01 – Native Executable

Ví dụ:

```text
usr/bin/application
bin/launcher
opt/product/product
```

Cần phân biệt role:

```text
Primary executable
Helper executable
Updater
Crash handler
Sandbox helper
CLI tool
Installer helper
```

Ví dụ Electron:

```text
application
chrome-sandbox
chrome_crashpad_handler
```

Không nên xem tất cả ELF là application binary chính.

## Metadata nên ghi

- Path.
- ELF type.
- Architecture.
- Role.
- Entry-point relation.
- Bundled/System.

---

# 7. CMP-02 – Shared Library

Ví dụ:

```text
libabc.so
libQt6Core.so.6
libcrypto.so.3
libssl.so.3
```

Cần phân biệt:

```text
Vendor library
Third-party library
System/runtime library
Application-specific library
Plugin library
```

## Metadata

- Path.
- SONAME nếu có.
- Architecture.
- Probable component name.
- Probable version.
- Bundled/System.
- Role.

Bước 3 chưa đánh giá CVE.

---

# 8. CMP-03 – Script / Source Code

Có thể gặp:

```text
.sh
.py
.js
.ts
.pl
.rb
.lua
```

Hoặc file không extension nhưng có shebang.

Nên phân loại role:

```text
Launcher
Install script
Maintenance script
Application code
Migration script
Update script
Helper script
```

Đây là nhóm quan trọng cho code analysis ở bước sau.

---

# 9. CMP-04 – Application Framework / Embedded App

Sau extract có thể phát hiện application logic nằm trong framework/container.

Ví dụ:

## Electron

```text
resources/app.asar
package.json
main.js
preload.js
node_modules/
```

## Java

```text
application.jar
```

## .NET

```text
Application.dll
Application.deps.json
Application.runtimeconfig.json
```

## Python packaged app

```text
.pyc
PYZ
embedded runtime
```

Bước 3 phải xác định được quan hệ:

```text
Outer Package:
AppImage

Embedded Application:
Electron
```

---

# 10. Electron Components

Electron nên được phân loại chi tiết hơn.

Các thành phần đáng chú ý:

```text
package.json
main.js
preload.js
renderer bundles
node_modules/
resources/
native addons
```

Native Node addon:

```text
*.node
```

thường là native binary.

Ví dụ:

```text
node_modules/keytar/build/Release/keytar.node
```

có thể classify:

```text
Type:
ELF Shared Object

Role:
Node Native Addon

Analysis Groups:
Native Binary
Dependency Analysis
```

---

# 11. CMP-05 – Configuration

Các format thường gặp:

```text
.conf
.ini
.cfg
.json
.yaml
.yml
.toml
.xml
.properties
.env
```

Không được xem mọi JSON là config.

Ví dụ:

```text
package.json
```

là metadata/dependency.

Trong khi:

```text
settings.json
```

có thể là runtime config.

## Sub-role nên hỗ trợ

```text
Application config
Network config
Runtime config
Security config
Logging config
Update config
Feature flags
Environment config
```

---

# 12. CMP-06 – Application Metadata

Linux không có một manifest duy nhất giống Android.

Metadata có thể nằm ở:

```text
.desktop
snap.yaml
Flatpak manifest
DEBIAN/control
RPM metadata
package.json
MANIFEST.MF
*.runtimeconfig.json
```

Ví dụ `.desktop`:

```ini
[Desktop Entry]
Name=Product
Exec=/opt/product/product %U
MimeType=x-scheme-handler/product;
```

Classify:

```text
Type:
Desktop Entry

Role:
Application launcher / protocol handler metadata
```

---

# 13. CMP-07 – Certificate / Key Material

Có thể gặp:

```text
.pem
.crt
.cer
.der
.p12
.pfx
.key
.pub
```

Không được kết luận chỉ theo extension.

Có thể là:

```text
CA certificate
Server certificate
Public certificate
Public key
Private key
Certificate chain
```

Ví dụ:

```text
Path:
resources/certs/root-ca.pem

Type:
X.509 Certificate

Role:
Bundled CA Certificate
```

Hoặc:

```text
Path:
config/client.key

Type:
Private Key

Role:
Credential Material Candidate
```

Việc đánh giá có nguy hiểm hay không thuộc Bước 4.

---

# 14. CMP-08 – Database / Local Storage

Có thể gặp:

```text
.db
.sqlite
.sqlite3
LevelDB
IndexedDB
RocksDB
LMDB
```

Nên phân biệt:

```text
Database
Cache
Local storage
Preloaded dataset
Application state
```

Ví dụ SQLite:

```text
Type     : SQLite Database
Role     : Application Data
Readable : Yes
```

Bước 3 chưa kiểm tra dữ liệu nhạy cảm.

---

# 15. CMP-09 – Dependency / Package Metadata

Đây là nhóm quan trọng cho SBOM/SCA sau này.

## Node

```text
package.json
package-lock.json
yarn.lock
pnpm-lock.yaml
```

## Python

```text
requirements.txt
Pipfile
poetry.lock
METADATA
```

## Java

```text
pom.xml
MANIFEST.MF
*.jar
```

## Rust

```text
Cargo.toml
Cargo.lock
```

## Go

```text
go.mod
go.sum
```

## .NET

```text
*.deps.json
*.csproj
packages.lock.json
```

Những file này nên classify là:

```text
Dependency Metadata
```

không phải config thông thường.

---

# 16. CMP-10 – Service / Startup Components

Các artifact Linux-specific:

```text
*.service
*.socket
*.timer
*.path
```

Ví dụ:

```text
usr/lib/systemd/system/product.service
```

Ngoài ra:

```text
/etc/init.d/product
/etc/xdg/autostart/product.desktop
```

Sub-role:

```text
Systemd service
Systemd timer
Systemd socket
Init script
Desktop autostart
User service
```

Bước 4 mới kiểm tra privilege/command/permission.

---

# 17. CMP-11 – Privilege / Authorization Components

Có thể gặp:

```text
polkit rules
polkit actions
sudoers fragments
PAM config
AppArmor profile
SELinux policy
Linux capability-related metadata
```

Ví dụ:

```text
/usr/share/polkit-1/actions/com.vendor.product.policy
```

Classify:

```text
Privilege Management Component
```

Chưa đánh giá privilege escalation.

---

# 18. Polkit

Ví dụ:

```xml
<action id="com.vendor.product.install">
```

Bước 3 chỉ ghi:

```text
Type:
Polkit Action

Role:
Privilege Authorization
```

Bước 4 mới kiểm tra:

- Ai được gọi.
- Authentication policy.
- Action nào được thực hiện.

---

# 19. CMP-12 – Plugin / Extension

Có thể gặp:

```text
plugins/
extensions/
modules/
providers/
drivers/
```

Ví dụ:

```text
plugins/libpdfplugin.so
```

hoặc:

```text
extensions/example/
manifest.json
main.js
```

Sub-role:

```text
Native plugin
Script plugin
Extension
Provider
Driver
```

Plugin nên được đánh dấu riêng vì có thể có attack surface độc lập.

---

# 20. CMP-13 – Network-related Components

Có thể gồm:

```text
Proxy config
Endpoint list
TLS config
Certificate bundle
WebSocket config
Update server config
DNS config
Remote API config
```

Ví dụ:

```text
network.json
server.conf
proxy.ini
```

Classify:

```text
Network Configuration
```

Chưa đánh giá:

- HTTP/HTTPS.
- TLS verification.
- WebSocket.
- Hardcoded IP/domain.

---

# 21. CMP-14 – Resource / Asset

Ví dụ:

```text
.png
.jpg
.svg
.ico
.qm
.mo
.po
.html
.css
fonts
translations
documentation
```

Có thể chia:

```text
Static asset
UI resource
HTML resource
Localization
Documentation
```

Phần lớn là low-priority nhưng không nên bỏ hoàn toàn.

---

# 22. CMP-15 – Nested Container

Nếu còn phát hiện:

```text
.zip
.jar
.asar
.tar
.iso
.squashfs
```

thì classify là:

```text
Nested Container
```

và giữ metadata:

```text
extract_status
depth
parent
```

Nếu đã extract ở Bước 2 thì vẫn giữ record để trace nguồn gốc.

---

# 23. CMP-16 – Unknown / Unclassified

Không ép mọi file vào category không chính xác.

Ví dụ:

```text
resource.dat
blob.bin
abc.pack
unknown.cache
```

nếu chưa xác định được:

```text
Type:
Unknown Binary

Confidence:
Low
```

Unknown là kết quả hợp lệ.

---

# 24. Không phân loại chỉ dựa trên extension

Ví dụ:

```text
config.dat
```

có thể thực tế là SQLite.

```text
resource.bin
```

có thể là ZIP.

```text
plugin.node
```

có thể là ELF.

Classification nên dựa trên:

```text
Extension
+
Magic
+
MIME
+
Internal Structure
+
Path
+
Context
```

---

# 25. Path cung cấp Context

Ví dụ:

```text
/etc/systemd/system/app.service
```

khác với:

```text
/resources/app.service
```

Hay:

```text
/usr/share/polkit-1/actions/*.policy
```

có ý nghĩa rõ hơn file `.policy` nằm trong documentation.

Do đó role nên được xác định từ:

```text
File Content
+
File Location
+
Application Context
```

---

# 26. File Type khác Role

Ví dụ:

```text
usr/bin/application
usr/lib/application/helper
```

đều có thể là ELF.

Nhưng role:

```text
Primary Executable
Helper Executable
```

Tương tự:

```text
package.json
config.json
```

đều là JSON nhưng role khác nhau.

Do đó component record cần có cả:

```text
File Type
Role
```

---

# 27. First-party / Third-party / Runtime

Bước 3 nên cố gắng phân biệt:

```text
First-party
Third-party
Framework/runtime
System
Unknown
```

Ví dụ:

```text
libVendorCrypto.so
```

có thể là first-party.

```text
libssl.so.3
```

third-party.

```text
libQt6Core.so
```

framework/third-party.

Điều này giúp giảm noise khi phân tích sau này.

---

# 28. Bundled và System Dependency

Cần phân biệt:

```text
Bundled with application
```

và:

```text
Expected from host system
```

Ví dụ DEB metadata:

```text
Depends: libssl3
```

nhưng package không bundle:

```text
libssl.so.3
```

→ System Dependency.

Trong khi AppImage chứa:

```text
usr/lib/libssl.so.3
```

→ Bundled Dependency.

---

# 29. Application / Runtime / Framework Components

Ví dụ Electron:

```text
libEGL.so
libGLESv2.so
chrome-sandbox
icudtl.dat
```

đa phần thuộc runtime/framework.

Trong khi:

```text
resources/app.asar
```

gần với application code hơn.

Nên classify:

```text
Application Component
Runtime Component
Framework Component
```

---

# 30. Build / Debug Artifacts

Có thể gặp:

```text
*.map
*.debug
*.sym
DWARF data
source maps
```

Classify:

```text
Debug / Build Artifact
```

Bước 4 mới đánh giá information exposure.

---

# 31. Source Map

Electron/web-based app có thể chứa:

```text
main.js.map
renderer.js.map
```

Classify:

```text
Type:
Source Map

Role:
Build/Debug Artifact
```

Không kết luận vulnerability ngay.

---

# 32. Logging Components

Có thể gặp:

```text
log4j.properties
logback.xml
spdlog config
winston config
debug config
```

Classify:

```text
Logging Configuration
```

Bước 4 mới kiểm tra:

- Sensitive logging.
- Verbose debug logging.
- Credential exposure.

---

# 33. Crypto-related Components

Có thể gặp:

```text
libcrypto.so
libsodium.so
BouncyCastle JAR
crypto config
key store
```

Classify:

```text
Crypto Library
Crypto Configuration
Key Store
Certificate Store
```

Chưa đánh giá thuật toán yếu.

---

# 34. Key Store

Có thể gặp:

```text
.jks
.p12
.pfx
keystore
truststore
```

Nên phân biệt:

```text
Trust Store
Key Store
Certificate Bundle
```

Nếu encrypted vẫn có thể classify loại container.

---

# 35. Update Components

Nhiều desktop app có:

```text
updater
update.json
latest.yml
app-update.yml
```

Classify:

```text
Updater Binary
Update Configuration
Update Metadata
```

Bước 4 mới kiểm tra:

- Update URL.
- Signature verification.
- HTTP/HTTPS.
- Update integrity.

---

# 36. Crash Reporting / Telemetry

Ví dụ:

```text
crashpad
sentry
telemetry config
analytics config
```

Classify:

```text
Crash Reporting Component
Telemetry Component
```

Telemetry không tự động là vulnerability.

---

# 37. IPC Components

Linux desktop app có thể dùng:

```text
D-Bus
Unix socket
FIFO
Shared memory
Local TCP socket
```

Artifact liên quan có thể là:

```text
*.service
D-Bus XML
socket config
```

Classify:

```text
IPC Configuration
```

Bước 4 mới xác định IPC security checks.

---

# 38. D-Bus Artifacts

Có thể gặp:

```text
/usr/share/dbus-1/services/
/usr/share/dbus-1/system-services/
```

Ví dụ:

```text
com.vendor.Product.service
```

Classify:

```text
Type:
D-Bus Service Definition

Role:
IPC / Service Activation
```

Đây là Linux-specific component nên được đưa vào taxonomy.

---

# 39. Browser / WebView Components

Electron, QtWebEngine hoặc CEF app có thể chứa:

```text
HTML
JavaScript
CSS
CEF runtime
Chromium runtime
QtWebEngine
```

Classify:

```text
Web Renderer Component
```

Bước 4 sau này có thể ánh xạ sang:

```text
XSS
WebView Security
CSP
Node Bridge
```

---

# 40. Native Addon

Các dạng:

```text
.node
.so
JNI library
```

có thể cần multi-label.

Ví dụ:

```text
keytar.node
```

có thể là:

```text
Type:
ELF Shared Object

Role:
Node Native Addon

Analysis Groups:
Native Binary
Dependency Analysis
```

---

# 41. Một file có thể thuộc nhiều Analysis Group

Không nên thiết kế:

```text
1 file = 1 category
```

Ví dụ:

```text
client.key
```

có thể đồng thời là:

```text
Certificate/Key Material
Sensitive File
Secret Candidate
```

Hoặc:

```text
libcrypto.so.3
```

có thể là:

```text
Shared Library
Third-party Dependency
Crypto Component
```

Do đó data model nên hỗ trợ:

```text
primary_type
roles[]
analysis_groups[]
```

---

# 42. Confidence và Evidence

Classification nên có confidence.

Ví dụ:

```text
Type       : SQLite
Confidence : High
Evidence   : Magic "SQLite format 3"
```

Hoặc:

```text
Role       : Updater Config
Confidence : Medium

Evidence:
- filename app-update.yml
- located under resources/
```

Các mức đề xuất:

```text
High
Medium
Low
Unknown
```

---

# 43. Component Record đề xuất

Ví dụ:

```json
{
  "path": "resources/app.asar.unpacked/node_modules/keytar/build/Release/keytar.node",
  "type": "elf_shared_object",
  "roles": [
    "node_native_addon",
    "third_party_dependency"
  ],
  "architecture": "x86_64",
  "origin": {
    "package": "ABC.AppImage",
    "container": "resources/app.asar",
    "depth": 2
  },
  "analysis_groups": [
    "native_binary",
    "dependency_analysis"
  ],
  "confidence": "high"
}
```

---

# 44. Component Tree

Ngoài inventory dạng danh sách, Bước 3 nên tạo component tree dễ đọc.

Ví dụ:

```text
ABC.AppImage
│
├── Native Runtime
│   ├── application
│   ├── chrome-sandbox
│   └── libEGL.so
│
├── Electron Application
│   └── app.asar
│       ├── package.json
│       ├── main.js
│       ├── preload.js
│       └── node_modules/
│
├── Configuration
│   └── config.json
│
└── Metadata
    └── application.desktop
```

Component tree giúp Lead hiểu cấu trúc ứng dụng nhanh hơn so với danh sách hàng nghìn file.

---

# 45. Không đưa toàn bộ asset vào report chính

Ví dụ application có:

```text
8,000 PNG
3,000 localization files
1,200 font/resource files
```

không cần liệt kê từng file.

Có thể collapse thành:

```text
Static Assets: 12,432
```

Detailed inventory vẫn nên được giữ ở machine-readable output.

---

# 46. Priority Classification

Có thể thêm priority để chuẩn bị cho Bước 4.

## High Priority

```text
Executable
Shared Library
Script/Source
Config
Certificate/Key
Database
Service
Polkit
D-Bus
Updater
Dependency Metadata
```

## Medium Priority

```text
Desktop Entry
Plugin
Source Map
Logging Config
Network Metadata
```

## Low Priority

```text
Image
Font
Translation
Documentation
```

Đây là **analysis priority**, không phải vulnerability severity.

---

# 47. Ví dụ kết quả tổng hợp Bước 3

```text
APPLICATION COMPONENT SUMMARY
==========================================

Application:
ABC Desktop 2.4.1

Package:
AppImage

Files after extraction:
4,821

Security-relevant components:
412

Native:
  Executables                 5
  Shared Libraries          141
  Native Plugins              8

Application Code:
  JavaScript                193
  Shell Scripts               4
  Native Addons               6

Configuration:
  Application Config         12
  Network Config              3
  Logging Config              2

Metadata:
  Desktop Entry               1
  Package Metadata            3

Security Components:
  Certificates                4
  Private Keys                0
  Polkit Rules                1
  D-Bus Services              2

Storage:
  SQLite Databases            2
  Other Local Storage         5

Dependencies:
  Node Package Metadata       1
  Lock Files                  1

Low-value Resources:
  Assets                  4,427
```

---

# 48. Mapping sơ bộ sang Bước 4

| Component | Nhóm kiểm tra tiếp theo |
|---|---|
| ELF executable | Native binary checks |
| `.so` | Shared library / hardening / dependency checks |
| JS/Python/Shell | Code analysis |
| Config | Configuration/security data checks |
| Certificate | Certificate/key checks |
| Private key | Sensitive file/secret checks |
| SQLite | Sensitive data/storage checks |
| `.desktop` | Entry point/handler checks |
| systemd unit | Service/privilege checks |
| Polkit | Authorization/privilege checks |
| D-Bus | IPC checks |
| `package.json` | Dependency/runtime checks |
| ASAR | Electron-specific checks |
| JAR | Java/dependency/code checks |
| Source map | Information disclosure/code recovery |
| Updater | Update mechanism checks |
| Network config | Network security checks |

Đây mới là routing, chưa phải checklist kiểm tra chi tiết.

---

# 49. Những nội dung KHÔNG thuộc Bước 3

Bước 3 không trả lời:

```text
libabc.so có RELRO hay không?
```

Không kiểm tra:

- Stack Canary.
- NX.
- PIE.
- FORTIFY.
- RPATH/RUNPATH.

Không trả lời:

```text
config.json có hardcoded password không?
```

Không tìm secret chuyên sâu.

Không trả lời:

```text
libssl.so có CVE gì?
```

Không thực hiện CVE/SCA assessment.

Không trả lời:

```text
main.js có command injection không?
```

Không chạy SAST.

Không thực hiện:

- Malware analysis.
- YARA.
- ClamAV.
- CodeQL.
- Semgrep.
- Gitleaks.
- Grype.

Các nội dung này thuộc bước sau.

---

# 50. Tiêu chí hoàn thành Bước 3

Bước 3 được coi là hoàn thành khi với gần như mọi artifact có giá trị có thể trả lời:

| Câu hỏi | Yêu cầu |
|---|---|
| File này là loại gì? | Phải xác định hoặc `Unknown` |
| Role của nó là gì? | Nên xác định |
| Nằm ở đâu? | Phải có path |
| Đến từ package/container nào? | Phải trace được |
| First-party / Third-party / Runtime? | Nên xác định |
| Bundled hay system dependency? | Nên xác định |
| Priority phân tích? | Nên có |
| Analysis group nào? | Phải có nếu relevant |
| Confidence? | Nên có |
| Evidence phân loại? | Nên có |

---

# 51. Tình hình đã hoàn thành ở Bước 3

Đến thời điểm hiện tại đã xác định được:

## Component taxonomy chính

- Native Executable.
- Shared Library.
- Script/Source.
- Embedded Application/Framework.
- Configuration.
- Metadata.
- Certificate/Key Material.
- Database/Local Storage.
- Dependency Metadata.
- Service/Startup.
- Privilege/Authorization.
- Plugin/Extension.
- Network-related Component.
- Resource/Asset.
- Nested Container.
- Unknown.

## Các chiều phân loại bổ sung

- File Type.
- Role.
- First-party / Third-party / Runtime / System.
- Bundled / System Dependency.
- Application / Framework / Runtime.
- Priority.
- Analysis Group.
- Confidence.
- Evidence.
- Parent Container.
- Extraction Depth.

## Các nhóm Linux-specific đã đưa vào scope

- systemd.
- Polkit.
- D-Bus.
- Desktop Entry.
- AppArmor/SELinux-related artifact.
- Autostart.
- Service activation.
- Native plugin/addon.

---

# 52. Kết luận

Nếu Bước 1 trả lời:

> **Ứng dụng đang được cung cấp dưới dạng gì?**

Bước 2 trả lời:

> **Có thể bung ứng dụng ra được những gì?**

thì Bước 3 trả lời:

> **Từng thứ sau khi bung ra là gì, có vai trò gì, thuộc nhóm nào và phải chuyển sang hướng kiểm tra nào?**

Bước 3 là lớp trung gian cần thiết giữa extraction và security checking.

Nếu bỏ qua Bước 3 và chạy scanner trực tiếp trên toàn bộ extracted filesystem thì dễ xảy ra:

- Scan sai loại artifact.
- Scan trùng.
- Scan framework/runtime như application code.
- Tạo nhiều false positive.
- Bỏ sót component Linux-specific.
- Không trace được finding về đúng package/component.

Do đó output cuối cùng của Bước 3 nên là:

```text
Component Inventory
        +
Component Tree
        +
Classification Metadata
        +
Analysis Routing Map
```

---

# 53. Phạm vi chuyển tiếp sang Bước 4

Sau khi Bước 3 hoàn thành, Bước 4 sẽ tập trung vào:

> **Xác định chính xác các hạng mục security cần kiểm tra cho từng loại component đã được phân loại.**

Ví dụ:

```text
ELF
 ↓
Hardening
Symbols
Dependencies
RPATH/RUNPATH
Dangerous APIs
...

Config
 ↓
Secret
Debug
Network endpoint
TLS configuration
...

D-Bus
 ↓
Activation
Privilege boundary
Access policy
...

Electron
 ↓
Preload
Node Integration
Context Isolation
CSP
IPC
...
```

Bước 4 sẽ xây checklist security; Bước 5 mới bắt đầu chọn tool tương ứng.

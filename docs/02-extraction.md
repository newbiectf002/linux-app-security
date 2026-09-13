# BÁO CÁO NGHIÊN CỨU – BƯỚC 2
## Phân tích khả năng Extract/Unpack ứng dụng Desktop trên Linux

**Phạm vi:** Linux Desktop Application  
**Giai đoạn:** Bước 2 – Package/Container Extraction Analysis  
**Mục tiêu tài liệu:** Xác định từng loại artifact/package có thể extract/unpack hay không, kỳ vọng cấu trúc đầu ra sau khi extract, các trường hợp ngoại lệ và tiêu chí hoàn thành trước khi chuyển sang Bước 3.

---

# 1. Tóm tắt dành cho Lead

Bước 2 nhằm trả lời câu hỏi:

> **Sau khi đã nhận diện đúng loại package/artifact ở Bước 1, có thể bung nội dung của artifact đó ra hay không, và sau khi bung thì thu được những thành phần gì để phục vụ phân tích tiếp theo?**

Đây là bước **extract/unpack**, chưa thực hiện đánh giá lỗ hổng.

Kết quả Bước 2 cần xác định:

- Artifact nào có thể extract.
- Artifact nào không cần extract.
- Artifact nào cần cơ chế unpack đặc thù.
- Cấu trúc đầu ra dự kiến sau extract.
- Có nested container/artifact bên trong hay không.
- Trạng thái extraction.
- Metadata filesystem nào cần được bảo toàn.
- Mối quan hệ giữa artifact gốc và các artifact được bung ra.

Bước 2 là cầu nối giữa:

```text
Bước 1
Nhận diện artifact
        ↓
Bước 2
Extract / Unpack
        ↓
Bước 3
Phân tích các thành phần sau extract
```

---

# 2. Mục tiêu của Bước 2

Bước 2 có 5 mục tiêu chính:

1. **Xác định khả năng extract**
2. **Xác định loại container/filesystem**
3. **Thu được cấu trúc application ở trạng thái expanded**
4. **Phát hiện nested artifact**
5. **Bảo toàn metadata cần thiết cho các bước sau**

Bước này không nhằm đánh giá:

- CVE.
- Secret.
- Malware.
- ELF hardening.
- Code weakness.
- Network security.

---

# 3. Phân biệt Extract, Decompress và Decompile

## 3.1 Extract

Lấy nội dung filesystem/payload bên trong package hoặc container.

Ví dụ:

```text
AppImage
    ↓
AppDir / filesystem
```

Hoặc:

```text
DEB
    ↓
Metadata + filesystem
```

## 3.2 Decompress

Chỉ loại bỏ compression layer.

Ví dụ:

```text
.tar.gz
    ↓
.tar
    ↓
files/directories
```

## 3.3 Decompile

Biến binary/bytecode thành representation gần source code hơn.

Ví dụ:

```text
.class
    ↓
Java decompiler
    ↓
Java-like source
```

Decompile **không thuộc Bước 2**.

Bước 2 chỉ dừng ở:

```text
JAR
 ↓
.class + resource + META-INF
```

---

# 4. Ma trận tổng quát khả năng extract

| Artifact | Có extract? | Kết quả chính |
|---|---:|---|
| DEB | Có | Metadata + filesystem |
| RPM | Có | Package payload |
| AppImage | Có | AppDir/filesystem |
| Snap | Có | SquashFS filesystem |
| Flatpak bundle | Có, đặc thù | Flatpak/OSTree content |
| Flatpakref | Không có app payload đầy đủ | Reference metadata |
| ZIP | Có | Files/directories |
| TAR/TAR.GZ | Có | Files/directories |
| 7z | Có | Files/directories |
| ASAR | Có | JavaScript/resources |
| JAR | Có | Class/resources/META-INF |
| WAR/EAR | Có | Java application tree |
| PyInstaller | Có thể | Python bytecode/resources |
| ELF executable | Không theo nghĩa package | Chuyển sang binary analysis |
| Shared Object `.so` | Không theo nghĩa package | Chuyển sang binary analysis |
| Script | Không cần | Phân tích trực tiếp |
| Directory | Đã expanded | Inventory/nested discovery |

---

# 5. Debian Package – `.deb`

Debian package là một artifact có khả năng extract tốt và cấu trúc tương đối rõ ràng.

Các thành phần chính thường gồm:

```text
debian-binary
control.tar.*
data.tar.*
```

## Sau extract có thể thu được

```text
deb-extracted/
├── DEBIAN/
│   ├── control
│   ├── conffiles
│   ├── md5sums
│   ├── preinst
│   ├── postinst
│   ├── prerm
│   └── postrm
│
└── filesystem/
    ├── usr/
    ├── opt/
    ├── etc/
    └── ...
```

Không phải package nào cũng có đầy đủ các file trên.

## Kết quả Bước 2 cần ghi nhận

```text
Package           : DEB
Extractable       : Yes
Metadata          : Present
Filesystem        : Present
Install Scripts   : Present / Absent
Extraction Status : ...
```

---

# 6. RPM Package

RPM có thể chứa:

```text
Lead
Signature
Header
Payload
```

Payload là phần chính cần được materialize thành filesystem phục vụ bước sau.

## Sau extract

Ví dụ:

```text
rpm-extracted/
├── usr/
│   ├── bin/
│   ├── lib/
│   └── share/
├── etc/
└── opt/
```

## Metadata cần giữ

- Name.
- Version.
- Release.
- Architecture.
- Requires.
- Provides.
- Script metadata.
- Signature metadata nếu có.

## Kết quả Bước 2

```text
Package           : RPM
Extractable       : Yes
Payload           : Present
Metadata          : Present
Extraction Status : ...
```

---

# 7. AppImage

AppImage là format quan trọng đối với desktop Linux.

## AppImage Type 2

Có thể extract thành:

```text
squashfs-root/
```

Cấu trúc ví dụ:

```text
squashfs-root/
├── AppRun
├── application.desktop
├── application.png
├── usr/
│   ├── bin/
│   ├── lib/
│   └── share/
└── resources/
```

## AppImage Type 1

Type 1 sử dụng cơ chế filesystem khác Type 2 và cần được xử lý riêng.

Do đó Bước 2 cần lưu:

```text
AppImage Type : 1 / 2 / Unknown
```

## Kết quả

```text
Package           : AppImage
Extractable       : Yes
Output Type       : AppDir/filesystem
Entry Artifact    : AppRun
Extraction Status : ...
```

---

# 8. Snap

Snap package có thể được xem như SquashFS package có metadata riêng.

Sau extract có thể thấy:

```text
snap-root/
├── meta/
│   ├── snap.yaml
│   ├── hooks/
│   └── gui/
│       └── application.desktop
├── bin/
├── usr/
├── lib/
└── ...
```

## Kết quả Bước 2

```text
Package           : Snap
Container         : SquashFS
Extractable       : Yes
Metadata          : meta/snap.yaml
Filesystem        : Present
Extraction Status : ...
```

---

# 9. Flatpak

Flatpak cần được xử lý riêng vì không phải mọi artifact bắt đầu bằng `.flatpak*` đều chứa application payload.

Cần phân biệt:

```text
.flatpak
.flatpakref
.flatpakrepo
Flatpak manifest
Installed Flatpak
```

## `.flatpak`

Đây là artifact có application/runtime content.

```text
Extractable/Materializable : Yes
```

## `.flatpakref`

Chỉ chứa reference/metadata trỏ tới application source/repository.

```text
Payload Embedded : No
```

## `.flatpakrepo`

Chủ yếu mô tả repository.

```text
Application Payload : No
```

## Kết quả Bước 2

Phải thể hiện rõ:

```text
Artifact Type
Payload Embedded
Materializable
Metadata
Extraction Status
```

---

# 10. Generic Archive

Các dạng phổ biến:

```text
.zip
.tar
.tar.gz
.tgz
.tar.xz
.tar.zst
.7z
```

Sau extract có thể thu được:

```text
application/
├── bin/
├── lib/
├── plugins/
├── resources/
└── config/
```

## Metadata cần cố gắng bảo toàn

- Directory structure.
- Symlink.
- Permission.
- Executable bit.
- Ownership metadata nếu available.
- Timestamp nếu cần phục vụ traceability.

Bước 2 chưa đánh giá các metadata này là an toàn hay không.

---

# 11. Nested Artifact

Một package có thể chứa các container khác bên trong.

Ví dụ:

```text
application.AppImage
       ↓
AppDir
       ↓
resources/app.asar
       ↓
JavaScript/resources
```

Hoặc:

```text
application.zip
       ↓
application/
       ↓
lib/application.jar
       ↓
.class/resources
```

Do đó Bước 2 không nên chỉ xử lý lớp package ngoài cùng.

Cần có khái niệm:

```text
Extraction Depth
```

Ví dụ:

```text
Depth 0 : Original package
Depth 1 : Extracted filesystem
Depth 2 : Nested container
Depth 3 : Nested resource
```

---

# 12. Electron ASAR

Khi gặp:

```text
resources/app.asar
```

thì ASAR được xem là nested container có giá trị cao.

Sau extract có thể thấy:

```text
app/
├── package.json
├── main.js
├── preload.js
├── node_modules/
├── dist/
└── assets/
```

Bước 2 chỉ làm:

```text
ASAR
 ↓
JavaScript/resources
```

Chưa đánh giá:

- `nodeIntegration`.
- `contextIsolation`.
- XSS.
- Secret.
- Dependency vulnerability.

---

# 13. Java JAR

JAR là archive có thể extract.

Sau extract:

```text
jar-root/
├── META-INF/
│   └── MANIFEST.MF
├── com/
│   └── company/
│       └── Main.class
└── application.properties
```

## Bước 2 dừng tại

- `.class` files.
- Resource files.
- Manifest.
- Config.

Không thực hiện decompile.

---

# 14. WAR / EAR

Nếu gặp Java container như:

```text
.war
.ear
```

có thể extract thành:

```text
WEB-INF/
META-INF/
classes/
lib/
```

Đây là nested artifact nên được hỗ trợ nếu application sử dụng Java framework tương ứng.

---

# 15. Python Packaged Application

Nếu artifact là source trực tiếp:

```text
application.py
```

thì không cần extract.

Nếu ứng dụng được đóng gói bằng:

- PyInstaller.
- Nuitka.
- cx_Freeze.

thì binary có thể chứa:

- Python bytecode.
- Embedded archive.
- Runtime.
- Resources.

## Kết quả cần hỗ trợ

```text
Packaging     : Python packaged app
Unpackable    : Yes / Potential / Unsupported
Result        : Bytecode/resources nếu lấy được
Status        : ...
```

Không decompile `.pyc` trong Bước 2.

---

# 16. Native ELF Executable

ELF executable không phải package theo nghĩa thông thường.

Ví dụ:

```text
application
```

là ELF executable.

Kết quả nên là:

```text
Artifact      : Native ELF
Extractable   : Not Applicable
Next Stage    : Binary/component analysis
```

Mặc dù ELF có:

- Section.
- Segment.
- Symbol.
- Debug data.
- Dynamic information.

việc phân tích các phần này không được xem là package extraction trong Bước 2.

---

# 17. Shared Library `.so`

Tương tự ELF executable.

Ví dụ:

```text
libabc.so
```

Kết quả:

```text
Artifact      : ELF Shared Object
Extractable   : Not Applicable
Next Stage    : Binary/shared library analysis
```

---

# 18. Script

Các file như:

```text
run.sh
application.py
launcher.js
```

không cần extract.

Kết quả:

```text
Artifact      : Script
Extractable   : Not Required
Readable      : Yes
```

---

# 19. Directory đã expanded

Nếu input của Bước 1 là directory:

```text
application/
```

thì:

```text
Extract Required : No
State            : Already Expanded
```

Tuy nhiên vẫn cần phát hiện nested container bên trong:

```text
*.asar
*.jar
*.zip
*.tar.*
*.7z
```

---

# 20. Symlink

Khi extract Linux application, symlink cần được giữ đúng.

Ví dụ:

```text
libssl.so
   → libssl.so.3
```

Nếu symlink bị biến thành regular file hoặc mất target, inventory ở bước sau có thể sai.

## Bước 2 nên thống kê

- Regular files.
- Directories.
- Symlinks.
- Broken symlinks.

---

# 21. Permission Metadata

Metadata filesystem cần được bảo toàn nếu format hỗ trợ.

Ví dụ:

```text
-rwxr-xr-x
-rwsr-xr-x
-rw-r--r--
```

Bước 2 chưa đánh giá security implication.

Nhưng các thuộc tính như:

- Executable bit.
- Setuid.
- Setgid.
- World writable.

có thể cần cho bước phân tích sau.

---

# 22. Nguyên tắc Extract nhưng không Execute

Đối với artifact không tin cậy:

```text
Extract ≠ Execute
```

Ưu tiên:

```text
Read
Parse
Extract
Materialize
```

Không nên coi:

```text
Install application
Launch application
Run installer
```

là phương pháp extract mặc định.

Mục đích là giảm rủi ro cho môi trường phân tích.

---

# 23. Không extract vào filesystem thật của máy phân tích

Package có thể chứa các path như:

```text
/usr/bin/app
/etc/app.conf
/opt/application/
```

Nhưng nội dung phải được giữ trong workspace riêng, ví dụ:

```text
workspace/
└── extracted/
    ├── usr/
    ├── etc/
    └── opt/
```

Không để extraction ghi trực tiếp vào:

```text
/usr
/etc
/opt
```

trên máy phân tích.

---

# 24. Path Traversal trong quá trình Extract

Archive không tin cậy có thể chứa path bất thường như:

```text
../../etc/passwd
```

hoặc symlink dẫn ra ngoài extraction directory.

Do đó extraction process phải đảm bảo:

> Mọi output đều nằm trong extraction root được chỉ định.

Đây là yêu cầu an toàn của pipeline, không phải finding của application.

---

# 25. Recursive Extraction cần giới hạn

Không nên extract recursive vô hạn.

Ví dụ:

```text
archive A
 ↓
archive B
 ↓
archive C
 ↓
archive D
```

Cần lưu:

- Depth.
- Parent artifact.
- Source artifact.
- Output location.

Ví dụ:

```text
Depth 0
ABC.AppImage

Depth 1
squashfs-root/

Depth 2
resources/app.asar

Depth 3
embedded/plugin.zip
```

---

# 26. Không phải mọi nested archive đều có cùng mức ưu tiên

Ví dụ:

## High-value

```text
app.asar
application.jar
plugin.zip
embedded package
```

## Medium-value

```text
config bundle
resource archive
runtime package
```

## Low-value

```text
icons.zip
language resources
documentation archive
```

Việc phân loại priority giúp tránh số lượng artifact tăng quá lớn.

---

# 27. Extraction Status

Mỗi artifact nên có status rõ ràng.

Đề xuất:

```text
NOT_REQUIRED
SUPPORTED
SUCCESS
PARTIAL
FAILED
ENCRYPTED
UNSUPPORTED
CORRUPTED
```

## Ví dụ

```text
artifact : application.AppImage
status   : SUCCESS
```

```text
artifact : protected.zip
status   : ENCRYPTED
```

```text
artifact : vendor.pkgx
status   : UNSUPPORTED
```

---

# 28. Password-Protected Archive

Nếu gặp archive được mã hóa:

```text
ZIP
7z
```

thì không xem là scanner error.

Kết quả:

```text
Extractable : Yes
Status      : ENCRYPTED
Credential  : Required
```

---

# 29. Corrupted Package

Một package có thể có:

- Header đúng.
- Magic đúng.
- Nhưng cấu trúc bên trong bị lỗi.

Ví dụ:

```text
Invalid ZIP central directory
Truncated SquashFS
Invalid TAR header
```

Kết quả:

```text
Status : CORRUPTED
```

Cần phân biệt với:

```text
UNSUPPORTED
```

---

# 30. Proprietary / Unknown Format

Có thể gặp package vendor tự định nghĩa.

Ví dụ:

```text
application.pkgx
```

Nếu không đủ thông tin để xử lý:

```text
Format       : Proprietary / Unknown
Extractable  : Unknown
Status       : UNSUPPORTED
```

Không nên đoán format.

---

# 31. Output Manifest của Bước 2

Bước 2 nên tạo dữ liệu mô tả quan hệ giữa package gốc và artifact được extract.

Ví dụ:

```json
{
  "source": "ABCDesktop.AppImage",
  "extraction": {
    "status": "success",
    "format": "appimage-type2",
    "output_type": "appdir",
    "depth": 1
  },
  "output": {
    "root": "squashfs-root",
    "files": 1452,
    "directories": 182,
    "symlinks": 77
  },
  "nested_artifacts": [
    {
      "path": "resources/app.asar",
      "type": "asar",
      "extractable": true
    }
  ]
}
```

Với nested artifact:

```json
{
  "source": "resources/app.asar",
  "parent": "ABCDesktop.AppImage",
  "depth": 2,
  "extraction": {
    "status": "success"
  }
}
```

---

# 32. Traceability giữa Artifact

Bước 2 cần giữ được quan hệ:

```text
Original Package
      ↓
Extracted Filesystem
      ↓
Nested Container
      ↓
Extracted Component
```

Mục đích là để sau này một finding có thể trace ngược:

```text
Finding
 ↓
File
 ↓
Nested container
 ↓
Original package
```

---

# 33. Cấu trúc lưu trữ logic đề xuất

Một cấu trúc logic có thể là:

```text
workspace/
├── original/
│   └── ABCDesktop.AppImage
│
├── extracted/
│   ├── depth-1/
│   │   └── appimage/
│   │
│   └── depth-2/
│       └── asar/
│
└── metadata/
    ├── step1.json
    └── step2.json
```

Mục tiêu không phải quy định cách chạy script mà là đảm bảo:

- Không mất artifact gốc.
- Không ghi đè các lớp extract.
- Giữ được chain-of-origin.

---

# 34. Ma trận chi tiết Bước 2

| Artifact | Bước xử lý | Expected output |
|---|---|---|
| DEB | Extract package | Control + filesystem |
| RPM | Extract payload | Filesystem |
| AppImage Type 2 | Extract AppDir/SquashFS | `squashfs-root` |
| AppImage Type 1 | Extract/mount filesystem | AppDir |
| Snap | Extract SquashFS | Filesystem + `meta/` |
| Flatpak bundle | Materialize Flatpak/OSTree | App content |
| Flatpakref | Không có app payload | Metadata/reference |
| ZIP | Extract | Files |
| TAR | Extract | Files + metadata |
| GZIP | Decompress | Underlying stream/file |
| 7z | Extract | Files |
| ASAR | Extract | JS/resources |
| JAR | Extract | `.class` + resources |
| WAR/EAR | Extract | Java application tree |
| PyInstaller | Framework-specific unpack | Python bytecode/resources |
| ELF executable | Không extract | Binary analysis |
| Shared Object | Không extract | Shared library analysis |
| Script | Không extract | Source analysis |
| Directory | Already expanded | Nested discovery |

---

# 35. Những nội dung KHÔNG thuộc Bước 2

Bước 2 không thực hiện:

## Security Hardening

Không đánh giá:

- RELRO.
- NX.
- Stack Canary.
- PIE.
- FORTIFY.
- RPATH.
- RUNPATH.

## Static Code Analysis

Không chạy:

- Semgrep.
- CodeQL.
- Cppcheck.

## Secret Detection

Không kết luận:

- Password leak.
- Token.
- API key.
- Private key.

## Vulnerability / CVE Assessment

Không xác định:

- Library vulnerable version.
- Known CVE.
- SCA finding.

## Malware Analysis

Không thực hiện:

- YARA assessment.
- ClamAV scan.
- Malware classification.

## Code Decompilation

Không decompile:

- `.class`.
- `.pyc`.
- Native binary.

---

# 36. Tiêu chí hoàn thành Bước 2

Bước 2 được coi là hoàn thành khi với mọi artifact thuộc phạm vi support có thể trả lời:

| Câu hỏi | Yêu cầu |
|---|---|
| Artifact có cần extract không? | Phải xác định |
| Có extract được không? | Phải xác định hoặc `Unknown` |
| Container/filesystem là gì? | Xác định nếu có thể |
| Sau extract thu được gì? | Phải mô tả |
| Extraction status? | Phải có |
| Metadata filesystem có được bảo toàn? | Nên có |
| Có symlink không? | Nên inventory |
| Có nested artifact không? | Phải tìm |
| Nested artifact có cần extract tiếp không? | Phải phân loại |
| Artifact gốc có được giữ nguyên? | Phải có |
| Quan hệ parent/child có trace được không? | Phải có |

---

# 37. Tình hình đã hoàn thành ở Bước 2

Đến thời điểm hiện tại, phạm vi nghiên cứu Bước 2 đã xác định được:

## Đã xác định nhóm artifact có thể extract

- DEB.
- RPM.
- AppImage.
- Snap.
- Flatpak bundle.
- ZIP.
- TAR và các biến thể compressed TAR.
- 7z.
- ASAR.
- JAR.
- WAR/EAR.
- Python packaged application ở mức framework-specific unpack.

## Đã xác định nhóm không cần extract

- Native ELF executable.
- Shared Object `.so`.
- Script.
- Directory đã expanded.

## Đã xác định các vấn đề cần xử lý trong extraction pipeline

- Nested container.
- Extraction depth.
- Parent/child traceability.
- Symlink preservation.
- Permission preservation.
- Path traversal protection.
- Recursive extraction limit.
- Encrypted archive.
- Corrupted artifact.
- Unsupported/proprietary format.

## Đã xác định trạng thái extraction tiêu chuẩn

```text
NOT_REQUIRED
SUPPORTED
SUCCESS
PARTIAL
FAILED
ENCRYPTED
UNSUPPORTED
CORRUPTED
```

---

# 38. Kết luận

Bước 2 đã xác định được cách tiếp cận tổng thể cho việc unpack application Linux.

Luồng xử lý về mặt logic là:

```text
Artifact từ Bước 1
        ↓
Có cần extract?
        ↓
Có hỗ trợ extract?
        ↓
Extract / Materialize
        ↓
Bảo toàn filesystem metadata
        ↓
Inventory output
        ↓
Phát hiện nested artifact
        ↓
Theo dõi extraction depth
        ↓
Tạo artifact tree
        ↓
Chuyển sang Bước 3
```

Kết quả quan trọng nhất của Bước 2 không chỉ là một thư mục đã được bung ra.

Bước 2 phải tạo được:

> **Một cây artifact có khả năng trace từ package gốc tới từng thành phần được extract.**

Điều này giúp các bước phân tích sau không mất context về nguồn gốc của file.

---

# 39. Phạm vi chuyển tiếp sang Bước 3

Sau khi Bước 2 hoàn thành, Bước 3 sẽ tập trung vào:

> **Phân tích và phân loại toàn bộ thành phần thu được sau extract để hiểu mỗi file là gì, vai trò gì trong application và nhóm kiểm tra nào sẽ áp dụng cho artifact đó.**

Ví dụ:

```text
Extracted Filesystem
      ↓
ELF executable
Shared Library
JavaScript
JAR
Certificate
Config
Database
Desktop Entry
Systemd unit
Polkit rule
Shell script
...
```

Bước 3 chưa chọn tool security cụ thể; mục tiêu trước tiên là xây **component taxonomy** cho toàn bộ artifact vừa thu được.

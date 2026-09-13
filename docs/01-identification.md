# BÁO CÁO NGHIÊN CỨU – BƯỚC 1  
## Nhận diện và kiểm kê file cài đặt/thực thi của ứng dụng Desktop trên Linux

**Phạm vi:** Linux Desktop Application  
**Giai đoạn:** Bước 1 – Application/File Identification & Inventory  
**Mục tiêu tài liệu:** Xác định các dạng file ứng dụng có thể gặp trên Linux, các thông tin cần thu thập ở bước nhận diện ban đầu và kết quả đầu ra cần có trước khi chuyển sang bước phân tích/extract.

---

## 1. Tóm tắt dành cho Lead

Bước 1 nhằm trả lời câu hỏi:

> **Ứng dụng Linux được cung cấp dưới dạng gì, sử dụng kiến trúc/runtime/framework nào và bên trong hoặc đi kèm có những nhóm artifact nào cần được xử lý ở các bước tiếp theo?**

Đây là bước **nhận diện và kiểm kê ban đầu**, chưa thực hiện đánh giá lỗ hổng, chưa phân tích sâu mã nguồn/binary và chưa thực hiện extract toàn bộ ứng dụng.

Kết quả của Bước 1 phải giúp xác định:

- Loại file/package ứng dụng được cung cấp.
- Kiến trúc CPU mà ứng dụng hỗ trợ.
- Loại executable/binary chính.
- Runtime hoặc framework chính nếu có thể nhận diện.
- Entry point của ứng dụng nếu xác định được.
- Các nhóm file/artifact liên quan có thể quan sát được.
- Những nhánh phân tích cần thực hiện ở các bước tiếp theo.

Bước này có thể được **tự động hóa ở mức cao**, tuy nhiên một số trường hợp đóng gói đặc biệt hoặc framework tùy biến có thể cần xác minh thủ công.

---

# 2. Mục tiêu của Bước 1

Bước 1 tập trung vào 4 mục tiêu chính:

1. **Identification**  
   Xác định chính xác loại file/package được cung cấp.

2. **Fingerprinting**  
   Xác định các đặc điểm kỹ thuật cơ bản của ứng dụng như kiến trúc, loại binary, runtime và framework.

3. **Inventory**  
   Kiểm kê các nhóm artifact có liên quan đến ứng dụng.

4. **Routing**  
   Cung cấp đủ thông tin để quyết định artifact nào cần được xử lý ở các bước tiếp theo.

Bước 1 **không nhằm kết luận một artifact có an toàn hay không**.

Ví dụ:

- Phát hiện ứng dụng sử dụng Electron → thông tin nhận diện.
- Phát hiện có 120 shared libraries → thông tin inventory.
- Phát hiện binary bị stripped → thông tin kỹ thuật.
- Phát hiện một file `.pem` → thông tin inventory.

Việc xác định các nội dung trên có tạo thành lỗ hổng bảo mật hay không thuộc các bước phân tích sau.

---

# 3. Input của Bước 1

Ứng dụng Linux có thể được cung cấp dưới nhiều hình thức.

Input không nên bị giới hạn ở một extension cụ thể.

Các dạng input cần tính đến gồm:

- File cài đặt/package.
- File executable độc lập.
- Shared library.
- File archive chứa toàn bộ application.
- Folder application đã được bung sẵn.
- Application được đóng gói bằng framework/runtime khác.

Do đó, hệ thống nhận diện không nên giả định rằng input luôn là `.deb` hoặc một executable ELF duy nhất.

---

# 4. Các loại package/phương thức phân phối cần nhận diện

## 4.1 Debian Package – `.deb`

Đây là định dạng package phổ biến trên Debian, Ubuntu và các distribution liên quan.

Ví dụ:

```text
application.deb
product_1.2.3_amd64.deb
```

Một Debian package có thể chứa:

- Metadata của package.
- Dependency information.
- File chương trình.
- Shared libraries.
- Configuration.
- Resource.
- Script thực hiện trong quá trình cài đặt/gỡ cài đặt.

### Thông tin cần nhận diện ở Bước 1

- Package type: Debian package.
- Package name.
- Version.
- Architecture.
- Maintainer/vendor nếu có.
- Dependency metadata nếu có thể lấy ở mức package.
- Kích thước package.
- Hash của file input.

### Ý nghĩa

Khi nhận diện được `.deb`, bước sau có thể xử lý riêng:

- Package metadata.
- Installation scripts.
- Application files.
- Native binary.
- Dependency.

---

## 4.2 RPM Package – `.rpm`

Được sử dụng trên các distribution thuộc hệ sinh thái RPM như:

- Red Hat.
- Fedora.
- Rocky Linux.
- AlmaLinux.
- SUSE và các hệ thống liên quan.

Ví dụ:

```text
application-1.2.3-1.x86_64.rpm
```

### Thông tin cần nhận diện

- Package type.
- Name.
- Version.
- Release.
- Architecture.
- Vendor.
- Packager.
- License metadata.
- Dependency metadata.
- Signature status nếu thông tin này có sẵn ở cấp package.

---

## 4.3 AppImage

AppImage là dạng application image có khả năng mang theo nhiều thành phần cần thiết để chạy ứng dụng.

Ví dụ:

```text
Application-x86_64.AppImage
```

Một AppImage sau này có thể chứa:

- Executable.
- `AppRun`.
- `.desktop`.
- Shared libraries.
- Resources.
- Framework/runtime.
- Application code.

### Thông tin cần nhận diện

- Package type: AppImage.
- Architecture.
- AppImage type nếu xác định được.
- Tên ứng dụng.
- Entry point ở mức package nếu có.
- Framework/runtime sơ bộ nếu nhận diện được.

### Lưu ý

Không nên kết luận một file là AppImage chỉ dựa vào tên `.AppImage`.

Extension chỉ được xem là một dấu hiệu hỗ trợ.

---

## 4.4 Snap – `.snap`

Snap sử dụng package riêng và có cơ chế confinement/sandbox của Snap.

Một Snap package thường có metadata liên quan tới:

```text
meta/snap.yaml
```

### Thông tin cần nhận diện

- Package type: Snap.
- Name.
- Version.
- Architecture.
- Confinement mode nếu metadata có thể đọc được.
- Application entry information.
- Package metadata chính.

Chi tiết về permission, interface, plugs và slots sẽ được phân tích ở bước phù hợp sau này.

---

## 4.5 Flatpak

Flatpak có thể xuất hiện dưới nhiều dạng:

```text
.flatpak
.flatpakref
.flatpakrepo
```

Ngoài ra có thể gặp Flatpak manifest ở dạng:

```text
JSON
YAML
```

### Thông tin cần nhận diện

- Loại Flatpak artifact.
- Application ID.
- Runtime.
- Runtime version.
- Architecture.
- Application command/entry point nếu có.
- Metadata chính.

Các quyền như filesystem, network, device hoặc socket không cần đánh giá sâu trong Bước 1.

---

## 4.6 Generic Archive

Không phải vendor nào cũng sử dụng package manager chuẩn.

Có thể nhận được:

```text
.zip
.tar
.tar.gz
.tgz
.tar.xz
.tar.zst
.7z
```

Ví dụ:

```text
product-linux-x64.tar.gz
```

Bên trong có thể là:

```text
product/
├── bin/
├── lib/
├── plugins/
├── config/
└── resources/
```

### Thông tin cần nhận diện

- Archive format.
- Compression type.
- Kiến trúc nếu có thể suy ra đáng tin cậy.
- Tên/version từ metadata đi kèm nếu có.

Việc extract toàn bộ archive thuộc Bước 2.

---

## 4.7 Directory đã được bung sẵn

Một trường hợp thực tế khác là bên cung cấp không gửi package mà gửi trực tiếp:

```text
application/
```

Ví dụ:

```text
application/
├── bin/
├── lib/
├── resources/
└── config/
```

Do đó Bước 1 cần xem **directory là một input hợp lệ**.

Trong trường hợp này, nhiệm vụ chính là fingerprint cấu trúc application và inventory các nhóm file bên trong.

---

# 5. Native executable trên Linux – ELF

Định dạng binary quan trọng nhất trên Linux là:

> **ELF – Executable and Linkable Format**

Không nên hiểu:

```text
ELF = executable
```

vì ELF có thể đại diện cho nhiều loại object khác nhau.

Các nhóm đáng quan tâm:

| ELF type | Ý nghĩa |
|---|---|
| `ET_EXEC` | Executable |
| `ET_DYN` | Shared object hoặc PIE executable |
| `ET_REL` | Relocatable object |
| `ET_CORE` | Core dump |

---

## 5.1 Thông tin ELF cần thu thập

Đối với ELF được phát hiện, Bước 1 nên ghi nhận tối thiểu:

- ELF32 / ELF64.
- Architecture.
- Endianness.
- ELF object type.
- Executable/shared object.
- Static/dynamic linkage.
- Stripped/not stripped.

Ví dụ kết quả:

```text
Format       : ELF64
Architecture : x86-64
Type         : PIE executable
Linkage      : Dynamic
Symbols      : Stripped
```

Đây chưa phải finding bảo mật.

Thông tin này dùng để xác định cách phân tích binary ở các bước sau.

---

# 6. Shared Libraries

Shared library thường gặp dưới dạng:

```text
.so
.so.1
.so.1.2
libABC.so
libcrypto.so.3
```

Ví dụ:

```text
lib/
├── libQt6Core.so.6
├── libQt6Network.so.6
├── libcrypto.so.3
└── libproduct.so
```

### Bước 1 cần xác định

- Có shared library hay không.
- Số lượng shared library.
- Architecture của library.
- Library native hay artifact khác giả extension.
- Library được bundle cùng application hay không nếu có thể xác định.

Chưa thực hiện:

- Stack Canary analysis.
- RELRO.
- NX.
- PIE.
- RPATH/RUNPATH.
- Symbol analysis.
- CVE assessment.

Các nội dung trên thuộc bước kiểm tra chuyên sâu sau này.

---

# 7. Script và interpreted application

Ứng dụng Linux không phải lúc nào cũng là native ELF.

Có thể gặp:

```text
.sh
.bash
.py
.pl
.rb
.js
```

Hoặc file không có extension:

```text
run
startup
launcher
```

nhưng nội dung chứa shebang như:

```text
#!/bin/bash
```

hoặc:

```text
#!/usr/bin/env python3
```

### Bước 1 cần xác định

- Script type.
- Interpreter.
- File có executable flag hay không nếu thông tin filesystem còn được giữ.
- Script có khả năng là launcher/entry point hay không.

### Nguyên tắc

Không được dựa hoàn toàn vào filename hoặc extension.

---

# 8. Nhận diện Runtime và Framework

Việc xác định framework ngay từ Bước 1 có giá trị lớn vì nó quyết định hướng phân tích ở các bước tiếp theo.

Các framework/runtime cần chú ý gồm:

- Native C/C++.
- Electron.
- Java.
- Python packaged application.
- .NET.
- Qt.
- GTK.
- Go.
- Rust.

---

# 9. Electron Application

Electron application có thể để lại các artifact đặc trưng như:

```text
resources/app.asar
chrome-sandbox
icudtl.dat
*.pak
snapshot_blob.bin
v8_context_snapshot.bin
libEGL.so
libGLESv2.so
```

Ví dụ:

```text
application/
├── application
├── chrome-sandbox
├── icudtl.dat
├── libEGL.so
├── libGLESv2.so
└── resources/
    └── app.asar
```

Nếu nhiều dấu hiệu phù hợp cùng xuất hiện, có thể fingerprint:

```text
Framework : Electron
Confidence: High
```

### Tại sao cần confidence

Một marker đơn lẻ có thể không đủ để kết luận chắc chắn.

Do đó framework detection nên thể hiện:

- Framework được nghi ngờ.
- Confidence.
- Evidence.

Ví dụ:

```text
Framework : Electron
Confidence: High

Evidence:
- resources/app.asar
- chrome-sandbox
- icudtl.dat
```

---

# 10. Java Application

Các dấu hiệu có thể gặp:

```text
.jar
.class
META-INF/
jre/
runtime/
bin/java
```

Ví dụ:

```text
application/
├── runtime/
│   └── bin/java
├── lib/
│   ├── application.jar
│   └── dependency.jar
└── application
```

### Bước 1 cần ghi nhận

- Runtime: Java.
- Bundled JRE: Yes/No/Unknown.
- Số lượng JAR nếu có inventory.
- Main application artifact nếu xác định được.

Chưa phân tích class, dependency vulnerability hoặc code ở bước này.

---

# 11. Python Application

Có thể gặp Python dưới dạng:

```text
.py
```

hoặc application đóng gói bằng các công nghệ như:

- PyInstaller.
- Nuitka.
- cx_Freeze.

Một packaged Python application có thể biểu hiện bên ngoài như một ELF executable.

Do đó:

```text
ELF
```

không đồng nghĩa với:

```text
Native C/C++
```

### Bước 1 nên cố gắng fingerprint

```text
Runtime/Packaging : Python / PyInstaller
Confidence        : ...
Evidence          : ...
```

Nếu không đủ bằng chứng, kết quả phải là:

```text
Unknown
```

thay vì đoán.

---

# 12. .NET Application

Các marker thường gặp:

```text
*.dll
*.deps.json
*.runtimeconfig.json
libhostfxr.so
libhostpolicy.so
```

Ví dụ:

```text
MyApp
MyApp.dll
MyApp.deps.json
MyApp.runtimeconfig.json
```

### Bước 1 cần ghi nhận

- Framework/runtime: .NET.
- Application DLL.
- Runtime configuration.
- Bundled runtime nếu có thể nhận diện.

---

# 13. Qt và GTK

Đối với native Linux desktop app, việc xác định UI/application framework cũng hữu ích.

## Qt

Các dấu hiệu:

```text
libQt5Core.so
libQt6Core.so
libQt6Gui.so
libQt6Widgets.so
plugins/platforms/
```

Có thể ghi nhận:

```text
Framework: Qt 6
```

nếu evidence đủ mạnh.

## GTK

Có thể gặp:

```text
libgtk-3.so
libgtk-4.so
libgdk*.so
```

Ở Bước 1 chỉ fingerprint framework.

Chưa đánh giá CVE hoặc security configuration.

---

# 14. Application Entry Point

Một mục tiêu quan trọng của Bước 1 là trả lời:

> **Ứng dụng thực sự bắt đầu chạy từ đâu?**

Entry point có thể là:

- ELF executable.
- Shell/Python launcher.
- `AppRun`.
- Java launcher.
- .NET launcher.
- Command được khai báo trong package metadata.
- Command từ `.desktop`.

Nếu chưa đủ thông tin để xác định chính xác thì cần ghi:

```text
Entry Point: Unknown
```

Không nên suy đoán.

---

# 15. Desktop Entry – `.desktop`

Linux desktop application thường sử dụng Desktop Entry để mô tả cách ứng dụng được hiển thị/khởi chạy.

Ví dụ:

```ini
[Desktop Entry]
Name=ABC Desktop
Exec=abc %U
Icon=abc
Type=Application
Categories=Utility;
MimeType=x-scheme-handler/abc;
```

### Các trường nên ghi nhận nếu có

- Name.
- Exec.
- TryExec.
- Type.
- MimeType.
- URL scheme handler.
- DBusActivatable.
- Actions nếu có.

Ở Bước 1, các trường này được dùng cho fingerprint và entry-point discovery.

Việc đánh giá nguy cơ từ URL handler, command argument hoặc D-Bus thuộc bước sau.

---

# 16. Kiến trúc CPU

Bước 1 phải xác định architecture khi có thể.

Các kiến trúc thường gặp:

```text
x86
x86_64 / amd64
ARM
AArch64 / arm64
RISC-V
```

Ví dụ output:

```text
Architecture: x86_64
```

Thông tin architecture cần thiết cho:

- Binary analysis.
- Reverse engineering.
- Dependency analysis.
- Tool/rule selection ở các bước sau.

---

# 17. Static và Dynamic Linkage

Native executable có thể:

```text
Statically linked
```

hoặc:

```text
Dynamically linked
```

Thông tin này nên được thu thập ở Bước 1.

### Lý do

Dynamic application có thể phụ thuộc vào shared libraries bên ngoài hoặc library được bundle.

Static application có nhiều dependency được đưa trực tiếp vào binary, làm thay đổi cách inventory thành phần ở bước sau.

Không đánh giá mức độ an toàn chỉ từ thuộc tính static/dynamic.

---

# 18. Stripped và Unstripped Binary

Bước 1 nên ghi nhận binary:

```text
stripped
```

hay:

```text
not stripped
```

Điều này không tự động là vulnerability.

Nó chỉ ảnh hưởng đến khả năng phân tích tiếp theo.

Ví dụ:

```text
Unstripped
    ↓
Có thể còn nhiều symbol/function name

Stripped
    ↓
Ít symbol phục vụ reverse engineering hơn
```

---

# 19. Không tin tưởng extension

Đây là nguyên tắc bắt buộc.

Ví dụ file tên:

```text
application.pdf
```

nhưng nội dung thật có thể là:

```text
ELF executable
```

Hoặc:

```text
image.png
```

thực tế lại là archive.

Do đó extension chỉ nên là:

> **Hint**

không phải:

> **Nguồn xác định file type cuối cùng**

---

# 20. Các lớp nhận diện file

Để hạn chế phân loại sai, một artifact nên được đối chiếu từ nhiều tín hiệu:

1. Filename.
2. Extension.
3. Magic bytes.
4. MIME/file format.
5. Header/structure.
6. Internal metadata nếu có thể đọc mà chưa cần extract sâu.
7. Framework/runtime markers.

Kết quả cuối cùng cần ưu tiên dữ liệu từ cấu trúc thật của file hơn filename.

---

# 21. Một số magic/header quan trọng

| Artifact | Signature/header điển hình |
|---|---|
| ELF | `7F 45 4C 46` |
| ZIP/JAR | `50 4B 03 04` |
| PDF | `%PDF` |
| GZIP | `1F 8B` |
| 7z | `37 7A BC AF 27 1C` |
| SQLite | `SQLite format 3` |

Magic number giúp phát hiện trường hợp:

- Đổi extension.
- Filename gây hiểu nhầm.
- Package lồng nhau.
- Artifact không có extension.

---

# 22. Inventory artifact cấp ban đầu

Bước 1 nên cố gắng thống kê các nhóm artifact có thể quan sát được.

Danh sách đề xuất:

```text
Package
ELF executable
ELF shared object
Script
JAR
ASAR
.desktop
Configuration file
Certificate
Archive
Database
Unknown binary
Other
```

Ví dụ:

```text
Detected artifacts:

ELF executable     : 5
Shared libraries   : 126
Scripts            : 3
ASAR               : 1
JAR                : 0
Desktop Entry      : 1
Certificates       : 2
Configuration      : 7
Unknown            : 4
```

Các con số này là **inventory**, không phải số lượng finding.

---

# 23. Phân cấp phạm vi hỗ trợ

Để tránh nghiên cứu quá rộng ngay từ đầu, nên chia artifact theo tier.

## Tier 1 – Bắt buộc

Các dạng có giá trị cao cho Linux desktop:

- Directory.
- AppImage.
- DEB.
- Generic archive.
- ELF executable.
- Shared Object `.so`.
- Script.

## Tier 2 – Nên hỗ trợ

- RPM.
- Snap.
- Flatpak.

## Tier 3 – Runtime/Framework

- Electron/ASAR.
- Java/JAR.
- Python packaged application.
- .NET.
- Qt/GTK.

## Tier 4 – Mở rộng

- WebAssembly.
- Native plugin.
- Proprietary/custom container.
- Các artifact framework đặc thù khác.

---

# 24. Những nội dung KHÔNG thuộc Bước 1

Để tránh chồng lấn với các bước sau, Bước 1 không thực hiện đánh giá sâu các nội dung sau:

### Không extract toàn bộ application

Extract/unpack đầy đủ thuộc:

> **Bước 2**

### Không đánh giá security hardening

Ví dụ:

- RELRO.
- Stack Canary.
- NX.
- PIE.
- FORTIFY.
- RPATH.
- RUNPATH.

Thuộc bước phân tích binary/shared library sau này.

### Không chạy SAST

Ví dụ:

- Semgrep.
- CodeQL.
- Cppcheck.

Thuộc bước phân tích code.

### Không tìm secret chuyên sâu

Ví dụ:

- API key.
- Password.
- Access token.
- Private key.

Thuộc nhóm secret/sensitive information analysis.

### Không đánh giá CVE

Ví dụ:

- Library version.
- Package vulnerability.
- CVE matching.

Thuộc dependency/SCA assessment.

### Không malware scan

Ví dụ:

- YARA.
- ClamAV.

Thuộc malware assessment.

### Không kết luận finding chỉ dựa trên artifact

Ví dụ:

```text
Có HTTP URL
Có system()
Có private IP
Có certificate
Có .so không stripped
```

không tự động đồng nghĩa với vulnerability.

---

# 25. Kết quả đầu ra mong đợi của Bước 1

Sau khi hoàn thành Bước 1, với mỗi application cần có một bản tóm tắt dạng:

```text
Application Identification
──────────────────────────────────────

Application      : ABC Desktop
Version          : 2.4.1
Input            : ABCDesktop.AppImage

Package Type     : AppImage
Architecture     : x86_64

Primary Binary   : abc-desktop
Binary Format    : ELF64
ELF Type         : PIE executable
Linkage          : Dynamic
Symbols          : Stripped

Framework        : Electron
Confidence       : High

Entry Point      : AppRun

Detected Artifacts:
  ELF Executable     : 5
  Shared Libraries   : 126
  Script             : 3
  ASAR               : 1
  Desktop Entry      : 1
  Certificate        : 2
  Configuration      : 7
```

---

# 26. Dữ liệu cấu trúc đề xuất

Ngoài phần report đọc được bởi người, kết quả Bước 1 nên có khả năng biểu diễn dưới dạng dữ liệu cấu trúc.

Ví dụ:

```json
{
  "input": {
    "name": "ABCDesktop.AppImage",
    "type": "file",
    "size": 253423422,
    "sha256": "..."
  },
  "application": {
    "name": "ABC Desktop",
    "version": "2.4.1",
    "entry_point": "AppRun"
  },
  "package": {
    "type": "appimage"
  },
  "architecture": "x86_64",
  "runtime": {
    "type": "electron",
    "confidence": "high"
  },
  "binary": {
    "format": "ELF64",
    "elf_type": "DYN",
    "linkage": "dynamic",
    "stripped": true
  },
  "artifacts": {
    "elf_executables": 5,
    "shared_objects": 126,
    "scripts": 3,
    "asar": 1,
    "jar": 0,
    "desktop_files": 1,
    "certificates": 2,
    "config_files": 7
  }
}
```

Mục đích của dữ liệu cấu trúc là để các bước sau có thể sử dụng cùng một kết quả nhận diện thống nhất.

---

# 27. Khả năng tự động hóa

Phần lớn Bước 1 có khả năng tự động hóa.

Các nội dung phù hợp để tự động nhận diện gồm:

- File/directory input.
- Hash và size.
- File format.
- Package format.
- ELF type.
- Architecture.
- Static/dynamic linkage.
- Stripped status.
- Shared libraries.
- Script/interpreter.
- Một số framework/runtime.
- Desktop Entry.
- Artifact inventory.

Tuy nhiên không phải mọi trường hợp đều có thể kết luận chính xác tuyệt đối.

Ví dụ:

- Custom packer.
- Proprietary package.
- Runtime được nhúng sâu.
- Binary bị obfuscate.
- Framework bị sửa đổi.
- Artifact giả extension.
- Application đóng gói nhiều lớp.

Vì vậy kết quả fingerprint nên hỗ trợ:

```text
High confidence
Medium confidence
Low confidence
Unknown
```

và lưu lại evidence dùng để đưa ra kết luận.

---

# 28. Tiêu chí hoàn thành Bước 1

Có thể coi Bước 1 hoàn thành khi trả lời được các câu hỏi sau:

| Câu hỏi | Yêu cầu |
|---|---|
| Input là file hay directory? | Phải xác định |
| Loại package/file là gì? | Phải xác định hoặc `Unknown` |
| Hash/size của input? | Phải có nếu là file |
| Architecture? | Có khi artifact hỗ trợ xác định |
| Binary chính là gì? | Xác định nếu có đủ thông tin |
| ELF/script/runtime? | Phân loại nếu có thể |
| Static/dynamic? | Có đối với ELF phù hợp |
| Stripped? | Có đối với ELF phù hợp |
| Framework/runtime? | Có hoặc `Unknown` |
| Entry point? | Có hoặc `Unknown` |
| Các nhóm artifact chính? | Phải inventory |
| Mức tin cậy của fingerprint? | Nên có |
| Evidence? | Nên có cho kết luận framework/runtime |

---

# 29. Kết luận

Bước 1 là lớp **Identification & Inventory** của toàn bộ quy trình phân tích ứng dụng Linux.

Mục tiêu chính không phải tìm lỗ hổng mà là hiểu đúng đối tượng đang được kiểm tra.

Kết quả Bước 1 phải cho biết:

```text
Ứng dụng là gì?
        ↓
Được đóng gói theo dạng nào?
        ↓
Chạy trên kiến trúc nào?
        ↓
Executable/runtime/framework là gì?
        ↓
Entry point ở đâu?
        ↓
Có những nhóm artifact nào?
        ↓
Nhóm nào cần được xử lý ở các bước tiếp theo?
```

Bước này có khả năng tự động hóa cao và nên trở thành nền tảng cho toàn bộ pipeline sau này.

Nếu nhận diện sai ở Bước 1, các bước extract, phân tích code, kiểm tra binary, dependency, secret và malware phía sau có thể chọn sai phương pháp hoặc bỏ sót artifact quan trọng.

---

## Phạm vi chuyển tiếp sang Bước 2

Sau khi hoàn tất Bước 1, Bước 2 sẽ tập trung vào:

> **Xác định từng loại package/container có thể được extract/unpack bằng cách nào, kết quả extract có cấu trúc ra sao và có trường hợp nào không thể hoặc không nên extract trực tiếp.**

Bước 2 không nằm trong phạm vi của tài liệu này.

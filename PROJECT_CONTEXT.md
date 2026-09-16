# PROJECT CONTEXT — Linux Application Security Analysis

> The status summary below is authoritative. The original detailed context is
> retained after it so no prior project information is lost.

## Project Goal

Build a systematic process for static and artifact-based security analysis of
Linux desktop applications, from artifact identification through reporting.

## Scope

- Linux Desktop Application
- Static analysis / artifact analysis
- Linux only

## Current Progress

- Step 1: Completed
- Step 2: Completed
- Step 3: Completed
- Step 4: Completed
- Step 5: Batch 1 (CHK-01–CHK-06) completed; later batches NOT STARTED
- Step 6: Minimal ELF result evaluation/correlation core implemented and validated
- Step 7: Minimal DefectDojo Generic Findings JSON export implemented
- Step 8: Offline HTML report MVP implemented and generated automatically by the CLI

## Approved Baseline

- `docs/01-identification.md`
- `docs/02-extraction.md`
- `docs/03-component-classification.md`
- `docs/04-security-checklist.md`

## Current MVP

The current static ELF MVP includes inventory, preserved raw evidence,
hardening/dynamic-linking/permission evidence, explicit dependency-resolution
states, minimal correlation rules, CLI orchestration, real-ELF validation,
DefectDojo Generic Findings export, offline HTML reporting, and regression tests.

## Deferred work

- Deeper dependency and provenance analysis
- ACL evaluation
- Runtime identity and group-membership evaluation
- Richer runtime context
- Advanced reporting and UI

## Important constraint

Do not choose tools only from documentation. Candidate tools must eventually be
installed and experimentally tested.

Step 5 Batch 1 evidence and recommendations are recorded under `research/`;
later tool-research batches remain deferred.

---

## Original detailed context

## 1. Mục tiêu dự án

Xây dựng một quy trình có hệ thống để phân tích và kiểm thử bảo mật ứng dụng/phần mềm chạy trên Linux, bắt đầu từ việc nhận diện artifact đầu vào cho đến đánh giá kết quả, tích hợp DefectDojo và lập báo cáo.

Mục tiêu của tài liệu này là làm **context trung tâm** cho toàn bộ project, để có thể mở chat mới cho từng bước mà vẫn giữ được các quyết định, phạm vi và trạng thái đã chốt.

---

## 2. Workflow tổng thể

Project được chia thành 8 bước:

1. **Nhận diện và kiểm kê file cài đặt/thực thi**
2. **Phân tích khả năng extract/unpack**
3. **Phân tích các thành phần sau khi extract**
4. **Xây dựng các hạng mục kiểm tra theo từng loại file/artifact**
5. **Xác định tool phù hợp cho từng hạng mục**
6. **Đánh giá và xác minh kết quả kiểm tra**
7. **Xác định kết quả có thể export/tích hợp DefectDojo**
8. **Lập báo cáo chi tiết**

Nguyên tắc quan trọng:

- Không nhảy bước.
- Khi đang làm một bước, chỉ đào sâu bước đó.
- Không đưa tool vào quá sớm nếu chưa tới Step 5.
- Không biến Step 1 thành vulnerability scanning.
- Mọi kết luận kỹ thuật quan trọng phải có evidence.
- Nếu chưa xác định được thì ghi `Unknown`, không suy đoán.
- Output phải đủ rõ để pentester và lead có thể đọc, review và tiếp tục công việc.

---

# 3. Current State

**Current Step:** Step 5 Batch 1 completed; Batch 2 not started  
**Status:** Steps 1–4 remain the approved baseline. Batch 1 evidence awaits human review.

Step 1 hiện được hiểu là bước **fingerprinting + inventory**, chưa phải bước kiểm thử lỗ hổng.

---

# 4. Step 1 — Nhận diện và kiểm kê ứng dụng Linux

## 4.1 Mục tiêu

Xác định chính xác các artifact đầu vào đang có và thu thập đủ metadata ban đầu để quyết định cách xử lý ở các bước sau.

Step 1 phải trả lời được các câu hỏi chính:

- Có những file/package nào?
- File đó thực sự là loại gì?
- Dùng cho architecture nào?
- Tên ứng dụng là gì?
- Version là gì?
- Entry point nằm ở đâu?
- Có runtime/framework nào có thể nhận diện được không?
- Có dependency/package metadata nào đáng chú ý không?
- Artifact có phải executable, installer, package, archive, image hay dạng khác không?

---

## 4.2 Phạm vi Step 1

### A. Inventory đầu vào

Liệt kê toàn bộ artifact nhận được, ví dụ:

- ELF executable
- Shared library (`.so`)
- Debian package (`.deb`)
- RPM package (`.rpm`)
- AppImage
- Snap
- Flatpak
- Tar archive
- ZIP archive
- Shell script
- Python package/application
- Java JAR/WAR
- .NET application
- Electron application
- Qt/GTK application
- Go binary
- Rust binary
- Các file launcher/config liên quan

Không được dựa hoàn toàn vào extension để kết luận loại file.

---

## 4.3 Metadata cần thu thập

Với mỗi artifact, ưu tiên ghi nhận:

### Identification

- File name
- File size
- File type thực tế
- MIME type nếu xác định được
- Hash
  - SHA-256
- Architecture
  - x86
  - x86_64
  - ARM
  - ARM64
  - Unknown
- Endianness nếu liên quan
- 32-bit / 64-bit

### Application information

- Application/Product name
- Version
- Build/version string nếu có
- Vendor/Publisher nếu có
- Package name
- Package version
- Package architecture

### Execution information

- Executable hay không
- Entry point hoặc launcher chính
- Interpreter/runtime nếu có
- Dynamic/static linking nếu xác định được
- Shared libraries/dependencies sơ bộ

### Technology fingerprint

Có thể nhận diện sơ bộ các nhóm:

- Native C/C++
- Electron / Node.js
- Java
- Python
- .NET
- Qt
- GTK
- Go
- Rust
- Shell
- Unknown

Framework/runtime chỉ được kết luận khi có evidence.

Ví dụ evidence:

- ELF imports
- Dynamic libraries
- Embedded strings
- Package metadata
- Runtime files
- Known directory structure
- Manifest
- Launcher scripts
- Bundled framework libraries

---

# 5. Step 1 — Những việc KHÔNG làm

Step 1 không bao gồm:

- Vulnerability scanning
- CVE assessment
- Static code security analysis chuyên sâu
- Dynamic analysis
- Reverse engineering chuyên sâu
- Decompile/disassemble sâu
- Extract/unpack đầy đủ
- Secret scanning
- SAST
- Dependency vulnerability scanning
- Runtime hooking
- Fuzzing
- DefectDojo integration
- Tool comparison chuyên sâu

Các nội dung trên sẽ thuộc các bước sau.

---

# 6. Boundary giữa Step 1 và Step 2

Step 1 chỉ cần xác định:

> Artifact này là gì và có đặc điểm gì?

Step 2 mới trả lời:

> Artifact này có thể extract/unpack như thế nào, extract được đến mức nào, và sau khi extract sẽ thu được những thành phần gì?

Ví dụ:

Step 1:

```text
sample.AppImage
Type: AppImage
Architecture: x86_64
Application: ExampleApp
Version: 1.2.3
Framework indication: Electron
```

Step 2 mới xử lý:

```text
Có thể extract AppImage hay không?
Dùng cơ chế nào?
Sau extract có app.asar hay không?
Có filesystem squashfs hay không?
Có native module hay không?
```

---

# 7. Output mong muốn của Step 1

Output chính:

`STEP_01_Identification.md`

Nội dung nên bao gồm:

1. Mục tiêu
2. Phạm vi
3. Loại artifact cần nhận diện
4. Metadata cần thu thập
5. Technology/runtime fingerprint
6. Cách phân loại kết quả
7. Trường hợp Unknown
8. Bảng inventory mẫu
9. Tiêu chí hoàn thành Step 1
10. Input cho Step 2

---

# 8. Bảng inventory chuẩn đề xuất

| ID | File | Real Type | Arch | App | Version | Entry Point | Runtime/Framework | Evidence | SHA-256 | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| 01 | example | ELF | x86_64 | Unknown | Unknown | example | Native | ELF metadata | ... | Identified |
| 02 | app.AppImage | AppImage | x86_64 | ExampleApp | 1.2.3 | AppRun | Electron | bundled Electron libs | ... | Identified |

Các trạng thái có thể dùng:

- `Identified`
- `Partially Identified`
- `Unknown`
- `Needs Step 2`

---

# 9. Tiêu chí hoàn thành Step 1

Một artifact được coi là đã hoàn thành Step 1 khi tối thiểu đã xác định được:

- File tồn tại trong inventory
- Real file type
- Architecture nếu áp dụng
- Hash
- Application/package identity nếu có thể
- Version nếu có thể
- Entry point/launcher nếu có thể
- Runtime/framework sơ bộ nếu có evidence
- Các trường chưa xác định được ghi rõ `Unknown`
- Có đủ dữ liệu để quyết định hướng xử lý ở Step 2

Không yêu cầu phải tìm được mọi thông tin.

Không được cố suy đoán để điền cho đủ bảng.

---

# 10. Automation

Step 1 **có khả năng tự động hóa cao** vì phần lớn công việc là:

- Enumeration
- Fingerprinting
- Metadata extraction
- Hashing
- Architecture detection
- Package metadata parsing
- Runtime/framework heuristic detection

Tuy nhiên automation chỉ hỗ trợ thu thập dữ liệu.

Kết luận cuối cùng vẫn cần logic để:

- Loại bỏ false classification
- Xử lý artifact bất thường
- Đánh giá mức độ tin cậy của framework detection
- Quyết định khi nào nên để `Unknown`

Chi tiết thiết kế script không thuộc report Step 1 hiện tại và sẽ được xử lý riêng nếu cần.

---

# 11. Quy tắc làm việc cho các chat tiếp theo

Khi mở một chat mới cho project này, sử dụng prompt dạng:

```text
Đọc PROJECT_CONTEXT.md trước.

Chúng ta đang làm Step X.

Chỉ tập trung vào Step X.
Không tự động mở rộng sang Step X+1 nếu tôi chưa yêu cầu.

Nếu nội dung mới làm thay đổi quyết định của project,
hãy chỉ ra phần nào trong PROJECT_CONTEXT.md cần cập nhật.
```

Nếu có output của bước trước:

```text
Đọc:
- PROJECT_CONTEXT.md
- STEP_01_Identification.md

Bây giờ bắt đầu Step 2.
Không nhảy sang Step 3.
```

---

# 12. Context management

`PROJECT_CONTEXT.md` chỉ chứa:

- Mục tiêu project
- Workflow
- Scope
- Boundary giữa các bước
- Quyết định đã chốt
- Current state
- Important constraints

Không đưa toàn bộ nội dung nghiên cứu chi tiết vào file này.

Các nội dung chi tiết phải nằm ở file riêng:

```text
PROJECT_CONTEXT.md
STEP_01_Identification.md
STEP_02_Extraction.md
STEP_03_Extracted_Analysis.md
STEP_04_Security_Checklist.md
STEP_05_Tooling.md
STEP_06_Result_Validation.md
STEP_07_DefectDojo.md
STEP_08_Report.md
```

---

# 13. Progress Tracking

## Step 1 — Identification & Inventory

**Status:** In Progress / Near completion

Đã chốt:

- Step 1 là fingerprint + inventory.
- Không thực hiện vulnerability scanning ở Step 1.
- Không đi sâu vào tool selection.
- Framework/runtime phải có evidence.
- Không xác định được thì ghi `Unknown`.
- Step 1 có thể tự động hóa phần lớn việc thu thập metadata.
- Report Step 1 không cần đi sâu vào cơ chế chạy script.
- Report Step 1 chưa cần tập trung cho DevOps.

Output:

```text
STEP_01_Identification.md
```

## Step 2 — Extraction

**Status:** Not started

## Step 3 — Extracted Component Analysis

**Status:** Not started

## Step 4 — Security Check Categories

**Status:** Not started

## Step 5 — Tool Selection

**Status:** Batch 1 (CHK-01–CHK-06) completed; Batch 2 not started

## Step 6 — Result Validation

**Status:** Not started

## Step 7 — DefectDojo Integration

**Status:** Not started

## Step 8 — Detailed Reporting

**Status:** Not started

---

# 14. Important Project Rule

Luôn ưu tiên:

```text
Understand artifact
        ↓
Extract
        ↓
Understand extracted components
        ↓
Define what must be tested
        ↓
Select tools
        ↓
Run / evaluate
        ↓
Normalize findings
        ↓
DefectDojo
        ↓
Report
```

Không đảo thành:

```text
Có tool gì → chạy hết → xem output → cố ghép thành quy trình
```

Đây là nguyên tắc thiết kế chính của project.

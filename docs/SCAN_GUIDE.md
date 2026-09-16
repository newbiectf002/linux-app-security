# Hướng dẫn scan ELF executable và shared object

## 1. Phạm vi hiện tại

Scanner MVP hiện hỗ trợ đúng hai loại input:

- ELF executable.
- ELF shared object (`.so`, kể cả file shared object không có đuôi `.so`).

Scanner thực hiện static inspection. Scanner không chạy target và không dùng
`ldd` trên binary được cung cấp.

Flow output:

```text
Target / App
    ↓
ELF discovery → raw/ evidence
    ↓
normalized/inventory.json
    ↓
Correlation rules → normalized/findings.json
    ↓
run.json
    ├── report.html
    └── defectdojo-generic-findings.json (khi export tường minh)
```

## 2. Chuẩn bị

Chạy lệnh từ thư mục gốc repository:

```sh
cd /workspace/linux-app-security
```

Các tool chính cần có:

```text
python3
file
sha256sum
readelf
objdump
nm
stat
getcap
dpkg-query (chỉ dùng cho package provenance trên Debian/Ubuntu host root)
```

Có thể dùng container của project nếu máy chính chưa có đủ tool:

```sh
docker compose build
docker compose run --rm research
```

## 3. Scan một ELF executable

Ví dụ target thực tế:

```text
/data/application/bin/application
```

Nếu chỉ có một file và không có filesystem root đi kèm:

```sh
python3 scripts/scan/scan-elf.py \
  /data/application/bin/application
```

Trong chế độ này, metadata, hardening, permissions, symbols và capability vẫn
được thu thập. Dependency hoặc absolute search path cần filesystem context có
thể trả về:

```text
TARGET_ROOT_CONTEXT_REQUIRED
RUNTIME_CONTEXT_REQUIRED
```

Nếu target nằm trong một filesystem/application tree đã extract, nên truyền
root tường minh:

```sh
python3 scripts/scan/scan-elf.py \
  /data/extracted-root/opt/product/bin/application \
  --target-root /data/extracted-root
```

`target` phải nằm bên trong `--target-root`. Root này được dùng để resolve
absolute RPATH/RUNPATH và system-like library paths mà không lấy nhầm library
từ host scanner.

## 4. Scan một ELF shared object `.so`

Ví dụ target thực tế:

```text
/data/extracted-root/opt/product/lib/libproduct.so.1
```

Scan file `.so` với extracted root:

```sh
python3 scripts/scan/scan-elf.py \
  /data/extracted-root/opt/product/lib/libproduct.so.1 \
  --target-root /data/extracted-root
```

Nếu không có extracted root:

```sh
python3 scripts/scan/scan-elf.py \
  /data/application/libproduct.so
```

Shared object được nhận diện bằng ELF metadata, không chỉ bằng extension.
Scanner thu thập DT_NEEDED, SONAME, hardening, permissions, imported/exported
capability symbols và dependency provenance khi đủ context.

## 5. Chọn thư mục output

Mặc định scanner ghi vào:

```text
output/runs/<run-id>/
```

Có thể chọn output root khác:

```sh
python3 scripts/scan/scan-elf.py \
  /data/extracted-root/opt/product/bin/application \
  --target-root /data/extracted-root \
  --output-dir /data/scan-results
```

Kết quả sẽ nằm tại:

```text
/data/scan-results/runs/<run-id>/
```

Mỗi lần chạy tạo một `run-id` mới và không overwrite run cũ.
Khi thành công, CLI in `run_root` cùng đường dẫn tới `run.json`, inventory và
findings. File đơn không phải ELF executable/shared object trả exit code khác 0;
evidence nhận diện vẫn được giữ trong run directory được nêu trong thông báo lỗi.

## 6. Scan cả thư mục

Scanner cũng nhận directory và kiểm tra các file bên trong:

```sh
python3 scripts/scan/scan-elf.py \
  /data/extracted-root/opt/product \
  --target-root /data/extracted-root
```

Các file không thuộc hai loại ELF MVP vẫn được inventory với trạng thái không
được implement; scanner không tự mở rộng sang package/script scanning.

## 7. Cấu trúc output

```text
output/runs/<run-id>/
├── run.json
├── normalized/
│   ├── inventory.json
│   └── findings.json
├── report.html
└── raw/
    ├── ev-000001-.../
    │   ├── metadata.json
    │   ├── stdout.txt
    │   └── stderr.txt
    └── ev-.../
```

### `run.json`

Chứa metadata run và đường dẫn tới normalized output.

### `normalized/inventory.json`

Chứa dữ liệu normalized theo component, gồm:

- ELF identity và architecture.
- Hardening indicators.
- Dynamic linking, RPATH/RUNPATH và DT_NEEDED.
- File permissions, SetUID/SetGID và Linux file capabilities.
- Imported/exported API capability indicators.
- Dependency resolution và provenance.
- `evidence_refs` để truy về raw evidence.

### `normalized/findings.json`

Hiện chỉ có năm rule correlation tối giản:

- Writable executable.
- Privileged writable executable.
- Writable shared object.
- Executable sử dụng writable resolved RPATH/RUNPATH directory.
- Privileged executable sử dụng writable resolved RPATH/RUNPATH directory.

`writable_by_non_owner` bao gồm cả group-writable và world-writable; đánh giá hiện tại không chứng minh runtime process thực sự thuộc group tương ứng.
ACL, runtime identity và runtime group membership chưa được đánh giá sâu.

Các hardening/API/dependency indicators khác không tự động trở thành finding.

### `raw/`

Giữ stdout, stderr, command metadata hoặc structured filesystem evidence của
từng invocation. Khi chuyển kết quả sang máy khác, nên copy nguyên thư mục run
để không làm đứt `evidence_refs`.

## 8. Xem nhanh kết quả

Sau khi scanner in ra `run_root`, có thể đặt biến:

```sh
SCAN_RUN=/workspace/linux-app-security/output/runs/<run-id>
```

Xem summary inventory:

```sh
jq '.summary' "$SCAN_RUN/normalized/inventory.json"
```

Xem danh sách ELF:

```sh
jq '.records[] | {path, type, status, component_id}' \
  "$SCAN_RUN/normalized/inventory.json"
```

Xem dependency:

```sh
jq '.records[] | {path, dependencies}' \
  "$SCAN_RUN/normalized/inventory.json"
```

Xem capability được phát hiện:

```sh
jq '.records[] | {path, capabilities}' \
  "$SCAN_RUN/normalized/inventory.json"
```

Xem findings:

```sh
jq '{summary, findings}' "$SCAN_RUN/normalized/findings.json"
```

Export findings sang JSON cho parser `Generic Findings Import` của DefectDojo:

```sh
python3 scripts/export/export-defectdojo.py \
  "$SCAN_RUN/normalized/findings.json"
```

Mặc định lệnh tạo `$SCAN_RUN/defectdojo-generic-findings.json`. Export chỉ map
dữ liệu đã có như severity, rule/component ID, affected path, classification,
confidence, remediation và evidence references; không tự tạo CVE, CWE hoặc
package/version. Findings rỗng tạo report hợp lệ với mảng `findings` rỗng.
Trường top-level `type` là `Linux ELF Security`; theo convention của Generic
Findings Import, DefectDojo có thể hiển thị Test Type dẫn xuất từ tên này.

Tạo HTML report tĩnh, tự chứa và mở trực tiếp bằng browser:

```sh
python3 scripts/report/generate-html-report.py \
  "$SCAN_RUN"
```

Report được ghi tại `$SCAN_RUN/report.html`, không dùng CDN, web server hoặc
external asset. Scan mới tự tạo report này mặc định; dùng `--no-report` trên
`scan-elf.py` để tắt. Standalone generator vẫn dùng được để tạo lại report từ
run cũ.

## 9. Package ownership trên live system

Chỉ dùng host package database khi chủ động scan live root `/`:

```sh
python3 scripts/scan/scan-elf.py \
  /usr/bin/example \
  --target-root /
```

Trên Debian/Ubuntu, scanner có thể dùng `dpkg-query` cho dependency đã resolve
về system path. Không dùng `--target-root /` cho artifact thuộc extracted root
hoặc đến từ máy khác, vì package database của host không đại diện cho target đó.

## 10. Di chuyển kết quả sang máy chính

Copy nguyên run:

```sh
cp -a \
  /workspace/linux-app-security/output/runs/<run-id> \
  /duong/dan/tren-may-chinh/
```

Hoặc tạo archive:

```sh
tar -C /workspace/linux-app-security/output/runs \
  -czf /tmp/linux-app-security-<run-id>.tar.gz \
  <run-id>
```

Không chỉ copy riêng `findings.json`: lead cần `inventory.json`, `run.json` và
`raw/` để review evidence đầy đủ.

## 11. Diễn giải an toàn

- Finding là kết quả correlation có evidence, không mặc nhiên là confirmed vulnerability.
- API như `system` hoặc `dlopen` chỉ là capability indicator.
- Missing RELRO, canary, PIE hoặc FORTIFY chưa tạo finding trong iteration hiện tại.
- Dependency `NOT_FOUND`, `UNKNOWN` hoặc unresolved context không tự động là vulnerability.
- `NOT_EVALUATED`, `TARGET_ROOT_CONTEXT_REQUIRED` và
  `RUNTIME_CONTEXT_REQUIRED` là trạng thái giới hạn evidence/context, không phải
  finding xác nhận.
- Không chạy target để “xác minh” nếu chưa có môi trường dynamic analysis cô lập và authorization riêng.

Các output mẫu nhỏ, đã sanitize và không chứa raw runtime evidence nằm trong
[`docs/examples/`](examples/).

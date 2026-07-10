# Bộ dataset IRIS (CWE-Bench-Java) — cấu trúc và các mẫu

Bộ dataset dùng để đánh giá pipeline là **CWE-Bench-Java**, công bố kèm bài báo
IRIS (*"IRIS: LLM-Assisted Static Analysis for Detecting Security
Vulnerabilities"*, Li et al., ICLR 2025; repo gốc:
`https://github.com/iris-sast/cwe-bench-java`). Đây là benchmark gồm **120 CVE
thực tế** trên các dự án Java mã nguồn mở (DSpace, Spark, WildFly, ActiveMQ,
XStream, Struts, Dubbo, ...), phủ nhiều loại CWE (path traversal, deserialization,
injection, SSRF, ...).

Toàn bộ dataset gồm 2 file CSV, bản đầy đủ đính kèm trong thư mục `dataset/`:

| File | Số bản ghi | Vai trò |
|---|---|---|
| `dataset/cwe_bench_java_project_info.csv` | 120 CVE | Ánh xạ CVE → dự án, phiên bản lỗi, commit vá (ground truth cho bước tìm patch) |
| `dataset/cwe_bench_java_fix_info.csv` | 1104 dòng | Ground truth mức method: file/class/method nào bị sửa trong commit vá (ground truth cho bước trích xuất định danh) |

**Lưu ý minh bạch:** 2 dòng gold trong bản chúng em dùng đã được đính chính so
với bản upstream sau khi audit thủ công (CVE-2020-17530 của Struts và
CVE-2022-24891 của ESAPI — commit gold gốc trỏ nhầm sang commit release/Javadoc,
không phải commit sửa lỗi thực). Chi tiết audit ở `docs/gold_audit_heldout.md`
trong repo đồ án.

---

## File 1: `project_info.csv` — mỗi dòng là 1 CVE

12 cột:

| Cột | Ý nghĩa |
|---|---|
| `id` | Số thứ tự bản ghi (1–120) |
| `project_slug` | Định danh duy nhất: `{owner}__{repo}_{CVE}_{version}` |
| `cve_id` | Mã CVE |
| `cwe_id`, `cwe_name` | Loại điểm yếu (CWE) và tên đầy đủ |
| `github_username`, `github_repository_name`, `github_url` | Repo GitHub của dự án bị lỗi |
| `github_tag` | Tag phiên bản CÒN LỖI (phiên bản được phân tích) |
| `advisory_id` | Mã GHSA advisory tương ứng |
| `buggy_commit_id` | Commit của phiên bản còn lỗi |
| `fix_commit_ids` | Commit vá lỗi (ground truth; nhiều commit ngăn cách bằng `;`) |

### Mẫu 1 — DSpace, CVE-2016-10726 (Path Traversal)

```
id:                     1
project_slug:           DSpace__DSpace_CVE-2016-10726_4.4
cve_id:                 CVE-2016-10726
cwe_id:                 CWE-022
cwe_name:               Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
github_username:        DSpace
github_repository_name: DSpace
github_tag:             4.4
github_url:             https://github.com/DSpace/DSpace
advisory_id:            GHSA-4m9r-5gqp-7j82
buggy_commit_id:        ca4c86b1baa4e0b07975b1da86a34a6e7170b3b7
fix_commit_ids:         4239abd2dd2ae0dedd7edc95a5c9f264fdcf639d
```

### Mẫu 2 — Spark (web framework), CVE-2018-9159 (Path Traversal, vá bằng 3 commit)

```
id:                     2
project_slug:           perwendel__spark_CVE-2018-9159_2.7.1
cve_id:                 CVE-2018-9159
cwe_id:                 CWE-022
cwe_name:               Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
github_username:        perwendel
github_repository_name: spark
github_tag:             2.7.1
github_url:             https://github.com/perwendel/spark
advisory_id:            GHSA-76qr-mmh8-cp8f
buggy_commit_id:        5316c0d0f057daaf556c3907c20df975f7bf8a8a
fix_commit_ids:         030e9d00125cbd1ad759668f85488aba1019c668;a221a864db28eb736d36041df2fa6eb8839fc5cd;ce9e11517eca69e58ed4378d1e47a02bd06863cc
```

### Mẫu 3 — WildFly, CVE-2018-1047 (Path Traversal)

```
id:                     4
project_slug:           wildfly__wildfly_CVE-2018-1047_11.0.0.Final
cve_id:                 CVE-2018-1047
cwe_id:                 CWE-022
github_tag:             11.0.0.Final
github_url:             https://github.com/wildfly/wildfly
advisory_id:            GHSA-fmr4-w67p-vh8x
buggy_commit_id:        4fd7bffaf2ee73201910684f2674aa1bced7fe81
fix_commit_ids:         735c77ce8b3bab6aa5072fb8575dc96db52d01ab;21c358acf0b06f38ec46034404c7a3d0bbbc132d;9ff55ed2da845a6f604b2edd1bc3bd311f1b776c
```

---

## File 2: `fix_info.csv` — mỗi dòng là 1 method bị sửa trong commit vá

13 cột:

| Cột | Ý nghĩa |
|---|---|
| `project_slug`, `cve_id` | Khóa nối sang `project_info.csv` |
| `github_username`, `github_repository_name` | Repo |
| `commit` | SHA commit vá chứa thay đổi này |
| `file` | Đường dẫn file Java bị sửa |
| `class` | Tên class chứa thay đổi |
| `class_start`, `class_end` | Dòng bắt đầu/kết thúc của class |
| `method` | Tên method bị sửa |
| `method_start`, `method_end` | Dòng bắt đầu/kết thúc của method |
| `signature` | Chữ ký đầy đủ của method |

### Mẫu 1 — ActiveMQ CVE-2014-3576: method `processControlCommand` bị sửa

```
project_slug:  apache__activemq_CVE-2014-3576_5.10.1
cve_id:        CVE-2014-3576
commit:        f07e6a53216f9388185ac2b39f366f3bfd6a8a55
file:          activemq-broker/src/main/java/org/apache/activemq/broker/TransportConnection.java
class:         TransportConnection   (dòng 104–1654)
method:        processControlCommand (dòng 1536–1538)
signature:     Response processControlCommand(ControlCommand)
```

### Mẫu 2 — DSpace CVE-2016-10726: method `setup` của `SafeResourceReader`

```
project_slug:  DSpace__DSpace_CVE-2016-10726_4.4
cve_id:        CVE-2016-10726
commit:        4239abd2dd2ae0dedd7edc95a5c9f264fdcf639d
file:          dspace-xmlui/src/main/java/org/dspace/app/xmlui/cocoon/SafeResourceReader.java
class:         SafeResourceReader (dòng 25–34)
method:        setup (dòng 34–65)
signature:     void setup(SourceResolver,Map,String,Parameters)
```

### Mẫu 3 — Spark CVE-2018-9159: 1 CVE có NHIỀU dòng fix_info (constructor + getPath)

```
project_slug:  perwendel__spark_CVE-2018-9159_2.7.1
cve_id:        CVE-2018-9159
commit:        030e9d00125cbd1ad759668f85488aba1019c668
file:          src/main/java/spark/resource/ClassPathResource.java
class:         ClassPathResource (dòng 41–252)
method:        ClassPathResource (constructor, dòng 75–86)
signature:     ClassPathResource(String,ClassLoader)

-- cùng commit, method thứ hai --
method:        getPath (dòng 112–113)
signature:     String getPath()
```

(Lưu ý: `fix_info.csv` cũng ghi cả các file **test** bị sửa trong commit vá —
ví dụ `EmbeddedJettyFactoryTest.java` của Spark; khi dùng làm ground truth cho
định danh lỗ hổng, pipeline lọc các dòng test ra.)

---

## Dataset được dùng ở đâu trong pipeline

1. **Đánh giá bước tìm patch (`patch_fetch`):** pipeline chỉ nhận `cve_id` +
   repo; commit nó tìm ra được so với cột `fix_commit_ids` (ground truth).
2. **Đánh giá bước trích xuất định danh (`research`):** các bucket
   `vulnerable_functions` / `vulnerable_classes` mà dossier sinh ra được so
   với cột `class` / `method` của `fix_info.csv`.
3. **Đánh giá reachability:** phiên bản còn lỗi (`github_tag` /
   `buggy_commit_id`) được build thành CodeQL database để chạy truy vấn.

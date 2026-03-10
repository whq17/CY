# ShieldScope: Defensive Surface Risk Mapper

โปรเจกต์นี้เน้นงาน **defensive security** สำหรับประเมินความเสี่ยงจากผลสแกนพอร์ตและ banner ด้วยแนวทาง heuristic แล้ว map ไปยัง **OWASP Top 10 (2021)** เพื่อช่วยทีม Blue Team/DevSecOps จัดลำดับการแก้ไขได้เร็วขึ้น

## Output Schema (ปรับคอลัมน์ผลลัพธ์)

ผลลัพธ์หลักใช้คอลัมน์:

- `Risk`
- `OWASP Mapping`

โดยสามารถสรุปเชิงข้อความแบบบรรทัดเดียวได้ในรูปแบบ:

```text
HIGH | Service=HTTP | Findings=plaintext protocol, outdated component banner | OWASP: A02 Cryptographic Failures; A06 Vulnerable and Outdated Components; A07 Identification and Authentication Failures
```

## Heuristic Mapping: Port Scan + Banner -> OWASP Top 10

### 1) Service Classification Logic

แยก service จากพอร์ต + banner keyword ดังนี้ (ใช้ร่วมกันเพื่อความแม่นยำ):

- **HTTP/HTTPS**: `http`, `nginx`, `apache`, `iis`, `tomcat`, `jetty`
- **FTP**: `ftp`, `vsftpd`, `proftpd`, `filezilla server`
- **Telnet**: `telnet`
- **MySQL**: `mysql`, `mariadb`
- **Redis**: `redis`
- **PostgreSQL**: `postgres`, `postgresql`

### 2) Findings Interpretation Logic

ตีความ finding พื้นฐานจากข้อมูลที่สแกนได้:

- `plaintext protocol`
  - protocol ไม่เข้ารหัสหรือ service มักถูกใช้แบบไม่เข้ารหัส (เช่น FTP, Telnet, HTTP)
- `backend service exposed`
  - service ฝั่ง backend ถูกเปิดสู่ external network โดยไม่ควรเข้าถึงตรง
- `outdated component banner`
  - banner ระบุเวอร์ชันเก่า/มีแนวโน้ม EOL หรือมี known CVE
- `auth surface`
  - service มีพื้นผิวการยืนยันตัวตน/credential attack surface (เช่น login prompt, database auth)
- `misconfiguration indicator`
  - สัญญาณ config เสี่ยง เช่น anonymous access, default realm, weak hardening hints

### 3) OWASP Heuristic Mapping

- `plaintext protocol` -> **A02:2021 Cryptographic Failures**
- `backend service exposed` -> **A05:2021 Security Misconfiguration**
- `outdated component banner` -> **A06:2021 Vulnerable and Outdated Components**
- `auth surface` -> **A07:2021 Identification and Authentication Failures**
- `misconfiguration indicator` -> **A05:2021 Security Misconfiguration**

### 4) Service-Aware Risk Hints

- **HTTP**
  - ถ้าเจอ `Server` banner เก่า + ไม่มี TLS -> เพิ่มน้ำหนักความเสี่ยง (A02 + A06)
- **FTP / Telnet**
  - จัดเป็น `HIGH` โดย default หากเปิดบน external network (plaintext + auth surface)
- **MySQL / PostgreSQL / Redis**
  - ถ้า public exposure -> อย่างน้อย `MEDIUM` ถึง `HIGH` ตาม finding เสริม (backend exposure, auth surface, misconfiguration)

## Suggested Scoring (แนวทาง)

- เริ่มต้น `LOW`
- ถ้าเจอ `plaintext protocol` -> ยกเป็นอย่างน้อย `MEDIUM`
- ถ้าเจอ `backend service exposed` หรือ `outdated component banner` -> +1 ระดับ
- ถ้าเจอหลาย finding ซ้อนกัน (>=3) -> `HIGH`

## Example Summaries

```text
HIGH | Service=HTTP | Findings=plaintext protocol, outdated component banner, auth surface | OWASP: A02:2021; A06:2021; A07:2021
HIGH | Service=Telnet | Findings=plaintext protocol, auth surface, misconfiguration indicator | OWASP: A02:2021; A07:2021; A05:2021
MEDIUM | Service=Redis | Findings=backend service exposed, misconfiguration indicator | OWASP: A05:2021
```

## Defensive Security Positioning

ชื่อโปรเจกต์ปรับเป็น **ShieldScope: Defensive Surface Risk Mapper** เพื่อสื่อว่าเป็นเครื่องมือฝั่งป้องกันสำหรับการวิเคราะห์ attack surface และจัดลำดับ remediation

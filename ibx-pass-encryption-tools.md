# IBX_PASS 암호화 도구 비교 조사 (seed key 입력 방식, AES256 이상)

작성일: 2026-10-25
작성자: k.s.k & kiro
목적: `dns-ibx.sh` 의 `IBX_PASS`(Infoblox WAPI 비밀번호)를 평문으로 두지 않고, **오픈소스 대칭(양방향) 암호화 도구**로 암호화해 저장하고, 실행 시 **seed key(패스프레이즈)를 입력받아** 복호화해서 쓰는 방식을 설계하기 위한 비교 자료.
요구사항: 암호화/복호화 시 seed key string 입력 / Linux·Windows 지원 / 알고리즘 **AES256 이상** / 버전 업그레이드 대응.

---

## 0. 한눈에 보기 (결론)

| 도구 | 알고리즘 | seed key 입력 | Linux | Windows | AES256 요건 | 추천 용도 |
|------|----------|---------------|:-----:|:-------:|:-----------:|-----------|
| **OpenSSL `enc`** | **AES-256-CBC** + PBKDF2 (`enc` 는 GCM 등 AEAD 미지원) | `-pass pass:`/`env:`/`stdin` | 기본 탑재 | Git/WSL/바이너리 | **충족(AES256)** | 스크립트 연동 1순위 |
| **GnuPG (`gpg -c`)** | **AES256** (`--cipher-algo AES256`) + S2K | `--passphrase*` / 대화형 | 기본 탑재 | Gpg4win/scoop | **충족(AES256)** | 파일 보관·장기 호환 |
| age (참고) | **ChaCha20-Poly1305**(256-bit AEAD) + scrypt | 대화형 passphrase | 바이너리 | 바이너리/winget | **미충족**(AES 아님) | 단순성 중시, AES 요건 없을 때 |

> 핵심 판단: 사용자의 "**AES256 이상**" 조건을 **알고리즘 명칭 그대로** 만족하는 것은 **OpenSSL**, **GnuPG** 두 가지입니다. age 는 현대적이고 안전하지만 AES 를 지원하지 않고 ChaCha20-Poly1305(AES256 과 동급 강도의 256-bit 암호)를 쓰므로, "AES256 계열" 명시 요건에는 부합하지 않아 **보조 참고**로만 소개합니다.
> 스크립트(`dns-ibx.sh`) 연동에는 **OpenSSL** 이 가장 매끄럽고(파이프/비대화형/Base64 한 줄), 파일 단위 장기 보관·범용 호환에는 **GnuPG** 가 강합니다.

---

## 1. OpenSSL `enc` — 1순위 (스크립트 연동)

### 1.1 개요
- OpenSSL 은 사실상 모든 Linux 에 기본 탑재. Windows 는 Git for Windows, WSL, Chocolatey/scoop, 공식 빌드로 사용.
- `openssl enc` 로 대칭 암호화. **`-aes-256-cbc`** + **`-pbkdf2`** 로 패스프레이즈(=seed key)에서 키 유도. (`-pbkdf2` 는 **OpenSSL 1.1.1 이상** 필요: CentOS/RHEL 7 의 1.0.2k, macOS 기본 LibreSSL 은 미지원)
- Base64(`-a`) 출력으로 환경변수/설정파일에 한 줄 보관 용이.

### 1.2 사용 예시 (seed key 입력 방식) — 본 환경에서 왕복 검증 완료
```bash
SEED="조직-공용-seed-key-문자열"       # 복호화 때도 같은 값을 입력해야 함

# [암호화] 평문 비밀번호 -> Base64 암호문 한 줄
ENC=$(printf '%s' 'S3cr3t-IBX-Pass!' \
      | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -a -A -pass pass:"$SEED")
echo "$ENC"      # 예: U2FsdGVkX18... (매번 salt 가 달라 값이 변함 = 정상)

# [복호화] 같은 seed key 로만 복원됨
DEC=$(printf '%s' "$ENC" \
      | openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -a -A -pass pass:"$SEED")
echo "$DEC"      # S3cr3t-IBX-Pass!
```
- `-pass pass:"$SEED"` : seed key 를 인자로 전달(간편). 더 안전하게는 `-pass env:SEED`(환경변수) 또는 `-pass stdin`(파이프)으로 전달해 `ps`/히스토리 노출을 줄임.
- `-iter 200000` : PBKDF2 반복 횟수(무차별 대입 지연). 값을 올리면 더 안전하지만 느려짐. **암·복호화에 같은 값 사용 필수**.
- `-salt`(기본 on), `-a -A` : salt 사용 + Base64 한 줄 출력.
- **정정(2026-10-26)**: 초안에는 `-aes-256-gcm` 도 쓸 수 있다고 적었으나 **오류**입니다. `openssl enc` 는 AEAD 암호를 지원하지 않아 `enc: AEAD ciphers not supported` 로 실패합니다(OpenSSL 3.2.3 실측). `enc` 에서는 CBC 를 쓰고, 무결성은 평문 앞 검증 마커(`SS1:`)로 보완합니다(`secret-mgr.sh` 참고).

### 1.3 dns-ibx.sh 연동 예시
```bash
# (1) 한 번만: 암호문을 파일로 저장 (평문 비번은 메모리에만)
read -rsp 'IBX 비밀번호: ' PW; echo
read -rsp 'SEED KEY: ' SEED; echo
printf '%s' "$PW" | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -a -A \
  -pass env:SEED > ~/.ibx_pass.enc        # SEED 는 env 로 전달
chmod 600 ~/.ibx_pass.enc
unset PW

# (2) 실행 시: seed key 입력받아 복호화 -> IBX_PASS 로 주입
read -rsp 'SEED KEY: ' SEED; echo
export IBX_PASS="$(openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -a -A \
  -pass env:SEED -in ~/.ibx_pass.enc)"
unset SEED
./dns-ibx.sh verify -f dns.info
unset IBX_PASS
```

### 1.4 버전 업그레이드 대응 (중요)
- **KDF 기본 해시 변경**: OpenSSL **1.1.0 부터** 패스워드 기반 키 유도 기본 해시가 **MD5 → SHA256** 으로 바뀜. 과거(1.0.x) 방식으로 만든 암호문을 신버전에서 풀면 복호화가 깨질 수 있음. 내용은 OpenSSL `enc` 매뉴얼과 다수 Q&A 에서 확인(재서술).
- **대응 원칙**: 항상 **`-pbkdf2 -iter <N>` 를 명시**하면 `EVP_BytesToKey`(구방식)에 의존하지 않아 **버전 간 호환성이 안정적**. iter 값·cipher·KDF 를 암호문과 함께 기록(메타)해 두면 안전.
- **cipher/iter 고정 및 기록**: 암호화에 쓴 cipher·KDF·iter 를 복호화에서 동일하게 지정. 암호문 옆에 메타(`aes-256-cbc:pbkdf2-sha256:600000`)로 함께 저장하면 나중에 기본값이 바뀌어도 복호화됨(`secret-mgr.sh` 방식).
- **마이그레이션 절차**: OpenSSL major 업그레이드(예: 1.1→3.x) 전, 기존 암호문을 **구버전으로 복호화 → 신버전 파라미터로 재암호화**하는 재암호화(rotate) 스크립트를 1회 수행 권장.
- 3.x 에서 레거시 알고리즘(일부 구형 cipher)은 `legacy` provider 필요하지만, **AES-256 은 기본 provider 라 영향 없음**.

### 1.5 장단점
- 장점: 어디에나 있음, 스크립트 친화적(파이프/Base64), AES256 명시 충족, PBKDF2 지원.
- 단점: 옵션을 정확히 맞춰야 함(틀리면 복호화 실패), `enc` 는 AEAD(GCM) 미지원이라 CBC 는 인증(무결성) 없음 → 오답 seed 가 우연히 통과할 수 있어 검증 마커 등으로 보완 필요.

---

## 2. GnuPG (`gpg --symmetric`) — 파일 보관·장기 호환

### 2.1 개요
- OpenPGP 표준 구현. Linux 기본 탑재, Windows 는 **Gpg4win**(또는 scoop/choco). 대칭 암호화는 `gpg -c`.
- `--cipher-algo AES256` 으로 **AES256 명시**. 패스프레이즈(=seed key)를 S2K 로 키 유도. 기본으로 무결성 보호(MDC/AEAD).

### 2.2 사용 예시 (seed key 입력 방식)
```bash
SEED="조직-공용-seed-key-문자열"

# [암호화] AES256 명시, 비대화형 패스프레이즈 입력
printf '%s' 'S3cr3t-IBX-Pass!' \
  | gpg --batch --yes --symmetric --cipher-algo AES256 \
        --s2k-digest-algo SHA512 --s2k-count 65011712 \
        --pinentry-mode loopback --passphrase "$SEED" \
        -o ~/.ibx_pass.gpg
chmod 600 ~/.ibx_pass.gpg

# [복호화] 같은 seed key 로 복원 -> IBX_PASS 주입
export IBX_PASS="$(gpg --batch --quiet --decrypt \
  --pinentry-mode loopback --passphrase "$SEED" ~/.ibx_pass.gpg)"
```
- 대화형으로 쓰면 `--passphrase` 없이 실행 시 안전하게 프롬프트로 seed key 를 입력받음(히스토리 노출 없음).
- `--s2k-count` 등으로 KDF 강도 조절.

### 2.3 버전 업그레이드 대응
- **기본 cipher 가 버전/빌드에 따라 다를 수 있음** → 반드시 **`--cipher-algo AES256` 명시**(기본값 의존 금지).
- GnuPG 2.1→2.2→2.4 로 오며 S2K 기본값/AEAD(OCB) 지원이 강화됨. 구버전과 주고받을 파일이면 `--s2k-*` 와 cipher 를 고정해 호환 유지.
- 과거 "message was not integrity protected" 경고는 구형 옵션 사용 시 발생 → 최신 기본값(MDC/AEAD)을 쓰면 해소.
- major 업그레이드 시 동일하게 **복호화→재암호화 rotate** 로 파라미터를 신규 기준에 맞춤.

### 2.4 장단점
- 장점: AES256 명시, 무결성 기본 보호, 표준(OpenPGP)이라 장기 생존성·상호운용성 우수, 키 관리 생태계 풍부.
- 단점: 설치 부피/옵션 많음(복잡), Windows 는 Gpg4win 별도 설치, 비대화형엔 `--pinentry-mode loopback` 필요.

---

## 3. age (참고) — 단순·현대적이나 AES 미사용

### 3.1 개요
- Filippo Valsorda(Go 암호화) 설계. "작고 명확한 키, 설정 없음, footgun 없음"이 모토.
- 패스프레이즈 모드(`-p`)는 **scrypt** 로 키 유도 후 **ChaCha20-Poly1305**(256-bit AEAD)로 암호화. **AES 는 지원하지 않음**.

### 3.2 사용 예시
```bash
# [암호화] 대화형으로 passphrase(=seed key) 입력
printf '%s' 'S3cr3t-IBX-Pass!' | age -p -a -o ~/.ibx_pass.age
# [복호화] 같은 passphrase 입력
export IBX_PASS="$(age -d ~/.ibx_pass.age)"
```
- Windows 는 공식 바이너리/winget, Linux 는 패키지/바이너리로 설치.

### 3.3 왜 보조 참고인가
- 보안성·사용성은 뛰어나지만 **알고리즘이 ChaCha20-Poly1305** 여서 "AES256 이상" 을 **알고리즘 명칭으로** 요구하는 본 건에는 부적합.
- (ChaCha20-Poly1305 는 AES-256-GCM 과 동급의 256-bit 인증 암호로, 강도 면에선 열위가 아님. 다만 조직 표준이 "AES 계열"을 명시하면 OpenSSL/GPG 를 써야 함.)
- 버전 업그레이드 대응: age 는 포맷 v1 이 안정적이고 하위호환을 중시. 다만 프로젝트 성숙도/장기 생존성은 OpenSSL·GnuPG 대비 상대적으로 신생.

---

## 4. 안정성·범용성 종합 비교

| 관점 | OpenSSL | GnuPG | age |
|------|---------|-------|-----|
| Linux 기본 탑재 | ◎ | ◎ | △(설치) |
| Windows 사용성 | ○(Git/WSL/빌드) | ○(Gpg4win) | ○(winget/바이너리) |
| AES256 명시 | ◎ | ◎ | ✗(ChaCha20) |
| 무결성(AEAD) | △(`enc` 는 AEAD 불가, 마커로 보완) | ◎(기본) | ◎(기본) |
| 스크립트 연동 | ◎ | ○ | ○ |
| 장기 호환/표준 | ○ | ◎(OpenPGP) | △(신생) |
| 버전 호환 리스크 | KDF 기본해시 변경(명시로 회피) | 기본 cipher 변동(명시로 회피) | 포맷 안정 |
| seed key 입력 | pass:/env:/stdin | --passphrase/대화형 | 대화형 |

---

## 5. 권장안

1. **스크립트 연동**: OpenSSL `-aes-256-cbc` + `-pbkdf2 -iter 600000`(실측 약 0.9초). 여러 프로그램을 한 파일로 관리하려면 `dns-infoblox/secret-mgr.sh` 사용. 암호문은 `~/.ibx_pass.enc`(chmod 600), seed key 는 실행 시 `read -rsp` 로 입력받아 `env:`/`stdin` 으로만 전달.
2. **장기 파일 보관/상호운용**: GnuPG `-c --cipher-algo AES256`.
3. **공통 수칙**
   - 평문 비밀번호·seed key 를 **명령줄 인자/셸 히스토리/로그에 남기지 말 것**(env/stdin/대화형 입력).
   - 복호화 파라미터(cipher/mode/iter/kdf)를 암호화와 **반드시 일치**시키고, 메타로 기록.
   - 암호문 파일 권한 `600`, `.gitignore` 등록. seed key 는 사람이 기억/별도 비밀관리.
   - OpenSSL/GnuPG **major 업그레이드 시 rotate(복호화→재암호화)** 로 호환성 유지.
   - 더 높은 수준이 필요하면 OS 비밀 저장소/HashiCorp Vault/클라우드 KMS 등 전용 시크릿 관리로 승격 고려.

---

## 6. 출처 (교차 검증)

- OpenSSL `enc` 매뉴얼(3.x) — ciphers(`-aes-256-cbc`), `-pbkdf2`, 기본 digest 변경 기록: https://docs.openssl.org/3.3/man1/openssl-enc/ , https://docs.openssl.org/3.0/man1/openssl-enc/
- OpenSSL 1.1.0 KDF 기본 해시 MD5→SHA256 변경(버전 호환): security.stackexchange / stackoverflow 다수 Q&A
- 비대화형 패스프레이즈 전달(`-pass env:`)로 `ps`/히스토리 노출 회피: systutorials 문서
- GnuPG 대칭 암호화(`-c`, `--cipher-algo`, S2K): https://gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html , linuxize/GPG 가이드
- age(README, passphrase/scrypt/ChaCha20-Poly1305, AES 미지원 논의): https://github.com/FiloSottile/age , FiloSottile/age Discussion #368(AES-GCM 지원 요청)
- 본 환경 실측: OpenSSL 3.2.3 로 AES-256-CBC+PBKDF2 암·복호화 왕복 성공, 잘못된 seed key 복호화 거부 확인.

> 외부 자료 내용은 라이선스 준수를 위해 재서술했습니다.

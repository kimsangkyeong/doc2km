# secret-mgr.sh — 여러 프로그램의 비밀번호를 단일 암호화 파일로 관리

작성일: 2026-10-26 (v1.0)
작성자: k.s.k & kiro
관련: `secret-mgr.sh`, `dns-ibx.sh`(v1.2 연동), `../ibx-pass-encryption-tools.md`(도구 비교 조사)

## 1. 질문 요약

- `openssl enc` 로 암호문을 만들고, 실행 시 복호화해서 `IBX_PASS` 로 주입하고 싶다.
- 비밀번호를 쓰는 프로그램이 여럿이라 **파일 1개에 프로그램명과 함께 record 형식**으로 관리하고, 프로그램별로 등록/조회하고 싶다.
- 별도 shell script 로 만들고 `dns-ibx.sh` 연동 방법도 제공, 다른 프로그램으로 확장 가능해야 한다.
- 동작을 cross-check 해 달라.

## 2. 설계

| 항목 | 내용 |
|------|------|
| 저장소 | **파일 1개** (`~/.secret-store.enc`, 환경변수 `SECRET_STORE` 또는 `-s` 로 변경) |
| 레코드 | 한 줄 = 한 프로그램 : `program|updated|cipher:kdf:iter|base64(openssl enc 출력)` |
| 암호화 | `openssl enc -aes-256-cbc -pbkdf2 -md sha256 -iter 600000 -salt -a -A` |
| seed key | 실행 시 숨김 입력(프롬프트). 디스크에 저장하지 않음. 레코드마다 **서로 다른 seed** 가능 |
| 메타 | 레코드가 자기 cipher/KDF/iter 를 갖고 있어, 기본값이 바뀌어도 **기존 레코드는 그대로 복호화** |
| 검증 마커 | 평문 앞에 `SS1:` 를 붙여 암호화. 복호화 후 마커가 없으면 오답 seed 로 판정 |

레코드 예 (`list` 는 이 중 암호문을 보여주지 않습니다):

```
# secret-mgr store (직접 편집 금지)
# program|updated|cipher:kdf:iter|base64(openssl enc payload)
dns-ibx|2026-10-26T09:10:11|aes-256-cbc:pbkdf2-sha256:600000|U2FsdGVkX1+...
app-b|2026-10-26T09:12:40|aes-256-cbc:pbkdf2-sha256:600000|U2FsdGVkX1/...
```

### 왜 이렇게 설계했나 (실측 근거)

- **GCM 불가**: `openssl enc` 는 AEAD 를 지원하지 않습니다(`enc: AEAD ciphers not supported`, OpenSSL 3.2.3 실측). 그래서 AES-256-CBC 를 쓰고, CBC 에 없는 무결성은 `SS1:` 마커로 보완했습니다. 마커 검사가 실제로 작동하는지는 "openssl 은 정상 복호화하지만 마커가 없는 레코드"를 만들어 거부되는 것으로 확인했습니다.
- **반복 600000**: [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) 가 PBKDF2-HMAC-SHA256 에 제시하는 작업량입니다. 실측 약 0.9초(200000 은 0.36초)라 대화형 사용에 무리 없습니다. 참고로 OWASP 는 Argon2id 를 1순위로 두고 PBKDF2 는 FIPS 준수 등이 필요할 때의 선택지로 안내하는데, `openssl enc` 는 Argon2 를 쓸 수 없어 PBKDF2 로 갑니다. 내용은 라이선스 준수를 위해 재서술했습니다.
- **seed/비밀번호를 인자로 넘기지 않음**: seed 는 `-pass env:`(해당 openssl 프로세스 환경변수), 평문은 stdin 으로만 전달해 `ps`·셸 히스토리에 남지 않게 했습니다.
- **쓰기 전 검증**: 암호화 직후 바로 복호화해 원문과 일치할 때만 저장합니다(읽을 수 없는 레코드 저장 방지). 저장은 임시파일 + `mv` 교체이고 직전 상태를 `.bak` 으로 1세대 보관합니다.

## 3. 사용법

### 3.1 등록 / 조회 / 관리

```bash
# 등록 (비밀번호 2회 + seed key 2회를 숨김 입력)
bash secret-mgr.sh set dns-ibx
bash secret-mgr.sh set app-b

# 목록 : 프로그램명/갱신시각/암호 파라미터만 표시 (비밀번호·암호문은 표시하지 않음)
bash secret-mgr.sh list

# 조회 : seed key 입력 -> stdout 으로 비밀번호 출력 (스크립트 연동용)
bash secret-mgr.sh get dns-ibx

# 복호화 가능 여부만 확인 (값 출력 없음)
bash secret-mgr.sh check dns-ibx

# 삭제 (확인 질문, 생략은 -y)
bash secret-mgr.sh delete app-b
```

- 같은 이름으로 `set` 하면 "덮어쓸까요?" 를 묻습니다. 비대화형이면 `-y` 가 필요합니다.
- 대화형 `get` 에서 seed 를 틀리면 최대 3회까지 다시 묻습니다.
- 종료코드: `0` 성공 / `1` 오류 / `3` 복호화 실패(오답 seed·손상) / `4` 미등록 / `5` 레코드 형식·메타 이상

### 3.2 dns-ibx.sh 연동 (자동)

`dns-ibx.sh` v1.2 는 **환경변수 `IBX_PASS` 가 비어 있을 때** 같은 폴더의 `secret-mgr.sh` 를 호출합니다. 비밀번호 우선순위는 `환경변수 IBX_PASS > conf 의 IBX_PASS > 암호화 저장소` 입니다.

```bash
# 1) 최초 1회 등록 (record 이름 = dns-ibx)
bash secret-mgr.sh set dns-ibx

# 2) 평소 사용 : seed key 만 입력하면 자동 복호화되어 WAPI 호출에 사용됨
./dns-ibx.sh verify -f dns.info
#   [INFO] 암호화 저장소에서 비밀번호를 복호화합니다 (program=dns-ibx)
#   [dns-ibx] seed key: ********
```

경로나 record 이름을 바꾸려면 `dns-ibx.conf` 또는 환경변수에 지정합니다.

```bash
SECRET_TOOL="/opt/tools/secret-mgr.sh"   # 공용 위치로 옮긴 경우
SECRET_PROGRAM="dns-ibx-prod"            # 운영/개발 계정 분리 등
```

### 3.3 직접 IBX_PASS 로 주입 (수동 방식)

```bash
export IBX_PASS="$(bash secret-mgr.sh get dns-ibx)"   # seed 프롬프트 -> 복호화
./dns-ibx.sh verify -f dns.info
unset IBX_PASS
```

### 3.4 다른 프로그램으로 확장

다른 스크립트는 `record 이름만 다르게` 같은 도구를 호출하면 됩니다. 저장소 파일은 공유하고, 프로그램마다 seed 를 달리할 수도 있습니다.

```bash
# 등록
bash secret-mgr.sh set backup-db
bash secret-mgr.sh set grafana-admin

# 각 프로그램 스크립트 안에서
DB_PASS="$(bash /opt/tools/secret-mgr.sh get backup-db)" || exit 1
mysqldump -u backup -p"$DB_PASS" ...      # 실제로는 인자 대신 설정파일/환경변수 방식 권장
```

주의: 위처럼 비밀번호를 명령줄 인자(`-p"$DB_PASS"`)로 쓰면 `ps` 에 노출되므로, 대상 프로그램이 지원하는 환경변수/설정파일/stdin 방식을 우선하세요.

### 3.5 무인 실행(cron) 시 seed 전달

```bash
printf '%s\n' '조직-seed-key' > /root/.seed; chmod 600 /root/.seed
SECRET_SEED_FILE=/root/.seed ./dns-ibx.sh verify -f dns.info --fix
```

seed 입력 우선순위: **`-S`/`SECRET_SEED_FILE` > `SECRET_SEED`(환경변수) > 대화형 프롬프트(권장)**.

> 한계: seed 파일이 암호문과 같은 서버에 있으면 그 서버가 뚫릴 때 둘 다 노출됩니다. 평문 저장보다는 낫지만 **난독화 수준**입니다. 무인 실행이 핵심 요건이면 Vault/클라우드 KMS 같은 전용 시크릿 관리 도입을 검토하세요. 환경변수 `SECRET_SEED` 도 같은 사용자/root 가 `/proc/<pid>/environ` 으로 볼 수 있어 파일(600)보다 약합니다.

## 4. 버전 업그레이드 대응

| 상황 | 대응 |
|------|------|
| 반복 횟수/KDF 를 올리고 싶음 | `SECRET_ITER=900000 bash secret-mgr.sh rekey --all --keep-seed` (seed 유지, 파라미터만 최신화) |
| seed key 를 교체 | `bash secret-mgr.sh rekey dns-ibx` (현재 seed → 새 seed 순서로 입력) |
| OpenSSL major 업그레이드(1.1.1 → 3.x 등) | 레코드가 메타를 갖고 `-pbkdf2 -md -iter` 를 항상 명시하므로 **그대로 복호화됨**. 이후 `rekey --all --keep-seed` 로 최신 파라미터 반영 |
| 서로 다른 seed 를 쓰는 레코드가 섞여 있음 | `rekey --all` 은 입력한 seed 로 풀리는 레코드만 변환하고, 나머지는 건드리지 않은 채 실패로 보고(종료코드 1) |
| 스크립트를 잃어버림 | 아래 5절의 일반 `openssl` 명령으로 직접 복구 가능 |

주의: 허용 목록에 없는 cipher/KDF 나 범위 밖 반복 횟수(10,000~10,000,000)의 메타는 변조·오류로 보고 거부합니다(종료코드 5).

## 5. 스크립트 없이 수동 복구

레코드는 표준 `openssl enc` 출력이라 도구가 없어도 복호화됩니다. 메타가 `aes-256-cbc:pbkdf2-sha256:600000` 이라면:

```bash
# 대상 record 의 4번째 필드(base64)를 B64 에 넣고
printf '%s' "$B64" | openssl enc -d -aes-256-cbc -pbkdf2 -md sha256 -iter 600000 -a -A -pass pass:'seed-key'
# 출력 : SS1:<비밀번호>     (앞의 SS1: 은 검증 마커이므로 제외하고 사용)
```

## 6. 교차 검증 결과 (cross-check)

실제 `openssl`(3.2.3)과 `curl` mock 으로 `_test_secret-mgr.sh` 92건, 기존 `_test_dns-ibx.sh` 48건(회귀) 모두 통과했습니다.

| 영역 | 확인한 내용 |
|------|-------------|
| 기본 동작 | 등록 → 조회 일치, 저장소에 평문·seed 없음, 메타 기록 |
| 오답 처리 | 틀린 seed → 종료코드 3·출력 없음, 미등록 → 4, **마커 없는 복호화 성공 케이스도 거부** |
| 다중 레코드 | 파일 1개에 여러 프로그램, seed 가 달라도 서로 교차 복호화 불가 |
| 입력 안전성 | 공백·따옴표·`$`·백틱·역슬래시·`|`·한글 포함 비밀번호 왕복, 짧은 seed/빈 값/잘못된 이름 거부 |
| 대화형 | 프롬프트 등록·조회, 틀리면 재시도, 3회 실패 종료, 확인 불일치 거부, 터미널 없으면 멈추지 않고 실패 |
| seed 경로 | seed 파일(CRLF 포함)·`-S`·환경변수, 우선순위(파일 > 환경변수) |
| 갱신/삭제 | 덮어쓰기 확인, 중복 줄 없음, `.bak` 생성, 삭제 후 다른 레코드 유지 |
| rekey | 파라미터만 갱신(값 유지), seed 교체(구 seed 거부), `--all` 혼합 seed, 틀린 현재 seed 거부 시 원본 보존 |
| 호환/복구 | **일반 `openssl enc -d` 로 수동 복호화 일치**, `Salted__` 헤더 확인, CRLF 저장소 읽기 |
| 변조 | 반복횟수 5, 미허용 cipher, 깨진 암호문, 필드 부족 → 모두 거부 |
| 기본 파라미터 | 기본값 600000 으로 등록·조회 왕복 |
| dns-ibx 연동 | 저장소에서 복호화한 비밀번호가 **curl 의 `-u admin:<비밀번호>` 로 정확히 전달**, 오답 seed 면 curl 호출 0회로 중단, `IBX_PASS` 환경변수 우선, 도구 없음/미등록은 명확히 실패, dry-run 경로 동작 |

웹 교차 확인: `enc -pbkdf2` 는 OpenSSL 1.1.1 부터 지원되며 CentOS/RHEL 7(1.0.2k)·macOS 기본 LibreSSL 은 미지원이라는 점을 여러 자료에서 확인했습니다([StackOverflow 답변](https://stackoverflow.com/questions/62426338/decrypt-pbkdf2-with-openssl-1-0-1e), [CentOS 버전 정리](https://superuser.com/questions/1567098/decrypting-file-in-openssl-1-1-1c-from-encryption-in-openssl-1-0-2k)). 내용은 라이선스 준수를 위해 재서술했습니다.

## 7. 한계와 사용 시 유의점

- **실제 Linux bastion 에서의 실행은 미검증**입니다. 이 환경(Git Bash + OpenSSL 3.2.3)에서만 확인했습니다. bastion 의 `openssl version` 이 1.1.1 이상인지 먼저 확인하세요. 미만이면 `secret-mgr.sh` 가 시작 시점에 이유를 알려주고 중단합니다.
- CBC 는 인증이 없어 **변조 탐지가 아닌 오답 seed 탐지** 수준입니다(`SS1:` 마커). 파일 자체의 변조 방지가 필요하면 파일 권한(600)과 접근 통제로 막아야 합니다.
- 동시에 여러 명이 같은 저장소를 수정하면 마지막 쓴 쪽이 이깁니다(잠금 없음). 변경 전 `.bak` 한 세대만 보관합니다.
- Windows(NTFS) 에서는 `chmod 600` 이 실제로 적용되지 않습니다(테스트에서도 해당 검사는 건너뜀). Linux bastion 에 두고 쓰는 것을 전제로 합니다.
- seed key 를 분실하면 복구할 방법이 없습니다. 별도 안전한 곳에 보관하세요.
- 저장소를 repo 안에 두더라도 커밋되지 않도록 `.gitignore` 에 `.secret-store*`, `*.enc`, `*.bak` 를 등록했습니다.

## 8. 파일 목록

| 파일 | 설명 |
|------|------|
| `secret-mgr.sh` | 비밀번호 저장소 관리 도구 (set/get/check/list/delete/rekey) |
| `dns-ibx.sh` | v1.2 : `IBX_PASS` 가 없으면 `secret-mgr.sh get` 으로 자동 복호화 |
| `dns-ibx.conf.example` | `SECRET_TOOL`/`SECRET_PROGRAM` 안내 추가 |
| `_test_secret-mgr.sh` | 92건 테스트 (실제 openssl, curl mock) |

# Bastion 서버에서 Infoblox WAPI 로 DNS A/PTR 레코드 관리

작성일: 2026-10-25 (v1.1)
대상: Infoblox NIOS WAPI **v2.11** (근거 문서: `Infoblox WAPI 2.11 Documentation.pdf`)
작성자: k.s.k & kiro

## 1. 질문 요약

리눅스 bastion 서버에서 API 로 Infoblox DNS 서버의 레코드를 관리하고 싶다.
- DNS/WAPI 프로그래밍 경험이 없어 전체 흐름과 사전 준비가 필요하다.
- A / PTR 레코드의 **조회 / 등록 / 삭제** 를 할 수 있어야 한다.
- Human error 를 줄이기 위해 **파일(`dns.info`)을 읽어 일괄 처리** + 편의용 **파라미터 단건 처리** 둘 다 제공.
- 전체 조회와 **정규식(regex) 기반 목록 조회**(`*.my.com`, `192.168.*`) 필요.
- 실제 수행 가능한 수준의 품질(cross-check).

## 2. Infoblox WAPI 핵심 개념 (초심자용)

WAPI 는 Infoblox NIOS 가 제공하는 **REST API** 입니다. HTTPS 로 Grid Master(또는 WAPI 를 처리하도록 지정된 멤버)에 요청을 보냅니다.

- **엔드포인트 형식**: `https://<GRID_IP>/wapi/v2.11/<objtype>`
- **오브젝트 타입**
  - A 레코드  → `record:a`   (필수 필드: `name`, `ipv4addr`)
  - PTR 레코드 → `record:ptr` (필수 필드: `ptrdname`, 그리고 `ipv4addr` 또는 reverse `name`)
- **HTTP 메서드 매핑**
  | 작업 | 메서드 | 설명 |
  |------|--------|------|
  | 조회 | `GET`    | `record:a?name~=...` 로 검색 |
  | 등록 | `POST`   | `record:a` 에 JSON/폼 데이터 전송 → `_ref` 반환 |
  | 수정 | `PUT`    | `<_ref>` 에 전송 |
  | 삭제 | `DELETE` | `<_ref>` 에 전송 |
- **`_ref` (object reference)**: 모든 객체의 고유 식별자. **삭제/수정은 먼저 GET 으로 `_ref` 를 찾은 뒤** 그 `_ref` 로 DELETE/PUT 합니다. (2단계)
- **검색 연산자**
  - `=`  : 정확히 일치 (exact)
  - `~=` : **정규식(regular expression)** 일치  ← `*.my.com`, `192.168.*` 조회에 사용
  - `:=` : 대소문자 무시 등 (객체/필드별 지원 상이)
- **유용한 파라미터**: `_return_fields=`(반환 필드 지정), `_max_results=`(최대 건수), `_paging=1&_page_id=`(페이징), `_return_as_object=1`(결과를 `{"result":[...]}` 로 감싸 일관성 확보).

> 교차 검증: 위 메서드/필드/연산자는 PDF(페이지 157~166 "Examples accessing WAPI using Curl", record:a / record:ptr 오브젝트 정의) 와 Infoblox 공식 WAPI 문서( record.a.html, record.ptr.html ) 및 커뮤니티 예제에서 모두 동일하게 확인했습니다. 내용은 라이선스 준수를 위해 재서술했습니다.

### 핵심 curl 패턴 (레퍼런스)

```bash
# A 레코드 생성
curl -k1 -u admin:PASS -X POST \
  https://192.168.1.2/wapi/v2.11/record:a \
  -d name=api-1.my.com -d ipv4addr=192.168.30.22

# PTR 레코드 생성 (ipv4addr 를 주면 reverse name 자동 생성)
curl -k1 -u admin:PASS -H "Content-Type: application/json" -X POST \
  https://192.168.1.2/wapi/v2.11/record:ptr \
  -d '{"ptrdname":"api-1.my.com","ipv4addr":"192.168.30.22"}'

# 정규식 검색 (이름이 .my.com 으로 끝나는 A 레코드)
curl -k1 -u admin:PASS -X GET \
  'https://192.168.1.2/wapi/v2.11/record:a?name~=.*\.my\.com&_return_fields=name,ipv4addr'

# 삭제: 1) _ref 조회  2) _ref 로 DELETE
REF=$(curl -k1 -u admin:PASS -X GET \
  'https://192.168.1.2/wapi/v2.11/record:a?name=api-1.my.com&ipv4addr=192.168.30.22&_return_as_object=1' \
  | jq -r '.result[0]._ref')
curl -k1 -u admin:PASS -X DELETE "https://192.168.1.2/wapi/v2.11/$REF"
```

> 참고: A 레코드 DELETE 시 `?remove_associated_ptr=true` 를 붙이면 연결된 PTR 도 함께 삭제됩니다. 단, Grid DNS 속성에서 "Enable PTR record removal for A/AAAA records" 가 켜져 있어야 동작합니다 (공식 record.a 문서). 본 스크립트는 안전을 위해 A 와 PTR 을 **명시적으로 각각** 다루도록 설계했습니다.

## 3. 사전 준비 (DNS 서버 측 + Bastion 서버 측)

### 3.1 Infoblox(DNS 서버) 측

1. **WAPI 전용 계정 생성**
   - 최소 권한 원칙. DNS 레코드 CRUD 에 필요한 권한만 부여한 admin group 을 만들고 전용 서비스 계정을 둡니다.
   - 가능하면 bastion IP 에서만 접근하도록 제한.
2. **정방향/역방향 Zone 존재 확인**
   - A 레코드를 넣을 **forward zone**(예: `my.com`)이 authoritative 로 존재해야 합니다.
   - PTR 레코드를 넣을 **reverse zone**(예: `30.168.192.in-addr.arpa`)이 존재해야 합니다.
   - Zone 이 없으면 레코드 생성이 실패합니다. (Zone 생성은 별도 권한/정책 사안이라 스크립트 범위 밖)
3. **API/WAPI 활성화 및 처리 멤버 확인**
   - 요청을 받을 Grid Master 또는 지정 멤버의 관리 인터페이스 IP 확인.
4. **TLS 인증서 정비 (권장)**
   - 기본 어플라이언스 인증서는 사설 CA 서명이라 검증 실패합니다.
   - 운영에서는 사내 CA 서명 인증서를 Grid 에 설치하고, bastion 에는 그 **CA 번들(PEM)** 을 배포해 `--cacert` 로 검증하세요. (`-k` 로 검증 생략은 테스트 전용)

### 3.2 Bastion(리눅스) 서버 측

1. **패키지 설치**
   ```bash
   # RHEL/CentOS/Rocky
   sudo yum install -y curl jq
   # Debian/Ubuntu
   sudo apt-get install -y curl jq
   ```
   - `curl` 필수, `jq` 는 JSON 파싱 품질/가독성을 위해 강력 권장(없으면 fallback 동작).
   - bash 4+ 필요.
2. **방화벽 정책 (아웃바운드 허용)**
   - bastion → Infoblox Grid **TCP 443 (HTTPS)** outbound 허용.
   - 예) `firewalld`:
     ```bash
     # bastion 에서 특정 목적지로의 443 을 리치 룰로 허용(zone 환경에 맞게 조정)
     sudo firewall-cmd --permanent --add-rich-rule=\
       'rule family="ipv4" destination address="192.168.1.2/32" port port="443" protocol="tcp" accept'
     sudo firewall-cmd --reload
     ```
   - Infoblox 쪽에서도 관리 인터페이스가 bastion IP 로부터의 443 인바운드를 허용해야 합니다(ACL/permission).
   - 중간 방화벽이 있으면 **bastion_IP → grid_IP:443** 규칙을 요청하세요.
3. **TLS 신뢰 설정**
   - CA 번들을 `/etc/pki/infoblox/grid-ca.pem` 등에 두고 conf 의 `CA_BUNDLE` 에 지정.
   - 또는 시스템 CA 저장소에 등록(`update-ca-trust` / `update-ca-certificates`).
4. **자격증명 보호**
   - 비밀번호는 파일에 평문 저장을 피하고 **암호화 저장소(`secret-mgr.sh`, 상세: `secret-mgr-guide.md`)** 또는 환경변수 `IBX_PASS` 로 주입 권장.
   - 부득이 conf 에 둘 경우 `chmod 600 dns-ibx.conf`, git 커밋 금지(.gitignore).
   - 실행 후 셸 히스토리에 비밀번호가 남지 않도록 주의(명령줄 인자로 비번 전달 금지).
5. **연결 사전 점검**
   ```bash
   # 포트 도달성
   nc -vz 192.168.1.2 443
   # 인증/스키마 확인 (한 건만)
   curl -k1 -u admin:PASS 'https://192.168.1.2/wapi/v2.11/record:a?_max_results=1'
   ```

### 3.3 체크리스트 요약

| 구분 | 항목 | 비고 |
|------|------|------|
| DNS | WAPI 전용 계정/권한 | 최소 권한, 소스 IP 제한 |
| DNS | forward/reverse zone 존재 | 없으면 생성 실패 |
| DNS | CA 서명 인증서 설치 | 검증 활성화용 |
| Bastion | curl, jq, bash4+ | `jq` 권장 |
| Bastion | 443 outbound 방화벽 | grid IP 대상 |
| Bastion | CA 번들 배포 | `--cacert` |
| Bastion | 자격증명 보호 | `IBX_PASS` 환경변수, chmod 600 |

## 4. 제공 산출물

| 파일 | 설명 |
|------|------|
| `dns-ibx.sh` | 메인 스크립트 (조회/등록/삭제, 파일·파라미터, regex) |
| `dns-ibx.conf.example` | 접속 설정 템플릿 (복사해서 `dns-ibx.conf` 로 사용) |
| `dns.info` | 일괄 처리 입력 파일 예시 |
| `_test_dns-ibx.sh` | 로직 단위 테스트(모의 curl). **48개 케이스 통과** |

> v1.1 변경: ① **verify(cross-check)** 서브커맨드와 `--fix` 보완 기능 추가, ② 표준 shell script 템플릿(`template.sh`) 포맷으로 리팩토링(헤더/버전표/섹션 마커/함수 주석블록, author `k.s.k & kiro`, 시그널 trap), ③ `dns.info` **포맷은 그대로 유지**(아래 "포맷 검토" 참고).

## 5. 설치 및 설정

```bash
cd dns-infoblox
cp dns-ibx.conf.example dns-ibx.conf
chmod 600 dns-ibx.conf
# dns-ibx.conf 에서 IBX_HOST / IBX_USER / (CA_BUNDLE) 설정
chmod +x dns-ibx.sh
```

## 6. 사용법

### 6.0 info 파일 포맷 검토 결과 (변경 없음)

verify 기능 추가에 맞춰 `dns.info` 포맷 변경이 필요한지 검토했습니다. **결론: 기존 포맷을 그대로 유지**합니다.

- 기존 포맷 `<insert|delete> <arg1> <arg2> <A|PTR>` 은 각 줄의 `action` 이 곧 "기대 상태"이므로, verify 가 별도 필드 없이 그대로 재사용할 수 있습니다.
- 같은 파일 하나로 **적용(apply) / 점검(verify) / 보완(fix)** 세 용도를 모두 처리 → 사용자 요청(동일 info 파일 사용)에 부합.
- 포맷을 바꾸면 기존 작업 파일 호환성이 깨지고 Human error 여지가 늘어 득보다 실이 큽니다.
- 변경한 것은 파일 **주석(설명) 보강**뿐입니다(용도/판정 기준 명시).

### 6.1 파일 기반 일괄 처리 (Human error 방지 — 권장)

입력 파일 `dns.info` (공백/탭 구분, `#` 주석·빈 줄 무시):

```
# <insert|delete>  <arg1>  <arg2>  <A|PTR>
insert  api-1.my.com    192.168.30.22   A
insert  192.168.30.22   api-1.my.com    PTR
delete  api-1.my.com    192.168.30.22   A
delete  192.168.30.22   api-1.my.com    PTR
```

- **A 레코드**: `arg1 = name(FQDN)`, `arg2 = ipv4addr`
- **PTR 레코드**: `arg1 = ipv4addr`, `arg2 = ptrdname(FQDN)` (질문 예시와 동일한 순서)

실행:

```bash
export IBX_PASS='서비스계정비밀번호'
./dns-ibx.sh --dry-run -f dns.info   # 먼저 미리보기(실제 호출 안 함)
./dns-ibx.sh -f dns.info             # 실제 반영
```

### 6.2 파라미터 기반 단건 처리 (편의)

```bash
./dns-ibx.sh insert api-1.my.com 192.168.30.22 A
./dns-ibx.sh insert 192.168.30.22 api-1.my.com PTR
./dns-ibx.sh delete api-1.my.com 192.168.30.22 A
./dns-ibx.sh delete 192.168.30.22 api-1.my.com PTR
```

### 6.3 점검(verify) — 동일 info 파일로 cross-check (v1.1 추가)

등록/삭제가 실제로 DNS 서버에 반영돼 있는지 **같은 `dns.info`** 로 점검합니다. 별도 파일을 만들 필요가 없습니다. 각 줄의 `action` 이 곧 "기대 상태"입니다.

| info 줄 | 기대 상태 | 어긋난 경우 | 의미 |
|---------|-----------|-------------|------|
| `insert ...` | 레코드가 **있어야** 정상 | **MISSING** | 등록했는데 DNS 에서 사라짐(누가 삭제) → 재등록 대상 |
| `delete ...` | 레코드가 **없어야** 정상 | **STALE** | 삭제했는데 DNS 에 남아 있음(삭제 누락/재생성) → 재삭제 대상 |

```bash
export IBX_PASS='서비스계정비밀번호'

# 점검만 (변경 없음). 문제가 있으면 종료코드 1
./dns-ibx.sh verify -f dns.info

# 어긋난 항목 자동 보완: MISSING 재등록, STALE 재삭제
./dns-ibx.sh verify -f dns.info --fix

# 보완 계획만 미리보기(네트워크 변경 없음)
./dns-ibx.sh verify -f dns.info --fix --dry-run
```

출력 예(모의 환경):

```
[INFO] OK      present : A aaa.my.com -> 10.0.1.1
[WARN] MISSING 재등록대상 : A bbb.my.com -> 10.0.1.2 (등록했으나 DNS 에서 사라짐)
[WARN] STALE   재삭제대상 : A ccc.my.com -> 10.0.1.3 (삭제했으나 DNS 에 남아 있음)
[INFO] ===== 점검 요약 =====
[INFO] 검사: 3  정상: 1  MISSING(재등록대상): 1  STALE(재삭제대상): 1  오류: 0
```

- 종료코드: 점검 모드는 MISSING/STALE/오류가 있으면 `1`. `--fix` 모드는 보완 실패/오류가 있으면 `1`.
- `--fix` 는 멱등: 이미 맞는 항목은 건드리지 않고, MISSING 만 재등록 / STALE 만 재삭제합니다.
- 정기 점검은 cron 으로 돌려 drift(외부 변경)를 조기에 탐지할 수 있습니다. 예) `0 * * * * IBX_PASS=... /path/dns-ibx.sh verify -f /path/dns.info --fix >> /var/log/dns-drift.log 2>&1`

### 6.4 조회 (전체 / 정규식)

```bash
./dns-ibx.sh list                 # A + PTR 전체
./dns-ibx.sh list A               # A 전체
./dns-ibx.sh list PTR             # PTR 전체

# 정규식(WAPI '~=' 로 전달). 셸 확장 방지 위해 작은따옴표로 감쌀 것.
./dns-ibx.sh search '.*\.my\.com' A       # 이름이 .my.com 으로 끝나는 A
./dns-ibx.sh search '192\.168\..*' PTR    # 192.168. 로 시작하는 PTR
./dns-ibx.sh search '.*\.my\.com'         # A + PTR 동시
```

> 사용자가 요청한 `**.my.com`, `192.168.**` 같은 와일드카드는 Infoblox 검색에선 **정규식(`~=`)** 으로 표현합니다. 셸 glob 과 혼동을 피하려고 정규식 메타문자를 명시적으로 쓰도록 했습니다.
> - `**.my.com` 의도 → `.*\.my\.com`
> - `192.168.**` 의도 → `192\.168\..*`

## 7. 품질 보증 (cross-check & 테스트)

- **문서 교차 검증**: PDF(v2.11) 의 curl 예제/오브젝트 정의 ↔ Infoblox 공식 온라인 문서(record.a/record.ptr) ↔ 커뮤니티 예제를 대조해 필드·메서드·연산자를 확정.
- **정적 분석**: `bash -n` 문법 검사 통과.
- **단위 테스트**: `_test_dns-ibx.sh` 에서 curl 을 모의(mock) 처리해 네트워크 없이 로직 검증 — **48/48 통과**.
  - 입력 검증(IPv4/FQDN), reverse PTR 네임 산출, URL 인코딩
  - `_ref` 조회(존재/부재), `ref_a`/`ref_ptr` 래퍼, A/PTR 등록(신규/중복 스킵), 삭제(존재/부재)
  - 명령 디스패치, 잘못된 타입 거부, `parse_info_line`(주석/빈줄/토큰부족)
  - `record_exists`, `verify_line`(insert→OK/MISSING, delete→OK/STALE), `--fix` 재등록, `verify_file` 요약/종료코드
- **verify end-to-end(dry-run)**: 동일 info 파일로 OK/MISSING/STALE 판정 및 `--fix` 재등록·재삭제 계획 출력 확인.
- **동작 확인(dry-run)**: 파일·파라미터 경로 모두 정상, 잘못된 IP 입력 거부 확인.

### 설계상 안전장치

- 생성 전 **중복 검사**(이미 있으면 스킵), 삭제 전 **존재 검사**(없으면 스킵) → 멱등성에 가깝게 동작.
- `--dry-run` 으로 네트워크 호출 없이 사전 검토.
- 입력 **형식 검증**(IPv4 옥텟 범위, FQDN 패턴) 으로 Human error 차단.
- 일괄 처리 중 **한 건 실패해도 중단하지 않고** 끝까지 처리 후 성공/실패 건수 요약.
- TLS 검증 기본 활성화(운영), `-k` 는 명시적으로 꺼야만 동작.

## 8. 한계 / 다음 단계

- Zone(정/역) 생성은 범위에서 제외(권한·정책 영향 큼). 필요 시 `zone_auth` 로 확장 가능.
- A 레코드만 지원(요청 범위). AAAA/CNAME 등은 동일 패턴으로 확장 가능.
- 실제 Infoblox Grid 가 없어 **실 서버 연동 end-to-end 테스트는 미수행**. 로직은 모의 테스트로 검증했으나, 최초 1회는 테스트 zone 에서 `--dry-run` → 실제 1건으로 검증 권장.
- `jq` 미설치 환경에서는 조회 출력이 원본 JSON 으로 표시됩니다(파싱 fallback). 가독성 위해 `jq` 설치 권장.

## 9. 출처

- 폴더 문서: `Infoblox WAPI 2.11 Documentation.pdf` — "Examples accessing WAPI using Curl"(p.157–166), `record:a` / `record:ptr` 오브젝트 정의(필드 표: name, ipv4addr, ptrdname 등).
- 웹(공식): Infoblox WAPI 문서 — [DNS A record object](https://ipam.illinois.edu/wapidoc/objects/record.a.html), [DNS PTR record object](https://ipam.illinois.edu/wapidoc/objects/record.ptr.html), [Examples accessing WAPI using Curl](https://ipam.illinois.edu/wapidoc/additional/sample.html)
- 웹(참고): [Add or Delete DNS records in Infoblox using Curl](https://rainingforks.com/blog/2018/add-or-delete-dns-records-in-infoblox-using-curl.html), Infoblox Community "Consolidate your WAPIs using the Request Object"

> 외부 자료 내용은 라이선스 준수를 위해 재서술했습니다.

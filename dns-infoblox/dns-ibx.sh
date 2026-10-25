#!/usr/bin/env bash
####################################################################################################
##
## File name   : dns-ibx.sh
## Description : Manage Infoblox DNS A/PTR records from a bastion host via WAPI (REST API).
## information : Supports file-based batch (dns.info), single-shot parameters, regex listing,
##               and a verify/cross-check mode that re-reads the SAME dns.info to detect records
##               that were changed out-of-band (e.g. someone deleted an inserted record) and
##               optionally re-applies them (--fix).
##               Target WAPI: Infoblox WAPI v2.11 (ref: Infoblox WAPI 2.11 Documentation.pdf).
##               Requires: bash 4+, curl, (recommended) jq.
##
##==================================================================================================
##  version   date             author          reason
##--------------------------------------------------------------------------------------------------
##  1.0       2026.10.25       k.s.k & kiro     First Created (list/search/insert/delete, file+param)
##  1.1       2026.10.25       k.s.k & kiro     Add verify (cross-check) & --fix; refactor to
##                                              standard shell template format
##  1.2       2026.10.25       k.s.k & kiro     IBX_PASS may come from the encrypted record store
##                                              (secret-mgr.sh get <program>) when not in env
##
####################################################################################################

# errexit 는 사용하지 않는다: 일괄 처리 중 한 건 실패해도 멈추지 않고
# 나머지를 계속 처리하며, 모든 오류는 명시적으로( || die / || return 1 ) 다룬다.
set -o nounset
set -o pipefail

# ======<<<< Signal common processing logic (Start) >>>>=============================================
logdatefmt="%Y%m%d-%H:%M:%S"   # date/time format variable for logging info : used in Signal logic
trap ' echo "$(date +${logdatefmt}) $0 signal(SIGINT ) captured" >&2; exit 1;' INT
trap ' echo "$(date +${logdatefmt}) $0 signal(SIGQUIT) captured" >&2; exit 1;' QUIT
trap ' echo "$(date +${logdatefmt}) $0 signal(SIGTERM) captured" >&2; exit 1;' TERM
# ======<<<< Signal common processing logic (End) >>>>===============================================

# ======<<<< Important Global Variable Registration Area Marking Comment (Start) >>>>================
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${DNS_IBX_CONF:-$SCRIPT_DIR/dns-ibx.conf}"   # 접속 설정 파일 경로

# ---- 암호화 비밀번호 저장소 연동 (IBX_PASS 가 비어 있을 때만 사용) ----------------------------
SECRET_TOOL="${SECRET_TOOL:-$SCRIPT_DIR/secret-mgr.sh}"   # 비밀번호 저장소 관리 스크립트
SECRET_PROGRAM="${SECRET_PROGRAM:-dns-ibx}"               # 저장소에서 찾을 프로그램(record) 이름

# ---- 접속/동작 기본값 (conf 로 덮어씀) --------------------------------------
IBX_HOST=""                         # Grid Master(또는 WAPI 처리 멤버) IP/FQDN
WAPI_VERSION="v2.11"                # WAPI 버전
IBX_USER=""                         # WAPI 계정
IBX_PASS="${IBX_PASS:-}"            # WAPI 비밀번호 (환경변수 주입 권장)
DNS_VIEW=""                         # DNS view (비우면 기본 view)
MAX_RESULTS=1000                    # 목록 조회 최대 건수
VERIFY_TLS="true"                   # TLS 검증 여부 (false 면 -k)
CA_BUNDLE=""                        # TLS 검증용 CA 번들(PEM) 경로
CONNECT_TIMEOUT=10                  # curl 연결 타임아웃(초)
MAX_TIME=60                         # curl 최대 수행 시간(초)

# ---- 실행 플래그 ------------------------------------------------------------
DRY_RUN="false"                     # true 면 실제 변경 호출 없이 계획만 출력
DO_FIX="false"                      # verify 시 true 면 어긋난 레코드를 보완(재등록/재삭제)
HAVE_JQ="false"                     # jq 설치 여부

# ---- verify 결과 집계용 전역 카운터 ----------------------------------------
declare -A verify_stat
verify_stat=([checked]=0 [ok]=0 [missing]=0 [stale]=0 [fixed]=0 [fixfail]=0 [error]=0)

# ---- 로그 색상 --------------------------------------------------------------
if [[ -t 2 ]]; then
  # bold + bright(90번대) 계열: 어두운 테마/흐린 팔레트에서도 가독성 확보
  C_RED=$'\033[1;91m'; C_GRN=$'\033[1;92m'; C_YEL=$'\033[1;93m'; C_CYN=$'\033[1;96m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_CYN=""; C_RST=""
fi
# ======<<<< Important Global Variable Registration Area Marking Comment (End) >>>>==================

# ======<<<< Function Registration Area Marking Comment (Start) >>>>=================================

####################################################################################################
##  Function Name : log / info / warn / err / die
##  Description : Standardized stderr logging helpers.
##  information : input  message string
##                output writes to stderr; die() exits with code 1
####################################################################################################
log()  { printf '%s\n' "$*" >&2; }
info() { printf '%s[INFO]%s %s\n' "$C_GRN" "$C_RST" "$*" >&2; }
warn() { printf '%s[WARN]%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
err()  { printf '%s[ERR ]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }
note() { printf '%s[ .. ]%s %s\n' "$C_CYN" "$C_RST" "$*" >&2; }
die()  { err "$*"; exit 1; }

####################################################################################################
##  Function Name : usage
##  Description : Print command-line usage.
##  information : input  none
##                output usage text to stderr
####################################################################################################
usage() {
  cat >&2 <<EOF
${SCRIPT_NAME} — Infoblox DNS A/PTR 레코드 관리 (WAPI ${WAPI_VERSION})

사용법:
  # 1) 파일 기반 일괄 처리 (Human error 방지용 권장)
  ${SCRIPT_NAME} -f dns.info
  ${SCRIPT_NAME} --file dns.info --dry-run

  # 2) 파라미터 기반 단건 처리 (편의성)
  ${SCRIPT_NAME} insert api-1.my.com 192.168.30.22 A
  ${SCRIPT_NAME} insert 192.168.30.22 api-1.my.com PTR
  ${SCRIPT_NAME} delete api-1.my.com 192.168.30.22 A
  ${SCRIPT_NAME} delete 192.168.30.22 api-1.my.com PTR

  # 3) 조회
  ${SCRIPT_NAME} list                       # A+PTR 전체
  ${SCRIPT_NAME} list A                      # A 전체 / list PTR
  ${SCRIPT_NAME} search '.*\\.my\\.com' A      # 이름 regex 로 A 조회
  ${SCRIPT_NAME} search '192\\.168\\..*' PTR   # IP regex 로 PTR 조회

  # 4) 점검(cross-check) : 같은 info 파일로 실제 DNS 상태 검증
  ${SCRIPT_NAME} verify -f dns.info          # insert 줄=있어야 정상, delete 줄=없어야 정상
  ${SCRIPT_NAME} verify -f dns.info --fix     # 어긋난 레코드를 보완(재등록/재삭제)
  ${SCRIPT_NAME} verify -f dns.info --fix -n  # 보완 계획만 미리보기

레코드 지정 규칙 (insert/delete/verify 공통):
  A   레코드 :  <name(fqdn)>  <ipv4addr>     예) insert api-1.my.com 192.168.30.22 A
  PTR 레코드 :  <ipv4addr>    <ptrdname>     예) insert 192.168.30.22 api-1.my.com PTR
  (A 는 'name ip', PTR 은 'ip name' 순서)

파일 형식 (dns.info) :
  공백/탭 구분, 한 줄에 하나. '#' 주석과 빈 줄은 무시.
    insert  api-1.my.com   192.168.30.22   A
    insert  192.168.30.22  api-1.my.com    PTR
    delete  api-1.my.com   192.168.30.22   A
    delete  192.168.30.22  api-1.my.com    PTR

옵션:
  -f, --file <path>    처리/점검할 입력 파일
  -n, --dry-run        실제 변경 호출 없이 수행할 작업만 출력
      --fix            verify 에서 어긋난 레코드를 자동 보완
  -c, --conf <path>    설정 파일 경로 (기본: \$SCRIPT_DIR/dns-ibx.conf)
  -h, --help           도움말

인증 (비밀번호 출처 우선순위: 환경변수 IBX_PASS > 암호화 저장소):
  # (권장) 암호화 저장소 사용 : 최초 1회 등록 후에는 seed key 만 입력
    bash secret-mgr.sh set ${SECRET_PROGRAM}
    ${SCRIPT_NAME} verify -f dns.info          # seed key 프롬프트가 뜨고 자동 복호화
  # 직접 주입
    IBX_PASS='secret' ${SCRIPT_NAME} verify -f dns.info
EOF
}

####################################################################################################
##  Function Name : load_pass_from_secret
##  Description : Fill IBX_PASS by decrypting this program's record from the encrypted store.
##                The seed key is asked by secret-mgr.sh (hidden prompt), never by this script.
##  information : input  SECRET_TOOL / SECRET_PROGRAM (globals)
##                output sets IBX_PASS; return 0 ok, 1 tool missing / decrypt failed / empty
####################################################################################################
load_pass_from_secret() {
  [[ -f "$SECRET_TOOL" ]] || return 1
  info "암호화 저장소에서 비밀번호를 복호화합니다 (program=${SECRET_PROGRAM})"
  local pw
  pw="$(bash "$SECRET_TOOL" get "$SECRET_PROGRAM")" || return 1
  [[ -n "$pw" ]] || return 1
  IBX_PASS="$pw"
}

####################################################################################################
##  Function Name : load_conf
##  Description : Load connection settings from the conf file and validate required values.
##                Password source order : env IBX_PASS  >  conf IBX_PASS  >  encrypted store.
##  information : input  CONF_FILE (global)
##                output sets IBX_* globals; die() on missing required values
####################################################################################################
load_conf() {
  [[ -f "$CONF_FILE" ]] || die "설정 파일이 없습니다: $CONF_FILE (dns-ibx.conf.example 참고)"
  local perm
  perm="$(stat -c '%a' "$CONF_FILE" 2>/dev/null || echo '')"
  if [[ -n "$perm" && "$perm" != "600" && "$perm" != "400" ]]; then
    warn "설정 파일 권한이 $perm 입니다. 'chmod 600 $CONF_FILE' 권장."
  fi
  # shellcheck disable=SC1090
  source "$CONF_FILE"

  [[ -n "$IBX_HOST" ]] || die "IBX_HOST 가 설정되지 않았습니다."
  [[ -n "$IBX_USER" ]] || die "IBX_USER 가 설정되지 않았습니다."
  if [[ -z "${IBX_PASS:-}" ]]; then
    load_pass_from_secret || die "비밀번호를 얻지 못했습니다. ① 환경변수 IBX_PASS 설정 또는 ② 암호화 저장소 등록/복호화 확인: bash ${SECRET_TOOL} set ${SECRET_PROGRAM}"
  fi
}

####################################################################################################
##  Function Name : check_deps
##  Description : Verify external command dependencies (curl required, jq optional).
##  information : input  none
##                output sets HAVE_JQ; die() if curl is missing
####################################################################################################
check_deps() {
  command -v curl >/dev/null 2>&1 || die "curl 이 필요합니다."
  if command -v jq >/dev/null 2>&1; then
    HAVE_JQ="true"
  else
    warn "jq 가 없어 JSON 파싱이 제한됩니다. 'yum/apt install jq' 권장."
  fi
}

####################################################################################################
##  Function Name : is_ipv4
##  Description : Validate an IPv4 dotted-quad string with per-octet range check.
##  information : input  candidate string
##                output return 0 valid, 1 invalid
####################################################################################################
is_ipv4() {
  local ip="$1" o IFS='.'
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  local oct; read -ra oct <<<"$ip"
  for o in "${oct[@]}"; do (( o >= 0 && o <= 255 )) || return 1; done
  return 0
}

####################################################################################################
##  Function Name : is_fqdn
##  Description : Validate a simple FQDN (labels separated by dots, min one dot).
##  information : input  candidate string
##                output return 0 valid, 1 invalid
####################################################################################################
is_fqdn() {
  [[ "$1" =~ ^([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,}$ ]]
}

####################################################################################################
##  Function Name : ptr_name_from_ip
##  Description : Convert an IPv4 address into its in-addr.arpa reverse name.
##  information : input  a.b.c.d
##                output d.c.b.a.in-addr.arpa (stdout)
####################################################################################################
ptr_name_from_ip() {
  local ip="$1" a b c d; IFS='.' read -r a b c d <<<"$ip"
  printf '%s.%s.%s.%s.in-addr.arpa' "$d" "$c" "$b" "$a"
}

####################################################################################################
##  Function Name : urlencode
##  Description : Percent-encode a string, keeping RFC3986 unreserved characters.
##  information : input  raw string
##                output encoded string (stdout)
####################################################################################################
urlencode() {
  local s="$1" i c out=""
  for (( i=0; i<${#s}; i++ )); do
    c="${s:$i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) out+="$c" ;;
      *) printf -v c '%%%02X' "'$c"; out+="$c" ;;
    esac
  done
  printf '%s' "$out"
}

####################################################################################################
##  Function Name : _base / _view_q / _tls_opts
##  Description : WAPI URL helpers and TLS option builder.
##  information : _base   -> https://HOST/wapi/VER
##                _view_q -> '&view=...' fragment when DNS_VIEW set
##                _tls_opts -> fills TLS_OPTS array (--cacert or -k)
####################################################################################################
_base()   { printf 'https://%s/wapi/%s' "$IBX_HOST" "$WAPI_VERSION"; }
_view_q() { [[ -n "$DNS_VIEW" ]] && printf '&view=%s' "$DNS_VIEW"; }
_tls_opts() {
  TLS_OPTS=()
  if [[ "${VERIFY_TLS,,}" == "true" ]]; then
    if [[ -n "$CA_BUNDLE" ]]; then
      [[ -f "$CA_BUNDLE" ]] || die "CA_BUNDLE 파일이 없습니다: $CA_BUNDLE"
      TLS_OPTS+=(--cacert "$CA_BUNDLE")
    fi
  else
    warn "TLS 검증이 비활성화(-k)되어 있습니다. 테스트 외 사용 금지."
    TLS_OPTS+=(-k)
  fi
}

####################################################################################################
##  Function Name : wapi_call
##  Description : Perform a WAPI HTTP request and return the response body.
##  information : input  <METHOD> <PATH_OR_REF_OR_URL> [curl extra args...]
##                output response body (stdout); return 1 on transport/HTTP error
####################################################################################################
wapi_call() {
  local method="$1"; shift
  local path="$1"; shift
  _tls_opts
  local url
  case "$path" in
    http*) url="$path" ;;              # full URL
    /*)    url="$(_base)$path" ;;      # /record:a ...
    *)     url="$(_base)/$path" ;;     # record:a/ZG5z... (_ref)
  esac

  local resp http body
  resp="$(curl -sS \
      --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
      "${TLS_OPTS[@]}" \
      -u "${IBX_USER}:${IBX_PASS}" \
      -w $'\n%{http_code}' \
      -X "$method" "$url" "$@" )" || { err "curl 호출 실패: $method $url"; return 1; }

  http="${resp##*$'\n'}"
  body="${resp%$'\n'*}"
  if [[ "$http" -lt 200 || "$http" -ge 300 ]]; then
    err "WAPI 오류 HTTP $http : $method $url"
    [[ -n "$body" ]] && printf '%s\n' "$body" >&2
    return 1
  fi
  printf '%s' "$body"
}

####################################################################################################
##  Function Name : get_ref
##  Description : Look up the first object reference (_ref) matching a query.
##  information : input  <objtype> <query-string>
##                output _ref string or empty (stdout); return 0 even when not found
####################################################################################################
get_ref() {
  local objtype="$1" query="$2" body
  body="$(wapi_call GET "/${objtype}?${query}&_return_as_object=1&_max_results=1")" || return 1
  if [[ "$HAVE_JQ" == "true" ]]; then
    printf '%s' "$body" | jq -r '.result[0]._ref // empty'
  else
    # jq 미설치 fallback : 첫 _ref 추출 (SIGPIPE 회피 위해 head 대신 grep -m1)
    local line
    line="$(printf '%s' "$body" | grep -o -m1 '"_ref"[[:space:]]*:[[:space:]]*"[^"]*"' || true)"
    if [[ -n "$line" ]]; then
      printf '%s' "$line" | sed -E 's/.*"_ref"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/'
    fi
  fi
  return 0   # "결과 없음" 은 오류가 아니라 정상(빈 문자열)
}

####################################################################################################
##  Function Name : ref_a / ref_ptr
##  Description : Convenience wrappers returning the _ref for an exact A/PTR record.
##  information : ref_a  <name> <ip>      ref_ptr <ip> <ptrdname>
##                output _ref or empty (stdout)
####################################################################################################
ref_a()   { get_ref record:a   "name=$(urlencode "$1")&ipv4addr=$(urlencode "$2")"; }
ref_ptr() { get_ref record:ptr "ipv4addr=$(urlencode "$1")&ptrdname=$(urlencode "$2")"; }

####################################################################################################
##  Function Name : print_list
##  Description : Query an object type and print records in a readable form.
##  information : input  <objtype> <query>
##                output formatted list (stdout); raw JSON if jq not present
####################################################################################################
print_list() {
  local objtype="$1" query="$2" body
  body="$(wapi_call GET "/${objtype}?${query}")" || return 1
  if [[ "$HAVE_JQ" == "true" ]]; then
    case "$objtype" in
      record:a)   printf '%s' "$body" | jq -r '.[] | "A    \(.name)\t\(.ipv4addr)\t[\(.view)]"' ;;
      record:ptr) printf '%s' "$body" | jq -r '.[] | "PTR  \(.ptrdname)\t<- \(.ipv4addr // .name)\t[\(.view)]"' ;;
      *)          printf '%s\n' "$body" | jq . ;;
    esac
  else
    printf '%s\n' "$body"
  fi
}

####################################################################################################
##  Function Name : cmd_list
##  Description : List all records of a given type (A | PTR | ALL).
##  information : input  [A|PTR|ALL]
##                output record listing
####################################################################################################
cmd_list() {
  local type="${1:-ALL}" extra; extra="$(_view_q)"
  case "${type^^}" in
    A)   print_list record:a   "_return_fields=name,ipv4addr,view&_max_results=${MAX_RESULTS}${extra}" ;;
    PTR) print_list record:ptr "_return_fields=ptrdname,ipv4addr,name,view&_max_results=${MAX_RESULTS}${extra}" ;;
    ALL)
      info "== A records =="
      print_list record:a   "_return_fields=name,ipv4addr,view&_max_results=${MAX_RESULTS}${extra}"
      info "== PTR records =="
      print_list record:ptr "_return_fields=ptrdname,ipv4addr,name,view&_max_results=${MAX_RESULTS}${extra}"
      ;;
    *) die "list 대상은 A | PTR | (생략=전체) 입니다." ;;
  esac
}

####################################################################################################
##  Function Name : cmd_search
##  Description : List records matching a regex (passed to WAPI '~=' operator).
##  information : input  <regex> [A|PTR|ALL]
##                output matching record listing
####################################################################################################
cmd_search() {
  local rx="${1:-}" type="${2:-ALL}" extra; extra="$(_view_q)"
  [[ -n "$rx" ]] || die "search 에는 정규식이 필요합니다. 예) search '.*\\.my\\.com' A"
  local rxe; rxe="$(urlencode "$rx")"
  case "${type^^}" in
    A)   print_list record:a   "name~=${rxe}&_return_fields=name,ipv4addr,view&_max_results=${MAX_RESULTS}${extra}" ;;
    PTR) print_list record:ptr "ptrdname~=${rxe}&_return_fields=ptrdname,ipv4addr,name,view&_max_results=${MAX_RESULTS}${extra}" ;;
    ALL)
      info "== A (name ~= $rx) =="
      print_list record:a   "name~=${rxe}&_return_fields=name,ipv4addr,view&_max_results=${MAX_RESULTS}${extra}"
      info "== PTR (ptrdname ~= $rx) =="
      print_list record:ptr "ptrdname~=${rxe}&_return_fields=ptrdname,ipv4addr,name,view&_max_results=${MAX_RESULTS}${extra}"
      ;;
    *) die "search 대상은 A | PTR | (생략=전체) 입니다." ;;
  esac
}

####################################################################################################
##  Function Name : insert_a / insert_ptr
##  Description : Create an A / PTR record (idempotent: skip if it already exists).
##  information : insert_a  <name> <ip>     insert_ptr <ip> <ptrdname>
##                output log line; return 0 ok, 1 on error
####################################################################################################
insert_a() {
  local name="$1" ip="$2"
  is_fqdn "$name" || die "A: name 이 FQDN 형식이 아닙니다: $name"
  is_ipv4 "$ip"   || die "A: ipv4addr 형식이 아닙니다: $ip"
  if [[ "$DRY_RUN" == "true" ]]; then info "[dry-run] CREATE A  $name -> $ip"; return 0; fi
  local exist; exist="$(ref_a "$name" "$ip")" || true
  if [[ -n "$exist" ]]; then warn "A 이미 존재: $name -> $ip (건너뜀)"; return 0; fi
  local payload ref
  payload="$(printf '{"name":"%s","ipv4addr":"%s"%s}' "$name" "$ip" \
             "$( [[ -n "$DNS_VIEW" ]] && printf ',"view":"%s"' "$DNS_VIEW" )")"
  ref="$(wapi_call POST "/record:a" -H "Content-Type: application/json" -d "$payload")" || return 1
  info "CREATE A  OK: $name -> $ip  ($ref)"
}
insert_ptr() {
  local ip="$1" ptrd="$2"
  is_ipv4 "$ip"   || die "PTR: ipv4addr 형식이 아닙니다: $ip"
  is_fqdn "$ptrd" || die "PTR: ptrdname 이 FQDN 형식이 아닙니다: $ptrd"
  if [[ "$DRY_RUN" == "true" ]]; then info "[dry-run] CREATE PTR $ip -> $ptrd"; return 0; fi
  local exist; exist="$(ref_ptr "$ip" "$ptrd")" || true
  if [[ -n "$exist" ]]; then warn "PTR 이미 존재: $ip -> $ptrd (건너뜀)"; return 0; fi
  local payload ref
  payload="$(printf '{"ptrdname":"%s","ipv4addr":"%s"%s}' "$ptrd" "$ip" \
             "$( [[ -n "$DNS_VIEW" ]] && printf ',"view":"%s"' "$DNS_VIEW" )")"
  ref="$(wapi_call POST "/record:ptr" -H "Content-Type: application/json" -d "$payload")" || return 1
  info "CREATE PTR OK: $ip -> $ptrd  ($ref)"
}

####################################################################################################
##  Function Name : delete_a / delete_ptr
##  Description : Delete an A / PTR record (idempotent: skip if absent).
##  information : delete_a  <name> <ip>     delete_ptr <ip> <ptrdname>
##                output log line; return 0 ok, 1 on error
####################################################################################################
delete_a() {
  local name="$1" ip="$2"
  is_fqdn "$name" || die "A: name 이 FQDN 형식이 아닙니다: $name"
  is_ipv4 "$ip"   || die "A: ipv4addr 형식이 아닙니다: $ip"
  if [[ "$DRY_RUN" == "true" ]]; then info "[dry-run] DELETE A  $name -> $ip"; return 0; fi
  local ref; ref="$(ref_a "$name" "$ip")" || return 1
  if [[ -z "$ref" ]]; then warn "A 없음(삭제 건너뜀): $name -> $ip"; return 0; fi
  wapi_call DELETE "$ref" >/dev/null || return 1
  info "DELETE A  OK: $name -> $ip"
}
delete_ptr() {
  local ip="$1" ptrd="$2"
  is_ipv4 "$ip"   || die "PTR: ipv4addr 형식이 아닙니다: $ip"
  is_fqdn "$ptrd" || die "PTR: ptrdname 이 FQDN 형식이 아닙니다: $ptrd"
  if [[ "$DRY_RUN" == "true" ]]; then info "[dry-run] DELETE PTR $ip -> $ptrd"; return 0; fi
  local ref; ref="$(ref_ptr "$ip" "$ptrd")" || return 1
  if [[ -z "$ref" ]]; then warn "PTR 없음(삭제 건너뜀): $ip -> $ptrd"; return 0; fi
  wapi_call DELETE "$ref" >/dev/null || return 1
  info "DELETE PTR OK: $ip -> $ptrd"
}

####################################################################################################
##  Function Name : record_exists
##  Description : Return whether an exact A/PTR record currently exists on the DNS server.
##  information : input  <A|PTR> <arg1> <arg2>   (A: name ip / PTR: ip ptrdname)
##                output return 0 exists, 1 absent, 2 lookup error
####################################################################################################
record_exists() {
  local type="$1" a1="$2" a2="$3" ref rc
  case "${type^^}" in
    A)   ref="$(ref_a   "$a1" "$a2")"; rc=$? ;;
    PTR) ref="$(ref_ptr "$a1" "$a2")"; rc=$? ;;
    *)   return 2 ;;
  esac
  [[ $rc -ne 0 ]] && return 2
  [[ -n "$ref" ]] && return 0 || return 1
}

####################################################################################################
##  Function Name : dispatch_record
##  Description : Route one (action, arg1, arg2, type) tuple to the proper CRUD function.
##  information : input  <insert|delete> <arg1> <arg2> <A|PTR>
##                output delegates to insert_*/delete_*; return propagates
####################################################################################################
dispatch_record() {
  local action="$1" a1="$2" a2="$3" type="${4:-}"
  [[ -n "$type" ]] || die "레코드 타입(A|PTR)이 필요합니다: $action $a1 $a2 <TYPE>"
  case "${action,,}:${type^^}" in
    insert:A)   insert_a   "$a1" "$a2" ;;
    insert:PTR) insert_ptr "$a1" "$a2" ;;
    delete:A)   delete_a   "$a1" "$a2" ;;
    delete:PTR) delete_ptr "$a1" "$a2" ;;
    *) die "지원하지 않는 조합: action='$action' type='$type' (insert/delete, A/PTR)" ;;
  esac
}

####################################################################################################
##  Function Name : parse_info_line
##  Description : Strip comment/whitespace from a raw info line and split into tokens.
##  information : input  <raw line>  ; writes action/a1/a2/type via namerefs
##                output return 0 parsed, 1 blank/comment(skip), 2 token error
####################################################################################################
parse_info_line() {
  local raw="$1"
  local -n _action="$2" _a1="$3" _a2="$4" _type="$5"
  local line rest
  line="${raw%%#*}"                                   # 주석 제거
  line="$(printf '%s' "$line" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
  [[ -z "$line" ]] && return 1                        # 빈 줄/주석
  # shellcheck disable=SC2086
  read -r _action _a1 _a2 _type rest <<<"$line"
  [[ -n "$_action" && -n "$_a1" && -n "$_a2" && -n "$_type" ]] || return 2
  return 0
}

####################################################################################################
##  Function Name : process_file
##  Description : Read an info file and APPLY each line (insert/delete) to the DNS server.
##  information : input  <info file path>
##                output per-line logs + summary; return 0 if no failures
####################################################################################################
process_file() {
  local file="$1"
  [[ -f "$file" ]] || die "입력 파일이 없습니다: $file"
  local ln=0 ok=0 fail=0 rc
  local raw action a1 a2 type
  while IFS= read -r raw || [[ -n "$raw" ]]; do
    ln=$((ln+1))
    parse_info_line "$raw" action a1 a2 type; rc=$?
    [[ $rc -eq 1 ]] && continue
    if [[ $rc -eq 2 ]]; then
      err "[$ln행] 토큰 부족: '$raw' (형식: <insert|delete> <arg1> <arg2> <A|PTR>)"
      fail=$((fail+1)); continue
    fi
    if dispatch_record "$action" "$a1" "$a2" "$type"; then
      ok=$((ok+1))
    else
      err "[$ln행] 처리 실패: '$raw'"; fail=$((fail+1))
    fi
  done < "$file"
  info "파일 처리 완료: 성공 ${ok}건, 실패 ${fail}건 (총 ${ln}행 스캔)"
  [[ "$fail" -eq 0 ]]
}

####################################################################################################
##  Function Name : verify_line
##  Description : Cross-check one info line against the real DNS state.
##                insert 줄 -> 레코드가 '있어야' 정상 ; 없으면 MISSING (누가 삭제한 것)
##                delete 줄 -> 레코드가 '없어야' 정상 ; 있으면 STALE   (삭제 누락/재생성)
##                DO_FIX=true 면 어긋난 항목을 보완(insert 재등록 / delete 재삭제).
##  information : input  <ln> <action> <arg1> <arg2> <type>
##                output per-line status log; updates verify_stat; return 0 ok/handled, 1 problem
####################################################################################################
verify_line() {
  local ln="$1" action="$2" a1="$3" a2="$4" type="$5"
  verify_stat[checked]=$(( verify_stat[checked] + 1 ))

  # 사전 형식 검증 (잘못된 입력은 점검 불가)
  case "${type^^}" in
    A)   is_fqdn "$a1" && is_ipv4 "$a2" || { err "[$ln행] A 인자 형식 오류: $a1 $a2"; verify_stat[error]=$(( verify_stat[error]+1 )); return 1; } ;;
    PTR) is_ipv4 "$a1" && is_fqdn "$a2" || { err "[$ln행] PTR 인자 형식 오류: $a1 $a2"; verify_stat[error]=$(( verify_stat[error]+1 )); return 1; } ;;
    *)   err "[$ln행] 알 수 없는 타입: $type"; verify_stat[error]=$(( verify_stat[error]+1 )); return 1 ;;
  esac

  record_exists "$type" "$a1" "$a2"; local ex=$?
  if [[ $ex -eq 2 ]]; then
    err "[$ln행] 조회 실패(네트워크/WAPI): $type $a1 $a2"
    verify_stat[error]=$(( verify_stat[error]+1 )); return 1
  fi

  local label="$type $a1 -> $a2"
  case "${action,,}" in
    insert)
      if [[ $ex -eq 0 ]]; then
        info "OK      present : $label"
        verify_stat[ok]=$(( verify_stat[ok]+1 )); return 0
      fi
      # 기대: 존재. 실제: 없음 -> 누가 삭제함
      warn "MISSING 재등록대상 : $label (등록했으나 DNS 에서 사라짐)"
      verify_stat[missing]=$(( verify_stat[missing]+1 ))
      if [[ "$DO_FIX" == "true" ]]; then
        note "fix -> 재등록 시도 : $label"
        if dispatch_record insert "$a1" "$a2" "$type"; then
          verify_stat[fixed]=$(( verify_stat[fixed]+1 ))
        else
          verify_stat[fixfail]=$(( verify_stat[fixfail]+1 ))
        fi
      fi
      return 1
      ;;
    delete)
      if [[ $ex -eq 1 ]]; then
        info "OK      absent  : $label"
        verify_stat[ok]=$(( verify_stat[ok]+1 )); return 0
      fi
      # 기대: 없음. 실제: 존재 -> 삭제 누락 / 재생성됨
      warn "STALE   재삭제대상 : $label (삭제했으나 DNS 에 남아 있음)"
      verify_stat[stale]=$(( verify_stat[stale]+1 ))
      if [[ "$DO_FIX" == "true" ]]; then
        note "fix -> 재삭제 시도 : $label"
        if dispatch_record delete "$a1" "$a2" "$type"; then
          verify_stat[fixed]=$(( verify_stat[fixed]+1 ))
        else
          verify_stat[fixfail]=$(( verify_stat[fixfail]+1 ))
        fi
      fi
      return 1
      ;;
    *)
      err "[$ln행] verify 미지원 action: $action"
      verify_stat[error]=$(( verify_stat[error]+1 )); return 1
      ;;
  esac
}

####################################################################################################
##  Function Name : verify_file
##  Description : Cross-check the whole info file against the live DNS server (same dns.info).
##                어긋난 항목을 찾아 리포트하고, --fix 시 보완한다.
##  information : input  <info file path>
##                output per-line status + summary; return 0 if all OK (or all fixed)
####################################################################################################
verify_file() {
  local file="$1"
  [[ -f "$file" ]] || die "입력 파일이 없습니다: $file"
  info "=== DNS 상태 점검(cross-check) 시작: $file ${DO_FIX:+}"
  [[ "$DO_FIX" == "true" ]] && note "--fix 활성화: 어긋난 레코드를 보완합니다.${DRY_RUN:+}"
  [[ "$DRY_RUN" == "true" ]] && note "--dry-run: 보완은 계획만 출력합니다."

  local ln=0 rc
  local raw action a1 a2 type
  while IFS= read -r raw || [[ -n "$raw" ]]; do
    ln=$((ln+1))
    parse_info_line "$raw" action a1 a2 type; rc=$?
    [[ $rc -eq 1 ]] && continue
    if [[ $rc -eq 2 ]]; then
      err "[$ln행] 토큰 부족: '$raw'"; verify_stat[error]=$(( verify_stat[error]+1 )); continue
    fi
    verify_line "$ln" "$action" "$a1" "$a2" "$type"
  done < "$file"

  # 요약
  log ""
  info "===== 점검 요약 ====="
  info "검사: ${verify_stat[checked]}  정상: ${verify_stat[ok]}  MISSING(재등록대상): ${verify_stat[missing]}  STALE(재삭제대상): ${verify_stat[stale]}  오류: ${verify_stat[error]}"
  if [[ "$DO_FIX" == "true" ]]; then
    info "보완: 성공 ${verify_stat[fixed]}  실패 ${verify_stat[fixfail]}"
  fi

  # 종료코드: 문제(미해결)가 있으면 1
  local unresolved
  if [[ "$DO_FIX" == "true" && "$DRY_RUN" != "true" ]]; then
    unresolved=$(( verify_stat[fixfail] + verify_stat[error] ))
  else
    unresolved=$(( verify_stat[missing] + verify_stat[stale] + verify_stat[error] ))
  fi
  [[ "$unresolved" -eq 0 ]]
}
# ======<<<< Function Registration Area Marking Comment (End) >>>>===================================

# ======<<<< Main Logic Coding Area Marking Comment (Start) >>>=======================================
main() {
  local file="" positional=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)    usage; exit 0 ;;
      -n|--dry-run) DRY_RUN="true"; shift ;;
      --fix)        DO_FIX="true"; shift ;;
      -f|--file)    file="${2:-}"; [[ -n "$file" ]] || die "--file 인자 필요"; shift 2 ;;
      -c|--conf)    CONF_FILE="${2:-}"; [[ -n "$CONF_FILE" ]] || die "--conf 인자 필요"; shift 2 ;;
      --)           shift; positional+=("$@"); break ;;
      -*)           die "알 수 없는 옵션: $1 (--help 참고)" ;;
      *)            positional+=("$1"); shift ;;
    esac
  done

  load_conf
  check_deps

  # 서브커맨드 우선 판별
  local sub="${positional[0]:-}"
  case "${sub,,}" in
    verify)
      [[ -n "$file" ]] || die "verify 에는 -f <info파일> 이 필요합니다."
      verify_file "$file"; exit $?
      ;;
    list)
      cmd_list "${positional[1]:-ALL}" ;;
    search)
      cmd_search "${positional[1]:-}" "${positional[2]:-ALL}" ;;
    insert|delete)
      [[ ${#positional[@]} -ge 4 ]] || die "형식: $sub <arg1> <arg2> <A|PTR>"
      dispatch_record "${positional[0]}" "${positional[1]}" "${positional[2]}" "${positional[3]}"
      ;;
    "")
      # 서브커맨드 없이 -f 만 준 경우 = 일괄 적용(apply)
      if [[ -n "$file" ]]; then
        process_file "$file"; exit $?
      fi
      usage; exit 1
      ;;
    *)
      err "알 수 없는 명령: $sub"; usage; exit 1 ;;
  esac
}

main "$@"
# ======<<<< Main Logic Coding Area Marking Comment (End) >>>=========================================

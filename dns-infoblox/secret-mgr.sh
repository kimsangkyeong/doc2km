#!/usr/bin/env bash
####################################################################################################
##
## File name   : secret-mgr.sh
## Description : Manage the secrets (passwords) of MANY programs in ONE encrypted record file.
## information : One record per program. Each record is encrypted on its own with OpenSSL `enc`
##               (AES-256-CBC + PBKDF2-HMAC-SHA256/512). The seed key (pass phrase) is typed at run
##               time and is never written to disk. Records carry their own cipher/KDF/iteration
##               meta, so records made with older parameters stay readable after an upgrade, and
##               `rekey` can migrate them to the current parameters.
##               Store line format : program|updated|cipher:kdf:iter|base64(openssl enc payload)
##               Requires          : bash 4+, openssl 1.1.1+ (needs `enc -pbkdf2`).
##               Exit codes        : 0 ok / 1 error / 3 decrypt failed / 4 not found / 5 corrupt
##
##==================================================================================================
##  version   date             author          reason
##--------------------------------------------------------------------------------------------------
##  1.0       2026.10.25       k.s.k & kiro     First Created (set/get/list/delete/check/rekey)
##
####################################################################################################

set -o nounset
set -o pipefail
umask 077    # 저장소/임시파일은 항상 소유자 전용(600)으로 생성

# ======<<<< Signal common processing logic (Start) >>>>=============================================
logdatefmt="%Y%m%d-%H:%M:%S"   # date/time format variable for logging info : used in Signal logic
trap ' echo "$(date +${logdatefmt}) $0 signal(SIGINT ) captured" >&2; exit 1;' INT
trap ' echo "$(date +${logdatefmt}) $0 signal(SIGQUIT) captured" >&2; exit 1;' QUIT
trap ' echo "$(date +${logdatefmt}) $0 signal(SIGTERM) captured" >&2; exit 1;' TERM
trap 'cleanup' EXIT           # 어떤 경로로 종료해도 임시파일/seed 흔적 정리
# ======<<<< Signal common processing logic (End) >>>>===============================================

# ======<<<< Important Global Variable Registration Area Marking Comment (Start) >>>>================
SCRIPT_NAME="$(basename "$0")"
SS_STORE="${SECRET_STORE:-${HOME:-.}/.secret-store.enc}"   # 모든 프로그램 레코드를 담는 단일 파일
SS_TTY="${SECRET_TTY:-/dev/tty}"                           # seed 입력 장치 (테스트에서만 변경)
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"                      # 사용할 openssl 실행파일

# ---- 현재 기본 암호 파라미터 (신규/rekey 시 사용. 기존 레코드는 자기 메타를 따른다) ---------------
SS_CIPHER="aes-256-cbc"             # enc 는 AEAD(GCM) 미지원 -> AES-256-CBC
SS_KDF="pbkdf2-sha256"              # 키 유도: PBKDF2-HMAC-SHA256
SS_ITER="${SECRET_ITER:-600000}"    # 반복 횟수 (OWASP 2023 PBKDF2-SHA256 권고치)
SS_MARK="SS1:"                      # 평문 앞 검증 마커 (CBC 는 무결성 없음 -> 오답 seed 탐지용)

# ---- 입력 검증 기준 ---------------------------------------------------------------------------
SS_ALLOWED_CIPHERS="aes-256-cbc"                  # 메타에서 허용하는 cipher 화이트리스트
SS_ALLOWED_KDFS="pbkdf2-sha256 pbkdf2-sha512"     # 메타에서 허용하는 KDF 화이트리스트
SS_MIN_SEED_LEN=8                                 # 신규 seed key 최소 길이
SS_MAX_TRIES=3                                    # 대화형 seed 입력 재시도 횟수

# ---- 실행 상태 --------------------------------------------------------------------------------
ASSUME_YES="false"       # -y : 확인 질문 생략
TTY_OPENED="false"       # seed 입력 장치를 fd 9 로 열었는지
TMP_FILE=""              # 저장소 교체용 임시파일 (cleanup 대상)
SEED_VALUE=""            # 방금 입력/수신한 seed key
SEED_SOURCE=""           # seed 출처: file | env | prompt
PLAIN=""                 # 복호화된 비밀번호
REC_LINE=""              # find_record 결과 한 줄
R_PROG=""; R_UPD=""; R_META=""; R_B64=""             # 레코드 분해 결과
M_CIPHER=""; M_KDF=""; M_ITER=""                     # 메타 분해 결과

# ---- 로그 색상 (dns-ibx.sh 와 동일: bold + bright) ---------------------------------------------
if [[ -t 2 ]]; then
  C_RED=$'\033[1;91m'; C_GRN=$'\033[1;92m'; C_YEL=$'\033[1;93m'; C_CYN=$'\033[1;96m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_CYN=""; C_RST=""
fi
# ======<<<< Important Global Variable Registration Area Marking Comment (End) >>>>==================

# ======<<<< Function Registration Area Marking Comment (Start) >>>>=================================

####################################################################################################
##  Function Name : info / warn / err / note / die
##  Description : Standardized stderr logging helpers (stdout is reserved for secret/list output).
##  information : input  message string
##                output stderr; die() exits with code 1
####################################################################################################
info() { printf '%s[INFO]%s %s\n' "$C_GRN" "$C_RST" "$*" >&2; }
warn() { printf '%s[WARN]%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
err()  { printf '%s[ERR ]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }
note() { printf '%s[ .. ]%s %s\n' "$C_CYN" "$C_RST" "$*" >&2; }
die()  { err "$*"; exit 1; }

####################################################################################################
##  Function Name : cleanup
##  Description : EXIT trap. Remove the temp file and wipe seed/secret variables.
##  information : input  none        output none
####################################################################################################
cleanup() {
  if [[ -n "$TMP_FILE" && -f "$TMP_FILE" ]]; then rm -f "$TMP_FILE"; fi
  SEED_VALUE=""; PLAIN=""
}

####################################################################################################
##  Function Name : usage
##  Description : Print command-line usage.
##  information : input  none        output usage text to stderr
####################################################################################################
usage() {
  cat >&2 <<EOF
${SCRIPT_NAME} — 여러 프로그램의 비밀번호를 단일 암호화 파일에서 record 로 관리 (OpenSSL AES-256)

사용법:
  ${SCRIPT_NAME} [옵션] <명령> [인자]

명령:
  set    <program> [--secret-stdin]   비밀번호 등록/갱신 (seed key 로 암호화)
  get    <program>                    복호화하여 stdout 으로 출력 (스크립트 연동용)
  check  <program>                    복호화 가능 여부만 확인 (값 출력 안 함)
  list                                등록된 프로그램/갱신시각/암호 파라미터 목록 (비밀번호 미출력)
  delete <program>                    레코드 삭제
  rekey  <program|--all> [--keep-seed] seed key 교체 또는 (--keep-seed) 암호 파라미터만 최신으로 갱신

옵션:
  -s, --store <file>       저장소 파일 (기본: \$SECRET_STORE 또는 ~/.secret-store.enc)
  -S, --seed-file <file>   seed key 를 담은 파일 첫 줄에서 읽기 (무인 실행용, chmod 600)
  -y, --yes                확인 질문 생략
  -h, --help               도움말

seed key 입력 우선순위:  -S/SECRET_SEED_FILE  >  SECRET_SEED(환경변수)  >  대화형 프롬프트(권장)
  rekey 의 새 seed:       SECRET_NEW_SEED_FILE > SECRET_NEW_SEED > 프롬프트

예시:
  ${SCRIPT_NAME} set dns-ibx                       # 프롬프트로 비밀번호/seed 입력
  export IBX_PASS="\$(${SCRIPT_NAME} get dns-ibx)"  # seed 입력 후 복호화
  ${SCRIPT_NAME} list
  ${SCRIPT_NAME} rekey --all --keep-seed           # openssl 업그레이드 후 파라미터 갱신

레코드 형식 (한 줄 = 한 프로그램, 단일 파일):
  program|updated|cipher:kdf:iter|base64(openssl enc 출력)
EOF
}

####################################################################################################
##  Function Name : valid_program_name
##  Description : Validate a program name (record key).
##  information : input  name        output return 0 valid / 1 invalid
####################################################################################################
valid_program_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; }

####################################################################################################
##  Function Name : file_mode_warn
##  Description : Warn when a secret-bearing file is readable by group/others.
##  information : input  <path> <label>     output warning to stderr only
####################################################################################################
file_mode_warn() {
  local perm
  perm="$(stat -c '%a' "$1" 2>/dev/null || true)"
  if [[ -n "$perm" && "$perm" != "600" && "$perm" != "400" ]]; then
    warn "$2 권한이 $perm 입니다. 'chmod 600 $1' 권장."
  fi
}

####################################################################################################
##  Function Name : open_tty / read_hidden / confirm
##  Description : Interactive input helpers. Input device is opened ONCE as fd 9 so that successive
##                prompts consume successive lines (real /dev/tty, or a file in tests).
##  information : read_hidden <prompt> <outvar>   (echo off, strips CR)
##                confirm <message>               (return 0 only for y/yes; -y auto-accepts)
####################################################################################################
open_tty() {
  [[ "$TTY_OPENED" == "true" ]] && return 0
  ( : <"$SS_TTY" ) 2>/dev/null || return 1
  exec 9<"$SS_TTY"
  TTY_OPENED="true"
}
read_hidden() {
  local prompt="$1" outvar="$2" val=""
  open_tty || return 1
  printf '%s' "$prompt" >&2
  IFS= read -r -s -u 9 val || true
  printf '\n' >&2
  val="${val%$'\r'}"
  printf -v "$outvar" '%s' "$val"
}
confirm() {
  [[ "$ASSUME_YES" == "true" ]] && return 0
  local ans=""
  open_tty || { err "확인 질문에 답할 터미널이 없습니다(비대화형). -y 옵션을 사용하세요."; return 1; }
  printf '%s [y/N]: ' "$1" >&2
  IFS= read -r -u 9 ans || true
  ans="${ans%$'\r'}"
  [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]
}

####################################################################################################
##  Function Name : obtain_seed
##  Description : Get a seed key from file, environment, or hidden prompt (in that order).
##  information : input  <label> <confirm:yes|no> <ENV_NAME> <FILE_ENV_NAME>
##                output sets SEED_VALUE / SEED_SOURCE ; return 0 ok, 1 failed
####################################################################################################
obtain_seed() {
  local label="$1" confirm_mode="$2" envn="$3" filen="$4" v="" v2="" f=""
  SEED_VALUE=""; SEED_SOURCE=""
  f="${!filen:-}"
  if [[ -n "$f" ]]; then
    [[ -r "$f" ]] || { err "seed 파일을 읽을 수 없습니다: $f"; return 1; }
    file_mode_warn "$f" "seed 파일"
    IFS= read -r v <"$f" || true
    v="${v%$'\r'}"; SEED_SOURCE="file"
  elif [[ -n "${!envn:-}" ]]; then
    v="${!envn}"; SEED_SOURCE="env"
  else
    if ! open_tty; then
      err "seed key 를 입력할 터미널이 없습니다. 무인 실행이면 SECRET_SEED_FILE(chmod 600)을 사용하세요."
      return 1
    fi
    read_hidden "${label}: " v || return 1
    if [[ "$confirm_mode" == "yes" ]]; then
      read_hidden "${label} 확인: " v2 || return 1
      [[ "$v" == "$v2" ]] || { err "seed key 가 서로 일치하지 않습니다."; return 1; }
    fi
    SEED_SOURCE="prompt"
  fi
  [[ -n "$v" ]] || { err "seed key 가 비어 있습니다."; return 1; }
  SEED_VALUE="$v"
}

####################################################################################################
##  Function Name : check_new_seed
##  Description : Enforce the minimum length for a NEWLY created seed key.
##  information : input  none (uses SEED_VALUE)     output return 0 ok / 1 too short
####################################################################################################
check_new_seed() {
  if (( ${#SEED_VALUE} < SS_MIN_SEED_LEN )); then
    err "seed key 는 ${SS_MIN_SEED_LEN}자 이상이어야 합니다."
    return 1
  fi
}

####################################################################################################
##  Function Name : parse_meta
##  Description : Split and validate "cipher:kdf:iter" against the allow-lists.
##  information : input  <meta>     output sets M_CIPHER/M_KDF/M_ITER ; return 0 ok / 1 invalid
####################################################################################################
parse_meta() {
  local extra=""
  M_CIPHER=""; M_KDF=""; M_ITER=""
  IFS=: read -r M_CIPHER M_KDF M_ITER extra <<<"$1"
  [[ -z "$extra" ]] || return 1
  [[ " $SS_ALLOWED_CIPHERS " == *" $M_CIPHER "* ]] || return 1
  [[ " $SS_ALLOWED_KDFS " == *" $M_KDF "* ]] || return 1
  [[ "$M_ITER" =~ ^[0-9]+$ ]] || return 1
  (( M_ITER >= 10000 && M_ITER <= 10000000 )) || return 1
}

####################################################################################################
##  Function Name : ss_enc / ss_dec
##  Description : openssl enc wrappers. Seed goes through the environment (-pass env:), the payload
##                through stdin, so neither shows up in `ps` or shell history.
##  information : ss_enc <plain> <seed> <cipher> <md> <iter>   -> base64 single line (stdout)
##                ss_dec <b64>   <seed> <cipher> <md> <iter>   -> plain (stdout), rc!=0 on failure
####################################################################################################
ss_enc() {
  printf '%s' "$1" | SS_PW="$2" "$OPENSSL_BIN" enc "-$3" -pbkdf2 -md "$4" -iter "$5" \
    -salt -a -A -pass env:SS_PW 2>/dev/null
}
ss_dec() {
  printf '%s' "$1" | SS_PW="$2" "$OPENSSL_BIN" enc -d "-$3" -pbkdf2 -md "$4" -iter "$5" \
    -a -A -pass env:SS_PW 2>/dev/null
}

####################################################################################################
##  Function Name : preflight
##  Description : Make sure openssl exists and supports `enc -pbkdf2` (OpenSSL 1.1.1+).
##                RHEL/CentOS 7 (OpenSSL 1.0.2) fails here with a clear message.
##  information : input  none        output die() when unusable
####################################################################################################
preflight() {
  command -v "$OPENSSL_BIN" >/dev/null 2>&1 || die "openssl 을 찾을 수 없습니다: $OPENSSL_BIN"
  local t
  t="$(printf 'ok' | SS_PW=pf "$OPENSSL_BIN" enc -aes-256-cbc -pbkdf2 -md sha256 -iter 1000 \
        -salt -a -A -pass env:SS_PW 2>/dev/null \
      | SS_PW=pf "$OPENSSL_BIN" enc -d -aes-256-cbc -pbkdf2 -md sha256 -iter 1000 \
        -a -A -pass env:SS_PW 2>/dev/null)" || true
  [[ "$t" == "ok" ]] || die "이 openssl 은 'enc -pbkdf2' 를 지원하지 않습니다(1.1.1 이상 필요). 현재: $("$OPENSSL_BIN" version 2>&1)"
}

####################################################################################################
##  Function Name : find_record / split_record / list_programs
##  Description : Read helpers for the single record file (tolerates CRLF, comments, blank lines).
##  information : find_record <program>   -> REC_LINE ; return 0 found / 1 absent
##                split_record            -> R_PROG/R_UPD/R_META/R_B64 ; return 0 ok / 1 corrupt
##                list_programs           -> program names (stdout, one per line)
####################################################################################################
find_record() {
  local line first
  REC_LINE=""
  [[ -f "$SS_STORE" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
    first="${line%%|*}"
    if [[ "$first" == "$1" ]]; then REC_LINE="$line"; return 0; fi
  done <"$SS_STORE"
  return 1
}
split_record() {
  local extra=""
  R_PROG=""; R_UPD=""; R_META=""; R_B64=""
  IFS='|' read -r R_PROG R_UPD R_META R_B64 extra <<<"$REC_LINE"
  [[ -n "$R_PROG" && -n "$R_META" && -n "$R_B64" && -z "$extra" ]]
}
list_programs() {
  local line
  [[ -f "$SS_STORE" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
    printf '%s\n' "${line%%|*}"
  done <"$SS_STORE"
}

####################################################################################################
##  Function Name : store_put / store_del
##  Description : Atomically rewrite the record file (temp file + mv, one .bak generation kept).
##                store_put replaces the program's line or appends it; store_del removes it.
##  information : store_put <program> <full record line>     return 0 ok
##                store_del <program>                        return 0 removed / 1 absent
####################################################################################################
store_put() {
  local prog="$1" newline="$2" line first found="false"
  mkdir -p "$(dirname "$SS_STORE")" || die "저장소 디렉터리를 만들 수 없습니다."
  TMP_FILE="$(mktemp "${SS_STORE}.XXXXXX")" || die "임시파일 생성 실패"
  if [[ -f "$SS_STORE" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%$'\r'}"
      first="${line%%|*}"
      if [[ -n "$line" && "${line:0:1}" != "#" && "$first" == "$prog" ]]; then
        printf '%s\n' "$newline" >>"$TMP_FILE"; found="true"
      else
        printf '%s\n' "$line" >>"$TMP_FILE"
      fi
    done <"$SS_STORE"
  else
    {
      printf '%s\n' "# secret-mgr store (직접 편집 금지)"
      printf '%s\n' "# program|updated|cipher:kdf:iter|base64(openssl enc payload)"
    } >>"$TMP_FILE"
  fi
  [[ "$found" == "true" ]] || printf '%s\n' "$newline" >>"$TMP_FILE"
  if [[ -f "$SS_STORE" ]]; then cp -p "$SS_STORE" "${SS_STORE}.bak" && chmod 600 "${SS_STORE}.bak"; fi
  chmod 600 "$TMP_FILE"
  mv -f "$TMP_FILE" "$SS_STORE" || die "저장소 교체 실패"
  TMP_FILE=""
}
store_del() {
  local prog="$1" line first removed="false"
  [[ -f "$SS_STORE" ]] || return 1
  TMP_FILE="$(mktemp "${SS_STORE}.XXXXXX")" || die "임시파일 생성 실패"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    first="${line%%|*}"
    if [[ -n "$line" && "${line:0:1}" != "#" && "$first" == "$prog" ]]; then
      removed="true"
    else
      printf '%s\n' "$line" >>"$TMP_FILE"
    fi
  done <"$SS_STORE"
  if [[ "$removed" != "true" ]]; then rm -f "$TMP_FILE"; TMP_FILE=""; return 1; fi
  cp -p "$SS_STORE" "${SS_STORE}.bak" && chmod 600 "${SS_STORE}.bak"
  chmod 600 "$TMP_FILE"
  mv -f "$TMP_FILE" "$SS_STORE" || die "저장소 교체 실패"
  TMP_FILE=""
}

####################################################################################################
##  Function Name : seal_record
##  Description : Encrypt PLAIN-text secret with the CURRENT default parameters, verify that it
##                decrypts back (never commit an unreadable record), and emit the record line.
##  information : input  <program> <secret> <seed>
##                output record line (stdout) ; return 0 ok / 1 failed
####################################################################################################
seal_record() {
  local prog="$1" secret="$2" seed="$3" meta b64 back ts
  meta="${SS_CIPHER}:${SS_KDF}:${SS_ITER}"
  parse_meta "$meta" || { err "현재 암호 파라미터가 허용 범위를 벗어났습니다: $meta"; return 1; }
  b64="$(ss_enc "${SS_MARK}${secret}" "$seed" "$M_CIPHER" "${M_KDF#pbkdf2-}" "$M_ITER")" || return 1
  [[ -n "$b64" ]] || return 1
  back="$(ss_dec "$b64" "$seed" "$M_CIPHER" "${M_KDF#pbkdf2-}" "$M_ITER")" || return 1
  [[ "$back" == "${SS_MARK}${secret}" ]] || return 1
  ts="$(date +%Y-%m-%dT%H:%M:%S)"
  printf '%s|%s|%s|%s' "$prog" "$ts" "$meta" "$b64"
}

####################################################################################################
##  Function Name : decrypt_record
##  Description : Decrypt the currently split record with a seed, using the RECORD'S OWN meta.
##                A wrong seed is detected by openssl padding failure OR a missing SS1: marker.
##  information : input  <seed>     output sets PLAIN ; return 0 ok / 3 wrong seed / 5 bad meta
####################################################################################################
decrypt_record() {
  local out=""
  parse_meta "$R_META" || { err "레코드 메타 형식 오류 또는 미허용 값: $R_META"; return 5; }
  { out="$(ss_dec "$R_B64" "$1" "$M_CIPHER" "${M_KDF#pbkdf2-}" "$M_ITER")"; } 2>/dev/null || return 3
  [[ "$out" == "$SS_MARK"* ]] || return 3
  PLAIN="${out#"$SS_MARK"}"
  return 0
}

####################################################################################################
##  Function Name : retrieve_secret
##  Description : Locate a record and decrypt it (re-prompting up to SS_MAX_TRIES for typed seeds).
##  information : input  <program>     output sets PLAIN ; return 0 / 3 decrypt / 4 not found / 5 corrupt
####################################################################################################
retrieve_secret() {
  local prog="$1" try=0 rc
  valid_program_name "$prog" || { err "프로그램 이름 형식 오류: $prog (영문/숫자/._-, 64자 이내)"; return 1; }
  find_record "$prog" || { err "등록되지 않은 프로그램: $prog (저장소: $SS_STORE)"; return 4; }
  split_record || { err "레코드가 손상되었습니다: $prog"; return 5; }
  while :; do
    try=$((try+1))
    obtain_seed "[$prog] seed key" no SECRET_SEED SECRET_SEED_FILE || return 3
    decrypt_record "$SEED_VALUE"; rc=$?
    [[ $rc -eq 0 ]] && return 0
    [[ $rc -eq 5 ]] && return 5
    if [[ "$SEED_SOURCE" == "prompt" && $try -lt $SS_MAX_TRIES ]]; then
      warn "복호화 실패(seed key 불일치?) 재시도 ${try}/${SS_MAX_TRIES}"
      continue
    fi
    err "복호화 실패: seed key 가 다르거나 레코드가 손상되었습니다 ($prog)"
    return 3
  done
}

####################################################################################################
##  Function Name : cmd_set
##  Description : Register or update a program's secret.
##  information : input  <program> [--secret-stdin]     return 0 ok, non-zero on failure
####################################################################################################
cmd_set() {
  local prog="${1:-}" from_stdin="false" secret="" secret2="" line
  [[ -n "$prog" ]] || die "형식: set <program> [--secret-stdin]"
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --secret-stdin) from_stdin="true" ;;
      *) die "알 수 없는 인자: $1" ;;
    esac
    shift
  done
  valid_program_name "$prog" || die "프로그램 이름 형식 오류: $prog (영문/숫자/._-, 64자 이내)"

  if find_record "$prog"; then
    confirm "'$prog' 레코드가 이미 있습니다. 덮어쓸까요?" || die "취소했습니다."
  fi

  if [[ "$from_stdin" == "true" ]]; then
    IFS= read -r secret || true
    secret="${secret%$'\r'}"
  else
    read_hidden "[$prog] 저장할 비밀번호: " secret || die "비밀번호 입력 실패(터미널 없음). --secret-stdin 을 사용하세요."
    read_hidden "[$prog] 비밀번호 확인: " secret2 || die "비밀번호 입력 실패"
    [[ "$secret" == "$secret2" ]] || die "비밀번호가 서로 일치하지 않습니다."
  fi
  [[ -n "$secret" ]] || die "비밀번호가 비어 있습니다."

  obtain_seed "[$prog] seed key" yes SECRET_SEED SECRET_SEED_FILE || exit 1
  check_new_seed || exit 1

  line="$(seal_record "$prog" "$secret" "$SEED_VALUE")" || die "암호화 또는 검증 실패. openssl 상태를 확인하세요."
  store_put "$prog" "$line"
  info "저장 완료: $prog  (저장소: $SS_STORE, ${SS_CIPHER}/${SS_KDF}/iter=${SS_ITER})"
}

####################################################################################################
##  Function Name : cmd_get / cmd_check
##  Description : get prints the decrypted secret to stdout (no newline unless stdout is a TTY);
##                check only reports whether the record can be decrypted.
##  information : input  <program>     return 0 / 3 / 4 / 5 (see header)
####################################################################################################
cmd_get() {
  [[ -n "${1:-}" ]] || die "형식: get <program>"
  retrieve_secret "$1" || return $?
  if [[ -t 1 ]]; then printf '%s\n' "$PLAIN"; else printf '%s' "$PLAIN"; fi
}
cmd_check() {
  [[ -n "${1:-}" ]] || die "형식: check <program>"
  retrieve_secret "$1" || return $?
  info "OK: $1 복호화 가능"
}

####################################################################################################
##  Function Name : cmd_list
##  Description : List registered programs. Never prints ciphertext or secrets.
##  information : input  none     output table (stdout)
####################################################################################################
cmd_list() {
  local p count=0
  if [[ ! -f "$SS_STORE" ]]; then info "저장소가 아직 없습니다: $SS_STORE"; return 0; fi
  printf '%-24s %-20s %s\n' "PROGRAM" "UPDATED" "CIPHER:KDF:ITER"
  while IFS= read -r p; do
    find_record "$p" || continue
    split_record || { printf '%-24s %-20s %s\n' "$p" "-" "(손상된 레코드)"; continue; }
    printf '%-24s %-20s %s\n' "$R_PROG" "$R_UPD" "$R_META"
    count=$((count+1))
  done < <(list_programs)
  info "총 ${count}건 (저장소: $SS_STORE)"
}

####################################################################################################
##  Function Name : cmd_delete
##  Description : Remove a program's record (a .bak of the previous store is kept).
##  information : input  <program>     return 0 ok / 4 not found
####################################################################################################
cmd_delete() {
  local prog="${1:-}"
  [[ -n "$prog" ]] || die "형식: delete <program>"
  valid_program_name "$prog" || die "프로그램 이름 형식 오류: $prog"
  find_record "$prog" || { err "등록되지 않은 프로그램: $prog"; return 4; }
  confirm "'$prog' 레코드를 삭제할까요?" || die "취소했습니다."
  store_del "$prog" || die "삭제 실패"
  info "삭제 완료: $prog (이전 상태는 ${SS_STORE}.bak)"
}

####################################################################################################
##  Function Name : cmd_rekey
##  Description : Re-encrypt records with the CURRENT parameters, optionally with a NEW seed key.
##                Use --keep-seed after an OpenSSL/parameter upgrade (same seed, new iter/KDF).
##                With --all one old seed is tried on every record; failures are reported and
##                skipped (records with other seeds are left untouched).
##  information : input  <program|--all> [--keep-seed]     return 0 if all targets converted
####################################################################################################
cmd_rekey() {
  local target="${1:-}" keep="false" old_seed new_seed p ok=0 fail=0 line
  local -a targets=()
  [[ -n "$target" ]] || die "형식: rekey <program|--all> [--keep-seed]"
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --keep-seed) keep="true" ;;
      *) die "알 수 없는 인자: $1" ;;
    esac
    shift
  done

  if [[ "$target" == "--all" ]]; then
    while IFS= read -r p; do targets+=("$p"); done < <(list_programs)
    [[ ${#targets[@]} -gt 0 ]] || { info "재암호화할 레코드가 없습니다."; return 0; }
  else
    valid_program_name "$target" || die "프로그램 이름 형식 오류: $target"
    targets=("$target")
  fi

  obtain_seed "현재 seed key" no SECRET_SEED SECRET_SEED_FILE || exit 1
  old_seed="$SEED_VALUE"
  if [[ "$keep" == "true" ]]; then
    new_seed="$old_seed"
  else
    obtain_seed "새 seed key" yes SECRET_NEW_SEED SECRET_NEW_SEED_FILE || exit 1
    check_new_seed || exit 1
    new_seed="$SEED_VALUE"
  fi

  for p in "${targets[@]}"; do
    if ! find_record "$p" || ! split_record; then err "[$p] 레코드를 읽을 수 없습니다."; fail=$((fail+1)); continue; fi
    if ! decrypt_record "$old_seed"; then
      err "[$p] 현재 seed 로 복호화 실패 -> 변경하지 않음"; fail=$((fail+1)); continue
    fi
    if ! line="$(seal_record "$p" "$PLAIN" "$new_seed")"; then
      err "[$p] 재암호화 실패 -> 변경하지 않음"; fail=$((fail+1)); continue
    fi
    store_put "$p" "$line"
    info "[$p] 재암호화 완료 (${SS_CIPHER}/${SS_KDF}/iter=${SS_ITER})"
    ok=$((ok+1))
  done
  info "rekey 결과: 성공 ${ok}건, 실패 ${fail}건"
  [[ "$fail" -eq 0 ]]
}
# ======<<<< Function Registration Area Marking Comment (End) >>>>===================================

# ======<<<< Main Logic Coding Area Marking Comment (Start) >>>=======================================
main() {
  local cmd="" rc=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)      usage; exit 0 ;;
      -y|--yes)       ASSUME_YES="true"; shift ;;
      -s|--store)     SS_STORE="${2:-}"; [[ -n "$SS_STORE" ]] || die "--store 인자 필요"; shift 2 ;;
      -S|--seed-file) SECRET_SEED_FILE="${2:-}"; [[ -n "$SECRET_SEED_FILE" ]] || die "--seed-file 인자 필요"; shift 2 ;;
      -*)             die "알 수 없는 옵션: $1 (--help 참고)" ;;
      *)              cmd="$1"; shift; break ;;
    esac
  done
  [[ -n "$cmd" ]] || { usage; exit 1; }

  # 환경변수로 들어온 seed 파일 경로는 선언만 해 둔다 (obtain_seed 의 간접참조용)
  : "${SECRET_SEED_FILE:=}" "${SECRET_SEED:=}" "${SECRET_NEW_SEED_FILE:=}" "${SECRET_NEW_SEED:=}"
  [[ -e "$SS_STORE" ]] && file_mode_warn "$SS_STORE" "저장소"

  case "${cmd,,}" in
    set)    preflight; cmd_set    "$@"; rc=$? ;;
    get)    preflight; cmd_get    "$@"; rc=$? ;;
    check)  preflight; cmd_check  "$@"; rc=$? ;;
    rekey)  preflight; cmd_rekey  "$@"; rc=$? ;;
    list)   cmd_list   "$@"; rc=$? ;;
    delete) cmd_delete "$@"; rc=$? ;;
    *)      err "알 수 없는 명령: $cmd"; usage; exit 1 ;;
  esac
  exit "$rc"
}

main "$@"
# ======<<<< Main Logic Coding Area Marking Comment (End) >>>=========================================

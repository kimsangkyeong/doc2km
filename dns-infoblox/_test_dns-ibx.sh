#!/usr/bin/env bash
# dns-ibx.sh 로직 단위 테스트 (실제 WAPI 없이 curl 을 mock 처리)
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
no()  { FAIL=$((FAIL+1)); printf 'FAIL - %s (got: %s)\n' "$1" "$2"; }
eq()  { [[ "$2" == "$3" ]] && ok "$1" || no "$1" "$2 != $3"; }

# ---- 테스트용 설정 & mock 준비 ---------------------------------------------
export DNS_IBX_CONF="$SCRIPT_DIR/_test.conf"
cat > "$DNS_IBX_CONF" <<EOF
IBX_HOST="10.0.0.1"
WAPI_VERSION="v2.11"
IBX_USER="admin"
IBX_PASS="pw"
DNS_VIEW=""
MAX_RESULTS=100
VERIFY_TLS="false"
CA_BUNDLE=""
EOF
chmod 600 "$DNS_IBX_CONF"

# curl mock: 호출 인자를 기록하고 메서드별로 가짜 응답을 돌려준다.
MOCK_LOG="$SCRIPT_DIR/_mock_curl.log"
: > "$MOCK_LOG"
export MOCK_LOG
mkdir -p "$SCRIPT_DIR/_mockbin"
# 존재한다고 간주할 레코드 키 목록(개행 구분)을 EXIST_KEYS 로 제어.
#   키 형식 : A|<name>|<ip>   또는   PTR|<ip>|<ptrdname>  (GET 쿼리 매칭용 부분문자열)
export EXIST_KEYS="${EXIST_KEYS:-}"
cat > "$SCRIPT_DIR/_mockbin/curl" <<'MOCKEOF'
#!/usr/bin/env bash
echo "CURL $*" >> "$MOCK_LOG"
method="GET"; url=""; prev=""
for a in "$@"; do
  case "$prev" in -X) method="$a" ;; esac
  case "$a" in http*) url="$a" ;; esac
  prev="$a"
done
if [[ "$method" == "GET" ]]; then
  # 조회(_return_as_object=1) : EXIST_KEYS 에 매칭되는 쿼리면 _ref 반환, 아니면 빈 결과
  if [[ "$url" == *"_return_as_object=1"* ]]; then
    found="no"
    IFS=$'\n'
    for key in $EXIST_KEYS; do
      [[ -z "$key" ]] && continue
      # key 예: "api-1.my.com" 또는 "192.168.30.22" 등 쿼리에 들어갈 토큰
      if [[ "$url" == *"$key"* ]]; then found="yes"; fi
    done
    unset IFS
    if [[ "$found" == "yes" ]]; then
      printf '%s\n%s' '{"result":[{"_ref":"record:x/REF:matched"}]}' '200'
    else
      printf '%s\n%s' '{"result":[]}' '200'
    fi
  else
    printf '%s\n%s' '[]' '200'   # list/search
  fi
elif [[ "$method" == "POST" ]]; then
  printf '%s\n%s' '"record:x/NEWREF:created"' '201'
elif [[ "$method" == "DELETE" ]]; then
  printf '%s\n%s' '"record:x/REF:deleted"' '200'
else
  printf '%s\n%s' '""' '200'
fi
MOCKEOF
chmod +x "$SCRIPT_DIR/_mockbin/curl"
export PATH="$SCRIPT_DIR/_mockbin:$PATH"

# ---- dns-ibx.sh 의 함수만 로드 (main 실행 방지) ----------------------------
# main "$@" 를 제거한 사본을 source 한다.
TMP_LIB="$SCRIPT_DIR/_lib_under_test.sh"
sed 's/^main "\$@"$/: # main disabled for test/' "$SCRIPT_DIR/dns-ibx.sh" > "$TMP_LIB"
# shellcheck disable=SC1090
source "$TMP_LIB"

# conf/deps 로드 (die 가 테스트를 죽이지 않도록 서브셸에서 확인)
load_conf
check_deps

echo "== 입력 검증 =="
is_ipv4 "192.168.30.22" && ok "is_ipv4 valid" || no "is_ipv4 valid" "fail"
is_ipv4 "999.1.1.1"     && no "is_ipv4 reject 999" "accepted" || ok "is_ipv4 reject 999"
is_ipv4 "192.168.30"    && no "is_ipv4 reject short" "accepted" || ok "is_ipv4 reject short"
is_fqdn "api-1.my.com"  && ok "is_fqdn valid" || no "is_fqdn valid" "fail"
is_fqdn "nope"          && no "is_fqdn reject bare" "accepted" || ok "is_fqdn reject bare"

echo "== reverse PTR name =="
eq "ptr_name_from_ip" "$(ptr_name_from_ip 192.168.30.22)" "22.30.168.192.in-addr.arpa"

echo "== urlencode =="
eq "urlencode regex" "$(urlencode '.*\.my\.com')" ".%2A%5C.my%5C.com"
eq "urlencode plain" "$(urlencode 'api-1.my.com')" "api-1.my.com"

echo "== get_ref (mock) =="
EXIST_KEYS="api-1.my.com"
ref="$(get_ref record:a 'name=api-1.my.com&ipv4addr=1.2.3.4')"
eq "get_ref found" "$ref" "record:x/REF:matched"
EXIST_KEYS=""
ref2="$(get_ref record:a 'name=none.my.com')"
eq "get_ref empty" "$ref2" ""

echo "== ref_a / ref_ptr 래퍼 =="
EXIST_KEYS="api-1.my.com"
eq "ref_a found"   "$(ref_a api-1.my.com 192.168.30.22)" "record:x/REF:matched"
EXIST_KEYS=""
eq "ref_a empty"   "$(ref_a gone.my.com 10.0.0.1)" ""

echo "== insert_a 신규 (mock, 미존재) =="
EXIST_KEYS=""
out="$(insert_a nonexist.my.com 10.0.0.9 2>&1)"; rc=$?
eq "insert_a new rc" "$rc" "0"
[[ "$out" == *"CREATE A  OK"* ]] && ok "insert_a new logs CREATE" || no "insert_a new logs CREATE" "$out"
grep -q 'POST' "$MOCK_LOG" && ok "insert_a issued POST" || no "insert_a issued POST" "no POST in log"

echo "== insert_a 중복 (mock, 존재) =="
EXIST_KEYS="api-1.my.com"
out="$(insert_a api-1.my.com 10.0.0.9 2>&1)"; rc=$?
[[ "$out" == *"이미 존재"* ]] && ok "insert_a dup skipped" || no "insert_a dup skipped" "$out"

echo "== delete_a 존재 (mock) =="
EXIST_KEYS="api-1.my.com"
out="$(delete_a api-1.my.com 10.0.0.9 2>&1)"; rc=$?
eq "delete_a rc" "$rc" "0"
[[ "$out" == *"DELETE A  OK"* ]] && ok "delete_a logs OK" || no "delete_a logs OK" "$out"

echo "== delete_a 미존재 (mock) =="
EXIST_KEYS=""
out="$(delete_a none.my.com 10.0.0.9 2>&1)"; rc=$?
[[ "$out" == *"없음"* ]] && ok "delete_a missing skip" || no "delete_a missing skip" "$out"

echo "== dispatch (insert PTR 순서: ip name) =="
EXIST_KEYS=""
out="$(dispatch_record insert 10.9.9.9 new.my.com PTR 2>&1)"; rc=$?
[[ "$out" == *"CREATE PTR OK"* ]] && ok "dispatch insert PTR" || no "dispatch insert PTR" "$out"

echo "== dispatch 잘못된 타입 =="
( dispatch_record insert a b XXX >/dev/null 2>&1 ) && no "dispatch bad type rejected" "accepted" || ok "dispatch bad type rejected"

echo "== parse_info_line =="
a=""; b=""; d=""; t=""
parse_info_line "  insert  api-1.my.com  192.168.30.22  A  " a b d t; rc=$?
eq "parse rc ok" "$rc" "0"
eq "parse action" "$a" "insert"
eq "parse arg1"   "$b" "api-1.my.com"
eq "parse arg2"   "$d" "192.168.30.22"
eq "parse type"   "$t" "A"
parse_info_line "   # just a comment" a b d t; eq "parse comment skip rc" "$?" "1"
parse_info_line "" a b d t;                      eq "parse blank skip rc"   "$?" "1"
parse_info_line "insert only-two tokens" a b d t; eq "parse token-short rc" "$?" "2"

echo "== record_exists (mock) =="
EXIST_KEYS="api-1.my.com"
record_exists A api-1.my.com 192.168.30.22; eq "record_exists present" "$?" "0"
EXIST_KEYS=""
record_exists A gone.my.com 192.168.30.22;  eq "record_exists absent"  "$?" "1"

echo "== verify_line : insert 줄, 레코드 존재 -> OK =="
EXIST_KEYS="api-1.my.com"; DRY_RUN="false"; DO_FIX="false"
verify_stat=([checked]=0 [ok]=0 [missing]=0 [stale]=0 [fixed]=0 [fixfail]=0 [error]=0)
out="$(verify_line 1 insert api-1.my.com 192.168.30.22 A 2>&1)"; rc=$?
eq "verify insert-present rc" "$rc" "0"
[[ "$out" == *"OK"* && "$out" == *"present"* ]] && ok "verify insert-present OK log" || no "verify insert-present OK log" "$out"

echo "== verify_line : insert 줄, 레코드 없음 -> MISSING =="
EXIST_KEYS=""
verify_stat=([checked]=0 [ok]=0 [missing]=0 [stale]=0 [fixed]=0 [fixfail]=0 [error]=0)
out="$(verify_line 1 insert gone.my.com 10.0.0.5 A 2>&1)"; rc=$?
eq "verify insert-missing rc" "$rc" "1"
[[ "$out" == *"MISSING"* ]] && ok "verify insert-missing log" || no "verify insert-missing log" "$out"

echo "== verify_line : delete 줄, 레코드 없음 -> OK(absent) =="
EXIST_KEYS=""
verify_stat=([checked]=0 [ok]=0 [missing]=0 [stale]=0 [fixed]=0 [fixfail]=0 [error]=0)
out="$(verify_line 1 delete gone.my.com 10.0.0.6 A 2>&1)"; rc=$?
eq "verify delete-absent rc" "$rc" "0"
[[ "$out" == *"absent"* ]] && ok "verify delete-absent log" || no "verify delete-absent log" "$out"

echo "== verify_line : delete 줄, 레코드 존재 -> STALE =="
EXIST_KEYS="still.my.com"
verify_stat=([checked]=0 [ok]=0 [missing]=0 [stale]=0 [fixed]=0 [fixfail]=0 [error]=0)
out="$(verify_line 1 delete still.my.com 10.0.0.7 A 2>&1)"; rc=$?
eq "verify delete-stale rc" "$rc" "1"
[[ "$out" == *"STALE"* ]] && ok "verify delete-stale log" || no "verify delete-stale log" "$out"

echo "== verify_line : insert MISSING + --fix -> 재등록 =="
# 카운터 확인은 서브셸을 쓰지 않고 현재 셸에서 수행(명령치환은 카운터를 공유 못 함).
EXIST_KEYS=""; DO_FIX="true"; DRY_RUN="false"
verify_stat=([checked]=0 [ok]=0 [missing]=0 [stale]=0 [fixed]=0 [fixfail]=0 [error]=0)
verify_line 1 insert fixme.my.com 10.0.0.8 A 2>"$SCRIPT_DIR/_vl.log"
eq "verify --fix fixed count" "${verify_stat[fixed]}" "1"
eq "verify --fix missing count" "${verify_stat[missing]}" "1"
grep -q "재등록 시도" "$SCRIPT_DIR/_vl.log" && ok "verify --fix logs retry" || no "verify --fix logs retry" "no log"
grep -q "CREATE A  OK" "$SCRIPT_DIR/_vl.log" && ok "verify --fix re-creates" || no "verify --fix re-creates" "no create"
rm -f "$SCRIPT_DIR/_vl.log"
DO_FIX="false"

echo "== process_file (주석/빈줄/토큰부족) =="
EXIST_KEYS=""
cat > "$SCRIPT_DIR/_test.info" <<EOF
# comment line
insert  api-1.my.com    192.168.30.22   A

insert  192.168.30.22   api-1.my.com    PTR
delete  api-1.my.com    192.168.30.22   A
badline-without-enough-tokens
EOF
out="$(process_file "$SCRIPT_DIR/_test.info" 2>&1)"; rc=$?
[[ "$out" == *"토큰 부족"* ]] && ok "file: bad line reported" || no "file: bad line reported" "$out"
[[ "$out" == *"파일 처리 완료"* ]] && ok "file: summary printed" || no "file: summary printed" "$out"

echo "== verify_file (same info, mock) =="
# aaa.my.com 만 존재한다고 간주. bbb.my.com 은 미존재 => MISSING 1건 => rc=1
EXIST_KEYS="aaa.my.com"; DO_FIX="false"; DRY_RUN="false"
verify_stat=([checked]=0 [ok]=0 [missing]=0 [stale]=0 [fixed]=0 [fixfail]=0 [error]=0)
cat > "$SCRIPT_DIR/_test.info" <<EOF
insert  aaa.my.com    10.0.1.1   A
insert  bbb.my.com    10.0.1.2   A
EOF
out="$(verify_file "$SCRIPT_DIR/_test.info" 2>&1)"; rc=$?
[[ "$out" == *"점검 요약"* ]] && ok "verify_file summary" || no "verify_file summary" "$out"
[[ "$out" == *"MISSING"* ]] && ok "verify_file detects MISSING" || no "verify_file detects MISSING" "$out"
eq "verify_file rc nonzero" "$rc" "1"

echo
echo "==================  결과: PASS=$PASS  FAIL=$FAIL  =================="
# 정리
rm -f "$TMP_LIB" "$DNS_IBX_CONF" "$SCRIPT_DIR/_test.info" "$MOCK_LOG"
rm -rf "$SCRIPT_DIR/_mockbin"
[[ "$FAIL" -eq 0 ]]

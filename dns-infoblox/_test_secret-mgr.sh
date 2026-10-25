#!/usr/bin/env bash
# secret-mgr.sh + dns-ibx.sh 연동 테스트 (실제 openssl 사용, 네트워크는 curl mock)
set -u
SD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SM="$SD/secret-mgr.sh"
DI="$SD/dns-ibx.sh"
export PATH="/usr/bin:$PATH"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
no()  { FAIL=$((FAIL+1)); printf 'FAIL - %s (got: %s)\n' "$1" "$2"; }
eq()  { [[ "$2" == "$3" ]] && ok "$1" || no "$1" "[$2] != [$3]"; }
has() { [[ "$2" == *"$3"* ]] && ok "$1" || no "$1" "[$3] not in [$2]"; }
hasnt() { [[ "$2" != *"$3"* ]] && ok "$1" || no "$1" "[$3] unexpectedly in output"; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
unset SECRET_SEED SECRET_SEED_FILE SECRET_NEW_SEED SECRET_NEW_SEED_FILE IBX_PASS SECRET_TOOL SECRET_PROGRAM
export SECRET_STORE="$WORK/store.enc"
export SECRET_ITER=20000                     # 테스트 속도용 (기본값 600000 은 별도 검증)
export SECRET_TTY="$WORK/no-such-tty"        # 실제 터미널을 절대 건드리지 않도록 기본은 '터미널 없음'

sm() { bash "$SM" "$@"; }

S_A='seed-key-AAAA'; S_B='seed-key-BBBB'
PW_A='S3cr3t-IBX-Pass!'

echo "== 1. 등록/조회 기본 =="
printf '%s\n' "$PW_A" | SECRET_SEED="$S_A" sm set dns-ibx --secret-stdin 2>/dev/null; rc=$?
eq "set dns-ibx rc" "$rc" "0"
out="$(SECRET_SEED="$S_A" sm get dns-ibx 2>/dev/null)"; rc=$?
eq "get returns exact secret" "$out" "$PW_A"
eq "get rc" "$rc" "0"
store_txt="$(cat "$SECRET_STORE")"
hasnt "store has no plaintext secret" "$store_txt" "S3cr3t"
hasnt "store has no seed" "$store_txt" "$S_A"
has "store has header comment" "$store_txt" "secret-mgr store"
has "record meta recorded" "$store_txt" "aes-256-cbc:pbkdf2-sha256:20000"
case "$(openssl version)" in OpenSSL\ 1.1.1*|OpenSSL\ 3*) ok "openssl >= 1.1.1" ;; *) no "openssl >= 1.1.1" "$(openssl version)" ;; esac

echo "== 2. 잘못된 seed / 없는 프로그램 =="
out="$(SECRET_SEED='wrong-seed-ZZZ' sm get dns-ibx 2>/dev/null)"; rc=$?
eq "wrong seed rc=3" "$rc" "3"
eq "wrong seed prints nothing" "$out" ""
out="$(SECRET_SEED="$S_A" sm get nope 2>/dev/null)"; rc=$?
eq "unknown program rc=4" "$rc" "4"

echo "== 3. 특수문자/한글 비밀번호 왕복 =="
SP='p@ss w0rd "q" '"'"'x'"'"' $HOME \back `cmd` 한글! #hash|pipe;&'
printf '%s\n' "$SP" | SECRET_SEED="$S_A" sm set special --secret-stdin 2>/dev/null
out="$(SECRET_SEED="$S_A" sm get special 2>/dev/null)"
eq "special chars roundtrip" "$out" "$SP"

echo "== 4. 여러 프로그램 / 서로 다른 seed (단일 파일) =="
printf '%s\n' 'bbb-secret' | SECRET_SEED="$S_B" sm set app-b --secret-stdin 2>/dev/null
eq "app-b get" "$(SECRET_SEED="$S_B" sm get app-b 2>/dev/null)" "bbb-secret"
eq "dns-ibx still ok" "$(SECRET_SEED="$S_A" sm get dns-ibx 2>/dev/null)" "$PW_A"
SECRET_SEED="$S_A" sm get app-b >/dev/null 2>&1; eq "cross-seed app-b rc=3" "$?" "3"
SECRET_SEED="$S_B" sm get dns-ibx >/dev/null 2>&1; eq "cross-seed dns-ibx rc=3" "$?" "3"
eq "record count in ONE file" "$(grep -vc '^#' "$SECRET_STORE")" "3"

echo "== 5. list : 비밀/암호문 미노출 =="
lst="$(sm list 2>/dev/null)"
has "list shows dns-ibx" "$lst" "dns-ibx"
has "list shows app-b" "$lst" "app-b"
has "list shows meta" "$lst" "aes-256-cbc:pbkdf2-sha256:20000"
hasnt "list hides ciphertext" "$lst" "U2FsdGVk"
hasnt "list hides secret" "$lst" "bbb-secret"

echo "== 6. 덮어쓰기 / 입력 검증 =="
printf '%s\n' 'new-pass-1' | SECRET_SEED="$S_A" sm set dns-ibx --secret-stdin >/dev/null 2>&1; rc=$?
[[ $rc -ne 0 ]] && ok "overwrite w/o -y refused (non-interactive)" || no "overwrite w/o -y refused" "rc=$rc"
eq "value unchanged after refusal" "$(SECRET_SEED="$S_A" sm get dns-ibx 2>/dev/null)" "$PW_A"
printf '%s\n' 'new-pass-1' | SECRET_SEED="$S_A" sm -y set dns-ibx --secret-stdin >/dev/null 2>&1
eq "overwrite with -y" "$(SECRET_SEED="$S_A" sm get dns-ibx 2>/dev/null)" "new-pass-1"
eq "no duplicate line after overwrite" "$(grep -c '^dns-ibx|' "$SECRET_STORE")" "1"
printf '%s\n' 'x' | SECRET_SEED='short' sm set shortseed --secret-stdin >/dev/null 2>&1; rc=$?
[[ $rc -ne 0 ]] && ok "short seed rejected" || no "short seed rejected" "rc=$rc"
printf '\n' | SECRET_SEED="$S_A" sm set emptysec --secret-stdin >/dev/null 2>&1; rc=$?
[[ $rc -ne 0 ]] && ok "empty secret rejected" || no "empty secret rejected" "rc=$rc"
printf '%s\n' 'x' | SECRET_SEED="$S_A" sm set 'bad|name' --secret-stdin >/dev/null 2>&1; rc=$?
[[ $rc -ne 0 ]] && ok "bad program name rejected" || no "bad program name rejected" "rc=$rc"
grep -q '^shortseed|\|^emptysec|\|^bad' "$SECRET_STORE" && no "rejected inputs not stored" "found" || ok "rejected inputs not stored"
sm get 'bad name' >/dev/null 2>&1; eq "get bad name rc=1" "$?" "1"

echo "== 7. check =="
SECRET_SEED="$S_A" sm check dns-ibx >/dev/null 2>&1; eq "check ok rc=0" "$?" "0"
SECRET_SEED="nope-nope-nope" sm check dns-ibx >/dev/null 2>&1; eq "check wrong rc=3" "$?" "3"

echo "== 8. seed 입력 경로 (파일 / 우선순위 / CRLF) =="
printf '%s\n' "$S_A" > "$WORK/seed.txt"; chmod 600 "$WORK/seed.txt"
eq "SECRET_SEED_FILE" "$(SECRET_SEED_FILE="$WORK/seed.txt" sm get dns-ibx 2>/dev/null)" "new-pass-1"
eq "-S option" "$(sm -S "$WORK/seed.txt" get dns-ibx 2>/dev/null)" "new-pass-1"
eq "file beats env" "$(SECRET_SEED_FILE="$WORK/seed.txt" SECRET_SEED=wrong-wrong-1 sm get dns-ibx 2>/dev/null)" "new-pass-1"
printf '%s\r\n' "$S_A" > "$WORK/seed-crlf.txt"
eq "CRLF seed file" "$(SECRET_SEED_FILE="$WORK/seed-crlf.txt" sm get dns-ibx 2>/dev/null)" "new-pass-1"
SECRET_SEED_FILE="$WORK/missing.txt" sm get dns-ibx >/dev/null 2>&1; [[ $? -ne 0 ]] && ok "missing seed file fails" || no "missing seed file fails" "rc=0"

echo "== 9. 대화형 프롬프트 경로 (SECRET_TTY=파일로 입력 모사) =="
printf '%s\n' 'tty-secret-1' 'tty-secret-1' 'seed-key-TTYX' 'seed-key-TTYX' > "$WORK/tty-set"
SECRET_TTY="$WORK/tty-set" sm set prompt-app >/dev/null 2>&1; eq "set via prompt rc" "$?" "0"
printf '%s\n' 'seed-key-TTYX' > "$WORK/tty-get"
eq "get via prompt" "$(SECRET_TTY="$WORK/tty-get" sm get prompt-app 2>/dev/null)" "tty-secret-1"
printf '%s\n' 'wrong-seed-1' 'seed-key-TTYX' > "$WORK/tty-retry"
out="$(SECRET_TTY="$WORK/tty-retry" sm get prompt-app 2>"$WORK/err.txt")"; rc=$?
eq "retry succeeds on 2nd attempt" "$out" "tty-secret-1"
has "retry message shown" "$(cat "$WORK/err.txt")" "재시도"
printf '%s\n' 'w1-wrong-seed' 'w2-wrong-seed' 'w3-wrong-seed' 'seed-key-TTYX' > "$WORK/tty-3x"
out="$(SECRET_TTY="$WORK/tty-3x" sm get prompt-app 2>/dev/null)"; rc=$?
eq "3 wrong tries -> rc=3" "$rc" "3"
eq "3 wrong tries -> no output" "$out" ""
printf '%s\n' 'aaa' 'bbb' 'seed-key-TTYX' 'seed-key-TTYX' > "$WORK/tty-mm"
SECRET_TTY="$WORK/tty-mm" sm set mismatch >/dev/null 2>&1; [[ $? -ne 0 ]] && ok "secret mismatch rejected" || no "secret mismatch rejected" "rc=0"
printf '%s\n' 'cccccc' 'cccccc' 'seed-key-1111' 'seed-key-2222' > "$WORK/tty-sm"
SECRET_TTY="$WORK/tty-sm" sm set seedmm >/dev/null 2>&1; [[ $? -ne 0 ]] && ok "seed mismatch rejected" || no "seed mismatch rejected" "rc=0"
printf '%s\n' 'n' > "$WORK/tty-no"
SECRET_TTY="$WORK/tty-no" SECRET_SEED="$S_A" sm delete prompt-app >/dev/null 2>&1; [[ $? -ne 0 ]] && ok "delete answered 'n' cancels" || no "delete 'n' cancels" "rc=0"
find_cnt="$(grep -c '^prompt-app|' "$SECRET_STORE")"; eq "record kept after 'n'" "$find_cnt" "1"
sm get prompt-app >/dev/null 2>&1; [[ $? -ne 0 ]] && ok "no tty + no seed -> fails (no hang)" || no "no tty + no seed fails" "rc=0"

echo "== 10. delete =="
sm -y delete app-b >/dev/null 2>&1; eq "delete rc" "$?" "0"
SECRET_SEED="$S_B" sm get app-b >/dev/null 2>&1; eq "deleted -> rc=4" "$?" "4"
eq "other record intact" "$(SECRET_SEED="$S_A" sm get dns-ibx 2>/dev/null)" "new-pass-1"
[[ -f "$SECRET_STORE.bak" ]] && ok ".bak generated" || no ".bak generated" "missing"
sm -y delete nope >/dev/null 2>&1; eq "delete unknown rc=4" "$?" "4"

echo "== 11. rekey (파라미터 업그레이드 / seed 교체 / --all) =="
printf '%s\n' 'rk-secret' | SECRET_SEED='seed-key-RKRK' sm set rk-app --secret-stdin >/dev/null 2>&1
has "rk-app iter=20000" "$(sm list 2>/dev/null)" "rk-app"
SECRET_ITER=30000 SECRET_SEED='seed-key-RKRK' sm rekey rk-app --keep-seed >/dev/null 2>&1; eq "rekey --keep-seed rc" "$?" "0"
has "meta upgraded to 30000" "$(grep '^rk-app|' "$SECRET_STORE")" "aes-256-cbc:pbkdf2-sha256:30000"
eq "value kept after param upgrade" "$(SECRET_SEED='seed-key-RKRK' sm get rk-app 2>/dev/null)" "rk-secret"
SECRET_SEED='seed-key-RKRK' SECRET_NEW_SEED='brand-new-seed-9' sm rekey rk-app >/dev/null 2>&1; eq "rekey new seed rc" "$?" "0"
SECRET_SEED='seed-key-RKRK' sm get rk-app >/dev/null 2>&1; eq "old seed rejected" "$?" "3"
eq "new seed works" "$(SECRET_SEED='brand-new-seed-9' sm get rk-app 2>/dev/null)" "rk-secret"
SECRET_SEED='brand-new-seed-9' SECRET_ITER=40000 sm rekey --all --keep-seed >/dev/null 2>&1; rc=$?
[[ $rc -ne 0 ]] && ok "rekey --all with mixed seeds reports failure" || no "rekey --all mixed seeds failure" "rc=0"
has "rk-app converted by --all" "$(grep '^rk-app|' "$SECRET_STORE")" ":40000"
eq "dns-ibx untouched by --all (other seed)" "$(SECRET_SEED="$S_A" sm get dns-ibx 2>/dev/null)" "new-pass-1"
SECRET_SEED='wrong-seed-0' SECRET_NEW_SEED='another-seed-8' sm rekey rk-app >/dev/null 2>&1; [[ $? -ne 0 ]] && ok "rekey with wrong old seed refused" || no "rekey wrong old seed" "rc=0"
eq "record intact after failed rekey" "$(SECRET_SEED='brand-new-seed-9' sm get rk-app 2>/dev/null)" "rk-secret"

echo "== 12. 일반 openssl 명령으로 수동 복구 가능 (스크립트 없이) =="
line="$(grep '^dns-ibx|' "$SECRET_STORE")"
IFS='|' read -r _p _u _m _b <<<"$line"; IFS=: read -r _c _k _i <<<"$_m"
manual="$(printf '%s' "$_b" | SS_PW="$S_A" openssl enc -d "-$_c" -pbkdf2 -md "${_k#pbkdf2-}" -iter "$_i" -a -A -pass env:SS_PW 2>/dev/null)"
eq "manual openssl decrypt = SS1:+secret" "$manual" "SS1:new-pass-1"
manual2="$(printf '%s' "$_b" | openssl enc -d -aes-256-cbc -pbkdf2 -md sha256 -iter "$_i" -a -A -pass "pass:$S_A" 2>/dev/null)"
eq "manual openssl (pass:literal) decrypt" "$manual2" "SS1:new-pass-1"
pk="$(printf '%s' "$_b" | base64 -d 2>/dev/null | head -c 8)"
eq "ciphertext has openssl 'Salted__' header" "$pk" "Salted__"

echo "== 13. 손상/변조 레코드 =="
sed 's/\r*$/\r/' "$SECRET_STORE" > "$WORK/crlf.enc"
eq "CRLF store readable" "$(SECRET_STORE="$WORK/crlf.enc" SECRET_SEED="$S_A" sm get dns-ibx 2>/dev/null)" "new-pass-1"
sed 's/^\(dns-ibx|[^|]*|aes-256-cbc:pbkdf2-sha256:\)[0-9]*|/\15|/' "$SECRET_STORE" > "$WORK/t-iter.enc"
SECRET_STORE="$WORK/t-iter.enc" SECRET_SEED="$S_A" sm get dns-ibx >/dev/null 2>&1; eq "iter=5 rejected rc=5" "$?" "5"
sed 's/^\(dns-ibx|[^|]*|\)aes-256-cbc:/\1des-ede3-cbc:/' "$SECRET_STORE" > "$WORK/t-cipher.enc"
SECRET_STORE="$WORK/t-cipher.enc" SECRET_SEED="$S_A" sm get dns-ibx >/dev/null 2>&1; eq "unknown cipher rejected rc=5" "$?" "5"
sed 's/^\(dns-ibx|[^|]*|[^|]*|\).*/\1AAAA/' "$SECRET_STORE" > "$WORK/t-b64.enc"
out="$(SECRET_STORE="$WORK/t-b64.enc" SECRET_SEED="$S_A" sm get dns-ibx 2>/dev/null)"; rc=$?
[[ $rc -ne 0 && -z "$out" ]] && ok "corrupt ciphertext fails, no output" || no "corrupt ciphertext" "rc=$rc out=$out"
sed 's/^\(dns-ibx|[^|]*|[^|]*|\).*/dns-ibx|2026|only-three|/' "$SECRET_STORE" > "$WORK/t-fmt.enc"
SECRET_STORE="$WORK/t-fmt.enc" SECRET_SEED="$S_A" sm get dns-ibx >/dev/null 2>&1; [[ $? -ne 0 ]] && ok "malformed record rejected" || no "malformed record" "rc=0"
# 마커 검증: openssl 복호화는 '성공'하지만 SS1: 마커가 없는 레코드는 반드시 거부해야 한다
# (CBC 는 무결성이 없어 오답 seed 가 우연히 padding 을 통과하는 경우를 모사)
nm="$(printf '%s' 'NOMARKER-value' | SS_PW="$S_A" openssl enc -aes-256-cbc -pbkdf2 -md sha256 -iter 20000 -salt -a -A -pass env:SS_PW)"
printf '# h\nnomark|2026-01-01T00:00:00|aes-256-cbc:pbkdf2-sha256:20000|%s\n' "$nm" > "$WORK/t-nomark.enc"
chk="$(printf '%s' "$nm" | SS_PW="$S_A" openssl enc -d -aes-256-cbc -pbkdf2 -md sha256 -iter 20000 -a -A -pass env:SS_PW 2>/dev/null)"
eq "precondition: openssl itself decrypts it fine" "$chk" "NOMARKER-value"
out="$(SECRET_STORE="$WORK/t-nomark.enc" SECRET_SEED="$S_A" sm get nomark 2>/dev/null)"; rc=$?
eq "no SS1: marker -> rc=3" "$rc" "3"
eq "no SS1: marker -> no output" "$out" ""
perm="$(stat -c '%a' "$SECRET_STORE" 2>/dev/null)"
touch "$WORK/permprobe"; chmod 600 "$WORK/permprobe"
if [[ "$(stat -c '%a' "$WORK/permprobe" 2>/dev/null)" == "600" ]]; then eq "store perm is 600" "$perm" "600"; else ok "store perm check skipped (fs has no POSIX perms)"; fi

echo "== 14. 기본 반복횟수(600000) 실사용 파라미터 =="
( unset SECRET_ITER; export SECRET_STORE="$WORK/default.enc"
  printf '%s\n' 'default-iter-pw' | SECRET_SEED="$S_A" bash "$SM" set d1 --secret-stdin >/dev/null 2>&1
  m="$(grep '^d1|' "$SECRET_STORE")"
  [[ "$m" == *"aes-256-cbc:pbkdf2-sha256:600000|"* ]] && echo "ok   - default meta 600000" || echo "FAIL - default meta ($m)"
  [[ "$(SECRET_SEED="$S_A" bash "$SM" get d1 2>/dev/null)" == "default-iter-pw" ]] && echo "ok   - default roundtrip" || echo "FAIL - default roundtrip"
) | tee "$WORK/dflt.out"
PASS=$((PASS + $(grep -c '^ok' "$WORK/dflt.out"))); FAIL=$((FAIL + $(grep -c '^FAIL' "$WORK/dflt.out")))

echo "== 15. dns-ibx.sh 연동 (실제 secret-mgr + curl mock) =="
mkdir -p "$WORK/bin"
cat > "$WORK/bin/curl" <<'MOCK'
#!/usr/bin/env bash
echo "CURL $*" >> "$MOCK_LOG"
printf '%s\n%s' '[]' '200'
MOCK
chmod +x "$WORK/bin/curl"
export MOCK_LOG="$WORK/curl.log"; : > "$MOCK_LOG"
cat > "$WORK/di.conf" <<'CONF'
IBX_HOST="10.0.0.1"
WAPI_VERSION="v2.11"
IBX_USER="admin"
VERIFY_TLS="false"
MAX_RESULTS=100
CONF
chmod 600 "$WORK/di.conf"
IPW='Infoblox!Pw 123'
printf '%s\n' "$IPW" | SECRET_STORE="$WORK/di-store.enc" SECRET_SEED='di-seed-1234' bash "$SM" set dns-ibx --secret-stdin >/dev/null 2>&1

run_di() { PATH="$WORK/bin:$PATH" bash "$DI" -c "$WORK/di.conf" "$@"; }

: > "$MOCK_LOG"
SECRET_STORE="$WORK/di-store.enc" SECRET_SEED='di-seed-1234' run_di list A >/dev/null 2>"$WORK/di.err"; rc=$?
eq "dns-ibx list rc (password from store)" "$rc" "0"
has "curl got decrypted password" "$(cat "$MOCK_LOG")" "-u admin:$IPW"
has "dns-ibx announced store usage" "$(cat "$WORK/di.err")" "암호화 저장소"

: > "$MOCK_LOG"
SECRET_STORE="$WORK/di-store.enc" SECRET_SEED='totally-wrong-1' run_di list A >/dev/null 2>"$WORK/di.err"; rc=$?
[[ $rc -ne 0 ]] && ok "wrong seed -> dns-ibx aborts" || no "wrong seed -> dns-ibx aborts" "rc=0"
eq "no curl call when decrypt failed" "$(cat "$MOCK_LOG")" ""
has "abort hint printed" "$(cat "$WORK/di.err")" "비밀번호를 얻지 못했습니다"

: > "$MOCK_LOG"
IBX_PASS='env-wins-pw' SECRET_TOOL="$WORK/does-not-exist.sh" run_di list A >/dev/null 2>&1; rc=$?
eq "IBX_PASS env has priority rc" "$rc" "0"
has "env password used" "$(cat "$MOCK_LOG")" "-u admin:env-wins-pw"

SECRET_TOOL="$WORK/does-not-exist.sh" run_di list A >/dev/null 2>&1; rc=$?
[[ $rc -ne 0 ]] && ok "no env + no tool -> clear failure" || no "no env + no tool" "rc=0"

SECRET_STORE="$WORK/di-store.enc" SECRET_SEED='di-seed-1234' SECRET_PROGRAM='not-registered' run_di list A >/dev/null 2>&1; rc=$?
[[ $rc -ne 0 ]] && ok "unregistered SECRET_PROGRAM fails" || no "unregistered SECRET_PROGRAM" "rc=0"

printf 'insert  a.my.com  10.0.0.1  A\n' > "$WORK/t.info"
: > "$MOCK_LOG"
SECRET_STORE="$WORK/di-store.enc" SECRET_SEED='di-seed-1234' run_di --dry-run -f "$WORK/t.info" >/dev/null 2>"$WORK/di.err"; rc=$?
eq "dry-run file apply with store password" "$rc" "0"
has "dry-run plan printed" "$(cat "$WORK/di.err")" "[dry-run] CREATE A"

echo
echo "==================  결과: PASS=$PASS  FAIL=$FAIL  =================="
[[ "$FAIL" -eq 0 ]]

# x64dbg-vm-gateway 빠른 시작 (한국어)

이 문서는 실제 VM에서 검증한 절차만 담았습니다. 검증 환경은 Linux host, VMware Workstation 17.6, Windows 10 게스트입니다. 상세 설계는 `docs/VM_ORCHESTRATION_PLAN.md`, 실측 기록은 `docs/PHASE0_RESULTS.md`, 영문 전체 레퍼런스는 `host/README.md`를 보세요.

## 1. 구성

```
Claude Code ──stdio(또는 HTTPS)──► x64dbg-vm-gateway (host)
                                     ├ vmrun: 전원·스냅샷·게스트 파일/프로세스
                                     └ HTTP+Bearer ──► 게스트 x64dbg/x32dbg 플러그인(v1.10)
```

- **AI가 쓰는 툴**
  - 게이트웨이 툴 21개: `analysis_*`, `vm_*`, `file_*`, `debugger_*`, `ida_*`, `jobs_*`, `session_status`, `gateway_doctor`
  - x64dbg 툴 83개(플러그인 v1.10): 원래 이름 그대로 중계합니다. 실제 Claude Code에서 합계 104개로 보이는 것을 확인했습니다.
- **루프:** `analysis_start` → 분석(미러 툴) → `analysis_collect` → `analysis_finish`(클린 스냅샷 복원)

## 2. 요구 사항

| 항목 | 내용 |
|---|---|
| host | Linux(검증됨). Windows와 macOS(Intel)는 코드상 지원하지만 실검증 전입니다. |
| VMware | Workstation 17(`vmrun` 포함) |
| 도구 | `uv`(Python 3.12 자동 설치), 플러그인을 빌드할 때만 Zig 0.14.0 |
| 게스트 | Windows 10 이상 + x64dbg(`release\x64`, `release\x32`) + VMware Tools. 암호가 있는 로컬 관리자 계정 |
| 네트워크 | host-only 권장(격리 점검이 bridged와 공유 폴더 RW를 거부합니다) |

## 3. 설치

릴리스 wheel에는 미리 빌드한 플러그인이 들어 있어 Zig가 필요 없습니다. GitHub 릴리스에서 `x64dbg_vm_gateway-<버전>-py3-none-any.whl`을 받아 설치합니다.

```bash
uv tool install ./x64dbg_vm_gateway-0.1.0-py3-none-any.whl   # x64dbg-vm-gateway 명령이 생깁니다
```

직접 빌드하려면 저장소에서 `scripts/build-release.sh`를 실행합니다(Zig 0.14.0과 uv 필요, 어느 디렉터리에서나 실행 가능). 플러그인을 빌드해 패키지에 넣고, `release/`에 wheel, sdist, `x64dbg-mcp-plugin-<버전>.zip`(`x64/plugins`, `x32/plugins`), `SHA256SUMS`를 만듭니다. `v*` 태그를 push하면 GitHub Actions가 같은 스크립트를 돌려 `release/*`를 릴리스에 첨부합니다.

```bash
scripts/build-release.sh
uv tool install --force release/x64dbg_vm_gateway-*.whl
```

`uv tool install ./host`도 됩니다. 다만 스크립트를 먼저 돌리지 않았다면 플러그인이 들어 있지 않으므로 `install-plugin --dist dist`가 필요합니다(`zig build -Doptimize=ReleaseSafe --prefix dist`로 빌드).

## 4. 설정

비밀값은 설정 파일에 넣지 않습니다. 환경 변수 이름만 적고, 값은 0600 권한의 env 파일에 둡니다.

```bash
mkdir -p ~/.config/x64dbg-vm-gateway
install -m 600 /dev/null ~/.config/x64dbg-vm-gateway/lab.env
# lab.env 내용:
#   X64DBG_GW_GUEST_USER=<게스트 계정>
#   X64DBG_GW_GUEST_PW=<게스트 암호>
```

`~/.config/x64dbg-vm-gateway/config.toml`(0600) 예시입니다. 스파이크 VM에서 검증한 형태입니다.

```toml
[gateway]
jobs_root = "~/mcp-lab/jobs"
default_profile = "lab"
env_file = "~/.config/x64dbg-vm-gateway/lab.env"
upload_roots = ["~/samples"]          # analysis_start가 읽을 수 있는 host 경로

[profiles.lab]
mode = "vmware"
vmx = "/vms/analysis_clone/analysis_clone.vmx"
clean_snapshot = "MCP_CLEAN"
protected_snapshots = ["MCP_CLEAN"]
guest_user_env = "X64DBG_GW_GUEST_USER"
guest_password_env = "X64DBG_GW_GUEST_PW"
guest_host = "auto"                   # 또는 고정 IP
job_root_guest = 'C:\mcp\jobs'
require_isolation = true
token_source = "guest-config"         # 게스트의 mcp_config.json에서 토큰을 읽습니다
relaunch_mode = "task"                # schtasks /run MCP-x64dbg 로 재기동

[profiles.lab.backends.x64]
port = 9094
exe = 'C:\x64dbg\release\x64\x64dbg.exe'
config = 'C:\x64dbg\release\x64\mcp_config.json'
launch_task = "MCP-x64dbg"

[profiles.lab.backends.x32]
port = 9095
exe = 'C:\x64dbg\release\x32\x32dbg.exe'
config = 'C:\x64dbg\release\x32\mcp_config.json'
launch_task = "MCP-x32dbg"
```

대화식으로 만들려면 `x64dbg-vm-gateway init`을 실행합니다.

## 5. 게스트 준비 (한 번만)

VM을 켜고 게스트 암호 환경 변수를 export한 뒤 한 번에 실행할 수 있습니다.

```bash
x64dbg-vm-gateway setup --dry-run   # 계획만 출력합니다(아무것도 접속·변경하지 않음)
x64dbg-vm-gateway setup             # (설정이 없으면 init) → doctor → install-plugin → provision → doctor
```

- 설정 파일이 없으면 `init` 마법사를 실행합니다. `--non-interactive --vmx ... --guest-user ... --x64dbg-root ...`도 받습니다.
- doctor에서 setup이 고칠 수 없는 항목(vmrun, .vmx, VM 전원, VMware Tools, 게스트 계정, 게스트 IP, 격리, VM 중복 실행, job 폴더)이 실패하면 힌트를 보여 주고 멈춥니다.
- 번들 플러그인을 설치하고(다른 빌드는 `--dist DIR`), `provision --snapshot`(기본값: 프로필의 `clean_snapshot`)을 실행합니다. 이어서 doctor로 다시 점검하고 Claude Code 등록 명령(§7)을 출력합니다.
- `--skip-plugin`, `--skip-provision`으로 일부만 실행합니다. 이미 있는 스냅샷은 바꾸지 않습니다. `--snapshot 새이름`으로 찍은 뒤 설정 파일의 `clean_snapshot`(과 `protected_snapshots`)을 직접 그 이름으로 바꿉니다.
- `--no-autologon`이면 재부팅 뒤 누군가 `--wait-ready`초 안에 VM에 로그온해야 합니다(디버거는 로그온 때 시작됩니다).
- `setup`과 번들 플러그인 설치는 단위 테스트로만 검증했고, 실제 VM에서는 아직 돌려 보지 않았습니다. 실 VM에서 검증한 절차는 아래 단계별 명령입니다.

한 단계씩 하려면:

```bash
# 1) 플러그인 배포: 디버거 종료 → 기존 플러그인을 plugins_backup\에 백업 → 복사 → 재기동 (실측 17~25초)
#    --dist를 빼면 번들 빌드를 씁니다. 프로비저닝 전의 게스트에는 --no-relaunch를 붙입니다.
x64dbg-vm-gateway install-plugin --dist dist --x64dbg-root 'C:\x64dbg\release'

# 2) 프로비저닝 → 재부팅 → 클린 스냅샷
x64dbg-vm-gateway provision --x64dbg-root 'C:\x64dbg\release' --snapshot MCP_CLEAN
```

프로비저닝이 하는 일은 다음과 같습니다.

- 자동 로그온을 설정합니다.
- 로그온 시 x64dbg·x32dbg를 최고 권한으로 실행하는 예약 작업을 등록합니다(재기동에도 씁니다).
- 플러그인 설정을 씁니다.
  - 외부 바인드에 필요한 `AllowExternal`, `AllowedClients=host IP`(자동 감지)를 넣습니다.
  - 손상된 토큰을 복구합니다.
- `C:\mcp\jobs`를 만들고, x64dbg DB 압축을 끕니다(IDA 연동용).

프로비저닝은 재부팅을 게스트 부팅 시각으로 확인한 뒤 플러그인 응답을 기다리고 스냅샷을 찍습니다(실측: 준비 39초, 전체 3분 14초). 스냅샷은 메모리 포함 켜짐 상태입니다. 복원하면 x64dbg가 떠 있는 상태 그대로 11~14초 만에 돌아옵니다.

## 6. 점검

```bash
x64dbg-vm-gateway doctor      # vmrun, 스냅샷, Tools, 게스트 계정, 격리, 백엔드 토큰·버전을 점검
x64dbg-vm-gateway status
```

## 7. Claude Code 등록

```bash
claude mcp add x64dbg-vm -- x64dbg-vm-gateway serve
# 설정 파일이 기본 위치가 아니면:
claude mcp add x64dbg-vm -e X64DBG_VM_GATEWAY_CONFIG=/path/config.toml -- x64dbg-vm-gateway serve
```

사용 예시(대화):

> `~/samples/a.exe` 분석 시작해. kernel32.CreateFileW에 BP 걸고 실행, 인자 확인하고 스택 덤프 저장한 다음 artifact 회수하고 복원해.

AI가 호출하는 흐름은 다음과 같습니다.

1. `analysis_start`
2. `SetBreakpoint`, `run`, `GetArguments`, `DumpMemory`(상대경로는 job의 `out` 폴더)
3. `analysis_collect`
4. `analysis_finish`

회수된 파일은 `~/mcp-lab/jobs/<job_id>/artifacts/`(manifest.json, files/, raw/out.zip)에 쌓입니다.

## 8. 다른 PC에서 접속 (원격 HTTP + TLS)

`config.toml`에 다음을 추가합니다.

```toml
[http]
enabled = true
bind = "0.0.0.0"
port = 9100
tls_cert = "/path/server.crt"
tls_key = "/path/server.key"
allow_clients = ["10.0.0.0/24"]
[http.token_envs]
read = "GW_TOKEN_READ"        # 관찰 툴만
analyze = "GW_TOKEN_ANALYZE"  # 게스트 변경 + 디버거 조작
admin = "GW_TOKEN_ADMIN"      # 스냅샷 복원·삭제, 전원, 파일 다운로드 포함
```

`x64dbg-vm-gateway serve --transport http`로 띄웁니다. 클라이언트는 `https://<host>:9100/mcp`에 `Authorization: Bearer <token>`으로 접속합니다. 비루프백 주소에 바인드하면서 TLS가 없으면 시작을 거부합니다. 모든 호출은 `<jobs_root>/_audit/`에 감사 로그로 남습니다.

## 9. IDA 연동 (ida-multi-mcp와 함께)

| 툴 | 하는 일 |
|---|---|
| `static_rebase` | x64dbg 런타임 주소(ASLR)와 IDA 주소·RVA를 서로 변환합니다. |
| `static_export_annotations` | x64dbg DB(라벨·주석·북마크·BP)를 `artifacts/static_sync.json`으로 내보냅니다. |
| `static_import_annotations` | IDA 쪽 이름과 주석을 x64dbg에 적용합니다. |

IDA 안에서는 `static/ida/x64dbg_sync.py`로 JSON을 가져오거나 내보낼 수 있습니다. 자세한 내용은 `static/ida/README.md`에 있습니다.

## 10. 안전 수칙

- **격리 점검:** 공유 폴더 RW 또는 bridged 네트워크면 `analysis_start`가 거부됩니다. 현재 `analysis_vm` VM은 `/srv/vm-share`가 RW라 그대로는 거부됩니다.
- **비신뢰 출력:** 게스트 출력은 `<untrusted_guest_output>`으로 감싸서 전달합니다. 그 안의 지시문은 데이터로만 취급합니다.
- **수집 전 복원 금지:** 수집 전에는 복원할 수 없습니다(fail-closed). 버릴 job은 사람만 `x64dbg-vm-gateway discard <job>`으로 정리할 수 있습니다.
- **스냅샷 보호:** 보호 스냅샷과 클린 스냅샷은 삭제할 수 없습니다.

## 11. 문제 해결 (실제로 겪은 것)

| 증상 | 원인 / 조치 |
|---|---|
| 업로드한 파일이 LoadBinary로 안 열리고 System32 파일만 열림 | 같은 .vmx의 **VM 프로세스가 2개**(revert 후 고아 인스턴스). `pgrep -af '^/usr/lib/vmware/bin/vmware-vmx'`로 확인하고 고아를 종료한다. 게이트웨이는 시작 전 이 상황을 검사해 거부한다(`VM_LOCKED`, doctor `single_vm_instance`). |
| 429 / `BACKEND_THROTTLED`, doctor에 "locked this host out" | 플러그인 인증 실패 잠금. **토큰 없는 요청은 모두 실패로 센다**(5회 → 300초). 토큰 없이 `curl`로 포트를 두드리는 것도 포함된다. 5분 기다린다. 반복되면 토큰이 틀린 것이다(`doctor`의 token 항목). |
| `BackendAuthError` + provision 안내 | 게스트 `mcp_config.json`이 손상됨(0으로 채워진 사례 있음). `provision`을 다시 실행한다. |
| `provision`이 `--user is required` | 구버전 CLI가 `guest_user_env`/`env_file`을 읽지 않던 결함(수정됨). 지금은 env 파일 값으로 동작한다. |
| `GetDebugState`가 `status: LOCKED` | 이전 플러그인 빌드. 정지 상태(PAUSED)와 같다. 플러그인을 다시 설치하면 PAUSED로 나온다. |
| `ida_export_annotations`가 빈 문서(`database.source = "not_written"`)와 경고를 돌려줌 | 세션에 라벨·주석·북마크·BP·함수가 하나도 없으면 x64dbg는 DB 파일을 쓰지 않는다. 플러그인(2026-11-24 빌드)은 이를 `No database file written`으로 알린다. 주석을 단 뒤 다시 export한다. 이전 빌드는 저장을 큐에 넣기만 하고 항상 "저장됨"이라고 답하므로, 게이트웨이가 빈 세션과 저장 실패를 구별하지 못한다는 경고를 붙인다. |
| 게스트 명령 인자 깨짐 | vmrun은 인자마다 따옴표를 씌우고 이스케이프하지 않는다. 게이트웨이가 미리 이스케이프한다. 직접 vmrun을 쓸 때는 PowerShell `-EncodedCommand`나 `-File`을 쓰고, cmd.exe는 쓰지 않는다. |
| 게스트 PowerShell 스크립트가 "인수 형식이 일치하지 않습니다" | Windows PowerShell 5.1의 `ConvertTo-Json @($List[object])` 문제. 게이트웨이 스크립트는 `.ToArray()`를 쓴다. |

## 12. 검증 현황

2026-11-24 기준, 스파이크 VM(Windows 10 + PowerShell 5.1)에서 확인한 범위입니다. 자세한 기록은 `docs/PHASE0_RESULTS.md`에 있습니다.

- **실 VM 검증 완료** — `pytest -m vm tests/vm` 10건 통과
  - doctor(단일 VM 인스턴스 포함), install-plugin(25초, `plugins_backup`), provision(부팅 시각 기반 재부팅 감지, 스냅샷까지 3분 14초)
  - x64·x32 전체 루프: 복원 → 업로드 → 로드 → BP/run/스택/덤프 → 수집(덤프·DB가 manifest에 기록) → IDA export → 복원. 분석 명령을 뺀 한 바퀴 약 48초
  - x64dbg 강제 종료 → `BACKEND_RESTARTED` → 재기동 → ack → 분석 재개
  - MCP stdio: 첫 툴 목록에 v1.10 툴이 들어 있음, `session_status` 호출
  - 실제 Claude Code 클라이언트(`claude -p --mcp-config`, `uv tool install`로 설치한 실행 파일)
    - 툴 104개가 보이고 `session_status`, `GetServerInfo`(v1.10)가 호출됩니다.
    - 분석 루프 전체가 68초에 끝났습니다. `analysis_start` → BP `kernel32.Sleep` → `run` 2회 → PAUSED → 스택 → 덤프 → 수집(`.dd64` + 덤프) → 복원.
    - `run`의 `timeoutMs`가 호출 예산(`max_call_s`)에 맞게 줄어드는 것도 확인했습니다.
- **추가 검증(2026-11-24 오전, 클린 스냅샷 `MCP_CLEAN_V110E`)**
  - 원격 HTTPS
    - 실제 Claude Code가 host-only 주소의 TLS 게이트웨이로 루프 전체를 돌렸습니다(122초).
    - `read` 토큰은 툴 45개만 보이고 변경 툴은 거부됐습니다. 토큰이 없거나 틀리면 401이었습니다.
  - `in_progress`: `max_call_s`를 15로 낮춘 설정에서 시작·수집·복원이 모두 `in_progress`를 돌려줬고, 클라이언트가 `session_status`로 기다렸습니다.
  - IDA 9.2(헤드리스)에서 `static/ida/x64dbg_sync.py` import·export가 동작했습니다.
  - `run`/step 직후 `GetDebugState`: 실행 중 `RUNNING`, 정지 후 `PAUSED`.
  - `LogRedirect`, `LoadBinary`의 인자와 작업 폴더가 동작했습니다. x64dbg를 죽이면 디버기도 함께 종료됩니다.
  - 빈 세션의 `SaveDatabase`·export·수집이 정상 처리됩니다(이번에 고친 결함).
- **미검증**
  - Windows/macOS host
  - 실제 다른 PC에서의 원격 접속(같은 host의 비루프백 주소로 대신 확인)
  - 기본 한도(110초)를 실제로 넘기는 호출
  - 게스트의 SYSTEM 서비스 `vmtoolsd`가 죽은 경우

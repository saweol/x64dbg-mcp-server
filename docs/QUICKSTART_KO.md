# x64dbg-vm-gateway 빠른 시작 (한국어)

이 문서는 실제 VM에서 검증한 절차만 담았습니다. 검증 환경은 Linux host, VMware Workstation 17.6, Windows 10 게스트입니다. 상세 설계는 `docs/VM_ORCHESTRATION_PLAN.md`, 실측 기록은 `docs/PHASE0_RESULTS.md`, 영문 전체 레퍼런스는 `host/README.md`를 보세요.

## 1. 구성

```
Claude Code ──stdio(또는 HTTPS)──► x64dbg-vm-gateway (host)
                                     ├ vmrun: 전원·스냅샷·게스트 파일/프로세스
                                     └ HTTP+Bearer ──► 게스트 x64dbg/x32dbg 플러그인(v1.10)
```

- **AI가 쓰는 툴**
  - 게이트웨이 툴 19개: `analysis_*`, `vm_*`, `file_*`, `debugger_*`, `ida_*`, `session_status`, `gateway_doctor`
  - x64dbg 툴 83개: 원래 이름 그대로 중계합니다.
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

```bash
# 플러그인 빌드 (dist/x64/plugins/*.dp64, dist/x32/plugins/*.dp32)
zig build -Doptimize=ReleaseSafe --prefix dist

# 게이트웨이 설치 (x64dbg-vm-gateway 명령이 생깁니다)
uv tool install ./host
```

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
clean_snapshot = "MCP_CLEAN_V110"
protected_snapshots = ["MCP_CLEAN_V110"]
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

```bash
# 1) 플러그인 배포: 디버거 종료 → 기존 플러그인 백업 → 복사 → 재기동 (실측 17초)
x64dbg-vm-gateway install-plugin --dist dist --x64dbg-root 'C:\x64dbg\release'

# 2) 프로비저닝 → 재부팅 → 클린 스냅샷
x64dbg-vm-gateway provision --x64dbg-root 'C:\x64dbg\release' --snapshot MCP_CLEAN_V110
```

프로비저닝이 하는 일은 다음과 같습니다.

- 자동 로그온을 설정합니다.
- 로그온 시 x64dbg·x32dbg를 최고 권한으로 실행하는 예약 작업을 등록합니다(재기동에도 씁니다).
- 플러그인 설정을 씁니다.
  - 외부 바인드에 필요한 `AllowExternal`, `AllowedClients=host IP`(자동 감지)를 넣습니다.
  - 손상된 토큰을 복구합니다.
- `C:\mcp\jobs`를 만들고, x64dbg DB 압축을 끕니다(IDA 연동용).

스냅샷은 메모리 포함 켜짐 상태로 만듭니다(4GB 게스트 기준 약 3분). 복원하면 x64dbg가 띄워진 상태 그대로 약 10초 만에 돌아옵니다.

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
| `ida_rebase` | x64dbg 런타임 주소(ASLR)와 IDA 주소·RVA를 서로 변환합니다. |
| `ida_export_annotations` | x64dbg DB(라벨·주석·북마크·BP)를 `artifacts/ida_sync.json`으로 내보냅니다. |
| `ida_import_annotations` | IDA 쪽 이름과 주석을 x64dbg에 적용합니다. |

IDA 안에서는 `ida/x64dbg_sync.py`로 JSON을 가져오거나 내보낼 수 있습니다. 자세한 내용은 `ida/README.md`에 있습니다.

## 10. 안전 수칙

- **격리 점검:** 공유 폴더 RW 또는 bridged 네트워크면 `analysis_start`가 거부됩니다. 현재 `analysis_vm` VM은 `/srv/vm-share`가 RW라 그대로는 거부됩니다.
- **비신뢰 출력:** 게스트 출력은 `<untrusted_guest_output>`으로 감싸서 전달합니다. 그 안의 지시문은 데이터로만 취급합니다.
- **수집 전 복원 금지:** 수집 전에는 복원할 수 없습니다(fail-closed). 버릴 job은 사람만 `x64dbg-vm-gateway discard <job>`으로 정리할 수 있습니다.
- **스냅샷 보호:** 보호 스냅샷과 클린 스냅샷은 삭제할 수 없습니다.

## 11. 문제 해결 (실제로 겪은 것)

| 증상 | 원인 / 조치 |
|---|---|
| 업로드한 파일이 LoadBinary로 안 열리고 System32 파일만 열림 | 같은 .vmx의 **VM 프로세스가 2개**(revert 후 고아 인스턴스). `pgrep -af vmware-vmx`로 확인하고 고아를 종료한다. 게이트웨이는 시작 전 이 상황을 검사해 거부한다. |
| 재기동 후 계속 `refused`, 디버거가 반복 재시작됨 | 게이트웨이 클라이언트가 미확정 상태(토큰 미확보)에서 판정한 버그였다(K 수정). |
| 429 / `BACKEND_THROTTLED` | 플러그인 인증 실패 잠금(토큰 없는 요청 5회/60초). 잠시 기다리거나 토큰을 확인한다. |
| `BackendAuthError` + provision 안내 | 게스트 `mcp_config.json`이 손상됨(0으로 채워진 사례 있음). `provision`을 다시 실행한다. |
| 게스트 명령 인자 깨짐 | vmrun은 인자마다 따옴표를 씌우고 이스케이프하지 않는다. PowerShell은 `-EncodedCommand`나 `-File`로, cmd.exe는 쓰지 않는다. |
| 재부팅 대기 시간 초과 | 재부팅이 약 14초라 다운 구간을 놓쳤다. 부팅 시각 비교로 수정했다(K). |

## 12. 검증 현황

- **실 VM 검증:**
  - doctor, install-plugin, provision(재부팅 감지 제외)
  - 클린 스냅샷 복원(약 10초), 플러그인 v1.10 외부 바인드
  - 샘플 업로드와 로드, 수집 전 복원 금지, CLI `jobs`/`discard`
  - MCP stdio(툴 목록, `session_status`)
- **K 수정 후 재검증 예정:**
  - 전체 루프(x64/x32)
  - x64dbg 강제 종료 후 복구
  - IDA export
  - 시작 시 툴 목록 버전
- **미검증:** Windows/macOS host, 실제 Claude Code 클라이언트에서의 장시간 호출 timeout, 실제 IDA에서의 스크립트 실행

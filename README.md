# x64dbg-mcp-server — VMware 분석 루프 포크

> 이 저장소는 [duty1g/x64dbg-mcp-server](https://github.com/duty1g/x64dbg-mcp-server)(MIT)의 **포크**입니다. 원작자의 공식 배포판이 아닙니다.
> 원본의 x64dbg MCP 플러그인을 바탕으로, **host에서 VMware 분석 VM과 디버거를 함께 다루는 MCP 게이트웨이**를 더했습니다.
> 포크 기준점은 upstream `main @ 31c05bc`(플러그인 v1.9)입니다. 라이선스는 [아래](#라이선스)에 정리했습니다.

**English summary.** A fork of duty1g/x64dbg-mcp-server (MIT). It adds `x64dbg-vm-gateway`, a host-side MCP server that reverts a VMware analysis VM to a clean snapshot, uploads the sample, keeps x64dbg/x32dbg alive in the guest, relays the plugin's 83 debugger tools under their original names and collects the artifacts back to the host. English references: [`host/README.md`](host/README.md) (gateway) and [`docs/PLUGIN.md`](docs/PLUGIN.md) (plugin). Licensed under MIT like the original; see [License](#라이선스).

---

## 한눈에 보기

AI 클라이언트(Claude Code 등)는 host에서 도는 게이트웨이 **하나에만** 연결합니다. 나머지는 게이트웨이가 맡습니다.

```
Claude Code ──stdio──────► x64dbg-vm-gateway (host, Python)
원격 PC ─────HTTPS────────►   ├─ vmrun ──────────► VMware: 전원, 스냅샷, 게스트 파일·프로세스
                              └─ HTTP + Bearer ──► 게스트 x64dbg :9094 / x32dbg :9095 (플러그인 v1.10)
```

분석 한 바퀴는 다음과 같이 돕니다.

```
analysis_start ──► 분석 (x64dbg 툴 83개를 원래 이름으로) ──► analysis_collect ──► analysis_finish
 클린 스냅샷 복원       SetBreakpoint, run, DumpMemory ...        결과물을 host로 회수     클린 스냅샷으로 복원
 샘플 업로드·해시 확인                                            (덤프, x64dbg DB, zip)
 디버거에 로드(정지 상태)
```

AI에게 보이는 툴은 게이트웨이 툴 21개와 플러그인 툴 83개, 합계 104개입니다.

## 왜 만들었나

원본 플러그인은 x64dbg 안에서 MCP 서버를 띄웁니다. 설치가 간단하고 디버거를 직접 다루기에 좋습니다. 그런데 악성코드를 VM에서 반복 분석하는 데 쓰려니 불편한 점이 넷 있었습니다.

1. **디버거가 죽으면 연결도 끊깁니다.** 샘플이 디버거를 죽이거나 x64dbg가 크래시하면 MCP 엔드포인트도 함께 사라집니다. AI 세션은 그 사실을 모른 채 실패만 반복합니다.
2. **VM 제어는 사람 몫이었습니다.** 분석 전 클린 스냅샷 복원, 전원 관리를 VMware 화면에서 손으로 했습니다.
3. **파일을 넣고 빼는 것도 손으로 했습니다.** 샘플을 VM에 넣고 덤프나 DB를 꺼내려면 공유 폴더를 켜야 했고, 그러면 격리가 깨집니다.
4. **클린 상태로 돌아가는 것을 사람이 챙겨야 했습니다.** 결과물을 챙기기 전에 복원하면 분석이 날아가고, 복원을 잊으면 다음 분석이 오염됩니다.

그래서 **"MCP가 로드된 클린 VM → 샘플 전송 → 지시에 따른 분석 → 결과물 회수 → 복원"** 루프를 AI가 처음부터 끝까지 돌릴 수 있게 하는 것을 목표로 삼았습니다. 사람은 무엇을 분석할지 지시하고, 되돌릴 수 없는 결정만 내립니다.

## 설계 철학

| 원칙 | 의미 |
|---|---|
| **단일 제어자** | VM과 분석 작업(job) 상태를 바꾸는 프로세스는 게이트웨이 하나뿐입니다. 게이트웨이의 수명은 VM·디버거와 무관하므로, x64dbg가 죽거나 VM을 복원해도 AI의 MCP 연결은 그대로입니다. 죽은 디버거는 게이트웨이가 다시 띄웁니다. |
| **원본을 감싸되 바꾸지 않는다** | 플러그인 툴은 원래 이름(`SetBreakpoint`, `run`, `DumpMemory` …) 그대로 중계합니다. 원본 사용법과 `SKILL.md`가 그대로 통하고, 플러그인은 게이트웨이 없이 단독으로도 예전처럼 쓸 수 있습니다. |
| **fail-closed** | 결과물 회수가 확인되기 전에는 복원하지 않습니다. AI가 `force` 같은 플래그로 이 규칙을 넘을 수 없습니다. 작업을 버리는 결정은 사람만 CLI(`discard`)로 내립니다. 클린·보호 스냅샷은 지울 수 없고, VM이 격리되어 있지 않으면(공유 폴더가 켜져 있거나, 네트워크가 host-only가 아닌 bridged·NAT 등) 분석을 시작하지 않습니다. |
| **상태 변경은 자동 재시도하지 않는다** | `run`, step, 브레이크포인트처럼 상태를 바꾸는 호출은 두 번 실행되면 분석이 틀어집니다. 그래서 자동 재시도는 읽기 호출에만 합니다. |
| **세상이 바뀌면 알린다(epoch)** | 디버거가 재기동되거나 VM이 복원되면 epoch를 올립니다. 그다음 상태 변경 호출은 `BACKEND_RESTARTED`로 막혀서, AI가 사라진 주소나 BP를 믿고 계속 진행하지 못합니다. AI가 `session_status`로 상황을 확인하면 다시 진행할 수 있습니다. |
| **게스트는 적대적이다** | 게스트에서 온 문자열·파일·zip·JSON은 모두 공격자 입력으로 다룹니다. 게스트 출력은 `<untrusted_guest_output>`으로 감싸 프롬프트 인젝션을 막고, zip은 안전하게 풀고, 회수한 파일은 host에서 실행하지 않습니다. |
| **비밀값은 설정 파일에 두지 않는다** | 설정 파일에는 환경 변수 **이름**만 적고, 값은 권한 0600인 env 파일에 둡니다. 플러그인 토큰은 게스트 설정에서 읽어 옵니다. |
| **검증한 것만 "된다"고 쓴다** | 실제 VM에서 확인한 것과 코드상 지원만 하는 것을 문서에서 구분합니다([검증 현황](#검증-현황)). |

## 원본 대비 달라진 점

| 영역 | 원본 (v1.9, `31c05bc`) | 이 포크 |
|---|---|---|
| x64dbg 플러그인 `src/` | v1.9, 툴 80개 | **v1.10, 툴 83개.** 네트워크 하드닝: 잘못된 bind 주소를 `0.0.0.0`으로 되돌리던 동작을 없애고 시작을 거부, 외부 바인드에 `AllowExternal`·`AllowedClients`·32자 이상 토큰 요구, 요청 타임아웃, 동시 연결 상한, 포트 독점 바인드. 인증 실패 잠금(429)과 SSE 끄기 옵션. 상태 변경 툴 직렬화. `GetServerInfo`·`SetArtifactDir`·`ProbeFile` 추가. `GetDebugState`가 정지 상태를 `LOCKED` 대신 `PAUSED`로 보고합니다. 자세한 내용은 [`docs/PLUGIN.md`](docs/PLUGIN.md)를 보세요. |
| host 게이트웨이 `host/` | 없음 | 새로 작성(Python). VM 제어, 파일 전송, 디버거 감시·재기동, job 상태기계, 원격 HTTPS, 감사 로그 |
| 게스트 준비 `guest/` | 없음 | `provision.ps1`: 자동 로그온, 디버거 자동 실행 예약 작업, 플러그인 설정, 작업 폴더 |
| IDA 연동 `ida/` | 없음 | x64dbg 런타임 주소 ↔ IDA 주소 변환, 주석·이름 주고받기 |
| 문서 | `README.md` | 원본 README는 [`docs/PLUGIN.md`](docs/PLUGIN.md)로 옮겼습니다. 설계·실측·빠른 시작 문서를 더했습니다. |

## 요구 사항

| 항목 | 내용 |
|---|---|
| host | Linux(실검증). Windows와 macOS(Intel)는 코드상 지원하지만 실검증 전입니다. |
| VMware | Workstation 17(`vmrun` 포함). 검증 환경은 17.6입니다. |
| 도구 | [uv](https://docs.astral.sh/uv/)(Python 3.11 이상을 알아서 준비합니다). 플러그인을 직접 빌드할 때만 [Zig 0.14.0](https://ziglang.org/download/#release-0.14.0)이 필요합니다. |
| 게스트 | Windows 10 이상, VMware Tools, x64dbg(`release\x64`, `release\x32`), 암호가 있는 로컬 관리자 계정 |
| 네트워크 | host-only(또는 네트워크 없음). 격리 점검이 공유 폴더가 켜진 VM과 host-only가 아닌 네트워크(bridged, NAT 등)를 거부합니다. |

## 설치와 준비

전체 절차와 설정 예시는 [`docs/QUICKSTART_KO.md`](docs/QUICKSTART_KO.md)에 있습니다. 아래는 요약입니다.

**1. 빌드와 설치**

```bash
zig build -Doptimize=ReleaseSafe --prefix dist   # 플러그인: dist/x64/plugins/*.dp64, dist/x32/plugins/*.dp32
uv tool install ./host                           # 게이트웨이: x64dbg-vm-gateway 명령
```

**2. 설정.** 비밀값은 0600 env 파일에 두고, 설정 파일에는 변수 이름만 적습니다.

```bash
mkdir -p ~/.config/x64dbg-vm-gateway
install -m 600 /dev/null ~/.config/x64dbg-vm-gateway/lab.env
#   X64DBG_GW_GUEST_PW=<게스트 암호>
x64dbg-vm-gateway init        # 대화식으로 config.toml 작성 (vmx 경로, 클린 스냅샷 이름, 게스트 계정, x64dbg 경로 등)
```

`init`은 게스트 계정을 `guest_user`에, 암호는 변수 이름만 `guest_password_env`(기본 `X64DBG_GW_GUEST_PW`)에 적습니다. 그다음 `config.toml`의 `[gateway]`에 `env_file = "~/.config/x64dbg-vm-gateway/lab.env"`와 `upload_roots`(분석할 샘플을 둘 host 경로)를 추가합니다. 계정 이름도 env 파일에 두려면 프로필에 `guest_user_env`를 씁니다.

**3. 게스트 준비 (한 번만)**

```bash
# 플러그인 배포: 디버거 종료 → 기존 플러그인을 plugins_backup\에 백업 → 복사 → 재기동
x64dbg-vm-gateway install-plugin --dist dist --x64dbg-root 'C:\x64dbg\release'

# 프로비저닝: 자동 로그온, 디버거 자동 실행(최고 권한), 플러그인 설정·토큰, 작업 폴더
#             → 재부팅 → 두 플러그인 응답 확인 → 메모리 포함 클린 스냅샷
x64dbg-vm-gateway provision --x64dbg-root 'C:\x64dbg\release' --snapshot MCP_CLEAN
```

**4. 점검**

```bash
x64dbg-vm-gateway doctor      # vmrun, 스냅샷, VMware Tools, 게스트 계정, 격리, VM 인스턴스 수, 백엔드 토큰·버전
```

**5. Claude Code에 등록**

```bash
claude mcp add x64dbg-vm -- x64dbg-vm-gateway serve
```

## 사용법

Claude Code에서 평소처럼 지시하면 됩니다.

> `~/samples/a.exe` 분석 시작해. kernel32.CreateFileW에 BP 걸고 실행해서 인자 확인하고, 스택 덤프 저장한 다음 artifact 회수하고 복원해.

AI는 대략 다음 순서로 툴을 호출합니다.

1. `analysis_start`: 격리를 점검하고 클린 스냅샷으로 복원합니다. 샘플을 해시 확인과 함께 올리고, 아키텍처에 맞는 디버거에 정지 상태로 로드합니다. 샘플을 자동으로 실행하지는 않습니다.
2. `SetBreakpoint` → `run` → `GetArguments` → `DumpMemory`: 상대 경로로 지정한 덤프는 job의 게스트 `out` 폴더에 저장됩니다.
3. `analysis_collect`: x64dbg DB를 저장하고 `out`을 묶어 host로 가져온 뒤, 안전하게 풀고 manifest를 돌려줍니다.
4. `analysis_finish`: 클린 스냅샷으로 복원합니다. 회수 전에는 거부됩니다.

회수한 결과물은 `~/mcp-lab/jobs/<job_id>/artifacts/`(`manifest.json`, `files/`, `raw/out.zip`)에 쌓입니다.

알아 두면 좋은 동작은 다음과 같습니다.

- **오래 걸리는 작업**(`analysis_start`, 복원, 전원)은 정해진 시간이 지나면 `{"state": "in_progress"}`를 돌려주고 백그라운드에서 계속합니다. 진행 상황은 `session_status`로 확인합니다.
- **디버거가 죽으면** 게이트웨이가 다시 띄웁니다. 다음 상태 변경 호출은 `BACKEND_RESTARTED`를 받고, `session_status`로 확인한 뒤 이어서 진행합니다. `analysis_start(reload_on_restart=true)`를 주면 샘플도 다시 로드합니다.
- **목록에 없는 플러그인 툴**은 `debugger_call`로 부를 수 있습니다.

### 게이트웨이 툴 (21개)

| 등급 | 툴 |
|---|---|
| 관찰(읽기 전용) | `session_status`, `gateway_doctor`, `vm_snapshots_list`, `vm_screenshot`, `ida_rebase`, `jobs_list`, `jobs_show` |
| 게스트 변경 | `file_upload`, `debugger_select`, `debugger_restart`, `debugger_call`, `analysis_start`, `analysis_collect`, `ida_export_annotations`, `ida_import_annotations` |
| host·VM 파괴적 | `vm_snapshot_take`, `vm_snapshot_revert`, `vm_snapshot_delete`, `vm_power`, `file_download`, `analysis_finish` |

마지막 등급은 MCP 클라이언트의 권한 설정에서 **사람의 승인을 받도록** 두기를 권합니다. 오류는 `{code, message, stage, retryable, hint, next_tool, details}` 형태로 돌아오므로 AI가 다음 행동을 정할 수 있습니다.

### CLI

| 명령 | 용도 |
|---|---|
| `serve [--transport stdio\|http]` | MCP 서버 (Claude Code는 stdio) |
| `doctor`, `status` | 환경 점검, 현재 상태 |
| `init` | 설정 파일 작성 |
| `jobs [list \| show JOB_ID]` | job 조회 (게이트웨이가 돌고 있어도 읽기 가능) |
| `discard JOB_ID` | **사람 전용.** 회수 없이 버려도 되는 job으로 표시 |
| `provision`, `install-plugin` | 게스트 준비, 플러그인 배포 |

### 다른 PC에서 접속

`serve --transport http`로 같은 툴을 `https://<host>:9100/mcp`에 엽니다.

- 비루프백 주소에 바인드하려면 TLS가 필요합니다.
- 토큰은 범위별로 따로 둡니다. `read`는 관찰만, `analyze`는 게스트 변경과 디버거 조작, `admin`은 전체입니다.
- 클라이언트 허용 목록과 요청 속도 제한이 있고, 모든 호출은 `<jobs_root>/_audit/`에 감사 로그로 남습니다.

설정은 [`docs/QUICKSTART_KO.md`](docs/QUICKSTART_KO.md) §8과 [`host/README.md`](host/README.md#remote-access-m3)에 있습니다.

### IDA 연동

IDA 쪽 MCP 서버(예: ida-multi-mcp)와 함께 쓰는 것을 전제로 합니다. 게이트웨이의 `ida_rebase`는 x64dbg 런타임 주소(ASLR)와 IDA 주소·RVA를 서로 변환합니다. `ida_export_annotations`와 `ida_import_annotations`는 라벨·주석·북마크를 주고받습니다. IDA 안에서는 `ida/x64dbg_sync.py`를 씁니다. 자세한 내용은 [`ida/README.md`](ida/README.md)에 있습니다.

## 안전 수칙

- **샘플은 VM 안에서만 실행합니다.** host-only 네트워크를 쓰고 공유 폴더는 끕니다. 설정 기본값(`require_isolation = true`)에서는 격리되지 않은 VM으로 분석을 시작하지 않습니다.
- **회수한 파일은 신뢰하지 않습니다.** 덤프, DB, 내려받은 파일을 host에서 실행하지 마세요.
- **토큰은 곧 권한입니다.**
  - 플러그인 토큰은 게스트에서 코드를 실행할 수 있는 권한입니다. 게스트의 악성코드가 읽을 수 있고 스냅샷 파일에도 남습니다.
  - 게이트웨이 HTTP 토큰은 VM 제어 권한이므로 환경 변수에 두고 범위별로 따로 씁니다.
- **플러그인 포트를 토큰 없이 두드리지 마세요.** 게스트 밖(host 등)에서 온 요청은 토큰이 없어도 인증 실패로 셉니다. 5회 실패하면 그 IP는 300초 동안 잠깁니다(429).

## 검증 현황

2026-11-24 기준입니다. 환경은 Linux host, VMware Workstation 17.6, Windows 10(PowerShell 5.1) 게스트이고, 사용자의 분석 VM을 하드 클론한 VM에서 확인했습니다. 기록은 [`docs/PHASE0_RESULTS.md`](docs/PHASE0_RESULTS.md)에 있습니다.

**확인한 것**

- 실 VM 테스트 10건 통과(E2E 5건, 게스트 동작 점검 5건)
  - `doctor`, `install-plugin`, `provision`(재부팅 감지부터 스냅샷까지)
  - x64·x32 전체 루프. 분석 명령을 뺀 한 바퀴가 약 48초입니다.
  - x64dbg 강제 종료 → `BACKEND_RESTARTED` → 재기동 → 분석 재개
  - MCP stdio
- 실제 Claude Code 클라이언트
  - 툴 104개가 보였습니다.
  - BP → `run` → 스택 → 덤프 → 회수 → 복원까지 분석 루프 전체가 68초에 끝났습니다.
- 클린 스냅샷 복원 후 x64dbg가 응답하기까지 11~14초가 걸렸습니다.
- 원격 HTTPS
  - 실제 Claude Code가 비루프백 주소의 TLS 게이트웨이로 분석 루프 전체를 돌렸습니다.
  - 범위별 토큰 권한, 401·403, 감사 로그도 확인했습니다.
- `in_progress` 경로: 호출 한도를 낮춘 설정에서 실제 Claude Code가 `in_progress`를 받고 `session_status`로 기다렸다가 이어 갔습니다.
- 실제 IDA 9.2(헤드리스)에서 `ida/x64dbg_sync.py`의 import·export·메뉴 등록이 동작했습니다.
- `run`/step 직후 `GetDebugState`는 실행 중 `RUNNING`, 멈춘 뒤 `PAUSED`로 일관됐습니다.
- `LogRedirect`, `LoadBinary`의 인자·작업 폴더가 동작했습니다. x64dbg를 죽이면 디버기도 함께 종료됩니다.

**아직 확인하지 않은 것**

- Windows·macOS host
- 실제로 다른 PC에서 원격 접속(같은 host의 비루프백 주소로 대신 확인)
- 기본 한도(110초)를 실제로 넘기는 호출(낮춘 한도로 같은 경로만 확인)
- VM 없이 고정 주소의 플러그인에 붙는 `endpoint` 프로필의 실환경 사용
- 게스트의 SYSTEM 서비스 `vmtoolsd`가 죽은 경우

## 개발 방식과 테스트

이 포크는 Claude Code(Claude Opus)와 함께 아래 순서로 만들었습니다.

1. **계획:** 저장소 분석 → 설계 → 여러 모델의 독립 검토(Claude Sonnet: 신뢰성·보안, Fable: 완결성·아키텍처, Mythos: 기술 타당성) → 반영. 결과는 [`docs/VM_ORCHESTRATION_PLAN.md`](docs/VM_ORCHESTRATION_PLAN.md)에 있습니다.
2. **Phase 0:** 사용자의 분석 VM을 건드리지 않고 하드 클론을 떠서, vmrun·VIX·플러그인 동작을 실측했습니다.
3. **기능별 TDD:** 실패하는 테스트 → 구현 → 다른 모델들의 코드 리뷰 → 반영 → 테스트 통과. 이 과정을 모두 거쳐야 기능을 완료로 봤습니다. 기능마다 에이전트를 따로 붙여 병렬로 개발했습니다.
4. **마지막 관문:** 실 VM E2E와 실제 Claude Code 클라이언트 확인. 여기서 나온 결함(응답 소켓 처리, 인증 잠금, `GetDebugState LOCKED`, PowerShell 5.1 JSON 등)도 같은 절차로 고쳤습니다.

```bash
cd host
uv run pytest                 # 단위 테스트 (VM 불필요: VM·게스트·플러그인은 fake)
uv run ruff check src tests
uv run pytest -m vm tests/vm  # 실 VM E2E: VM을 복원·변경하므로 버려도 되는 클론에서만 실행
cd .. && zig build test       # 플러그인 단위 테스트
```

## 문서

| 문서 | 내용 |
|---|---|
| [`docs/QUICKSTART_KO.md`](docs/QUICKSTART_KO.md) | 실 VM에서 검증한 설치·사용 절차, 실제로 겪은 문제 해결 |
| [`host/README.md`](host/README.md) | 게이트웨이 영문 레퍼런스 (설정, 툴, 원격 접속, 테스트) |
| [`docs/PLUGIN.md`](docs/PLUGIN.md) | x64dbg 플러그인 레퍼런스 (원본 README + v1.10 변경) |
| [`ida/README.md`](ida/README.md) | IDA 연동 |
| [`docs/VM_ORCHESTRATION_PLAN.md`](docs/VM_ORCHESTRATION_PLAN.md) | 설계, 상태 모델, 다중 모델 검토 반영 기록 |
| [`docs/PHASE0_RESULTS.md`](docs/PHASE0_RESULTS.md) | 실측 기록, 발견·수정한 결함 |
| [`SKILL.md`](SKILL.md) | 원본의 x64dbg MCP 사용 스킬 |

## 라이선스

이 포크는 원본과 같은 **MIT 라이선스**를 따릅니다. 전문은 [`LICENSE`](LICENSE)에 있습니다.

**저작권 표기.** `LICENSE`에는 저작권 줄이 두 개 있습니다.

```
Copyright (c) 2026 duty1g          ← 원본 x64dbg-MCP Server
Copyright (c) 2026 saweol (...)    ← 이 포크에서 추가·변경한 부분 (README.md에 범위 명시)
```

MIT는 원본의 저작권 표시와 허가 문구를 유지하는 것을 조건으로 수정·재배포를 허락합니다. 그래서 원본 표기는 그대로 두고 포크 표기를 덧붙였습니다.

**어느 부분이 누구의 것인가.**

| 부분 | 출처 |
|---|---|
| `src/`, `build.zig`, `build.zig.zon`, `.github/`, `.gitignore`, `SKILL.md`, `logo.png`, `docs/PLUGIN.md` | 원본(duty1g와 upstream 기여자들, git 이력 참고). 이 포크에서 수정한 내용은 같은 파일에 함께 들어 있습니다. |
| `host/`, `guest/`, `ida/`, `docs/`의 나머지 문서, 이 `README.md` | 이 포크에서 새로 작성 |

**이 코드를 가져다 쓸 때.** 일부만 가져가더라도 `LICENSE` 파일(두 저작권 줄과 허가 문구)을 함께 넣어 주세요. MIT가 요구하는 것은 이것뿐입니다. 소프트웨어는 "있는 그대로" 제공되며 어떤 보증도 없습니다.

**이 저장소에 포함되지 않은 것.** 아래는 각자의 라이선스를 따르며, 사용자가 따로 설치합니다.

| 구성 요소 | 라이선스 |
|---|---|
| [x64dbg](https://x64dbg.com/) | GPLv3. 플러그인은 x64dbg에 로드되지만 x64dbg 자체는 이 저장소에 없습니다. |
| VMware Workstation / `vmrun` | 상용(Broadcom) |
| IDA Pro | 상용(Hex-Rays) |
| ida-multi-mcp | 별도 프로젝트 |
| 게이트웨이의 Python 직접 의존성(uv가 설치) | `mcp`, `anyio`, `jsonschema`: MIT / `starlette`, `uvicorn`: BSD-3-Clause. 간접 의존성 전체는 `host/uv.lock`에 있습니다. |

이 포크는 원작자, x64dbg 프로젝트, Broadcom(VMware), Hex-Rays와 관계가 없습니다. 각 이름은 해당 소유자의 상표입니다. 이 절은 저장소의 표기 방침을 정리한 것이며 법률 자문이 아닙니다.

## 면책

이 도구는 정당한 리버스 엔지니어링, 악성코드 분석, 보안 연구, 교육 목적으로만 써야 합니다. 디버거 완전 제어(메모리 읽기·쓰기, 코드 실행, 프로세스 조작)와 VM 제어를 네트워크로 노출합니다. 사용에 따른 책임은 사용자에게 있습니다. 분석 권한이 있는 소프트웨어에만 쓰고, 플러그인이나 게이트웨이를 신뢰할 수 없는 네트워크에 노출하지 마세요.

## 감사의 말

- x64dbg MCP 플러그인을 만들고 MIT로 공개한 [@duty1g](https://github.com/duty1g)와 upstream 기여자들
- [x64dbg](https://x64dbg.com/) 프로젝트
- [Model Context Protocol](https://modelcontextprotocol.io/)

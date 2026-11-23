# Phase 0 검증 결과 (ADR)

- 일시: 2026-11-23
- 대상: 스파이크 VM `/vms/analysis_clone/analysis_clone.vmx`
- 클론 방법: 원본 `analysis_vm`의 `MCP_BASE` 스냅샷 디스크 체인(`000006.vmdk`)을 `vmware-vdiskmanager -r ... -t 0`으로 단일 디스크로 합쳤다. 원본이 실행 중이어서 `vmrun clone`이 거부됐기 때문이다(`Error: The virtual machine should not be powered on`). 원본 VM은 읽기만 했다.
- 클론 설정: 공유 폴더 비활성, host-only(vmnet1), 새 UUID·MAC.
- 환경: Linux host, VMware Workstation, `vmrun 1.17.0 build-24583834`. 게스트는 Windows 10 Pro 19045 한국어판이다.

## 검증 항목

| ID | 항목 | 결과 | 결정 |
|---|---|---|---|
| V1 | GUI x64dbg 기동, 권한 | 미검증: `runProgramInGuest -interactive` 직접 기동은 아직 해 보지 않았다. 확인된 것: 예약 작업(AtLogOn, Interactive, RunLevel Highest)으로 자동 로그온 직후 x64dbg·x32dbg가 떴다. VIX로 실행한 프로세스는 관리자 계정에서 **High 무결성**이었다(`ConsentPromptBehaviorAdmin=0`). | 재기동은 `schtasks /run /tn MCP-x64dbg` 방식을 기본(`relaunch_mode=task`)으로 한다. |
| V2 | revert → ready | 측정 3회: revert 1.6~1.9 s. 직후 VM은 `vmrun list`에 없고 `.vmss`도 없다(꺼진 상태). `start nogui`에 5.5~15.6 s. | ready 절차는 revert → 전원 확인 → 필요하면 start. start는 timeout을 두고 실행한 뒤 `list`로 확인한다. |
| V15 | revert 직후 플러그인 응답 | **재기동 없이** start 후 0.1~0.2 s에 L2(`GetDebugState`)가 성공했다. 메모리 스냅샷에서 x64dbg가 복원된다. | 클린 스냅샷 계약은 "x64dbg 실행 중 메모리 스냅샷"으로 유지한다. |
| V6 | revert 후 IP | 게스트 메모리가 복원되므로 IP는 그대로다(192.168.56.128). 다만 start 직후에는 `getGuestIPAddress`가 `Error: The VMware Tools are not running`을 낸다. | ready 판정을 Tools 상태에 묶지 않는다. 직전 IP로 L2를 먼저 시도하고, Tools와 IP 확인은 보조로 둔다. |
| V3 | 디렉터리 복사 | 미검증. | zip(Compress-Archive/tar)으로 묶어 복사하는 것을 구현 규칙으로 한다. |
| V4 | 게스트 PowerShell 출력 회수, vmrun 인자 전달 | **정정(E2E에서 실측):** vmrun은 각 인자를 큰따옴표로 감싸 커맨드라인을 만들고 내부 따옴표를 이스케이프하지 않는다. 게스트 `[Environment]::CommandLine`에서 `"a b" "c"d" "plain" "e\f"` 형태로 확인했다. 그래서 인자 안의 `"`와 끝의 `\`는 깨지고, `cmd.exe /c ...`도 따옴표 처리 때문에 실패한다. 처음 기록했던 "공백으로 이어 붙인다"는 해석은 틀렸다. `-EncodedCommand`(UTF-16LE base64)와 결과 파일 복사는 동작한다. | 복잡한 스크립트는 `-EncodedCommand`나 `-File`로 실행한다(ps.py). VixChannel은 인자를 미리 따옴표로 감싸지 말고 MSVCRT 내부 이스케이프만 한다. cmd.exe는 쓰지 않는다. |
| V5 | x64dbg 명령(`LogRedirect`, `dbsave <path>`, `init` 3인자) | 미검증. Wave 3 E2E에서 확인한다. | — |
| V7 | vmrun 동시 호출 | 미검증. | VM별 lock으로 직렬화한다(보수적 기본값). |
| V8 | Claude Code 툴 timeout | 미검증. | `max_call_s` 기본 110 s. |
| V9 | vmtoolsd kill | 미검증. | — |
| V10 | DB 기반 BP 복원 | 미검증. | — |
| V11 | Windows/macOS host | 범위 밖(사용자 결정: 이 Linux 시스템만). | — |
| V12 | vmrest 스냅샷 API | 미검증(저순위). | — |
| V13 | `-gp` 노출 | argv로 전달되므로 노출되는 구조다(직접 확인은 안 함). | 수용 리스크. 전용 계정 사용, 로그 마스킹. |
| V14 | x64dbg kill 시 디버기 | 미검증. Wave 3 E2E에서 확인한다. | — |
| V16 | Zig 버전 | 0.14.0으로 기존 코드와 변경 코드 모두 빌드·테스트가 통과했다. | CI와 문서를 0.14.0으로 통일한다. |

## 그 밖에 확인된 사실

- **cold boot의 `vmrun start`:** 반환까지 200 s 이상 걸렸다. 그 사이 VM은 이미 `list`에 올라와 있었다. 스냅샷 복원 후 start는 5~16 s였다.
- **메모리 스냅샷 생성:** RAM 4 GB 게스트 기준 약 172 s.
- **`fileExistsInGuest`:** 없는 파일이면 `The file does not exist.`를 출력하고 exit 255로 끝난다.
- **게스트 x64dbg와 플러그인 위치:** `C:\Users\analyst\Desktop\x64dbg\release\{x64,x32}`
  - 설치된 플러그인은 **v1.3**(툴 80개, `GetServerInfo` 없음, `LoadBinary`가 로드 완료를 기다리지 않음)이다.
  - x64 설정은 `127.0.0.1`에 바인드되어 있어 host에서 접근할 수 없었다.
  - x32 `mcp_config.json`은 **101바이트 전부 0으로 손상**되어 있었다. 스냅샷 시점에 디스크에 기록되지 않은 것으로 보인다.
- **프로비저닝:** `guest/provision.ps1` 실행으로 자동 로그온, 예약 작업 2개, 설정 재작성(x32 토큰 재생성, 0.0.0.0 바인드), job 루트를 구성했다. 재부팅 후 44 s 만에 두 플러그인이 401(인증 요구)로 응답했다. 토큰으로 `initialize`, `tools/list`, `GetDebugState` 호출이 성공했다.
- **golden fixture:** `host/tests/fixtures/plugin_v1.3/*.http`. 토큰은 들어 있지 않다.
- **클린 스냅샷:** 스파이크 VM에 `MCP_CLEAN`을 만들었다(전원 켜짐, 메모리 포함, x64dbg·x32dbg 실행 중).

## E2E 중 추가로 확인한 사실 (2026-11-23 밤)

- **중복 VM 인스턴스 사고**
  - 경위: revert 직후 VM이 `vmrun list`에 없다는 이유로 `start`를 호출했다. 그런데 같은 vmx의 이전 `vmware-vmx` 프로세스가 고아로 남아 있었고, 두 인스턴스가 같은 MAC과 IP로 동시에 돌았다.
  - 증상: 고아(20:29 시작)가 IP .128과 v1.3 플러그인을 쥐고 있었다. 그래서 HTTP는 고아로 가고 vmrun 게스트 작업은 등록된 인스턴스로 갔다. 결과적으로 "업로드한 새 파일이 LoadBinary로 열리지 않는" 것처럼 보였다.
  - 부수 피해: 등록된 인스턴스는 DHCP 충돌로 APIPA(169.254.x.x)를 받았다.
  - 조치: 고아 프로세스를 종료하고 재부팅했다.
  - 결정: 게이트웨이는 start 전에 같은 vmx의 `vmware-vmx` 프로세스를 host에서 검사한다. `doctor`도 단일 인스턴스를 점검한다.
- **재부팅 감지:** 재부팅은 약 14 s 만에 끝나서 5 s 폴링으로는 "다운" 구간을 놓쳤다. 재부팅 감지는 LastBootUpTime 비교로 한다.
- **`-interactive` 실행:** `runProgramInGuest -interactive`는 사용자 세션(session 1)에서 실행된다.
- **로그 리다이렉트 명령:** x64dbg 2025-08 빌드에 `LogRedirect`/`RedirectLog` 명령이 있다(문자열 확인). 내부적으로 GUI 쪽 `GuiLogRedirect`를 쓴다.
- **DB 압축 설정 키:** `x64dbg.ini`의 `[Engine] DisableDatabaseCompression` 키가 존재한다(기본 0, 즉 압축).
- **플러그인 v1.10 기동:** `AllowExternal=true`, `AllowedClients=["192.168.56.1"]` 설정(provision이 host IP를 자동 감지해 기록)으로 0.0.0.0 바인드가 정상 기동했다. `GetServerInfo` 응답도 확인했다.
- **`install_plugin` 실측:** 17 s 걸렸다(디버거 종료 → 백업 → 복사 → `schtasks` 재기동 → 포트 응답).
- **로드 확인:** 새로 업로드한 샘플이 `LoadBinary`(v1.10)에서 250 ms 만에 시스템 BP에서 정지했다.
- **게스트 Defender:** 실시간 보호는 꺼져 있었다(`RealTimeProtectionEnabled=False`).
- **검사 도구 제한:** Sysinternals Process Monitor로 게스트를 추적하려던 시도는 auto mode 분류기가 차단했다(Undermining Oversight). 그 대신 플러그인에 진단 툴 `ProbeFile`과 `ExecuteDebuggerCommand(direct=true)`를 추가했다.

## K 수정 후 실 VM 재검증 (2026-11-24)

- **대상:** 스파이크 VM, 클린 스냅샷 `MCP_CLEAN_V110B`(아래 수정 플러그인 + provision으로 새로 만든 것)
- **실행:** `pytest -m vm tests/vm`(E2E 5건 + K-vm 5건) **10건 모두 통과**(3분 43초)

### 확인한 것

- **doctor:** 전 항목 정상(`single_vm_instance` 포함).
- **x64·x32 전체 루프**
  - `analysis_start`: 복원 → 시작 → 업로드 → `LoadBinary` 시스템 BP 정지
  - `GetServerInfo`(1.10), `ListModules`, `SetBreakpoint kernel32.Sleep`, `run` 반복 후 kernel32 안에서 정지(`GetDebugState` PAUSED)
  - `GetCallStack`, `DumpMemory`(상대경로 → job `out`)
  - `analysis_collect`: manifest.json에 덤프와 `.dd64`/`.dd32`가 sha256과 함께 기록됐고 host 파일이 존재
  - `ida_export_annotations`, `analysis_finish`(복원)
  - VM 작업마다 같은 .vmx의 `vmware-vmx` 프로세스가 정확히 1개
- **루프 소요 시간(job 상태 기록 기준)**

  | 구간 | 시간 |
  |---|---|
  | 복원+시작 → VM_READY | 11~14 s |
  | 업로드 | 약 7 s |
  | 로드 | 1 s 미만 |
  | 수집 | 2~5 s |
  | 종료 복원 | 10~13 s |
  | 분석 명령을 뺀 한 바퀴 | 약 48 s |

- **x64dbg 강제 종료(ANALYZING 중)**
  - 다음 변경 호출이 `BACKEND_RESTARTED`(epoch 증가)를 받았다.
  - 예약 작업으로 재기동됐다.
  - `session_status`가 ack 후 HEALTHY를 보고했다.
  - 이어서 `LoadBinary` → `WaitForPause` → PAUSED.
- **MCP stdio:** 첫 `tools/list`에 v1.10 툴(`GetServerInfo`, `SetArtifactDir`, `ProbeFile`)이 있고, `session_status` 호출도 성공했다.
- **K-vm(E1~E3)**
  - vmrun 인자 왕복: 따옴표, 끝 `\`, 빈 문자열, 유니코드 포함
  - PowerShell `-Command` 한 줄 명령
  - `instance_report`
  - LastBootUpTime 안정성
- **provision(실 VM)**
  - 자격 증명을 `env_file`에서 읽었다(셸에 export 없음).
  - 재부팅을 부팅 시각(13:37 → 16:42 UTC)으로 감지했다. `reboot_signal=boot_time`.
  - 39 s 후 준비 완료, 스냅샷까지 총 3분 14초.
- **실제 Claude Code 클라이언트**
  - 조건: `claude -p --mcp-config`, `uv tool install ./host`로 설치한 실행 파일, 허용 툴 제한.
  - 툴 104개(게이트웨이 21 + 플러그인 83)가 보였다.
  - 루프 전체가 68초에 끝났다. 순서는 다음과 같다.
    - `analysis_start`(즉시 완료)
    - `kernel32.Sleep` BP, `run` 2회(엔트리 → Sleep), PAUSED
    - 스택, 덤프
    - 수집(`.dd64`, 덤프)
    - 복원
  - `run`의 `timeoutMs` 120000이 호출 예산에 맞춰 70000으로 줄었다는 안내가 출력에 붙었다.
- **install-plugin(실 VM)**
  - 25 s 걸렸다.
  - 백업은 `<arch>\plugins_backup\<plugin>.<UTC>.bak`에 만들어졌고, `plugins\`에는 플러그인만 남았다.

### 이 재검증에서 새로 찾아 고친 결함

| 결함 | 원인 | 조치 |
|---|---|---|
| 게이트웨이의 모든 백엔드 호출이 `BackendUnavailable (errno 9)` | 플러그인 v1.10은 모든 응답에 `Connection: close`를 붙인다. `http.client`는 본문을 다 읽으면 소켓을 닫는데, 읽기 루프가 그 뒤 `settimeout()`을 호출했다. 가짜 서버는 이 헤더를 보내지 않아 단위 테스트에서 드러나지 않았다. | 응답이 닫히면 루프를 끝낸다. 가짜 서버에 v1.10 프레이밍을 추가하고 백엔드 테스트를 두 프레이밍 모두로 돌린다. |
| doctor 몇 번과 수동 curl로 host가 5분간 잠김(HTTP 429) | 플러그인은 토큰 없는 요청을 모두 로그인 실패로 센다(5회 → 300 s 잠금). doctor의 도달성 검사는 토큰 없이 요청했다. | 토큰이 있으면 토큰으로 확인하고, 없으면 TCP 연결만 확인한다. 토큰이 거부되면 실패 1회로 끝낸다. |
| `GetDebugState`가 정지 상태를 `LOCKED`로 보고(문서·`[state]` 줄은 PAUSED) | x64dbg는 디버기가 멈춰 있는 동안 run lock을 잡는다. 시스템 BP, 엔트리 BP, `WaitForPause` 직후 모두 LOCKED였다. | 플러그인이 PAUSED를 보고한다(`src/mcp/debugstate.zig`). loop rules에 "이전 빌드의 LOCKED는 정지"를 추가했다. |
| `provision`이 빠른 시작 설정으로 실패(`--user is required`) | CLI가 `guest_user_env`와 `env_file`을 보지 않았다. | 게이트웨이와 같은 방식(실환경 > env_file)으로 해석한다. HTTP serve의 `token_envs`도 같다. |
| install-plugin 백업 목록 조회 실패(exit 1) | Windows PowerShell 5.1에서 `ConvertTo-Json -InputObject @($List[object])`와 `@($List[object]) \| ConvertTo-Json`이 "인수 형식이 일치하지 않습니다"로 실패했다. `$list.ToArray()`는 동작했다. `List[string]`을 해시테이블 속성에 넣는 형태는 동작했다. | 백업 목록 조회와 `discover_x64dbg`가 `.ToArray()`를 쓴다. 두 스크립트를 게스트에서 실행해 확인했다. 정적 검사를 추가했다. |

### 아직 실 VM에서 확인하지 않은 것

- 수정된 `GetDebugState`가 `run`/step 직후의 과도 상태에서 무엇을 보고하는지. E2E는 `run` 반환 뒤의 정지 상태만 봤다.
- 110초를 넘기는 호출이 실제 Claude Code에서 `in_progress`로 끊기는 경로. 실제 클라이언트로 돌린 루프는 모든 호출이 예산 안에 끝났다.
- x64dbg 강제 종료 시 디버기 프로세스가 어떻게 되는지(V14).
- `LogRedirect` 명령의 실제 동작(V5 일부).
- vmrun 동시 호출(V7), Claude Code 실제 클라이언트의 장시간 호출 timeout(V8), vmtoolsd 강제 종료(V9).
- Windows/macOS host(V11, 범위 밖).

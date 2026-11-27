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

## 남은 항목 실 VM 검증과 수정 (2026-11-24 오전)

- **대상:** 스파이크 VM, 클린 스냅샷 `MCP_CLEAN_V110E`(아래 플러그인 수정의 최종 빌드 + provision으로 새로 만든 것)
- **실 VM 스위트:** `pytest -m vm tests/vm` 결과는 아래 "최종 실행"에 적었다.

### 확인한 것

- **`run`/step 직후 `GetDebugState`**
  - `StepOver` 5회, 매번 직후 3회 조회: 모두 `PAUSED`.
  - `run`(BP에서 다음 BP까지) 중 30 ms 간격 조회: `PAUSED` → `RUNNING`(0.03 s) → `PAUSED`(0.52 s). 실행 중 `RUNNING` 15회, 그 밖의 상태는 나오지 않았다.
- **V5 (x64dbg 명령)**
  - `LogRedirect "<out>\x64dbg_redirect.log"` → `log` → `LogRedirectStop`: 로그 파일에 마커가 기록되고 수집으로 회수됐다.
  - `init` 3인자(`LoadBinary`의 `arguments`, `workingDir`): PEB의 명령줄이 `"...\24db8e22265a.exe" alpha "b c" d`, 현재 폴더가 job `out\`였다. 샘플이 그 폴더에 쓴 `e2e_sample_output.txt`도 회수됐다. 끝이 `\`인 인자는 플러그인이 거부한다(x64dbg가 인용할 수 없는 형태, 의도된 제한).
  - `dbsave`: 세션에 주석이 없으면 파일을 쓰지 않는다. 아래 결함으로 이어졌다.
- **V14 (x64dbg 강제 종료 시 디버기)**: x64dbg를 죽이면 디버기 프로세스도 1초 안에 사라졌다. 다음 호출은 `BACKEND_RESTARTED`였고 디버거는 재기동됐다.
- **V9 (부분)**
  - 사용자 세션의 `vmtoolsd.exe`를 종료한 뒤에도 업로드, 디버거 호출, 수집, 복원이 정상이었다.
  - SYSTEM 서비스 `vmtoolsd.exe`는 분석 계정 권한으로 종료할 수 없었다(`GUEST_AUTH`). 서비스가 죽은 경우는 확인하지 못했다.
- **`in_progress` 경로 (실제 Claude Code)**
  - `max_call_s = 15`(대기 상한 5 s)로 낮춘 설정에서 확인했다. 기본 110 s를 넘기는 작업을 만들기 어려워서, 같은 코드 경로를 낮은 한도로 태웠다.
  - 헤드리스 Claude Code가 아래 원격 HTTPS로 접속했다. `analysis_start`, `analysis_collect`, `analysis_finish`가 각각 `in_progress`를 받았고, 클라이언트가 `session_status`를 폴링해 완료를 기다린 뒤 다음 단계로 갔다. 전체 122 s, job DONE, 복원됨.
- **원격 HTTPS (M3)**
  - 게이트웨이를 host-only 어댑터 주소에 TLS(자체 서명)로 바인드하고, 허용 목록은 host 자신(`/32`)만 두었다. 다른 PC 대신 같은 host에서 비루프백 주소로 접속했다.
  - 토큰 없음·틀린 토큰은 401이었다. 신뢰하지 않는 인증서와 평문 HTTP는 연결되지 않았다.
  - `read` 토큰: 툴 45개(변경 툴 없음). `vm_power`는 `FORBIDDEN`이었다. 다른 범위의 토큰으로 같은 세션을 쓰면 404였다.
  - `admin` 토큰: 툴 104개.
  - 감사 로그에 토큰 값은 없었다. 거부 기록은 같은 클라이언트·결과마다 묶여(`suppressed` 횟수) 기록된다.
- **IDA 9.2 (idalib, 헤드리스)**: 스크래치 폴더에 복사한 샘플로 `ida/x64dbg_sync.py`를 실행했다.
  - import: 이름 변경(`start` → `gw_probe_entry`), 기존 주석을 보존한 주석 병합, 북마크 태그
  - 같은 문서를 다시 import하면 주석이 바뀌지 않았다(멱등).
  - export: 문서에 해당 항목이 들어 있었다. 메뉴 등록도 성공했다.
- **수정한 `SaveDatabase` (실제 x64dbg, 각 0.3~0.5 s)**

  | 경우 | 응답 |
  |---|---|
  | 빈 세션, 새 파일 | `No database file written` (자리표시 파일을 x64dbg가 지움) |
  | 없는 폴더 | 오류: `cannot create ... (Win32 error 3)` |
  | BP 있음, 새 파일 / 기존 파일 다시 저장 | `Database saved to` |
  | BP를 모두 지운 뒤 기존 파일 | `No database file written` (x64dbg가 기존 파일을 지움) |
  | `ida_export_annotations` 빈 세션 / BP 있음 | `not_written`, 항목 0 / `saved`, 항목 1 |
  | `analysis_collect` 빈 세션 | `COLLECTED`, DB 없음 |

### 이 검증에서 찾아 고친 결함

| 결함 | 원인 | 조치 |
|---|---|---|
| 주석이 없는 세션에서 `ida_export_annotations`가 `GUEST_OP_FAILED`(파일 없음). 플러그인 v1.9 경로에서는 수집도 partial | x64dbg는 세션에 라벨·주석·북마크·BP·함수가 없으면 DB 파일을 쓰지 않고 기존 파일을 지운다. `dbsave`는 항상 성공을 반환하고 파일을 만들지 못해도 로그만 남긴다. 플러그인은 명령을 큐에 넣고 "Database saved to"라고 답했다. | 플러그인(`src/mcp/dbsave.zig`): 대상에 파일이 없으면 0바이트 자리표시 파일을 만들고(못 만들면 오류), `dbsave`를 큐에 넣은 뒤 최대 10 s 파일을 본다. 지워짐 = 빈 세션, 바뀐 뒤 안정 = 저장(0바이트로 남으면 쓰기 실패), 그대로 = 오류("큐에 남아 나중에 실행될 수 있으니 다시 호출" 안내). 관찰 중 폴더가 사라진 경우는 빈 세션으로 보지 않는다. 게이트웨이는 그 표시를 믿고 빈 문서와 경고를 돌려준다. 이전 빌드면 5 s 기다린 뒤 "빈 세션과 저장 실패를 구별할 수 없다"는 경고를 붙인다. v1.9의 기본 경로 DB가 없으면 예전처럼 partial이다. |
| (중간 시도) BP 목록으로 빈 세션을 확인하는 방식이 실 VM에서 빈 세션을 "BP 있음"으로 오판 | x64dbg가 자동으로 거는 일회성 BP(엔트리·TLS)가 `ListBreakpoints`에 나오고, 플러그인 출력은 일회성 여부를 담지 않는다. 이런 BP는 DB에 저장되지 않는다. | 폐기하고 위의 파일 관찰 방식으로 바꿨다. |
| (리뷰) 동기 실행(`DbgCmdExecDirect`)으로 바꾸면 플러그인 연결 스레드가 GUI 스레드를 기다린다 | `DbSave`가 GUI에서 디버기 노트를 동기로 받는다(x64dbg 원본). | `dbsave`는 큐로 보내고 파일을 관찰한다. |
| x64dbg 강제 종료 직후 첫 호출이 `connect()`에서 60 s 넘게 대기(`test_d` 시간 초과) | 게스트가 닫힌 포트로 온 SYN에 응답하지 않아 연결이 끝나지 않았다. 연결 대기 한도가 호출 전체 한도와 같았다. | 연결 단계 한도 10 s(주소 후보가 나눠 씀). 넘으면 `BackendUnavailable`(`not_sent`)로 보고하고 바로 복구(health check, 재기동)로 넘긴다. 읽기 전용 재시도는 생략하고, 재시도는 남은 예산으로 줄인다. |
| E2E teardown이 사람 전용 `discard`를 시도해 실패하고, VM에 partial job이 남음 | 테스트 결함 | 수집과 복원을 한 번 더 시도하고, 안 되면 사람이 결정하라는 안내와 함께 실패한다. |
| 플러그인 `cmdExec`/`cmdExecDirect`가 C++ `bool` 반환값을 마스킹하지 않음 | 다른 브리지 함수와 달리 `& 0xFF`가 빠져 있었다. | 마스킹했다. |

다른 모델 리뷰: Sonnet 2회, Mythos 3회(3차는 x64dbg 원본 `database.cpp`·`cmd-user-database.cpp` 대조). 리뷰가 지적한 것 중 반영한 것은 다음과 같다.
- 연결 한도가 주소마다 누적되던 문제
- v1.9 수집의 fail-open 확대
- 폐기한 방식을 서술하던 문서
- "없음"과 "확인 불가"의 혼동
- 미전송 호출을 "결과 불명"으로 보고하던 문제
- 동기 실행의 GUI 대기
- 쓰기 실패를 빈 세션으로 오판하던 문제
- 0바이트로 잘린 파일
- 부동소수 비교에 기대던 연결 한도 판정

반영하지 않은 것과 그 이유는 다음과 같다.
- **잘린 JSON(디스크가 쓰는 도중 가득 참):** 플러그인은 "저장됨"으로 본다. export는 파싱 오류로 fail-closed이지만, 수집은 그 파일을 그대로 담는다. 좁은 경로라 기록만 했다.
- **v1.9 기본 경로에 이전 세션의 DB가 남아 있는 경우:** 원래 있던 문제다.
- **주소가 6개를 넘을 때 연결 한도가 소진된 뒤의 후보:** 시도하지 않는다. 엔드포인트는 보통 IP 리터럴이라 실무 영향이 작다.

### 아직 확인하지 않은 것

- Windows·macOS host
- SYSTEM 서비스 `vmtoolsd`가 죽은 경우(V9 나머지)
- vmrun 동시 호출(V7). 게이트웨이가 VM별 락으로 직렬화하므로 실제로 동시에 부르지 않는다.
- 실제로 다른 PC에서의 원격 접속(같은 host의 비루프백 주소로 대신 확인)
- 기본 한도(110 s)를 실제로 넘기는 호출(낮춘 한도로 같은 경로만 확인)
- x64dbg 명령 큐가 긴 명령으로 막혀 `SaveDatabase`의 10 s 관찰이 부족한 경우(그때는 오류로 보고되고 수집은 partial)
- 이전 플러그인 빌드와 게이트웨이의 실 VM 조합(단위 테스트만)

### 최종 실행 (클린 스냅샷 `MCP_CLEAN_V110E`)

- `pytest -m vm tests/vm`: **10건 모두 통과**(3분 32초). VM 작업마다 같은 .vmx의 `vmware-vmx` 프로세스가 정확히 1개였다.
- 위 `SaveDatabase` 표의 7가지 경우를 최종 빌드로 다시 돌려 같은 결과를 얻었다.
- `test_d`(x64dbg 강제 종료)는 69 s 걸렸다. 내역은 `analysis_start` 약 15 s, vmrun 종료 약 6 s, 연결 한도 10 s, 재기동 약 20 s다. 테스트 기본 한도 60 s로는 여유가 없어 이 테스트만 180 s로 올렸다.
- 단위 테스트 2,952개 통과(5개 건너뜀), `zig build test` 통과, ruff 통과.

## 정적 도구 연동과 원스톱 설치 검증 (2026-11-24 오후)

### 확인한 것

- **원스톱 설치(실 VM)**
  - `scripts/build-release.sh`로 만든 wheel을 격리된 폴더에 `uv tool install`로 설치했다. 이 wheel에는 플러그인과 정적 스크립트가 들어 있다.
  - 설치본의 `setup --snapshot MCP_CLEAN_V110F`가 248 s에 끝났다. 순서는 사전 점검 → 번들 플러그인 배포 → 프로비저닝(재부팅) → 스냅샷 → 재점검 → 등록 명령 출력이다.
  - 이 실행에서 결함 1건을 찾았다(아래 표).
- **정적 도구(E2E 샘플, rva 0x102C)**
  - 동기화 스크립트로 이름 변경, 주석, 재적용(멱등), 내보내기를 확인했다.
    - Ghidra 12.2: `pyghidraRun -H`. 일반 `analyzeHeadless`는 Python 스크립트를 실행하지 못한다.
    - radare2 6.2.6, rizin 0.9.1
    - Cutter 2.5.0(Qt6·Qt5)·2.4.1: 내장 Python
  - MCP 서버를 실제 MCP 클라이언트로 붙여 이름 변경, 주석, 디컴파일을 확인했다.
    - pyghidra-mcp 0.3.0
    - GhidraMCP 2.0(헤드리스)
    - r2mcp 1.9.0
  - CutterMCP 2.0은 기본 등록에서 뺐다.
    - 플러그인이 모든 인터페이스에 인증 없이 바인드한다.
    - 요청 값을 이스케이프 없이 rizin 명령에 넣는다.
    - 주석 기능이 404를 성공처럼 돌려준다.
- **정적·동적 왕복(실제 Claude Code)**
  - 게이트웨이(설치본)와 r2mcp를 나란히 등록했다.
  - radare2로 `Sleep` 루프 함수(정적 `0x14000102C`, baddr `0x140000000`)를 찾았다.
  - `static_rebase`가 런타임 주소 `0x7FF6…102C`를 돌려줬고, x64dbg BP가 첫 `run`에서 걸렸다.
  - radare2에 이름 `gw_main_loop`와 주석을 남긴 뒤 회수하고 복원했다. 전체 84 s.

### 이 검증에서 찾아 고친 결함

| 결함 | 원인 | 조치 |
|---|---|---|
| 실제 `setup`이 만든 클린 스냅샷에 `C:\mcp\tmp\ps-<id>.out`이 남음. 경고는 "손으로 지우라"고 했지만 스냅샷이 찍힌 뒤라 의미가 없었다. | 재부팅이 끊은 PowerShell 실행이 자기 출력 파일을 지우지 못했다. 그 시점에 VMware Tools가 내려가는 중이었다. | 프로비저닝이 스냅샷 직전에 게스트 임시 폴더의 `ps-<16 hex>.out/.ps1`만 지운다. 실패하면 경고만 남긴다. |
| (리뷰) Windows용 `mcp-config` 출력이 cmd·PowerShell 메타문자를 막지 못했다. 테스트는 POSIX host를 가정했다. | `subprocess.list2cmdline`은 셸 인용이 아니다. | PowerShell 기준 작은따옴표 인용으로 바꿨다. 테스트는 host 셸을 고정한다. |
| (리뷰) 정적 서버 설정의 `args`·`command`·`url`·`env` 값에 넣은 비밀값이 등록 명령으로 출력될 수 있었다. | 비밀 검사가 `env` 이름에만 있었다. | 비밀처럼 보이는 옵션·`KEY=VALUE`·URL 자격 증명·헤더를 설정 단계에서 거부한다. 제어·양방향 문자도 거부한다. |

다른 모델 리뷰는 기능별로 받았다(정적 코어 Sonnet, 패키징 Sonnet·Fable·Mythos, 통합 Sonnet). 반영하지 않은 지적과 그 이유는 각 커밋 메시지에 있다.

### 아직 확인하지 않은 것

- Windows·macOS host. Windows용 PowerShell 출력은 단위 테스트만 했고, pwsh 왕복 테스트는 이 host에 pwsh가 없어 건너뛰었다.
- Ghidra GUI와 GhidraMCP GUI 모드, Ghidra 11.x
- 태그 릴리스 워크플로의 실제 실행
- ida-multi-mcp의 툴 이름은 문서 기준이다. 이번에 다시 실행해 보지는 않았다.

## 사용성 개선 라운드 (2026-11-26)

이번 라운드에 들어간 기능: `setup`의 대화식 질문과 암호 파일, `demo`, MCP 프롬프트 5개, `analysis_report`·`jobs report`, `mcp-config` 옵션(`--permissions` strict/lab, `--apply`, `--client json`, `--tool`, `--set`), `snapshot refresh/prune`, 게이트웨이 하나로 VM 여러 대. 기능마다 TDD로 만들고 다른 모델 리뷰(Sonnet·Fable·Mythos)를 반영했다. Mythos는 여러 VM 라우팅에서 다른 프로필의 job을 건드리는 경로 4개(같은 `.vmx`를 쓰는 다른 프로필 경유 `debugger_restart`·변경 호출, job_id 없는 `analysis_finish`의 복원, `analysis_report`의 대상)를 찾았고, 모두 거부하도록 고쳤다. 최종 코드의 단위 테스트는 3947건 통과(6 skip)다.

실 VM에서 확인한 것(대상: 스파이크 VM, 클린 스냅샷 `MCP_CLEAN_V110F`, `build-release.sh`로 만든 wheel의 격리 설치본):

- **`demo --arch both`**: 통과, 92 s.
  - x64: `analysis_start` 27.4 s(시스템 BP에서 멈춤) → `kernel32.Sleep` BP → `run` 2회 만에 Sleep에서 멈춤 → `GetCallStack` 첫 줄 `kernel32.Sleep` → 회수 6.0 s(파일 1개) → 복원 13.2 s. 합계 47.2 s.
  - x32: 같은 순서로 44.5 s.
  - 끝난 뒤 스파이크 VM의 `vmware-vmx`는 1개였다.
- **`jobs report`**: demo의 job으로 Markdown 보고서를 만들었다. 플래그와 상태 사유는 `untrusted_guest_output` 블록 안에 있었다.
- **실제 Claude Code(`claude -p`, 설치본 stdio)**
  - 툴 105개(게이트웨이 22 + 플러그인 83)와 슬래시 명령 5개(`mcp__x64dbg-vm__analyze-sample`, `trace-api`, `find-oep`, `static-dynamic`, `report`)가 보였다.
  - `/mcp__x64dbg-vm__report <job>`을 실행하자 `analysis_report(format="markdown")`와 `jobs_show`를 불러 보고서를 썼다.
- **MCP Python SDK 클라이언트**: `prompts/list`가 5개를, `prompts/get analyze-sample`이 단계별 계획을 돌려줬다.
- **`snapshot prune --keep 1`**(미리 보기만): 보호 스냅샷 6개와 현재 클린 스냅샷을 "삭제 안 함"으로 표시했고, 지운 것은 없다(스냅샷 7개 그대로).
- **실 VM 테스트 스위트**: 10건 통과, 3분 21초.
- **리뷰 반영 후 최종 코드로 다시**: wheel을 새로 빌드해 `demo --arch both` 통과(x64 47.9 s, x32 39.0 s), 실 VM 스위트 10건 통과(3분 30초). 끝난 뒤 스파이크 VM의 `vmware-vmx`는 1개였다.

실 VM에서 확인하지 않은 것:

- `snapshot refresh`, `snapshot prune --yes`(스냅샷을 만들거나 지우는 일이라 사용자 결정 없이 하지 않았다)
- 게이트웨이 하나로 VM 두 대(두 번째 VM이 아직 없다)
- `mcp-config --apply`(이 host의 Claude 설정을 바꾸는 일이라 실행하지 않았다)와 `--permissions` 규칙이 Claude Code에서 실제로 적용되는지
- 프롬프트 4개를 끝까지 실행한 결과

## `setup` 대화식 첫 실행 (2026-11-27)

- **방법**: 설정이 없는 상태(`XDG_CONFIG_HOME`을 빈 임시 폴더로)에서 설치본의 `setup --skip-provision --clean-snapshot MCP_CLEAN_V110F`를 실제 pty(제어 터미널)로 돌렸다. 답은 스크립트가 넣었다. VM은 목록에서 스파이크 VM 줄을 골랐고, 계정과 암호는 lab env 파일에서 읽어 pty에만 썼다. 암호 환경 변수는 지운 상태였다. 프로비저닝은 2026-11-24 `setup` 실행에서 확인한 경로라 뺐다(새 스냅샷을 만들지 않으려고).
- **질문 순서**: VM 목록(실행 중인 VM과 VMware 라이브러리의 VM) → 게스트 계정 → 암호(getpass, 에코 없음) → 게스트에서 x64dbg 찾기(2개 발견, 기존 설정과 같은 폴더를 골랐다) → 암호 파일 저장. 43 s에 끝났고 종료 코드는 0이다.
- **비밀 처리**: 원본 터미널 출력에 암호가 0번 나왔다. 설정 파일(0600)에는 암호가 없고, 암호 파일(0600)에는 계정과 암호 두 줄이 있다. job 폴더의 다른 파일에도 암호가 없다. 설정을 먼저 쓰고, 사전 점검에서 게스트가 암호를 받아들인 뒤 암호 파일을 쓰고 `gateway.env_file`을 추가했다.
- **그 설정으로 `demo --arch x64`**: 암호 환경 변수 없이 통과했다. 게이트웨이가 `env_file`의 암호로 게스트에 로그온했다.
- **찾아서 고친 것**: `setup`이 `env_file`을 추가한 뒤에도 등록 안내가 "암호를 환경 변수로 export한 곳에서 Claude Code를 시작하라"고 했다. 안내를 `env_file`을 추가하기 전에 읽은 설정으로 만들었기 때문이다. 이제 방금 쓴 암호 파일을 가리킨다.
- **눈여겨볼 것**
  - 게스트 x64dbg 검색의 기본 선택([1])은 먼저 찾은 폴더다. 이 VM에서는 쓰지 않는 옛 폴더가 [1]이었다. 폴더가 여럿이면 번호를 직접 골라야 한다.
  - 이 설정(`guest_host` 자동)으로 `demo`를 8번 돌렸다. 처음 2번만 VM 준비가 느렸다(복원 뒤 `analysis_finish` 115.7 s, 다음 `analysis_start`의 `PREPARING_VM` 292 s). 나머지 6번은 평소대로였다(`analysis_start` 26~36 s, `analysis_finish` 11~27 s). `guest_host`를 고정한 설정은 1번 돌렸고 정상이었다(28.6 s, 14.1 s). vmrun 호출 시간을 기록한 3번에서 `getGuestIPAddress -wait`는 최대 0.54 s였다. 복원하고 켠 직후 IP 조회를 직접 잰 4번도 모두 9 s 안에 끝났다. 처음 2번이 느렸던 원인은 찾지 못했다. IP 자동 조회 때문이라는 근거는 이번 측정에서 나오지 않았다.


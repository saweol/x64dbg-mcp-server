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
| V4 | 게스트 PowerShell 출력 회수 | `-Command`에 큰따옴표가 들어간 스크립트는 vmrun이 인자를 한 줄로 이어 붙이면서 따옴표가 사라져 실패했다(exit 1). `-EncodedCommand`(UTF-16LE base64)와 결과 파일 복사는 동작했다. | 복잡한 스크립트는 `-EncodedCommand`나 `-File`로 실행한다(ps.py). |
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

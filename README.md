# x64dbg-mcp-server — VMware 분석 루프 포크

> 이 저장소는 [duty1g/x64dbg-mcp-server](https://github.com/duty1g/x64dbg-mcp-server)(MIT)의 **포크**입니다. 원작자의 공식 배포판이 아닙니다.
> 원본의 x64dbg MCP 플러그인을 바탕으로, **host에서 VMware 분석 VM과 디버거를 함께 다루는 MCP 게이트웨이**를 더했습니다. 정적 분석 도구(IDA, Ghidra, radare2, Cutter)와 함께 쓸 수 있습니다.
> 포크 기준점은 upstream `main @ 31c05bc`(플러그인 v1.9)입니다. 라이선스는 [아래](#라이선스)에 정리했습니다.

**English summary.** A fork of duty1g/x64dbg-mcp-server (MIT). It adds `x64dbg-vm-gateway`, a host-side MCP server that reverts a VMware analysis VM to a clean snapshot, uploads the sample, keeps x64dbg/x32dbg alive in the guest, relays the plugin's 83 debugger tools under their original names and collects the artifacts back to the host. A static-analysis tool of your choice (IDA, Ghidra, radare2, Cutter) runs next to it through its own MCP server; the gateway converts addresses between the two sides and exchanges names and comments. One wheel carries the gateway, a prebuilt plugin and the static sync scripts; `x64dbg-vm-gateway setup` prepares the guest and takes the clean snapshot. English references: [`host/README.md`](host/README.md) (gateway), [`static/README.md`](static/README.md) (static tools) and [`docs/PLUGIN.md`](docs/PLUGIN.md) (plugin). Licensed under MIT like the original; see [License](#라이선스).

---

## 한눈에 보기

AI 클라이언트(Claude Code 등)에는 MCP 서버 두 개를 나란히 등록합니다.

- **동적 분석:** 이 저장소의 게이트웨이
- **정적 분석:** 고른 정적 분석 도구의 MCP 서버

```
                         ┌─ x64dbg-vm-gateway (host, Python) ── 동적 분석
Claude Code ──MCP────────┤    ├─ vmrun ──────────► VMware: 전원, 스냅샷, 게스트 파일·프로세스
(원격 PC는 HTTPS)        │    └─ HTTP + Bearer ──► 게스트 x64dbg :9094 / x32dbg :9095 (플러그인 v1.10)
                         │
                         └─ 정적 분석 도구의 MCP 서버 (host) ── 정적 분석
                              IDA: ida-multi-mcp │ Ghidra: pyghidra-mcp │ radare2: r2mcp
```

두 쪽은 **모듈 + RVA**로 주소를 맞춥니다. 디버거의 런타임 주소는 ASLR로 실행할 때마다 바뀌지만, 모듈 기준 오프셋(RVA)은 같기 때문입니다. 게이트웨이의 `static_rebase`가 이 주소 변환을 하고, `static_export_annotations` / `static_import_annotations`가 이름과 주석을 주고받습니다.

분석 한 바퀴는 다음과 같이 돕니다.

```
analysis_start ──► 분석 (x64dbg 툴 83개 + 정적 도구) ──► analysis_collect ──► analysis_finish
 클린 스냅샷 복원      SetBreakpoint, run, DumpMemory ...      결과물을 host로 회수    클린 스냅샷으로 복원
 샘플 업로드·해시 확인 decompile, rename, static_rebase ...    (덤프, x64dbg DB, zip)
 디버거에 로드(정지 상태)
```

게이트웨이가 AI에게 보여 주는 툴은 게이트웨이 툴 21개와 플러그인 툴 83개, 합계 104개입니다.

## 왜 만들었나

원본 플러그인은 x64dbg 안에서 MCP 서버를 띄웁니다. 설치가 간단하고 디버거를 직접 다루기에 좋습니다. 그런데 악성코드를 VM에서 반복 분석하는 데 쓰려니 불편한 점이 넷 있었습니다.

1. **디버거가 죽으면 연결도 끊깁니다.** 샘플이 디버거를 죽이거나 x64dbg가 크래시하면 MCP 엔드포인트도 함께 사라집니다. AI 세션은 그 사실을 모른 채 실패만 반복합니다.
2. **VM 제어는 사람 몫이었습니다.** 분석 전 클린 스냅샷 복원, 전원 관리를 VMware 화면에서 손으로 했습니다.
3. **파일을 넣고 빼는 것도 손으로 했습니다.** 샘플을 VM에 넣고 덤프나 DB를 꺼내려면 공유 폴더를 켜야 했고, 그러면 격리가 깨집니다.
4. **클린 상태로 돌아가는 것을 사람이 챙겨야 했습니다.** 결과물을 챙기기 전에 복원하면 분석이 날아가고, 복원을 잊으면 다음 분석이 오염됩니다.

그래서 **"MCP가 로드된 클린 VM → 샘플 전송 → 지시에 따른 분석 → 결과물 회수 → 복원"** 루프를 AI가 처음부터 끝까지 돌릴 수 있게 하는 것을 목표로 삼았습니다. 사람은 무엇을 분석할지 지시하고, 되돌릴 수 없는 결정만 내립니다.

실제 분석에서는 정적 분석으로 함수를 찾고, 동적 분석으로 값을 확인하고, 그 결과를 다시 정적 분석 DB에 남기는 왕복이 잦습니다. 그래서 이미 쓰고 있는 정적 분석 도구를 그대로 붙여 쓸 수 있게 했습니다.

## 설계 철학

| 원칙 | 의미 |
|---|---|
| **단일 제어자** | VM과 분석 작업(job) 상태를 바꾸는 프로세스는 게이트웨이 하나뿐입니다. 게이트웨이의 수명은 VM·디버거와 무관하므로, x64dbg가 죽거나 VM을 복원해도 AI의 MCP 연결은 그대로입니다. 죽은 디버거는 게이트웨이가 다시 띄웁니다. |
| **원본을 감싸되 바꾸지 않는다** | 플러그인 툴은 원래 이름(`SetBreakpoint`, `run`, `DumpMemory` …) 그대로 중계합니다. 원본 사용법과 `SKILL.md`가 그대로 통하고, 플러그인은 게이트웨이 없이 단독으로도 예전처럼 쓸 수 있습니다. |
| **도구는 고르게 한다** | 정적 분석은 각 도구의 MCP 서버에 맡깁니다. 게이트웨이는 도구 중립적인 주소 변환과 주석 교환만 맡으므로, 정적 도구를 바꿔도 동적 쪽은 그대로입니다. |
| **fail-closed** | 결과물 회수가 확인되기 전에는 복원하지 않습니다. AI가 `force` 같은 플래그로 이 규칙을 넘을 수 없습니다. 작업을 버리는 결정은 사람만 CLI(`discard`)로 내립니다. 클린·보호 스냅샷은 지울 수 없고, VM이 격리되어 있지 않으면(공유 폴더가 켜져 있거나, 네트워크가 host-only가 아닌 bridged·NAT 등) 분석을 시작하지 않습니다. |
| **상태 변경은 자동 재시도하지 않는다** | `run`, step, 브레이크포인트처럼 상태를 바꾸는 호출은 두 번 실행되면 분석이 틀어집니다. 그래서 자동 재시도는 읽기 호출에만 합니다. |
| **세상이 바뀌면 알린다(epoch)** | 디버거가 재기동되거나 VM이 복원되면 epoch를 올립니다. 그다음 상태 변경 호출은 `BACKEND_RESTARTED`로 막혀서, AI가 사라진 주소나 BP를 믿고 계속 진행하지 못합니다. AI가 `session_status`로 상황을 확인하면 다시 진행할 수 있습니다. |
| **게스트는 적대적이다** | 게스트에서 온 문자열·파일·zip·JSON은 모두 공격자 입력으로 다룹니다. 게스트 출력은 `<untrusted_guest_output>`으로 감싸 프롬프트 인젝션을 막고, zip은 안전하게 풀고, 회수한 파일은 host에서 실행하지 않습니다. |
| **비밀값은 설정 파일에 두지 않는다** | 설정 파일에는 환경 변수 **이름**만 적고, 값은 권한 0600인 env 파일에 둡니다. 플러그인 토큰은 게스트 설정에서 읽어 옵니다. |
| **설치는 짧게** | 게이트웨이 wheel 하나에 빌드된 플러그인과 정적 동기화 스크립트를 넣었습니다. 게스트 준비부터 클린 스냅샷까지는 `setup` 한 번으로 끝납니다. |
| **검증한 것만 "된다"고 쓴다** | 실제 VM과 실제 도구에서 확인한 것과 코드상 지원만 하는 것을 문서에서 구분합니다([검증 현황](#검증-현황)). |

## 원본 대비 달라진 점

| 영역 | 원본 (v1.9, `31c05bc`) | 이 포크 |
|---|---|---|
| x64dbg 플러그인 `src/` | v1.9, 툴 80개 | **v1.10, 툴 83개.** 자세한 내용은 [`docs/PLUGIN.md`](docs/PLUGIN.md)에 있습니다.<br>• 잘못된 bind 주소면 `0.0.0.0`으로 되돌리지 않고 시작을 거부합니다.<br>• 외부 바인드에는 `AllowExternal`·`AllowedClients`와 32자 이상 토큰이 필요합니다.<br>• 요청 타임아웃, 동시 연결 상한, 포트 독점 바인드를 두었습니다.<br>• 인증 실패 잠금(429)과 SSE 끄기 옵션을 넣었습니다.<br>• 상태 변경 툴을 직렬화했습니다.<br>• `GetServerInfo`·`SetArtifactDir`·`ProbeFile`을 추가했습니다.<br>• `GetDebugState`가 정지 상태를 `PAUSED`로 보고합니다.<br>• `SaveDatabase`가 "저장됨 / 빈 세션이라 파일 없음 / 실패"를 구별합니다. |
| host 게이트웨이 `host/` | 없음 | 새로 작성(Python). VM 제어, 파일 전송, 디버거 감시·재기동, job 상태기계, 원격 HTTPS, 감사 로그, 정적 도구 연동, `setup` |
| 게스트 준비 `guest/` | 없음 | `provision.ps1`: 자동 로그온, 디버거 자동 실행 예약 작업, 플러그인 설정, 작업 폴더 |
| 정적 도구 연동 `static/` | 없음 | IDA·Ghidra·radare2(rizin, Cutter) 동기화 스크립트와 공용 코어 |
| 배포 `scripts/`, `.github/` | 없음 | 플러그인을 넣은 wheel과 플러그인 zip을 만드는 `build-release.sh`, 태그 릴리스 워크플로 |
| 문서 | `README.md` | 원본 README는 [`docs/PLUGIN.md`](docs/PLUGIN.md)로 옮겼습니다. 설계·실측·빠른 시작 문서를 더했습니다. |

## 필요한 것

| # | 구성 요소 | 어디에 | 내용 | 누가 설치하나 |
|---|---|---|---|---|
| 1 | **정적 분석 도구** | host | IDA Pro, Ghidra, radare2, Cutter 중 하나 이상과 그 도구의 MCP 서버 | 사용자 ([4단계](#4단계-정적-분석-도구-준비)) |
| 2 | **동적 분석 환경** | host의 VMware | VMware Workstation 17(`vmrun` 포함)과 Windows 10/11 게스트 VM | 사용자 ([2단계](#2단계-동적-분석-vm-준비)) |
| 3 | **게스트의 x64dbg/x32dbg와 MCP 플러그인** | VM 안 | x64dbg(`release\x64\x64dbg.exe`, `release\x32\x32dbg.exe`)와 이 저장소의 플러그인 v1.10 | x64dbg는 사용자가 압축만 풉니다. 플러그인은 `setup`이 자동으로 배포합니다. |
| 4 | **VMware 클린 스냅샷** | VMware | 디버거와 플러그인이 떠 있는 상태의 메모리 포함 스냅샷 | `setup`이 자동으로 찍습니다. |
| + | **게이트웨이** | host | `x64dbg-vm-gateway`. wheel에 플러그인과 정적 동기화 스크립트가 들어 있습니다. | 사용자 ([1단계](#1단계-게이트웨이-설치), 명령 한 줄) |
| + | **MCP 클라이언트** | host | Claude Code 등 | 사용자 ([5단계](#5단계-mcp-클라이언트에-등록)) |

host는 Linux에서 실검증했습니다. Windows와 macOS(Intel)는 코드상 지원하지만 실검증 전입니다.

## 설치 가이드

먼저 전체 흐름입니다. 각 단계의 설명은 아래에 이어집니다.

```bash
uv tool install ./x64dbg_vm_gateway-<버전>-py3-none-any.whl     # 1. 게이트웨이(플러그인 포함)
#                                                                 2. VMware에 Windows VM 준비(수동)
x64dbg-vm-gateway setup --vmx /vms/analysis/analysis.vmx \
    --guest-user analyst --x64dbg-root 'C:\x64dbg\release'      # 3. 게스트 준비 + 클린 스냅샷
x64dbg-vm-gateway mcp-config                                    # 4·5. 정적 도구와 MCP 등록 명령 출력
```

### 1단계: 게이트웨이 설치

[uv](https://docs.astral.sh/uv/)가 필요합니다. uv는 Python 3.11 이상을 알아서 준비합니다.

**릴리스 wheel로 설치(권장).** 릴리스에서 `x64dbg_vm_gateway-<버전>-py3-none-any.whl`을 받아 설치합니다. 빌드된 플러그인(x64·x32)과 정적 동기화 스크립트가 들어 있어 Zig가 필요 없습니다.

```bash
uv tool install ./x64dbg_vm_gateway-<버전>-py3-none-any.whl
x64dbg-vm-gateway --help
```

**소스에서 빌드.** [Zig 0.14.0](https://ziglang.org/download/#release-0.14.0)이 필요합니다. 스크립트가 플러그인을 빌드해 wheel에 넣고, `release/`에 다음을 만듭니다.

- wheel
- 플러그인 zip(`x64dbg-mcp-plugin-<버전>.zip`)
- `SHA256SUMS`

```bash
scripts/build-release.sh
uv tool install release/x64dbg_vm_gateway-*.whl
```

### 2단계: 동적 분석 VM 준비

VMware Workstation에서 Windows 10/11 VM을 하나 만들고 아래를 맞춥니다. 이 단계만 사람 손이 필요합니다.

| 항목 | 설정 |
|---|---|
| VMware Tools | 설치합니다. 게이트웨이가 파일과 프로세스를 다루는 통로입니다. |
| 계정 | **암호가 있는** 로컬 관리자 계정 하나. 자동 로그온과 게스트 작업에 씁니다. |
| x64dbg | [x64dbg 릴리스](https://x64dbg.com/)를 압축 해제합니다(예: `C:\x64dbg\release\x64`, `C:\x64dbg\release\x32`). 한 번 실행해 둘 필요는 없습니다. |
| 네트워크 | host-only(또는 연결 없음) |
| 공유 폴더 | 끕니다. |

마지막 두 항목은 격리 점검에 걸리는 조건입니다. 맞지 않으면 분석 시작이 거부됩니다. VM을 켜 둔 채로 다음 단계로 갑니다.

### 3단계: `setup`으로 게스트 준비와 클린 스냅샷

게스트 계정 암호는 설정 파일에 넣지 않습니다. 셸 환경 변수로 넘기거나, 0600 권한의 env 파일에 둡니다.

```bash
read -rs X64DBG_GW_GUEST_PW && export X64DBG_GW_GUEST_PW      # 화면에 표시되지 않습니다

x64dbg-vm-gateway setup --dry-run --vmx /vms/analysis/analysis.vmx \
    --guest-user analyst --x64dbg-root 'C:\x64dbg\release'      # 무엇을 할지 먼저 확인
x64dbg-vm-gateway setup --vmx /vms/analysis/analysis.vmx \
    --guest-user analyst --x64dbg-root 'C:\x64dbg\release' --snapshot MCP_CLEAN
```

`setup`은 다음 순서로 진행합니다. 고칠 수 없는 문제가 있으면 게스트를 바꾸기 전에 멈추고, 무엇을 고칠지 알려 줍니다.

1. 설정 파일이 없으면 만듭니다(`init`과 같은 내용).
2. `doctor`로 vmrun, VM, VMware Tools, 계정, 격리를 점검합니다.
3. wheel에 들어 있는 플러그인을 게스트에 배포합니다. 기존 플러그인은 `plugins_backup\`에 백업합니다.
4. 게스트를 프로비저닝합니다.
   - 자동 로그온을 설정합니다.
   - 로그온 시 디버거를 최고 권한으로 띄우는 예약 작업을 등록합니다.
   - 플러그인 설정과 토큰을 씁니다.
   - 작업 폴더를 만듭니다.
5. 재부팅한 뒤 두 플러그인이 응답하면 메모리 포함 클린 스냅샷을 찍습니다.
6. `doctor`로 다시 점검하고, MCP 클라이언트 등록 명령을 출력합니다.

실측으로는 프로비저닝부터 스냅샷까지 약 3분이 걸렸습니다. 이후 매 분석은 이 스냅샷에서 시작해 이 스냅샷으로 돌아갑니다. 단계별로 따로 하려면 `init`, `install-plugin`, `provision`, `doctor`를 직접 실행해도 됩니다. 절차는 [`docs/QUICKSTART_KO.md`](docs/QUICKSTART_KO.md)에 있습니다.

### 4단계: 정적 분석 도구 준비

쓸 도구를 설치하고, 게이트웨이 설정(`~/.config/x64dbg-vm-gateway/config.toml`)에 적습니다. 여러 개를 적으면 첫 번째가 기본 도구입니다.

```toml
[static]
tools = ["ghidra"]           # "ida", "ghidra", "radare2", "cutter" 중에서
```

| 도구 | 설치 | MCP 서버 | 동기화 스크립트 | 검증한 버전 |
|---|---|---|---|---|
| IDA Pro | 상용 설치본 | ida-multi-mcp(별도 설치): `python3 -m ida_multi_mcp` | `static/ida/x64dbg_sync.py` | IDA 9.2 |
| Ghidra | [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) 압축 해제 + JDK(Ghidra 12.2는 JDK 25) | [pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp)(헤드리스, 기본). 대안: [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) | `static/ghidra/x64dbg_sync_ghidra.py` (`pyghidraRun -H`로 실행) | Ghidra 12.2, pyghidra-mcp 0.3.0, GhidraMCP 2.0 |
| radare2 | [radare2](https://github.com/radareorg/radare2/releases) | [r2mcp](https://github.com/radareorg/radare2-mcp): `r2pm -ci r2mcp`, 등록 명령 `r2pm -r r2mcp` | `static/radare2/x64dbg_sync_r2.py` (r2pipe) | radare2 6.2.6, r2mcp 1.9.0 |
| Cutter | [Cutter](https://cutter.re/) | 기본 등록 없음(아래 주의 참고) | `static/radare2/x64dbg_sync_r2.py` (Cutter의 Python에서 실행) | Cutter 2.5.0, 2.4.1 |

그다음 두 명령으로 마무리합니다.

```bash
x64dbg-vm-gateway mcp-config            # 게이트웨이와 설정한 정적 도구의 MCP 등록 명령을 출력
x64dbg-vm-gateway static-scripts --dest ~/x64dbg-static   # 동기화 스크립트를 원하는 폴더로 복사
```

`mcp-config`는 각 도구의 등록 명령을 출력합니다. 사용자마다 다른 값(Ghidra 설치 폴더, 프로젝트 폴더, 분석할 바이너리 등)은 `<...>`로 표시되니 채워 넣습니다. Windows host에서는 PowerShell에 붙여 넣을 수 있게 인용한 명령이 나옵니다. 매번 채우기 번거로우면 설정 파일에 고정해 둘 수 있습니다. 토큰·암호 같은 비밀값은 이 설정에 넣을 수 없습니다(거부됨). 비밀값은 그 MCP 서버 자체의 설정이나 환경에 둡니다.

```toml
[static.servers.ghidra]
command = ["/opt/pyghidra-venv/bin/pyghidra-mcp", "--transport", "stdio",
           "--project-path", "/work/ghidra-projects", "--project-name", "lab",
           "--wait-for-analysis", "/work/samples/a.exe"]
env = { GHIDRA_INSTALL_DIR = "/opt/ghidra_12.2_PUBLIC", JAVA_HOME = "/opt/jdk-25" }
```

도구별로 알아 둘 점은 다음과 같습니다.

- **Ghidra:**
  - Python 동기화 스크립트는 일반 `analyzeHeadless`로는 돌지 않습니다. `pyghidraRun -H`로 실행합니다.
  - pyghidra-mcp는 `--wait-for-analysis`를 주면 분석이 끝난 뒤에야 첫 응답을 합니다. 큰 바이너리는 클라이언트의 시작 대기 시간을 넉넉히 둡니다.
- **radare2:** r2mcp에는 프로젝트 저장 툴이 없습니다. 서버가 끝나면 이름과 주석도 사라집니다. 남기려면 동기화 스크립트로 프로젝트에 적용합니다.
- **Cutter:** 공개된 CutterMCP 2.0은 그대로 쓰면 **위험합니다.**
  - Cutter 플러그인이 모든 인터페이스의 8000번 포트에 인증 없이 바인드합니다.
  - 요청 값을 이스케이프하지 않고 rizin 명령에 넣습니다. 셸 명령(`!`)까지 실행될 수 있습니다.
  - 주석 기능도 고장 나 있습니다.

  그래서 기본 등록을 두지 않았습니다. Cutter에서는 동기화 스크립트를 쓰고, AI가 정적 분석을 하게 하려면 같은 바이너리에 radare2의 r2mcp를 붙이기를 권합니다. Cutter 2.5.0 Qt6 AppImage는 Python 플러그인을 읽지 못합니다(rizinorg/cutter#3659). 스크립트는 Cutter의 Python 콘솔에서 실행합니다.

각 스크립트의 사용법은 [`static/README.md`](static/README.md)에 있습니다.

### 5단계: MCP 클라이언트에 등록

`setup`과 `mcp-config`가 출력한 명령을 그대로 실행합니다. Claude Code 기준 예시는 다음과 같습니다.

```bash
claude mcp add x64dbg-vm -- x64dbg-vm-gateway serve           # 동적 분석(게이트웨이)
claude mcp add radare2 -- r2pm -r r2mcp                        # 정적 분석(예: radare2)
claude mcp list
```

게이트웨이 설정 파일이 기본 위치가 아니면 출력에 `-e X64DBG_VM_GATEWAY_CONFIG=<경로>`가 붙습니다. 비밀값을 `claude mcp add -e`로 넘기면 Claude 설정 파일에 기록되니 피합니다. 게스트 암호는 env 파일이나 셸 환경에 둡니다.

## 사용법

### 동적 분석만

> `~/samples/a.exe` 분석 시작해. kernel32.CreateFileW에 BP 걸고 실행해서 인자 확인하고, 스택 덤프 저장한 다음 artifact 회수하고 복원해.

AI는 대략 다음 순서로 툴을 호출합니다.

1. `analysis_start`: 격리를 점검하고 클린 스냅샷으로 복원합니다. 샘플을 해시 확인과 함께 올리고, 아키텍처에 맞는 디버거에 정지 상태로 로드합니다. 샘플을 자동으로 실행하지는 않습니다.
2. `SetBreakpoint` → `run` → `GetArguments` → `DumpMemory`: 상대 경로로 지정한 덤프는 job의 게스트 `out` 폴더에 저장됩니다.
3. `analysis_collect`: x64dbg DB를 저장하고 `out`을 묶어 host로 가져온 뒤, 안전하게 풀고 manifest를 돌려줍니다.
4. `analysis_finish`: 클린 스냅샷으로 복원합니다. 회수 전에는 거부됩니다.

회수한 결과물은 `~/mcp-lab/jobs/<job_id>/artifacts/`(`manifest.json`, `files/`, `raw/out.zip`)에 쌓입니다.

### 정적 분석과 함께

> Ghidra에서 `a.exe`의 설정 복호화 함수를 찾아. 그 함수가 끝나는 지점에 x64dbg BP를 걸고 실행해서 복호화된 문자열을 읽고, 알아낸 이름과 값을 Ghidra 주석으로 남겨.

1. 정적 MCP(예: pyghidra-mcp)의 `decompile_function`, 심볼 검색으로 함수를 찾습니다. 주소는 정적 이미지 베이스 기준입니다(예: `0x140001234`).
2. `analysis_start`로 동적 분석을 시작합니다.
3. `static_rebase(direction="static_to_runtime", address="0x140001234")`로 런타임 주소를 얻습니다.
4. `SetBreakpoint` → `run` → `ReadMemory` / `GetArguments`로 값을 읽습니다.
5. 정적 MCP의 `rename_function` / `set_comment`로 결과를 남깁니다. 런타임에서 찾은 주소는 `static_rebase(direction="runtime_to_static")`로 바꿔 씁니다.
6. x64dbg에 단 라벨·주석·BP를 한꺼번에 넘기려면 `static_export_annotations`로 문서를 만들고, 정적 도구의 동기화 스크립트로 적용합니다. 반대 방향은 정적 도구에서 내보낸 항목을 `static_import_annotations`로 x64dbg에 적용합니다.
7. `analysis_collect` → `analysis_finish`로 회수하고 복원합니다.

### 알아 두면 좋은 동작

- **오래 걸리는 작업**(`analysis_start`, 복원, 전원)은 정해진 시간이 지나면 `{"state": "in_progress"}`를 돌려주고 백그라운드에서 계속합니다. 진행 상황은 `session_status`로 확인합니다.
- **디버거가 죽으면** 게이트웨이가 다시 띄웁니다. 다음 상태 변경 호출은 `BACKEND_RESTARTED`를 받고, `session_status`로 확인한 뒤 이어서 진행합니다. `analysis_start(reload_on_restart=true)`를 주면 샘플도 다시 로드합니다.
- **목록에 없는 플러그인 툴**은 `debugger_call`로 부를 수 있습니다.
- **주석이 하나도 없는 세션**에서는 x64dbg가 DB 파일을 쓰지 않습니다. 그래서 `static_export_annotations`는 빈 문서와 그 사실을 알리는 경고를 돌려줍니다.

### 게이트웨이 툴 (21개)

| 등급 | 툴 |
|---|---|
| 관찰(읽기 전용) | `session_status`, `gateway_doctor`, `vm_snapshots_list`, `vm_screenshot`, `static_rebase`, `jobs_list`, `jobs_show` |
| 게스트 변경 | `file_upload`, `debugger_select`, `debugger_restart`, `debugger_call`, `analysis_start`, `analysis_collect`, `static_export_annotations`, `static_import_annotations` |
| host·VM 파괴적 | `vm_snapshot_take`, `vm_snapshot_revert`, `vm_snapshot_delete`, `vm_power`, `file_download`, `analysis_finish` |

마지막 등급은 MCP 클라이언트의 권한 설정에서 **사람의 승인을 받도록** 두기를 권합니다. 오류는 `{code, message, stage, retryable, hint, next_tool, details}` 형태로 돌아오므로 AI가 다음 행동을 정할 수 있습니다. 예전 이름 `ida_rebase`, `ida_export_annotations`, `ida_import_annotations`도 당분간 호출할 수 있습니다(목록에는 나오지 않음).

### CLI

| 명령 | 용도 |
|---|---|
| `setup` | 설정 → 점검 → 플러그인 배포 → 프로비저닝 → 클린 스냅샷 → 등록 명령 출력 (`--dry-run`, `--skip-plugin`, `--skip-provision`) |
| `mcp-config` | 게이트웨이와 설정한 정적 도구의 MCP 등록 명령 출력 |
| `static-scripts [--dest DIR]` | 정적 동기화 스크립트의 위치 출력 또는 복사 |
| `serve [--transport stdio\|http]` | MCP 서버 (Claude Code는 stdio) |
| `doctor`, `status` | 환경 점검(정적 도구 포함), 현재 상태 |
| `init` | 설정 파일 작성 |
| `install-plugin`, `provision` | 플러그인 배포(기본은 wheel에 든 빌드), 게스트 준비 |
| `jobs [list \| show JOB_ID]` | job 조회 (게이트웨이가 돌고 있어도 읽기 가능) |
| `discard JOB_ID` | **사람 전용.** 회수 없이 버려도 되는 job으로 표시 |

### 다른 PC에서 접속

`serve --transport http`로 같은 툴을 `https://<host>:9100/mcp`에 엽니다.

- 비루프백 주소에 바인드하려면 TLS가 필요합니다.
- 토큰은 범위별로 따로 둡니다. `read`는 관찰만, `analyze`는 게스트 변경과 디버거 조작, `admin`은 전체입니다.
- 클라이언트 허용 목록과 요청 속도 제한이 있고, 모든 호출은 `<jobs_root>/_audit/`에 감사 로그로 남습니다.

설정은 [`docs/QUICKSTART_KO.md`](docs/QUICKSTART_KO.md) §8과 [`host/README.md`](host/README.md#remote-access-m3)에 있습니다.

## 안전 수칙

- **샘플은 VM 안에서만 실행합니다.** host-only 네트워크를 쓰고 공유 폴더는 끕니다. 설정 기본값(`require_isolation = true`)에서는 격리되지 않은 VM으로 분석을 시작하지 않습니다.
- **회수한 파일은 신뢰하지 않습니다.** 덤프, DB, 내려받은 파일을 host에서 실행하지 마세요. 정적 분석 도구로 여는 것도 분석 대상 파일을 여는 것과 같습니다.
- **토큰은 곧 권한입니다.**
  - 플러그인 토큰은 게스트에서 코드를 실행할 수 있는 권한입니다. 게스트의 악성코드가 읽을 수 있고 스냅샷 파일에도 남습니다.
  - 게이트웨이 HTTP 토큰은 VM 제어 권한이므로 환경 변수에 두고 범위별로 따로 씁니다.
- **플러그인 포트를 토큰 없이 두드리지 마세요.** 게스트 밖(host 등)에서 온 요청은 토큰이 없어도 인증 실패로 셉니다. 5회 실패하면 그 IP는 300초 동안 잠깁니다(429).
- **정적 도구의 MCP 서버도 권한입니다.** 대부분 바이너리를 열고 DB를 바꿀 수 있습니다. 네트워크로 열리는 서버(예: CutterMCP)는 loopback에만 바인드되는지 확인합니다.

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
- `run`/step 직후 `GetDebugState`는 실행 중 `RUNNING`, 멈춘 뒤 `PAUSED`로 일관됐습니다.
- `LogRedirect`, `LoadBinary`의 인자·작업 폴더가 동작했습니다. x64dbg를 죽이면 디버기도 함께 종료됩니다.
- 정적 도구(E2E 샘플로 이름 변경·주석·재적용·내보내기 확인)
  - IDA 9.2(헤드리스)
  - Ghidra 12.2(`pyghidraRun -H`)
  - radare2 6.2.6
  - rizin 0.9.1
  - Cutter 2.5.0·2.4.1(내장 Python)
- 정적 MCP 서버(실제 MCP 클라이언트로 이름 변경·주석·디컴파일 확인)
  - pyghidra-mcp 0.3.0
  - GhidraMCP 2.0(헤드리스)
  - r2mcp 1.9.0
- 원스톱 설치: `build-release.sh`로 만든 wheel(플러그인과 정적 스크립트 포함)을 격리 설치했습니다. 그 설치본의 `setup`이 실 VM에서 플러그인 배포부터 클린 스냅샷까지 248초에 끝냈습니다.
- 정적·동적 왕복: 실제 Claude Code에 게이트웨이와 r2mcp를 나란히 등록했습니다. 아래 흐름이 84초에 끝났습니다.
  - radare2로 함수를 찾았습니다.
  - `static_rebase`로 주소를 바꾼 뒤 x64dbg BP가 걸렸습니다.
  - radare2에 이름과 주석을 남겼습니다.
  - 회수하고 복원했습니다.

**아직 확인하지 않은 것**

- Windows·macOS host
- 실제로 다른 PC에서 원격 접속(같은 host의 비루프백 주소로 대신 확인)
- 기본 한도(110초)를 실제로 넘기는 호출(낮춘 한도로 같은 경로만 확인)
- VM 없이 고정 주소의 플러그인에 붙는 `endpoint` 프로필의 실환경 사용
- 게스트의 SYSTEM 서비스 `vmtoolsd`가 죽은 경우
- Ghidra GUI, GhidraMCP의 GUI 모드, CutterMCP(위험해서 기본에서 뺌), Ghidra 11.x
- 태그 릴리스 워크플로의 실제 실행

## 개발 방식과 테스트

이 포크는 Claude Code(Claude Opus)와 함께 아래 순서로 만들었습니다.

1. **계획:** 저장소 분석 → 설계 → 여러 모델의 독립 검토(Claude Sonnet: 신뢰성·보안, Fable: 완결성·아키텍처, Mythos: 기술 타당성) → 반영. 결과는 [`docs/VM_ORCHESTRATION_PLAN.md`](docs/VM_ORCHESTRATION_PLAN.md)에 있습니다.
2. **Phase 0:** 사용자의 분석 VM을 건드리지 않고 하드 클론을 떠서, vmrun·VIX·플러그인 동작을 실측했습니다.
3. **기능별 TDD:** 실패하는 테스트 → 구현 → 다른 모델들의 코드 리뷰 → 반영 → 테스트 통과. 이 과정을 모두 거쳐야 기능을 완료로 봤습니다. 기능마다 에이전트를 따로 붙여 병렬로 개발했습니다.
4. **마지막 관문:** 실 VM E2E, 실제 Claude Code 클라이언트, 실제 정적 도구로 확인했습니다. 여기서 나온 결함도 같은 절차로 고쳤습니다. 예를 들면 응답 소켓 처리, 인증 잠금, `GetDebugState LOCKED`, PowerShell 5.1 JSON, 빈 x64dbg DB, 연결 대기입니다.

```bash
cd host
uv run pytest                 # 단위 테스트 + static/ 스크립트 테스트 (VM 불필요: VM·게스트·플러그인은 fake)
uv run ruff check src tests
uv run pytest -m vm tests/vm  # 실 VM E2E: VM을 복원·변경하므로 버려도 되는 클론에서만 실행
cd .. && zig build test       # 플러그인 단위 테스트
scripts/build-release.sh      # wheel(플러그인 포함), 플러그인 zip, SHA256SUMS
```

## 문서

| 문서 | 내용 |
|---|---|
| [`docs/QUICKSTART_KO.md`](docs/QUICKSTART_KO.md) | 실 VM에서 검증한 설치·사용 절차, 실제로 겪은 문제 해결 |
| [`host/README.md`](host/README.md) | 게이트웨이 영문 레퍼런스 (설정, 툴, 원격 접속, 테스트, 릴리스) |
| [`static/README.md`](static/README.md) | 정적 도구별 동기화 스크립트와 MCP 서버 |
| [`static/ida/README.md`](static/ida/README.md) | IDA 연동 상세 |
| [`docs/PLUGIN.md`](docs/PLUGIN.md) | x64dbg 플러그인 레퍼런스 (원본 README + v1.10 변경) |
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
| `src/`, `build.zig`, `build.zig.zon`, `.github/workflows/ci.yml`, `.gitignore`, `SKILL.md`, `logo.png`, `docs/PLUGIN.md` | 원본(duty1g와 upstream 기여자들, git 이력 참고). 이 포크에서 수정한 내용은 같은 파일에 함께 들어 있습니다. |
| `host/`, `guest/`, `static/`, `scripts/`, `.github/workflows/release.yml`, `docs/`의 나머지 문서, 이 `README.md` | 이 포크에서 새로 작성 |

**이 코드를 가져다 쓸 때.** 일부만 가져가더라도 `LICENSE` 파일(두 저작권 줄과 허가 문구)을 함께 넣어 주세요. MIT가 요구하는 것은 이것뿐입니다. 소프트웨어는 "있는 그대로" 제공되며 어떤 보증도 없습니다. 릴리스 wheel에 든 플러그인 바이너리도 이 저장소의 소스를 빌드한 것이라 같은 MIT를 따릅니다.

**이 저장소에 포함되지 않은 것.** 아래는 각자의 라이선스를 따르며, 사용자가 따로 설치합니다.

| 구성 요소 | 라이선스 |
|---|---|
| [x64dbg](https://x64dbg.com/) | GPLv3. 플러그인은 x64dbg에 로드되지만 x64dbg 자체는 이 저장소에 없습니다. |
| VMware Workstation / `vmrun` | 상용(Broadcom) |
| IDA Pro | 상용(Hex-Rays) |
| Ghidra | Apache-2.0 (NSA) |
| radare2 / rizin | LGPL-3.0 |
| Cutter | GPL-3.0 |
| 정적 도구의 MCP 서버(ida-multi-mcp, pyghidra-mcp, GhidraMCP, r2mcp, CutterMCP) | 각 프로젝트의 라이선스 |
| 게이트웨이의 Python 직접 의존성(uv가 설치) | `mcp`, `anyio`, `jsonschema`: MIT / `starlette`, `uvicorn`: BSD-3-Clause. 간접 의존성 전체는 `host/uv.lock`에 있습니다. |

이 포크는 원작자, x64dbg 프로젝트, Broadcom(VMware), Hex-Rays, NSA, radare2·rizin 프로젝트와 관계가 없습니다. 각 이름은 해당 소유자의 상표입니다. 이 절은 저장소의 표기 방침을 정리한 것이며 법률 자문이 아닙니다.

## 면책

이 도구는 정당한 리버스 엔지니어링, 악성코드 분석, 보안 연구, 교육 목적으로만 써야 합니다. 디버거 완전 제어(메모리 읽기·쓰기, 코드 실행, 프로세스 조작)와 VM 제어를 네트워크로 노출합니다. 사용에 따른 책임은 사용자에게 있습니다. 분석 권한이 있는 소프트웨어에만 쓰고, 플러그인이나 게이트웨이를 신뢰할 수 없는 네트워크에 노출하지 마세요.

## 감사의 말

- x64dbg MCP 플러그인을 만들고 MIT로 공개한 [@duty1g](https://github.com/duty1g)와 upstream 기여자들
- [x64dbg](https://x64dbg.com/), [Ghidra](https://github.com/NationalSecurityAgency/ghidra), [radare2](https://github.com/radareorg/radare2), [rizin·Cutter](https://rizin.re/) 프로젝트
- 정적 도구 MCP 서버 프로젝트들(ida-multi-mcp, pyghidra-mcp, GhidraMCP, radare2-mcp)
- [Model Context Protocol](https://modelcontextprotocol.io/)

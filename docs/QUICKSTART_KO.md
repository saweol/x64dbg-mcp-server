# x64dbg-vm-gateway 빠른 시작 (한국어)

설치부터 첫 분석까지 한 줄로 따라가는 문서입니다. 중심은 `setup` 한 번입니다. 단계를 손으로 나눠 하는 방법은 [부록 A](#부록-a-단계별-수동-설치)에 있습니다.

- 무엇이 실검증됐고 무엇이 단위 테스트뿐인지는 [README의 검증 현황](../README.md#검증-현황) 한곳에만 적습니다.
- 막히면 [README의 문제 해결](../README.md#문제-해결)을 보세요. 증상별 표와 오류 코드 목록이 있습니다.
- 영문 전체 레퍼런스는 [`host/README.md`](../host/README.md), 설계는 [`VM_ORCHESTRATION_PLAN.md`](VM_ORCHESTRATION_PLAN.md), 실측 기록은 [`PHASE0_RESULTS.md`](PHASE0_RESULTS.md)에 있습니다.

## 0. 흐름

```
1 설치 ─► 2 VM 준비 ─► 3 setup ─► 4 demo ─► 5 Claude Code 등록 ─► 6 첫 분석
 몇 분      사람 손      약 4분      몇 분       명령 한 줄            대화
```

| 구성 | 내용 |
|---|---|
| host | Linux(실검증). Windows와 macOS(Intel)는 코드상 지원하지만 실검증 전입니다. Windows 명령은 [README의 Windows host 표](../README.md#windows-host에서-실검증-전)에 있습니다. |
| VMware | Workstation 17(`vmrun` 포함) |
| 도구 | `uv`(게이트웨이는 Python 3.11 이상, 없으면 uv가 내려받음). 릴리스가 나오기 전에는 소스 빌드용 Zig 0.14.0 |
| 게스트 | Windows 10/11 + x64dbg(`release\x64`, `release\x32`) + VMware Tools. 암호가 있는 로컬 관리자 계정 |
| 네트워크 | host-only(필수). 공유 폴더 끔 |

AI에게 보이는 툴은 게이트웨이 툴 22개(`analysis_*`, `vm_*`, `file_*`, `debugger_*`, `static_*`, `jobs_*`, `session_status`, `gateway_doctor`)와 플러그인 v1.10의 x64dbg 툴 83개, 합계 105개입니다. 분석 루프는 `analysis_start` → 분석(x64dbg 툴) → `analysis_collect` → `analysis_finish`(클린 스냅샷 복원)입니다.

## 1. 설치

uv가 없으면 먼저 설치합니다.

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

릴리스는 <https://github.com/saweol/x64dbg-mcp-server/releases>에 올릴 예정입니다. 아직 올라간 릴리스가 없으니 지금은 소스에서 빌드합니다. [Zig 0.14.0](https://ziglang.org/download/#release-0.14.0)이 PATH에 있거나 `ZIG=/path/to/zig`로 지정돼 있어야 합니다.

```bash
git clone https://github.com/saweol/x64dbg-mcp-server.git && cd x64dbg-mcp-server
scripts/build-release.sh
(cd release && sha256sum -c SHA256SUMS)
uv tool install release/x64dbg_vm_gateway-*.whl
x64dbg-vm-gateway --help
```

`build-release.sh`는 플러그인과 무해한 데모 샘플을 빌드해 wheel에 넣고, `release/`에 wheel, sdist, 플러그인 zip(`x64dbg-mcp-plugin-<버전>.zip`), `SHA256SUMS`를 만듭니다. 다시 설치할 때는 `uv tool install --force ...`입니다.

릴리스가 나오면 wheel과 `SHA256SUMS`를 받아 `sha256sum -c --ignore-missing SHA256SUMS`로 확인한 뒤 `uv tool install ./x64dbg_vm_gateway-<버전>-py3-none-any.whl`로 설치합니다. Zig는 필요 없습니다.

`x64dbg-vm-gateway`를 찾을 수 없다고 나오면 `uv tool update-shell`을 실행하고 새 셸을 엽니다.

## 2. VM 준비

전체 점검표와 설명은 [README 2단계](../README.md#2단계-분석-vm-준비)에 있습니다. 요점만 적습니다.

- [ ] 쓰던 분석 VM이 있다면 **전체 클론**을 만들어 씁니다. 원본은 건드리지 않습니다.
- [ ] Windows 10/11(실검증은 Windows 10 Pro 19045 한국어판)
- [ ] **로컬** 관리자 계정, 암호 있음. 이 암호는 **실험실 전용**으로 씁니다. 자동 로그온이 게스트 레지스트리(`Winlogon`의 `DefaultPassword`)에 평문으로 남겨, 모든 스냅샷에 들어갑니다.
- [ ] VMware Tools 설치
- [ ] x64dbg 압축 해제(예: `C:\x64dbg\release`). 위치를 모르면 `setup`이 찾아 줍니다.
- [ ] 네트워크 어댑터 **Host-only**(Custom(VMnet1) 아님). host-only 네트워크는 Linux에서 `vmware-netcfg`로 확인합니다.
- [ ] 공유 폴더 Disabled
- [ ] 실험실 VM이면 Defender 실시간 보호 끄기(또는 `C:\mcp` 제외), Windows Update 일시 중지
- [ ] VM 켜기

VM을 끈 상태에서 `.vmx`를 확인합니다.

```bash
grep -iE '^(ethernet[0-9]+\.(present|connectionType|startConnected)|sharedFolder[0-9]+\.(present|enabled)|isolation\.tools\.hgfs\.disable) ' \
    /vms/analysis/analysis.vmx
# 기대하는 값:
#   ethernet0.connectionType = "hostonly"      (켜진 어댑터 모두)
#   isolation.tools.hgfs.disable = "TRUE"      (또는 켜진 sharedFolderN 항목이 없음)
```

## 3. setup

VM을 켠 채로 실행합니다. 먼저 `--dry-run`으로 계획을 봅니다. `--dry-run`은 게스트에 접속하지도, 아무것도 바꾸지도 않습니다.

```bash
x64dbg-vm-gateway setup --dry-run
x64dbg-vm-gateway setup
```

터미널에서는 빠진 값을 차례로 묻습니다.

1. VM: host에서 찾은 VM 목록의 번호, 또는 `.vmx` 경로
2. 게스트 계정(예: `analyst`)
3. 암호(화면에 보이지 않음). `X64DBG_GW_GUEST_PW`에 이미 있으면 묻지 않습니다.
4. x64dbg 폴더(`x64\`, `x32\`가 든 폴더). 게스트에서 찾아 줄 수 있습니다.
5. 암호를 파일로 저장할지. 저장하면 `~/.config/x64dbg-vm-gateway/<프로필>.env`(0600)에 쓰고, 설정의 `gateway.env_file`이 그 파일을 가리킵니다. 사전 점검에서 게스트가 그 암호를 받아들인 뒤에만 씁니다.

플래그로 다 넘기면 묻지 않습니다(터미널이 아닐 때도 같음).

```bash
read -rs X64DBG_GW_GUEST_PW && export X64DBG_GW_GUEST_PW
x64dbg-vm-gateway setup --non-interactive --vmx /vms/analysis/analysis.vmx \
    --guest-user analyst --x64dbg-root 'C:\x64dbg\release' --snapshot MCP_CLEAN --save-password-file
```

`setup`은 설정 파일 작성 → 사전 점검(`doctor`) → 플러그인 배포 → 프로비저닝(자동 로그온, 예약 작업, 플러그인 설정과 토큰, `C:\mcp\jobs`, DB 압축과 절전 끄기) → 재부팅 → 플러그인 응답 대기 → 메모리 포함 클린 스냅샷 → 재점검 → 등록 명령 출력 순서로 갑니다. 고칠 수 없는 문제(vmrun, `.vmx`, VM 전원, VMware Tools, 게스트 계정, 게스트 IP, 격리, VM 중복 실행, job 폴더)가 있으면 게스트를 바꾸기 전에 힌트와 함께 멈춥니다.

실측으로는 `setup` 전체가 248초(약 4분) 걸렸습니다(값을 플래그로 준 실행). 그중 메모리 스냅샷이 가장 오래 걸립니다(RAM 4 GB 게스트에서 약 3분).

- 다시 돌리면 이미 있는 스냅샷 이름에서 멈춥니다. 덮어쓰지 않습니다. `doctor`가 통과하면 준비는 끝난 것입니다. 새로 찍으려면 `--snapshot 새이름`을 주고, 설정의 `clean_snapshot`(과 `protected_snapshots`)을 그 이름으로 바꿉니다.
- `--skip-plugin`, `--skip-provision`으로 일부만 실행합니다.
- `--no-autologon`이면 재부팅 뒤 `--wait-ready`초(기본 300) 안에 누군가 VM에 로그온해야 합니다. 디버거는 로그온 때 시작됩니다.

## 4. demo

Claude Code를 띄우기 전에 실행합니다. MCP 클라이언트가 게이트웨이를 돌리고 있으면 `LOCK_TIMEOUT`으로 멈춥니다.

```bash
x64dbg-vm-gateway demo
```

wheel에 든 무해한 샘플로 `analysis_start` → `SetBreakpoint kernel32.Sleep` → `run`(kernel32에서 멈출 때까지) → `GetCallStack` → `analysis_collect` → `analysis_finish(revert=true)`를 차례로 합니다. 단계마다 ` ok ` / `FAIL`과 걸린 시간을 찍고, 끝에 `demo: PASS (x64, x32)`처럼 결과를 냅니다. 실패하면 힌트가 나옵니다. 끝나면 VM은 클린 스냅샷으로 돌아갑니다.

`demo`가 PASS면 게이트웨이, 플러그인, 클린 스냅샷, 복원까지 한 바퀴가 도는 것입니다.

## 5. Claude Code 등록

Claude Code를 띄울 폴더에서 실행합니다.

```bash
x64dbg-vm-gateway mcp-config --tool gateway --apply    # 묻고 나서 claude mcp add 실행
claude mcp list
```

- `claude mcp add`는 기본으로 지금 폴더(local 범위)에만 등록합니다. 어디서나 쓰려면 `mcp-config --tool gateway`가 출력한 명령의 `claude mcp add` 바로 뒤에 `--scope user`를 넣어 직접 실행합니다.
- 등록 명령은 설치된 실행 파일을 절대 경로로 가리킵니다. 다시 설치해서 경로가 바뀌면 다시 등록합니다.
- 암호 파일을 저장하지 않았다면 `X64DBG_GW_GUEST_PW`를 export한 셸에서 `claude`를 띄웁니다. `claude mcp add -e`로 암호를 넘기지 마세요. Claude 설정 파일에 기록됩니다.
- 툴 승인을 미리 정하려면 `mcp-config --permissions`(strict, 기본)나 `--permissions-mode lab`의 출력을 `.claude/settings.json`에 합칩니다([README 권한 설정](../README.md#권한-설정)).

`claude`를 띄운 뒤 `/mcp`에서 `x64dbg-vm`이 연결됐는지 봅니다.

## 6. 첫 분석

먼저 상태만 봅니다.

> x64dbg-vm 게이트웨이 상태를 확인해 줘. session_status와 gateway_doctor만 호출하고, 아무것도 바꾸지 마.

그다음 무해한 샘플로 한 바퀴 돕니다. 소스에서 빌드했다면 샘플이 저장소에 있습니다. 샘플은 `gateway.upload_roots`(기본: 홈 폴더) 안에 있어야 합니다.

```bash
mkdir -p ~/samples && cp host/src/x64dbg_vm_gateway/data/samples/e2e_sample_x86_64.exe ~/samples/hello64.exe
```

> `~/samples/hello64.exe` 분석을 시작해. kernel32.Sleep에 BP를 걸고 run으로 거기서 멈추면 콜 스택과 인자를 보여 줘. 그다음 회수하고 복원한 뒤 analysis_report로 정리해.

같은 일을 MCP 프롬프트로도 시작할 수 있습니다.

```
/mcp__x64dbg-vm__analyze-sample /home/analyst/samples/hello64.exe
```

실제 샘플용 프롬프트와 MCP 프롬프트 5개의 인자는 [README 처음 분석하기](../README.md#처음-분석하기)에 있습니다.

결과는 `~/mcp-lab/jobs/<job_id>/artifacts/`(`manifest.json`, `files/`, `raw/out.zip`)에 쌓입니다. 사람이 보려면 다음을 씁니다. 게이트웨이가 돌고 있어도 됩니다.

```bash
x64dbg-vm-gateway jobs list
x64dbg-vm-gateway jobs report <JOB_ID> --out ~/mcp-lab/jobs/<JOB_ID>/artifacts/report.md
```

manifest 필드, x64dbg DB 열기, 감염 상태 스냅샷(`keep_snapshot`), 화면 캡처는 [README 결과 보기](../README.md#결과-보기)에 있습니다.

## 7. 다음 단계

| 하고 싶은 것 | 볼 곳 |
|---|---|
| 정적 도구(radare2, Ghidra, IDA, Cutter) 붙이기 | [README 정적 도구는 선택](../README.md#정적-도구는-선택), [`static/README.md`](../static/README.md) |
| VM 여러 대를 게이트웨이 하나로 | [README VM 여러 대](../README.md#vm-여러-대) |
| 게스트를 바꾼 뒤 클린 스냅샷 다시 찍기, 오래된 스냅샷 정리 | [README 클린 스냅샷 갱신과 정리](../README.md#클린-스냅샷-갱신과-정리) |
| 다른 PC에서 접속 | [부록 C](#부록-c-다른-pc에서-접속) |
| 문제 해결, 오류 코드 | [README 문제 해결](../README.md#문제-해결) |

---

## 부록 A. 단계별 수동 설치

`setup`이 하는 일을 한 단계씩 하는 방법입니다. 실 VM 검증(`pytest -m vm`)은 이 단계별 명령으로도 돌렸습니다.

### A-1. 설정 파일

비밀값은 설정 파일에 넣지 않습니다. 환경 변수 이름만 적고, 값은 0600 권한의 env 파일에 둡니다.

```bash
mkdir -p ~/.config/x64dbg-vm-gateway
install -m 600 /dev/null ~/.config/x64dbg-vm-gateway/lab.env
# lab.env 내용:
#   X64DBG_GW_GUEST_USER=<게스트 계정>
#   X64DBG_GW_GUEST_PW=<게스트 암호>
```

대화식으로 만들려면 `x64dbg-vm-gateway init`, 한 번에 만들려면 `init --non-interactive --vmx ... --guest-user ... --x64dbg-root ...`을 씁니다. 손으로 쓴다면 `~/.config/x64dbg-vm-gateway/config.toml`(0600)은 이런 모양입니다. 실 VM 검증에 쓴 형태입니다.

```toml
[gateway]
jobs_root = "~/mcp-lab/jobs"
default_profile = "lab"
env_file = "~/.config/x64dbg-vm-gateway/lab.env"
upload_roots = ["~/samples"]          # analysis_start가 읽을 수 있는 host 경로

[profiles.lab]
mode = "vmware"
vmx = "/vms/analysis/analysis.vmx"
clean_snapshot = "MCP_CLEAN"
protected_snapshots = ["MCP_CLEAN"]
guest_user_env = "X64DBG_GW_GUEST_USER"
guest_password_env = "X64DBG_GW_GUEST_PW"
guest_host = "auto"                   # 또는 게스트의 고정 IP (host-only 대역, 예: 192.168.56.x)
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

### A-2. 플러그인 배포

디버거 종료 → 기존 플러그인을 `plugins_backup\`에 백업 → 복사 → 재기동 순서입니다. 실측 17~25초였습니다. `--dist`를 빼면 wheel에 든 빌드를 씁니다. 프로비저닝 전의 게스트에는 `--no-relaunch`를 붙입니다. 디버거를 다시 띄우는 예약 작업은 프로비저닝 때 생기기 때문입니다.

```bash
x64dbg-vm-gateway install-plugin --x64dbg-root 'C:\x64dbg\release' --no-relaunch
```

### A-3. 프로비저닝과 클린 스냅샷

```bash
x64dbg-vm-gateway provision --x64dbg-root 'C:\x64dbg\release' --snapshot MCP_CLEAN
```

프로비저닝이 하는 일은 다음과 같습니다.

- 자동 로그온을 설정합니다(암호가 게스트 레지스트리에 남습니다. 실험실 전용 암호를 쓰세요).
- 로그온 시 x64dbg·x32dbg를 최고 권한으로 실행하는 예약 작업을 등록합니다(재기동에도 씁니다).
- 플러그인 설정을 씁니다.
  - 외부 바인드에 필요한 `AllowExternal`, `AllowedClients=host IP`(자동 감지)를 넣습니다.
  - 손상된 토큰을 복구합니다.
- `C:\mcp\jobs`를 만들고, x64dbg DB 압축과 절전을 끕니다.

재부팅을 게스트 부팅 시각으로 확인한 뒤 플러그인 응답을 기다리고 스냅샷을 찍습니다. 실측으로는 재부팅 뒤 39초에 준비됐고, 스냅샷까지 3분 14초가 걸렸습니다. 스냅샷은 메모리 포함 켜짐 상태입니다. 복원하면 x64dbg가 떠 있는 상태 그대로 11~14초 만에 돌아옵니다.

주요 옵션은 `--user U`(게스트 계정), `--bind ADDR`(기본 `0.0.0.0`), `--no-autologon`, `--no-reboot`, `--wait-ready S`(기본 300)입니다.

### A-4. 점검

```bash
x64dbg-vm-gateway doctor      # vmrun, 스냅샷, Tools, 게스트 계정, 격리, 백엔드 토큰·버전을 점검 (실패하면 종료 코드 1)
x64dbg-vm-gateway status
```

## 부록 B. 등록 명령 다루기

```bash
x64dbg-vm-gateway mcp-config                    # 게이트웨이와 설정한 모든 정적 도구의 claude mcp add 명령
x64dbg-vm-gateway mcp-config --tool gateway     # 게이트웨이만
x64dbg-vm-gateway mcp-config --tool ghidra --set binary=/home/analyst/samples/a.exe ...   # 자리 표시 채우기
x64dbg-vm-gateway mcp-config --client json      # Claude Desktop, Cursor, VS Code용 mcpServers 문서
x64dbg-vm-gateway mcp-config --apply            # 채울 값이 없는 등록만 실행(묻고 나서, --yes면 묻지 않음)
x64dbg-vm-gateway static-scripts --dest ~/x64dbg-static   # 정적 동기화 스크립트 복사
```

설정 파일이 기본 위치가 아니면 게이트웨이 명령에 `-e X64DBG_VM_GATEWAY_CONFIG=<경로>`가 붙습니다. `<...>`로 남은 값은 직접 채우거나 `--set NAME=VALUE`로 채웁니다.

## 부록 C. 다른 PC에서 접속

`config.toml`에 다음을 추가합니다. 같은 host 안에서만 쓴다면 SSH 터널(`ssh -L 9100:127.0.0.1:9100 lab-host`)과 기본 loopback 바인드가 더 간단합니다.

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

`x64dbg-vm-gateway serve --transport http`로 띄웁니다. 클라이언트는 `https://<host>:9100/mcp`에 `Authorization: Bearer <token>`으로 접속합니다. 비루프백 주소에 바인드하면서 TLS가 없으면 시작을 거부합니다. 모든 호출은 `<jobs_root>/_audit/`에 감사 로그로 남습니다. 인증서 만들기와 클라이언트 등록은 [`host/README.md`](../host/README.md#remote-access-m3)에 있습니다.

## 부록 D. 안전 수칙

- **격리 점검:** 공유 폴더가 켜져 있거나 host-only가 아닌 네트워크면 `analysis_start`가 거부됩니다(`ISOLATION_REQUIRED`).
- **비신뢰 출력:** 게스트 출력은 `<untrusted_guest_output>`으로 감싸서 전달합니다. 그 안의 지시문은 데이터로만 취급합니다.
- **수집 전 복원 금지:** 수집 전에는 복원할 수 없습니다(fail-closed). 버릴 job은 사람만 `x64dbg-vm-gateway discard <job>`으로 정리할 수 있습니다.
- **스냅샷 보호:** 보호 스냅샷과 클린 스냅샷은 삭제할 수 없습니다.
- **암호:** 게스트 암호는 실험실 전용으로 씁니다. 자동 로그온이 게스트 레지스트리와 모든 스냅샷에 남깁니다.

전체 수칙은 [README 안전 수칙](../README.md#안전-수칙)에 있습니다.

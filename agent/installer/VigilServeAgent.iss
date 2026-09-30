
#define MyAppName "VigilServe Agent"
#define MyAppVersion "1.1.68"
#define MyAppPublisher "VigilServe"
#define MyAppExeName "VigilServeAgent.exe"
#define MyAppIconName "agent_icon.ico"

[Setup]
AppId={{B4A7C9E2-1D3F-4A5B-8C7E-9F2A1B3C4D5E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\VigilServe\Agent
DefaultGroupName=VigilServe
AllowNoIcons=yes
OutputDir=output
OutputBaseFilename=VigilServeAgent-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
; X64-only: the Agent builds (PyInstaller onedir + bundled Python) only ship x64.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
SetupIconFile=..\installer_icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
; Let the installer close/restart the running agent itself; no admin-only
; taskkill/netsh commands are needed when installing under %LocalAppData%.
CloseApplications=yes
RestartApplications=yes
; Without VersionInfoVersion the compiled setup.exe gets a BLANK FileVersion
; (only ProductVersion is filled in automatically). Explorer's Details tab and
; the push-update flow both read FileVersion, so keep it explicit and in sync
; with AppVersion.
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Installer
VersionInfoProductName={#MyAppName}

[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
; Desktop shortcut: checked by default (2026-09-15 user request). Inno Setup
; treats a task without "unchecked" as checked on a fresh install.
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Dirs]
Name: "{app}\logs"; Permissions: users-full

[Files]
Source: "..\dist\VigilServeAgent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\agent_icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\tray_idle.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\tray_running.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\tray_error.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\tray_connecting.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\agent_config.json"; DestDir: "{app}"; Flags: ignoreversion onlyifdoesntexist
; 服务端本地 CA（安全加固阶段 2）：Agent 用它校验服务端 HTTPS 证书。
; build_installer.py 会在打包前生成/刷新这个文件；CA 只用于验签，可公开分发。
Source: "..\ca\vigilserve-ca.crt"; DestDir: "{app}\ca"; Flags: ignoreversion
Source: "..\stop_agent.bat"; DestDir: "{app}"; Flags: ignoreversion
; 再嵌一份（不安装），供 [Code] 用 ExtractTemporaryFile 取到 {tmp}。
; 为什么需要：覆盖安装（升级）走到 ssInstall 时**新文件还没落地**，而旧版本
; 的 {app} 里根本没有这份脚本 —— 只认 {app} 的路径在升级场景会直接落空。
Source: "..\stop_agent.bat"; Flags: dontcopy

[Icons]
Name: "{group}\VigilServe Agent"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppIconName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
; --config：直接打开配置面板。带这个参数启动时 agent.py 会先把后台 Agent
; 拉起来（没人跑的话），所以配完保存立刻上线，不会停在离线状态。
Name: "{autodesktop}\VigilServe Agent"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--config"; IconFilename: "{app}\{#MyAppIconName}"; Tasks: desktopicon

[Code]
// The MeshCentral MeshAgent component was removed on 2026-09-15: remote desktop
// now runs over the Agent's own tunnel (Guacamole protocol), so no third-party
// service install - and therefore no UAC prompt - is needed anymore.
// NOTE: inside [Code] use Pascal comments, i.e. // or brace style, not ";".

// 装完之后要做什么（在 DeinitializeSetup 里执行）：
//   全新安装 → 打开配置面板；推送更新（/UPDATEFLOW）→ 只把后台 Agent 拉起来。
//
// 🚨 为什么不再放 `[Run]` 段：`[Run]` 的条目在**向导窗口还开着**的时候就执行，
//    配了 `nowait` 更是安装向导（"完成 VigilServe Agent 安装向导"那一页）还没关、
//    配置面板就已经蹦出来了 —— 用户明确要求「点『完成』关闭安装窗口后再弹出」。
//    DeinitializeSetup 恰好在用户点完「完成」、向导关闭之后被调用，时机正好。
var
  LaunchConfigAfterClose: Boolean;
  LaunchAgentAfterClose: Boolean;
  // 卸载时是否连本机配置一起清除。必须是**全局**变量：
  // 🚨 Inno 的 [Code] 里函数内 `var` 声明的是局部变量，跨过程传不出去 ——
  //    这个结果要在 InitializeUninstall 里问、在 usUninstall 里才执行。
  PurgeConfigOnUninstall: Boolean;

function IsUpdateFlow: Boolean;
begin
  Result := Pos('/UPDATEFLOW', UpperCase(GetCmdTail)) > 0;
end;

// The install path is fixed ({localappdata}\VigilServe\Agent) because it takes
// part in the push-update flow. 2026-09-15 user request: hide the "Browse..."
// button and make the path edit box grey / read-only.
procedure InitializeWizard;
begin
  WizardForm.DirEdit.Enabled := False;   // read-only + greyed out
  WizardForm.DirEdit.Color := $F0F0F0;   // explicit grey for the disabled look
  WizardForm.DirBrowseButton.Visible := False;
end;

// ── 结束 Agent 进程 ────────────────────────────────────────────────────
// Agent 常驻系统托盘、主窗口平时隐藏，Inno 自带的 CloseApplications 只对
// 「有窗口」的程序发 WM_CLOSE，对它并不完全可靠，所以这里自己动手。

function PowershellExe: String;
begin
  Result := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  if not FileExists(Result) then
    Result := 'powershell.exe';
end;

// 现在还有几个 VigilServeAgent 进程。返回 -1 表示数不出来（没有 PowerShell）。
function AgentProcessCount: Integer;
var
  ResultCode: Integer;
begin
  Result := -1;
  if Exec(PowershellExe,
          '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "exit (Get-Process -Name VigilServeAgent -ErrorAction SilentlyContinue | Measure-Object).Count"',
          '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Result := ResultCode;
end;

// UseTempCopy=True 时从 {tmp} 取脚本（[Files] 里那份 dontcopy），用于
// **新文件还没落地**的升级场景；False 时用已安装的 {app} 那份，用于卸载。
// 两种情况都把 {app} 作为 %1 传进去，脚本才知道该清理谁。
procedure StopAgentProcesses(UseTempCopy: Boolean);
var
  ResultCode: Integer;
  BatPath: String;
begin
  if UseTempCopy then
  begin
    ExtractTemporaryFile('stop_agent.bat');
    BatPath := ExpandConstant('{tmp}\stop_agent.bat');
  end
  else
    BatPath := ExpandConstant('{app}\stop_agent.bat');

  if FileExists(BatPath) then
    Exec(ExpandConstant('cmd.exe'), '/C "' + BatPath + '" "' + ExpandConstant('{app}') + '"',
         ExpandConstant('{tmp}'), SW_HIDE, ewWaitUntilTerminated, ResultCode)
  else
    // 1.1.47 之前的版本没装这个脚本 —— 别就此放弃，直接 taskkill 一次兜底。
    Exec(ExpandConstant('cmd.exe'),
         '/C taskkill /F /T /IM VigilServeAgent.exe',
         ExpandConstant('{tmp}'), SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// 结束进程并**确认它真的结束了**，最多试 MaxRounds 轮。
//
// 🚨 为什么必须确认：光跑一遍 stop_agent.bat 是不够的 —— Agent 若曾以管理员
//    身份启动过，没提权的卸载程序 taskkill 会失败，而 bat 把错误吞掉、
//    安装程序也看不出区别。结果就是"卸载很顺利"但文件仍被占用：安装目录里
//    留下 exe/dll，或最后弹「部分文件无法删除」。用户报的正是这个现象。
//    现在每轮结束之后再数一遍进程，数到 0 才算成功。
function StopAgentAndWait(MaxRounds: Integer): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to MaxRounds do
  begin
    StopAgentProcesses(False);
    Sleep(600);
    if AgentProcessCount <= 0 then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

// Pascal 要先声明后使用 —— 这三个过程的实体在下面，这里提前打个招呼。
procedure AskPurgeConfigOnUninstall; forward;
procedure ReportUninstallToServer; forward;

// 卸载入口：先把 Agent 结束干净，结束不掉就请用户手动退出后重试。
//
// 放在 InitializeUninstall 而不是 usUninstall 步：那一步已经进到"正在卸载"，
// 没法再把流程停下来问用户。这里返回 False 会直接中止卸载。
function InitializeUninstall(): Boolean;
var
  R: Integer;
begin
  Result := True;
  while True do
  begin
    if StopAgentAndWait(3) then
      Break;
    R := MsgBox('Agent 仍在运行，无法删除安装文件。' + #13#10 + #13#10 +
                '请先退出 Agent：右键单击任务栏通知区域中的 VigilServe Agent 图标，' +
                '选择「退出」。若图标不可见，请在任务管理器中结束 VigilServeAgent.exe。' +
                '若 Agent 以管理员身份运行，请以管理员身份重新运行本卸载程序。' + #13#10 + #13#10 +
                '「是」：重新尝试结束进程' + #13#10 +
                '「否」：忽略并继续卸载（安装目录可能残留文件）' + #13#10 +
                '「取消」：中止卸载',
                mbError, MB_YESNOCANCEL);
    if R = IDNO then
      Break;                // 忽略并继续卸载
    if R <> IDYES then
    begin
      Result := False;      // 取消 → 中止卸载，等用户退出 Agent 后重来
      Break;
    end;
  end;

  // 🚨 用 `Break` 而不是 `Exit`：这两件事**无论进程有没有杀干净都要做**
  // （用户选「忽略并继续」时也一样）。写 Exit 的话它们会被跳过。
  if Result then
  begin
    AskPurgeConfigOnUninstall;   // 只问，结果存全局变量；真删在 usUninstall 步
    ReportUninstallToServer;     // 必须在删配置之前 —— 签名要用配置里的私钥
  end;
end;

// ssInstall = 真正开始拷文件之前。覆盖安装（升级）走的正是这条路径。
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    StopAgentProcesses(True)
  else if CurStep = ssPostInstall then
  begin
    if IsUpdateFlow then
      LaunchAgentAfterClose := True
    else
      LaunchConfigAfterClose := True;
  end;
end;

// 卸载时询问是否清除本机配置（`%LOCALAPPDATA%\VigilServe\Config\Agent`）。
//
// 目录里有：设备私钥 `identity\node.key`、本机 9998 服务证书 `api_tls\`、
// 服务端地址与端口 `agent_config.json`。
//   · 保留：重装后设备身份不变，服务端无需重新批准，可直接接入；
//   · 清除：等同换了一台新设备，须重新走一遍「加入管理」并核对配对码。
// 这两种都是合理选择，取决于这台机器是「修一下」还是「彻底交还」，所以问一句。
//
// 默认按钮是「否」（MB_DEFBUTTON2）：静默卸载（推送升级走的正是这条路）
// 不弹窗时 MsgBox 返回默认按钮，从而保留配置 —— 升级绝不能把身份清掉。
//
// 🚨 **只问不删**。真正的 DelTree 在 `ApplyPurgeConfigOnUninstall`（usUninstall
// 步）里做 —— 中间还夹着 `ReportUninstallToServer`：上报要用配置目录里的私钥
// 签名，先把配置删了就什么都发不出去，服务端只能干等心跳超时才显示离线，
// 而且「是否清配置」这个只有本机知道的事实也永远传不到服务端。
procedure AskPurgeConfigOnUninstall;
begin
  PurgeConfigOnUninstall := False;
  if not DirExists(ExpandConstant('{localappdata}\VigilServe\Config\Agent')) then
    Exit;
  PurgeConfigOnUninstall := MsgBox(
            '是否同时清除本机配置文件？' + #13#10 + #13#10 +
            '包括：设备身份私钥、本地服务证书、服务端地址与端口。' + #13#10 +
            '选择「是」会连 VigilServe 目录及其中残留的空文件夹一并删除，' + #13#10 +
            '重新安装须重新在服务端加入管理。' + #13#10 + #13#10 +
            '选择「否」将保留配置，重新安装后可继续接入。',
            mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
end;

// 告知服务端：这台机器上的 Agent 要卸载了，配置清不清。
//
// 不报会怎样：在线判定只看 `last_seen`（心跳写的），Agent 没了要等
// 「采集周期 × 2.5」才判离线 —— 这段时间主机列表上它还是绿的，管理员
// 点「加入管理」看到的都是假象。而「是否清配置」更是本机才知道的事实：
// 清了 = 设备身份一起没了，服务端必须把它移出管理，否则界面上一直显示
// 已纳管，实际没有任何一台机器握着那把私钥。
//
// 失败不影响卸载：exe 内部有超时，且退出码被忽略。
procedure ReportUninstallToServer;
var
  ResultCode: Integer;
  ExePath: String;
  Params: String;
begin
  ExePath := ExpandConstant('{app}\{#MyAppExeName}');
  if not FileExists(ExePath) then
    Exit;
  if PurgeConfigOnUninstall then
    Params := '--report-uninstall --purge'
  else
    Params := '--report-uninstall';
  // ewWaitUntilTerminated：必须等它发完再往下走 —— 后面的步骤会把配置目录
  // 和 {app} 一起删掉，那时 exe 已经不存在了。Agent 内部 6 秒超时，不会拖住卸载。
  Exec(ExePath, Params, ExpandConstant('{app}'), SW_HIDE,
       ewWaitUntilTerminated, ResultCode);
end;

// 按 InitializeUninstall 里问到的结果真正删配置。
//
// 删的是整个 `Config`，不只是 `Config\Agent`：VigilServe 目录下还有别的
// 运行期产物（日志、空文件夹），只删子目录的话父目录清不干净 —— 用户要的是
// 「勾选清除后 VigilServe 目录一并消失」。整棵树交给 CleanupLeftovers 收尾。
procedure ApplyPurgeConfigOnUninstall;
begin
  if not PurgeConfigOnUninstall then
    Exit;
  DelTree(ExpandConstant('{localappdata}\VigilServe\Config'), True, True, True);
end;

// 延迟删目录。
//
// 🚨 卸载器此刻正从 {app}（= %LOCALAPPDATA%\VigilServe\Agent）里运行，
// Windows 不允许删除正在运行的可执行文件，直接 DelTree 会留下 unins000.exe。
// 但 usPostUninstall 一返回卸载器就退出了，所以拉起一个独立 cmd：
// 先等 5 秒（`ping -n 6` 是 5 次间隔），那时句柄已全放开，再 `rd /s /q` 整树删。
// `ewNoWait` 不阻塞卸载向导 —— 这个 cmd 的命是独立的，父进程退出也照跑。
procedure ScheduleDeferredDirRemove(const Dir: String);
var
  ResultCode: Integer;
begin
  if not DirExists(Dir) then
    Exit;
  Exec(ExpandConstant('cmd.exe'),
       '/C ping -n 6 127.0.0.1 >nul & rd /s /q "' + Dir + '"',
       ExpandConstant('{tmp}'), SW_HIDE, ewNoWait, ResultCode);
end;

// 文件删完之后收尾：开机自启项、VigilServe 目录。
// 自启项（HKCU\...\Run\VigilServeAgent）是程序自己写的，删文件删不到它 ——
// 不清掉的话，下次登录 Windows 还会去找那个已经不存在的 exe。
procedure CleanupLeftovers;
begin
  RegDeleteValue(HKEY_CURRENT_USER,
                 'Software\Microsoft\Windows\CurrentVersion\Run', 'VigilServeAgent');
  if PurgeConfigOnUninstall then
    // 选了清除：整棵树连里头的空文件夹一起抹掉。放在这一步是因为 Inno 此时
    // 已经把它记录过的文件删完了，剩下的一律是不在记录里的运行期残留。
    ScheduleDeferredDirRemove(ExpandConstant('{localappdata}\VigilServe'))
  else
    // 保留配置：只在**空了**的时候删（RemoveDir 对非空目录不动作）。
    // Config 还在里面，这里自然就不会碰它。
    RemoveDir(ExpandConstant('{localappdata}\VigilServe'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    // InitializeUninstall 已经确认过一遍了，这里再补一刀：万一在这之间
    // （用户点「准备卸载」那一页的间隙）Agent 又被拉起来。
    StopAgentProcesses(False);
    // 上报已经发完（InitializeUninstall 里做的），这里才轮到删配置。
    ApplyPurgeConfigOnUninstall;
  end
  else if CurUninstallStep = usPostUninstall then
    CleanupLeftovers;
end;

// 用户点「完成」、向导窗口关闭之后才执行 —— 见文件顶部 LaunchConfigAfterClose 的说明。
procedure DeinitializeSetup();
var
  ResultCode: Integer;
begin
  if LaunchConfigAfterClose then
    Exec(ExpandConstant('{app}\{#MyAppExeName}'), '--config', ExpandConstant('{app}'),
         SW_SHOWNORMAL, ewNoWait, ResultCode)
  else if LaunchAgentAfterClose then
    // 推送更新：静默把后台 Agent 拉起来，**不要**弹配置面板去打搅正在工作的主机。
    Exec(ExpandConstant('{app}\{#MyAppExeName}'), '', ExpandConstant('{app}'),
         SW_HIDE, ewNoWait, ResultCode);
end;

[UninstallDelete]
; Ensure the install directory is fully removed, including runtime-created files
; such as logs, caches, or auto-generated JSON that were not part of the install list.
Type: filesandordirs; Name: "{app}\*"
Type: dirifempty; Name: "{app}"

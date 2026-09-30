; VigilServe Setup
; Compatible with Windows 10, Windows 11 and Windows Server 2016+
; Generated for Inno Setup 7.

#define MyAppName "VigilServe"
#define MyAppNameLong "VigilServe"
#define MyAppVersion "1.1.65"
#define MyAppPublisher "Chinaxld"
#define MyAppURL "https://github.com/vigilserve"
#define MyAppExeName "VigilServeTray.exe"
#define MyAppCopyright "Copyright (C) 2026 Chinaxld"

[Setup]
; NOTE: AppId is a unique GUID for this application.
AppId={{B5E8F1A2-3C7D-4E89-9A1F-7D6B3E2C8F4A}
AppName={#MyAppNameLong}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} v{#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
AppCopyright={#MyAppCopyright}
DefaultDirName={autopf}\VigilServe
DefaultGroupName=VigilServe
DisableProgramGroupPage=yes
LicenseFile=license.txt
InfoBeforeFile=
OutputDir=output
OutputBaseFilename=VigilServe-Setup-{#MyAppVersion}
SetupIconFile=branding\installer.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
UninstallDisplayIcon={app}\tray\VigilServeTray.exe
UninstallDisplayName={#MyAppNameLong}
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Installer
VersionInfoCopyright={#MyAppCopyright}
VersionInfoProductName={#MyAppName}
MinVersion=10.0
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "simpchinese"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Messages]
simpchinese.WelcomeLabel2=本安装程序将引导您完成 VigilServe 在您计算机上的安装。%n%nVigilServe 是一款面向中小团队的服务器运维与监控平台，支持远程主机纳管、服务进程采集、资源管理、Web 终端与告警推送。%n%n请在继续之前关闭其他 VigilServe 进程，建议先阅读并同意《用户协议》。%n%n[AppVerName]

[CustomMessages]
CreateDesktopIcon=创建桌面快捷方式
LaunchAfterInstall=关闭安装窗口后自动启动托盘程序
EnableAutoStart=开机启动
StartupOptions=启动选项:
AdditionalIcons=附加图标:

[Tasks]
; 桌面快捷方式默认勾选：控制台是日常入口，装完找不到入口是最常见的"装了像没装"。
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "launchtray"; Description: "{cm:LaunchAfterInstall}"; GroupDescription: "{cm:StartupOptions}"
Name: "autostart"; Description: "{cm:EnableAutoStart}"; GroupDescription: "{cm:StartupOptions}"

[Files]
Source: "source\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "branding\installer.ico"; DestDir: "{app}\branding"; Flags: ignoreversion
; License file (so it's available post-install too)
Source: "license.txt"; DestDir: "{app}"; Flags: ignoreversion
; 同一份停服脚本再嵌一份（不安装），供 [Code] 用 ExtractTemporaryFile 取到 {tmp}。
; 为什么需要：覆盖安装（升级）时走到 ssInstall 这一步**新文件还没落地**，
; 而 1.1.45 之前的旧版本里 {app} 下根本没有这份脚本 —— 只认 {app} 的路径
; 在升级场景会直接落空，python 继续占着文件，安装卡在「无法删除/替换文件」。
Source: "scripts\stop_services.bat"; Flags: dontcopy

[InstallDelete]
; A `.deps_installed` marker is NOT part of the shipped tree (the build strips
; it), but Inno leaves files behind on upgrade that the new source does not
; contain. One from an earlier release would tell the tray its dependencies are
; fine and let a broken runtime survive the upgrade, so always drop it.
Type: files; Name: "{app}\backend\.deps_installed"

[Dirs]
; Ensure log / data directories exist on first install.
;
; Permissions: users-modify —— {app} 默认是 C:\Program Files\VigilServe，
; 受 UAC 保护、Users 组只有读+执行。而运行期要往 {app}\backend 下写：
;   monitor.db / monitor.db-wal / monitor.db-shm   （SQLite 运行库）
;   data\initial_admin_password.txt                （首装随机口令）
;   data\secret.key / data\web_ticket_epoch.json   （Fernet 密钥 / 票据 epoch）
;   certs\                                         （本地 CA 与服务器证书）
;   .deps_installed                                （start.bat 依赖标记）
; 未提权启动时这些写入全被拒，表现为「账号已建但初始口令文件不存在」这类
; 很难从界面看出根因的故障。这里显式授权，installer 之外的启动方式也不会踩。
Name: "{app}\logs"; Permissions: users-modify
Name: "{app}\backend"; Permissions: users-modify
Name: "{app}\backend\data"; Permissions: users-modify

[Icons]
; --panel：托盘程序启动后**直接打开控制面板窗口**。没有这个参数它只在系统托盘
; 里放个图标，用户双击快捷方式看不到任何反应，会以为没启动成功。
Name: "{group}\VigilServe 服务控制台"; Filename: "{app}\tray\VigilServeTray.exe"; Parameters: "--panel"
Name: "{group}\卸载 VigilServe"; Filename: "{uninstallexe}"
Name: "{commondesktop}\VigilServe 服务控制台"; Filename: "{app}\tray\VigilServeTray.exe"; Parameters: "--panel"; Tasks: desktopicon
; Native Startup-folder shortcut for autostart task - Inno handles install/uninstall
; automatically, no blocking [Run] entry needed (which previously hung the installer due
; to the hidden setup_autostart.bat pause prompt under LF-only line endings).
; Use {commonstartup} because the installer runs in admin mode; {userstartup} in admin
; mode resolves to the admin user's profile and silently fails for non-admin logons.
; 开机自启**故意不带 --panel**：每次登录都弹控制面板窗口很烦，自启只要驻留托盘即可。
Name: "{commonstartup}\VigilServe 服务控制台"; Filename: "{app}\tray\VigilServeTray.exe"; WorkingDir: "{app}"; Tasks: autostart

[Registry]
Root: HKLM; Subkey: "Software\VigilServe"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\VigilServe"; ValueType: string; ValueName: "Version"; ValueData: "{#MyAppVersion}"; Flags: uninsdeletekey

[Run]
; Launch the tray program immediately after install (if user wants). The flag
; combination below ensures Inno does NOT block waiting for the batch to terminate.
;
; 这里**故意不写 postinstall**：带了这个 flag 的 [Run] 条目会被 Inno 渲染成
; 「安装完成」页上的第二个勾选框 —— 而 [Tasks] 里已经有同名同义的 launchtray
; （出现在「选择附加任务」页）。结果是同一样勾选被问两次：
;   安装前一次：「关闭安装窗口后自动启动托盘程序」
;   安装结束时又一次：同样的文案
; 去掉 postinstall 之后：勾选只在「选择附加任务」页出现一次，用户勾了就在安装
; 收尾时直接拉起托盘，不再于最后一页重复提示。Description 也随之删除（它只在
; postinstall 的勾选框里用得上，留着反而容易被人再加回 postinstall）。
; 🚨 2026-09-30：这一条 [Run] **已移除**，改由 [Code] 里的 `ssDone` 拉起托盘。
;
;   原因：不带 `postinstall` 的 [Run] 条目会在**安装步骤一结束、「完成」页还没点**
;   的时候就执行 —— 现场表现是：安装向导窗口还开着，托盘已经起来并把配置面板
;   弹到前台，用户以为安装还没完就先跳出了一个窗口。
;
;   那加回 `postinstall` 行不行？不行：带 postinstall 的条目会被 Inno 渲染成
;   「安装完成」页上的又一个勾选框，而 [Tasks] 里已经有同义的 launchtray
;   （出现在「选择附加任务」页）—— 同一样事就会问两次。
;
;   所以正确位置是 `ssDone`：勾选只出现一次（在选择附加任务页），真正启动推迟到
;   用户点完「完成」、向导关闭之后。
; NOTE: the autostart task is now implemented via the native [Icons] entry above
; pointing at {userstartup}, so there is no blocking [Run] entry needed.

[UninstallDelete]
; Remove generated logs / bundled docs / runtime markers on uninstall.
;
; 🚨 `backend\data` / `backend\certs` / `backend\monitor.db*` **故意不在这里删**
; —— 它们必须同进同退（原因见 AskPurgeDataOnUninstall 的注释），删不删由操作员
; 在卸载时决定，不能由脚本单方面拍板。
;
; 但下面这些**纯安装产物**是无条件删的：里面没有任何用户数据，留着只会占地方。
; 2026-09-29 补：原先把它们交给 Inno「删自己记录过的文件」处理，可是**运行期
; 生成的文件不在记录里** —— 最典型的是 `__pycache__`（python 一导入就生成）。
; 目录里只要剩一个它不认识的文件，整个目录就删不掉，现场表现是卸载完
; `C:\Program Files\VigilServe` 里还杵着 `backend` 与 `python_runtime` 两个
; 文件夹、约 30 MB（用户 1.1.57 实测）。`filesandordirs` 是整树删，不挑文件。
Type: filesandordirs; Name: "{app}\python_runtime"
Type: filesandordirs; Name: "{app}\frontend"
Type: filesandordirs; Name: "{app}\tray"
Type: filesandordirs; Name: "{app}\branding"
Type: filesandordirs; Name: "{app}\scripts"
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\docs_bundle"
Type: files; Name: "{app}\backend\.deps_installed"
Type: files; Name: "{app}\.first_run_done"
Type: files; Name: "{app}\install_options.ini"
; `backend` 下散落的 `__pycache__` 由 [Code] 里的 CleanupInstallDir 递归处理
; （取决于操作员选「清除/保留数据」，无法在这里用无条件条目表达）。
; 最后这一条是兜底：上面都删干净后，Inno 会再尝试删一次空的 {app}。
Type: dirifempty; Name: "{app}"

[Code]
const
  MyAppVersionStr = '{#MyAppVersion}';

var
  // 卸载时操作员是否选了「清除数据」。
  // 🚨 必须声明在这里：[Code] 里函数内 var 声明的是**局部**变量，跨过程传不出去，
  // 而「问」发生在 usUninstall、「删目录」发生在 usPostUninstall，是两个回调。
  PurgeDataOnUninstall: Boolean;

function BoolToStr(b: Boolean): String;
begin
  if b then
    Result := 'true'
  else
    Result := 'false';
end;

// 停服：托盘连子进程树一起结束，再按映像路径 / 监听端口清理残留 python。
// 全程只认「属于本安装目录」的进程，绝不使用 `taskkill /F /IM python.exe`
// （那会杀掉机器上所有 Python）。
//
// UseTempCopy=True 时从 {tmp} 取脚本（[Files] 里那份 dontcopy），
// 用于**新文件还未落地**的升级场景；False 时用已安装的 {app} 那份，用于卸载。
// 两种情况下都把 {app} 作为 %1 传进去，脚本才知道该清理谁。
procedure StopVigilServices(UseTempCopy: Boolean);
var
  ResultCode: Integer;
  BatPath: String;
begin
  // 托盘及其子进程树：后端与 WEB 代理都是托盘 Popen 拉起的，只杀托盘会留下孤儿。
  Exec(ExpandConstant('cmd.exe'), '/C taskkill /F /T /IM VigilServeTray.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if UseTempCopy then
  begin
    ExtractTemporaryFile('stop_services.bat');
    BatPath := ExpandConstant('{tmp}\stop_services.bat');
  end
  else
    BatPath := ExpandConstant('{app}\stop_services.bat');
  if FileExists(BatPath) then
    Exec(ExpandConstant('cmd.exe'), '/C "' + BatPath + '" "' + ExpandConstant('{app}') + '"', ExpandConstant('{tmp}'), SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// Hook to write install options into a config file so the tray program
// knows whether to auto-start the backend service on launch.
procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfigPath: String;
  ConfigText: String;
  ResultCode: Integer;
begin
  // ssInstall：真正开始拷文件之前。Inno 自带的 CloseApplications 只给「有窗口」
  // 的程序发 WM_CLOSE，对无窗口的 python（8001/8009）无效，所以这里自己停。
  // 覆盖安装（升级）走的正是这条路径 —— 1.1.45 之前只改了卸载钩子，升级照样被占用。
  if CurStep = ssInstall then
    StopVigilServices(True);
  if CurStep = ssPostInstall then
  begin
    ConfigPath := ExpandConstant('{app}\install_options.ini');
    ConfigText :=
      'launch_tray=' + BoolToStr(WizardIsTaskSelected('launchtray')) + #13#10 +
      'auto_start=' + BoolToStr(WizardIsTaskSelected('autostart')) + #13#10 +
      'install_dir=' + ExpandConstant('{app}') + #13#10 +
      'install_version=' + MyAppVersionStr + #13#10;
    SaveStringToFile(ConfigPath, ConfigText, False);
  end;
  // ssDone：用户已经点了「完成」、向导窗口关闭之后。
  // 托盘必须等到这一步才起来 —— 早于此（例如放在 [Run] 里不带 postinstall）
  // 就会出现「安装窗口还开着，配置面板先弹出来」。
  if CurStep = ssDone then
  begin
    // 静默安装保持原来的行为（原 [Run] 条目带 skipifsilent）：不拉起托盘。
    if (not WizardSilent()) and WizardIsTaskSelected('launchtray') then
      Exec(ExpandConstant('{app}\start_tray.bat'), '', ExpandConstant('{app}'),
           SW_SHOW, ewNoWait, ResultCode);
  end;
end;

// 卸载时询问是否清除数据。
//
// 🚨 为什么必须问一句，而不是脚本自己决定：
//   `backend\data\secret.key` 是主机凭据（WinRM/SSH/WEB/SNMPv3 口令）的 Fernet
//   密钥，`backend\monitor.db` 里存着用它加密的密文。以前卸载无条件删 data、
//   留 monitor.db —— 重装后密钥是新生成的、库里还是旧密文，decrypt_secret()
//   解密失败又静默返回空串，结果是所有主机凭据集体失效且**没有任何告警**
//   （这个组合是在现场重装排查时发现的最危险一处）。
//   两者必须同进同退，所以把选择权交回给操作员。
//
// 默认按钮是「否」（MB_DEFBUTTON2）：静默卸载时 MsgBox 不弹窗、返回默认按钮，
//   若默认是「是」就会在无人确认的情况下清空数据 —— 那正是要避免的事故。
//
// 🚨 **只问不删**：真正的删除在下面 `CleanupInstallDir` 里做，且必须排在
// `StopVigilServices` **之后** —— 后端 python 正握着 monitor.db 的句柄，
// 先删库只会得到一堆「文件正在使用」的失败，目录照样留着。
procedure AskPurgeDataOnUninstall;
begin
  PurgeDataOnUninstall := False;
  PurgeDataOnUninstall := MsgBox('是否同时清除本机保存的数据？' + #13#10 + #13#10 +
            '包括：监控数据库、主机凭据密钥、服务端证书。' + #13#10 +
            '选择「是」会连 VigilServe 整个安装目录一并删除，' + #13#10 +
            '重新安装不保留任何历史数据。' + #13#10 + #13#10 +
            '选择「否」将保留这些数据，便于重新安装后继续使用。',
            mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
end;

// 递归删掉目录树里的 `__pycache__`。
//
// 🚨 为什么需要：Inno 默认只删「它自己安装时记录过的文件」，`__pycache__`
// 是 python 一导入就生成的，**根本不在记录里**。目录里只要还剩一个它不认识的
// 文件，整个目录就删不掉 —— 现场表现是卸载完 `C:\Program Files\VigilServe`
// 里还杵着 `backend` 与 `python_runtime` 两个文件夹、约 30 MB（1.1.57 实测）。
//
// 只对 `backend` 用：别处（python_runtime / frontend / tray）要么会被
// `[UninstallDelete]` 的 filesandordirs 整树删掉，要么在清除数据时被 DelTree。
procedure RemovePyCache(const Dir: String);
var
  FindRec: TFindRec;
  Sub: String;
begin
  if not FindFirst(Dir + '\*', FindRec) then
    Exit;
  try
    repeat
      if (FindRec.Name <> '.') and (FindRec.Name <> '..') then
      begin
        Sub := Dir + '\' + FindRec.Name;
        if (FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY) <> 0 then
        begin
          if FindRec.Name = '__pycache__' then
            DelTree(Sub, True, True, True)
          else
            RemovePyCache(Sub);
        end;
      end;
    until not FindNext(FindRec);
  finally
    FindClose(FindRec);
  end;
end;

// 选了「清除数据」时把 {app} 整个清空，只留下卸载器自己的文件。
//
// 为什么不能只靠 `[UninstallDelete]`：见 RemovePyCache 的说明。`filesandordirs`
// 虽然也是整树删，但它是无条件执行的，没法表达「仅在操作员选清除时」；
// 而 `backend\data` 里存着凭据密钥，绝不能无条件删。
//
// 🚨 `unins*.exe` / `unins*.dat` **必须跳过**：此刻卸载器正从 {app} 里运行，
// Windows 不允许删除正在运行的可执行文件，硬删只会留下一个删不掉的孤立 exe。
// 等 Inno 走完自己的流程会把它删掉，那时 {app} 已经空了，目录随即消失。
procedure CleanupInstallDir;
var
  FindRec: TFindRec;
  Entry: String;
begin
  if not FindFirst(ExpandConstant('{app}\*'), FindRec) then
    Exit;
  try
    repeat
      Entry := FindRec.Name;
      if (Entry <> '.') and (Entry <> '..') and (Pos('unins', Lowercase(Entry)) <> 1) then
      begin
        if (FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY) <> 0 then
          DelTree(ExpandConstant('{app}') + '\' + Entry, True, True, True)
        else
          DeleteFile(ExpandConstant('{app}') + '\' + Entry);
      end;
    until not FindNext(FindRec);
  finally
    FindClose(FindRec);
  end;
end;

// 延迟删目录。
//
// 卸载器此刻正从目标目录里运行，`DelTree` 删不掉它自己；但 usPostUninstall
// 一返回，卸载器进程就会退出。这里拉起一个独立 cmd，先等 5 秒（`ping -n 6`
// 是 5 次间隔）再 `rd /s /q`，那时句柄已经全放开了。
// `ewNoWait` 是不阻塞卸载向导 —— 这个 cmd 的命是独立的，父进程退出也照跑。
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

// Hook to clean up before uninstall.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    // 先问（人读提示要时间，趁这会儿把下面的活排好），再停服，最后才动文件。
    AskPurgeDataOnUninstall;
    // Stop running services to avoid file-in-use errors. The Startup-folder
    // autostart shortcut (created by the native [Icons] entry above) is
    // removed automatically by Inno Setup, so no remove_autostart.bat
    // invocation is required here.
    //
    // ⚠ 后端 (main.py:8001) 与设备 WEB 代理 (web_proxy_server.py:8009) 都是
    // **无窗口**的 python 进程：Inno 自带的 CloseApplications 只对有窗口的
    // 程序发 WM_CLOSE，对它们无效；以前那句按 WINDOWTITLE 过滤的 taskkill
    // 也永远匹配不上（没有窗口就没有标题）。结果就是 python_runtime\python.exe
    // 一直占着文件，卸载失败。
    //
    // 卸载时 {app} 里一定有这份脚本（本卸载器本身就是 1.1.45+ 装出来的），
    // 直接用它，不必再解一份到 {tmp}。
    // 🚨 必须排在清目录之前：脚本本身就在 {app} 里，先删就跑不成了。
    StopVigilServices(False);
    if PurgeDataOnUninstall then
      CleanupInstallDir
    else
      // 保留数据：backend 会留下（里面有 data / certs / monitor.db）。
      // 但里面运行期生成的 __pycache__ 该清掉 —— 它不在 Inno 的安装记录里，
      // 留着既占地方又让目录看起来像没卸干净。
      RemovePyCache(ExpandConstant('{app}\backend'));
  end
  else if CurUninstallStep = usPostUninstall then
  begin
    // 兜底：Inno 自己的删除流程走完后再来一次，把 {app} 彻底抹掉
    // （此时 {app} 里最多只剩 unins*.exe，等卸载器退出即可删）。
    if PurgeDataOnUninstall then
      ScheduleDeferredDirRemove(ExpandConstant('{app}'));
  end;
end;
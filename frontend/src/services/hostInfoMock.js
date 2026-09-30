/* 主机信息 / 应用管理 / 事件日志 —— 阶段一 Mock 数据。
 *
 * 这是**数据契约**：后端 + Agent 采集落地后必须返回同样的结构，
 * 组件不用改（只把 services/hostInfo.js 的 USE_MOCK 置为 false）。
 *
 * 字段说明（AIDA64 风格，尽量细化）：
 * - 值为 null / [] 表示「采集不到」，前端显示「—」，不臆造数据 */
/**
 * 系统启动项 —— 主机信息与「应用管理 / 启动项管理」共用同一份数据。
 * 每项必须带 id（切换启用状态时要按 id 下发）。
 */
const STARTUP = [
  { id: 's1', name: 'VigilServeAgent', command: '"C:\\Program Files\\VigilServe\\Agent\\VigilServeAgent.exe"', location: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', enabled: true, impact: '低' },
  { id: 's2', name: 'SecurityHealth', command: '%ProgramFiles%\\Windows Defender\\MSASCuiL.exe', location: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', enabled: true, impact: '低' },
  { id: 's3', name: 'Dell Peripheral Manager', command: '"C:\\Program Files\\Dell\\DPM\\DPM.exe"', location: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', enabled: false, impact: '中' },
  { id: 's4', name: 'OneDrive', command: '"C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background', location: 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', enabled: false, impact: '低' },
]

export function mockHostInfo(serverName) {
  return {
    collected_at: '2026-09-16 16:20:31',
    agent_version: '1.1.68',
    machine: {
      computer_name: serverName || 'EXAMPLE-HOST',
      domain: 'WORKGROUP',
      manufacturer: 'Dell Inc.',
      model: 'PowerEdge T340',
      serial: '8K2Q9X2',
      chassis_type: '塔式',
      bios: { vendor: 'Dell Inc.', version: '2.15.0', date: '2023-11-08', mode: 'UEFI' },
      motherboard: { manufacturer: 'Dell Inc.', model: '0H7V4D', chipset: 'Intel C246', serial: '/8K2Q9X2/CN129636AK00CC/' },
    },
    os: {
      name: 'Microsoft Windows Server 2016 Standard',
      version: '10.0',
      build: '14393.6931',
      edition: 'Standard',
      arch: 'x64',
      install_date: '2024-03-12 09:41:07',
      last_boot: '2026-09-09 07:12:55',
      uptime_seconds: 7 * 86400 + 9 * 3600 + 7 * 60 + 36,
      timezone: '(UTC+08:00) 北京，重庆，香港特别行政区，乌鲁木齐',
      system_dir: 'C:\\Windows\\system32',
      product_id: '00429-70000-00000-AA123',
      locale: 'zh-CN',
    },
    security: {
      uac: '默认 — 仅在应用尝试更改计算机时通知',
      secure_boot: '已启用',
      tpm: { present: true, version: '2.0', ready: true },
      firewall: { domain: '已启用', private: '已启用', public: '已启用' },
      defender: {
        name: 'Windows Defender 防病毒',
        enabled: true,
        realtime_protection: true,
        tamper_protection: true,
        cloud_protection: true,
        antispyware: true,
        antivirus: true,
        engine_version: '1.1.24090.1',
        signature_version: '1.407.1234.0',
        signature_updated: '2026-09-16 03:11:02',
        last_scan: '2026-09-15 02:00:00',
        last_scan_type: '快速扫描',
      },
      products: [
        { type: '防病毒', name: 'Windows Defender 防病毒', state: '已启用', up_to_date: true },
        { type: '防火墙', name: 'Windows 防火墙', state: '已启用', up_to_date: true },
        { type: '反间谍软件', name: 'Windows Defender 防病毒', state: '已启用', up_to_date: true },
      ],
      bitlocker: [{ drive: 'C:', status: '已加密', protection: '开启', encryption: 'XTS-AES 128' }],
    },
    updates: {
      auto_update: '自动下载并计划安装',
      last_check: '2026-09-16 06:32:18',
      last_installed: '2026-09-15 03:05:41',
      pending_count: 2,
      pending: [
        { kb: 'KB5046617', title: '2026-09 适用于 Windows Server 2016 的累积更新（x64）', severity: '重要', released: '2026-09-10', category: '安全更新', reboot_required: true },
        { kb: 'KB890830', title: 'Windows 恶意软件删除工具 x64', severity: '低', released: '2026-09-09', category: '工具', reboot_required: false },
      ],
      installed_recent: [
        { kb: 'KB5045585', title: '2026-08 累积更新', installed_on: '2026-09-15 03:05:41' },
        { kb: 'KB5044000', title: '.NET Framework 4.8 累积更新', installed_on: '2026-09-02 04:12:09' },
      ],
      failed: [],
    },
    users: {
      current: { name: 'Administrator', domain: 'EXAMPLE-HOST', logon_time: '2026-09-16 08:14:22', session: '控制台', elevated: true },
      accounts: [
        { name: 'Administrator', full_name: '内置管理员', enabled: true, admin: true, locked: false, password_expires: false, last_logon: '2026-09-16 08:14:22', description: '管理计算机(域)的内置帐户' },
        { name: 'svc_backup', full_name: '备份服务账号', enabled: true, admin: false, locked: false, password_expires: false, last_logon: '2026-09-16 01:00:03', description: '定时备份任务专用' },
        { name: 'Guest', full_name: '来宾', enabled: false, admin: false, locked: false, password_expires: false, last_logon: '从未', description: '供来宾访问计算机的内置帐户' },
        { name: 'DefaultAccount', full_name: '默认账户', enabled: false, admin: false, locked: false, password_expires: false, last_logon: '从未', description: '系统管理的用户帐户' },
      ],
    },
    startup: STARTUP.map((s) => ({ ...s })),
    shares: [
      { name: 'ADMIN$', path: 'C:\\Windows', description: '远程管理', access: '管理员', hidden: true },
      { name: 'C$', path: 'C:\\', description: '默认共享', access: '管理员', hidden: true },
      { name: '数据备份', path: 'D:\\Backup', description: '每日镜像备份', access: 'Everyone:读取', hidden: false },
      { name: '公共文档', path: 'E:\\Public', description: '部门共享', access: 'Everyone:读写', hidden: false },
    ],
    cpu: {
      model: 'Intel Xeon E-2224',
      vendor: 'GenuineIntel',
      sockets: 1,
      cores: 4,
      threads: 4,
      base_mhz: 3400,
      current_mhz: 4100,
      max_mhz: 4600,
      cache: { l1d: '4 × 32 KB', l1i: '4 × 32 KB', l2: '4 × 256 KB', l3: '8 MB' },
      temperature: 52,
      package_power: 41.2,
      usage: 23.4,
      process: '14 nm',
      features: ['AES-NI', 'AVX2', 'VT-x', 'VT-d', 'Turbo Boost 2.0'],
      load_per_core: [31, 24, 18, 20],
    },
    memory: {
      total_gb: 32,
      slots_used: 2,
      slots_total: 4,
      type: 'DDR4',
      channels: '双通道',
      speed_mhz: 2666,
      usage: 46.8,
      modules: [
        { slot: 'DIMM_A1', capacity_gb: 16, type: 'DDR4-2666', speed_mhz: 2666, manufacturer: 'Samsung', part_number: 'M391A2K43BB1-CTD', voltage: 1.2, temperature: 44, ecc: true },
        { slot: 'DIMM_B1', capacity_gb: 16, type: 'DDR4-2666', speed_mhz: 2666, manufacturer: 'Samsung', part_number: 'M391A2K43BB1-CTD', voltage: 1.2, temperature: 45, ecc: true },
      ],
    },
    storage: [
      {
        model: 'Samsung SSD 870 EVO 1TB',
        interface: 'SATA III',
        media_type: 'SSD',
        size_gb: 931.5,
        serial: 'S5SUNJ0R123456K',
        firmware: 'SVT02B6Q',
        temperature: 34,
        health: '良好 (98%)',
        smart: { power_on_hours: 9421, power_cycle_count: 213, reallocated_sectors: 0, wear_leveling: '92%' },
        partitions: [
          { letter: 'C:', label: '系统', fs: 'NTFS', size_gb: 200, used_gb: 118.4, free_gb: 81.6, percent: 59 },
          { letter: 'D:', label: '数据', fs: 'NTFS', size_gb: 731.5, used_gb: 402.1, free_gb: 329.4, percent: 55 },
        ],
      },
      {
        model: 'WDC WD40EZAZ-00SF3B0',
        interface: 'SATA III',
        media_type: 'HDD',
        size_gb: 3726,
        serial: 'WD-WX12A80TUVXY',
        firmware: '80.00A80',
        temperature: 39,
        health: '良好 (100%)',
        smart: { power_on_hours: 12603, power_cycle_count: 96, reallocated_sectors: 0, wear_leveling: null },
        partitions: [
          { letter: 'E:', label: '归档', fs: 'NTFS', size_gb: 3725, used_gb: 2980.6, free_gb: 744.4, percent: 80 },
        ],
      },
    ],
    network: [
      {
        name: 'Intel(R) Ethernet Connection I219-LM',
        type: '以太网',
        mac: 'F4:8E:38:1A:2B:3C',
        ipv4: ['192.0.2.10/24'],
        ipv6: ['fe80::4d1:9f2a:3c7b:8e10'],
        gateway: ['192.0.2.1'],
        dns: ['192.0.2.1', '192.0.2.2'],
        dhcp: false,
        speed: '1 Gbps',
        mtu: 1500,
        status: '已连接',
        vlan: null,
      },
      {
        name: 'Intel(R) Ethernet Server Adapter I350-T2 #2',
        type: '以太网',
        mac: 'A0:36:9F:7C:1D:22',
        ipv4: [],
        ipv6: [],
        gateway: [],
        dns: [],
        dhcp: true,
        speed: '1 Gbps',
        mtu: 1500,
        status: '已断开',
        vlan: null,
      },
    ],
    displays: [
      { index: 1, name: 'DELL P2419H (DP)', primary: true, x: 0, y: 0, width: 1920, height: 1080, refresh: 60, scale: 100, orientation: '横向', connection: 'DisplayPort' },
      { index: 2, name: 'DELL P2419H (HDMI)', primary: false, x: 1920, y: 0, width: 1920, height: 1080, refresh: 60, scale: 100, orientation: '横向', connection: 'HDMI' },
      { index: 3, name: 'Lenovo L24q-30 (DP)', primary: false, x: -2560, y: -180, width: 2560, height: 1440, refresh: 75, scale: 125, orientation: '横向', connection: 'DisplayPort' },
    ],
    devices: [
      { category: '主板', name: 'Dell 0H7V4D', vendor: 'Dell Inc.', status: '正常', details: 'Intel C246 芯片组' },
      { category: '显示适配器', name: 'NVIDIA Quadro P620', vendor: 'NVIDIA', status: '正常', details: '2 GB GDDR5，驱动 31.0.15.3623' },
      { category: '显示适配器', name: 'Matrox/VIA 集成显卡', vendor: 'Intel', status: '正常', details: 'UHD Graphics P630' },
      { category: '存储控制器', name: 'Intel C246 SATA AHCI', vendor: 'Intel', status: '正常', details: '' },
      { category: '存储控制器', name: 'PERC H330 Adapter', vendor: 'Dell', status: '正常', details: 'RAID 1' },
      { category: '网络适配器', name: 'Intel I219-LM', vendor: 'Intel', status: '正常', details: '' },
      { category: '网络适配器', name: 'Intel I350-T2', vendor: 'Intel', status: '正常', details: '' },
      { category: '声音设备', name: 'Realtek High Definition Audio', vendor: 'Realtek', status: '正常', details: '' },
      { category: '键盘', name: 'Dell KB216 有线键盘', vendor: 'Dell', status: '正常', details: 'HID' },
      { category: '鼠标', name: 'Dell MS116 光电鼠标', vendor: 'Dell', status: '正常', details: 'HID' },
      { category: 'USB 设备', name: 'USB 大容量存储设备 (SanDisk U盘)', vendor: 'SanDisk', status: '正常', details: 'USB 3.0' },
      { category: '打印机', name: 'HP LaserJet M403', vendor: 'HP', status: '正常', details: '默认打印机' },
      { category: '电池/UPS', name: 'APC Smart-UPS 1500', vendor: 'APC', status: '正常', details: 'USB 连接，电量 100%' },
      { category: '安全设备', name: 'TPM 2.0', vendor: 'Infineon', status: '正常', details: '已启用' },
    ],
  }
}

export function mockApplications() {
  const app = (o) => ({
    source: 'registry',
    uninstallable: true,
    scope: 'user',
    size_mb: null,
    install_location: null,
    ...o,
  })
  return [
    app({ id: 'a1', name: 'Google Chrome', version: '128.0.6613.138', publisher: 'Google LLC', installed_on: '2026-05-12', scope: 'user', size_mb: 512, install_location: 'C:\\Program Files\\Google\\Chrome', uninstall_cmd: '"C:\\Program Files\\Google\\Chrome\\Application\\128.0.6613.138\\Installer\\setup.exe" --uninstall' }),
    app({ id: 'a2', name: 'WPS Office', version: '12.1.0.20356', publisher: 'Kingsoft', installed_on: '2025-11-03', scope: 'user', size_mb: 1024, install_location: 'C:\\Users\\Administrator\\AppData\\Local\\Kingsoft\\WPS Office', uninstall_cmd: '"C:\\Users\\Administrator\\AppData\\Local\\Kingsoft\\WPS Office\\uninstall.exe"' }),
    app({ id: 'a3', name: '7-Zip', version: '24.07', publisher: 'Igor Pavlov', installed_on: '2024-08-21', scope: 'user', size_mb: 5, install_location: 'C:\\Program Files\\7-Zip', uninstall_cmd: '"C:\\Program Files\\7-Zip\\Uninstall.exe"' }),
    app({ id: 'a4', name: 'VigilServe Agent', version: '1.1.63', publisher: 'VigilServe', installed_on: '2026-07-30', scope: 'user', size_mb: 78, install_location: 'C:\\Program Files\\VigilServe\\Agent', uninstall_cmd: '"C:\\Program Files\\VigilServe\\Agent\\uninstall.exe" /S' }),
    app({ id: 'a5', name: 'Microsoft Visual C++ 2015-2022 Redistributable (x64)', version: '14.40.33810', publisher: 'Microsoft Corporation', installed_on: '2024-03-12', scope: 'system', size_mb: 25, install_location: null, uninstall_cmd: 'MsiExec.exe /X{...}' }),
    app({ id: 'a6', name: 'Microsoft .NET Runtime 8.0.8 (x64)', version: '8.0.8', publisher: 'Microsoft Corporation', installed_on: '2026-02-02', scope: 'system', size_mb: 90, install_location: null, uninstall_cmd: 'MsiExec.exe /X{...}' }),
    app({ id: 'a7', name: 'Windows Defender 防病毒', version: '4.18.24090.1', publisher: 'Microsoft Corporation', installed_on: '2024-03-12', scope: 'system', uninstallable: false, size_mb: null, install_location: null, uninstall_cmd: null }),
    app({ id: 'a8', name: 'Microsoft Edge WebView2 Runtime', version: '128.0.2739.42', publisher: 'Microsoft Corporation', installed_on: '2025-09-18', scope: 'system', size_mb: 180, install_location: null, uninstall_cmd: 'MsiExec.exe /X{...}' }),
    app({ id: 'a9', name: 'TeamViewer', version: '15.56.6', publisher: 'TeamViewer GmbH', installed_on: '2025-04-09', scope: 'user', size_mb: 140, install_location: 'C:\\Program Files\\TeamViewer', uninstall_cmd: '"C:\\Program Files\\TeamViewer\\uninstall.exe"' }),
    app({ id: 'a10', name: 'SQL Server Management Studio', version: '20.1.10.0', publisher: 'Microsoft Corporation', installed_on: '2025-06-25', scope: 'user', size_mb: 780, install_location: 'C:\\Program Files (x86)\\Microsoft SQL Server Management Studio 20', uninstall_cmd: 'MsiExec.exe /X{...}' }),
  ]
}

export function mockUpdates() {
  return [
    { id: 'u1', kb: 'KB5046617', title: '2026-09 适用于 Windows Server 2016 的累积更新（x64）', category: '安全更新', installed_on: '2026-09-10', severity: '重要', uninstall_cmd: 'wusa /uninstall /kb:5046617' },
    { id: 'u2', kb: 'KB5045585', title: '2026-08 累积更新', category: '安全更新', installed_on: '2026-09-15', severity: '重要', uninstall_cmd: 'wusa /uninstall /kb:5045585' },
    { id: 'u3', kb: 'KB890830', title: 'Windows 恶意软件删除工具 x64', category: '工具', installed_on: '2026-09-09', severity: '低', uninstall_cmd: null },
    { id: 'u4', kb: 'KB5044000', title: '.NET Framework 4.8 累积更新', category: '重要更新', installed_on: '2026-09-02', severity: '中等', uninstall_cmd: 'wusa /uninstall /kb:5044000' },
  ]
}

export function mockStartup() {
  return STARTUP.map((s) => ({ ...s }))
}

export function mockEventLogs() {
  return [
    { id: 'e1', time: '2026-09-16 15:48:12', source: 'Microsoft-Windows-Winsrv', event_id: 10001, level: '错误', category: '系统', message: '服务 VSS 意外终止。已执行自动恢复操作。' },
    { id: 'e2', time: '2026-09-16 14:02:41', source: 'Disk', event_id: 51, level: '警告', category: '系统', message: '在设备 \\Device\\Harddisk1\\DR1 上检测到分页错误。' },
    { id: 'e3', time: '2026-09-16 09:11:03', source: 'Service Control Manager', event_id: 7036, level: '信息', category: '系统', message: 'VigilServeAgent 服务已进入 运行 状态。' },
    { id: 'e4', time: '2026-09-16 07:12:55', source: 'Kernel-General', event_id: 12, level: '信息', category: '系统', message: '操作系统已启动（系统启动时间）。' },
    { id: 'e5', time: '2026-09-15 23:31:20', source: 'Microsoft-Windows-Security-Auditing', event_id: 4625, level: '严重', category: '安全', message: '帐户登录失败。登录类型 3，用户 svc_backup。' },
    { id: 'e6', time: '2026-09-15 20:07:44', source: 'Ntfs', event_id: 55, level: '错误', category: '系统', message: '文件系统结构已损坏，请运行 chkdsk。' },
    { id: 'e7', time: '2026-09-15 03:05:41', source: 'Microsoft-Windows-WindowsUpdateClient', event_id: 19, level: '信息', category: '系统', message: '已成功安装更新 KB5045585。' },
  ]
}

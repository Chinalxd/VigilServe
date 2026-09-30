"""Real remote agent — executes WinRM/SSH commands to detect server information.

Usage:
    agent = RemoteAgent(server)
    if agent.connect():
        info = agent.detect()
        # info = {"os_type": "...", "cpu_cores": 8, "total_memory_gb": 32.0,
        #         "disk_partitions": [...]}
"""

import json


class RemoteAgent:
    def __init__(self, server):
        self.server = server
        self.session = None

    def connect(self) -> bool:
        """Connect to the server using the configured protocol."""
        try:
            if self.server.protocol == "WinRM":
                return self._connect_winrm()
            elif self.server.protocol == "SSH":
                return self._connect_ssh()
            else:
                return False
        except Exception as e:
            print(f"[Agent] Connection failed to {self.server.name}: {e}")
            return False

    def _connect_winrm(self) -> bool:
        from winrm.protocol import Protocol

        # 交付审查 P1-6 复核（2026-09-23）：这里原先写死了 `http://`，于是那个
        # `server_cert_validation='ignore'` 是**死参数**，http 连接根本没有 TLS，
        # 参数不起作用，表现类似"关掉了证书校验"，实际暴露的是另一件事：整条管理链路
        # （含 NTLM 凭据与被执行的命令）跑在明文上。
        # 现在按端口选协议：5986 是 WinRM 的 HTTPS 端口 走 TLS 并用本地 CA 校验；
        # 其余（5985 等）维持 http，**现有部署行为不变**，但代码不再自欺欺人。
        # 要让某台主机真正加密，在设备上开 WinRM HTTPS 监听并把连接端口改到 5986。
        port = int(self.server.connection_port or 0)
        scheme = "https" if port == 5986 else "http"
        url = f"{scheme}://{self.server.ip_address}:{port}/wsman"

        kwargs = dict(
            endpoint=url,
            transport='ntlm',
            username=self.server.username,
            password=self.server.password_plain,
            read_timeout_sec=30,
            operation_timeout_sec=20,
        )
        if scheme == "https":
            kwargs["server_cert_validation"] = "validate"
            try:
                from services import tls as _tls
                if _tls.CA_CERT.exists():
                    kwargs["ca_trust_path"] = str(_tls.CA_CERT)
                else:
                    # 没有本地 CA 就退回系统信任库（仍然校验证书链）
                    kwargs["ca_trust_path"] = True
            except Exception:  # noqa: BLE001
                kwargs["server_cert_validation"] = "validate"
        else:
            # http：不存在证书校验这件事，参数保留仅为兼容旧行为
            kwargs["server_cert_validation"] = "ignore"

        self.session = Protocol(**kwargs)
        try:
            shell_id = self.session.open_shell()
            self.session.close_shell(shell_id)
            return True
        except:
            pass
        return False

    def _connect_ssh(self) -> bool:
        import paramiko
        self.session = paramiko.SSHClient()
        # S5：主机密钥钉扎，认证前比对，防中间人。
        # 原来这里是 WarningPolicy（只打日志就放行、不落盘不比对），等于连谁都信。
        # prepare_client() 会把已钉扎的公钥塞进 known_hosts 并设好首连策略。
        from services import ssh_pinning as pin
        pin.prepare_client(self.session, self.server)
        from paramiko.transport import Transport
        Transport._preferred_hostkeys = (
            'ssh-rsa', 'ssh-dss', 'ecdsa-sha2-nistp256',
            'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
            'ssh-ed25519',
        )
        try:
            self.session.connect(
                hostname=self.server.ip_address,
                port=self.server.connection_port,
                username=self.server.username,
                password=self.server.password_plain or None,
                timeout=15,
                look_for_keys=False,
                allow_agent=False,
                banner_timeout=15,
            )
        except Exception:
            # 认证前就被 paramiko 拦下（密钥不匹配）时，把对方出示的密钥记进 pending
            # 并告警，否则管理员只看到一句 SSHException，不知道对面现在是什么指纹。
            try:
                pin.note_connect_failure(self.server, self.session)
            except Exception:  # noqa: BLE001
                pass
            raise
        # 双保险：连上之后再复核一次。正常情况下上面那道已经拦住了；
        # 万一 paramiko 行为有变，也绝不会带着错误密钥去跑命令。
        pin.verify_after_connect(self.server, self.session)
        return True

    def detect(self) -> dict:
        """Run detection commands and return parsed results."""
        if not self.session:
            return {}
        try:
            if self.server.protocol == "WinRM":
                return self._detect_winrm()
            elif self.server.protocol == "SSH":
                return self._detect_ssh()
        except Exception as e:
            print(f"[Agent] Detection failed for {self.server.name}: {e}")
        return {}

    def _run_winrm(self, ps_cmd: str) -> str:
        """Run a PowerShell command via WinRM and return stdout."""
        import base64
        try:
            encoded = base64.b64encode(ps_cmd.encode('utf-16-le')).decode()
            full_cmd = f"powershell -NoProfile -EncodedCommand {encoded}"
            shell_id = self.session.open_shell()
            command_id = self.session.run_command(shell_id, full_cmd)
            stdout, stderr, code = self.session.get_command_output(shell_id, command_id)
            self.session.cleanup_command(shell_id, command_id)
            self.session.close_shell(shell_id)
            if code == 0:
                return stdout.decode('utf-8', errors='ignore').strip()
        except Exception as e:
            print(f"[Agent] WinRM exception on {self.server.name}: {e}")
            return ""

    def _run_ssh(self, cmd: str) -> str:
        """Run a shell command via SSH and return stdout."""
        try:
            _, stdout, stderr = self.session.exec_command(cmd, timeout=10)
            return stdout.read().decode('utf-8', errors='ignore').strip()
        except Exception as e:
            print(f"[Agent] SSH exception on {self.server.name}: {e}")
            return ""


    def _detect_winrm(self) -> dict:
        computer_name = self._run_winrm("$env:COMPUTERNAME")

        os_raw = self._run_winrm("(Get-CimInstance Win32_OperatingSystem).Caption")
        os_type = os_raw.strip() if os_raw else ""
        os_version = ""
        if "???" in os_type or not os_type:
            ver = self._run_winrm("(Get-CimInstance Win32_OperatingSystem).Version")
            build = self._run_winrm("(Get-CimInstance Win32_OperatingSystem).BuildNumber")
            if ver:
                os_type = _win_ver_to_name(ver.strip(), build.strip() if build else "", os_raw)

        try:
            build = self._run_winrm("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').CurrentBuildNumber")
            ubr = self._run_winrm("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').UBR")
            if build:
                os_version = f"{build}.{ubr}" if ubr else build
        except Exception:
            pass

        cpu_cores = 0
        cpu_model = ""
        cpu_raw = self._run_winrm("$cpu=Get-CimInstance Win32_Processor; $cpu.NumberOfLogicalProcessors")
        try:
            cpu_cores = int(cpu_raw.strip().split()[0])
        except:
            cpu_cores = 0
        model_raw = self._run_winrm("(Get-CimInstance Win32_Processor).Name")
        cpu_model = model_raw.strip().split("\n")[0].strip() if model_raw else ""

        mem_raw = self._run_winrm("$os=Get-CimInstance Win32_ComputerSystem; [math]::Round($os.TotalPhysicalMemory/1GB,1)")
        try:
            total_memory_gb = float(mem_raw.strip())
        except:
            total_memory_gb = 0.0

        disk_raw = self._run_winrm(
            "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | "
            "ForEach-Object { $s=[math]::Round($_.Size/1GB,1); $f=[math]::Round($_.FreeSpace/1GB,1); "
            "$u=$s-$f; $p=[math]::Round($u/$s*100,1); "
            "[PSCustomObject]@{DeviceID=$_.DeviceID;SizeGB=$s;FreeGB=$f;UsedGB=$u;Percent=$p;FileSystem=$_.FileSystem} } | "
            "ConvertTo-Json -Compress"
        )
        disk_partitions = self._parse_winrm_disks(disk_raw)

        return {
            "computer_name": computer_name,
            "os_type": os_type,
            "os_version": os_version,
            "cpu_cores": cpu_cores,
            "cpu_model": cpu_model,
            "total_memory_gb": total_memory_gb,
            "disk_partitions": disk_partitions,
        }

    def _parse_winrm_disks(self, raw: str) -> list:
        if not raw:
            return []
        try:
            disks = json.loads(raw)
            if isinstance(disks, dict):
                disks = [disks]
            result = []
            for d in disks:
                size = float(d.get("SizeGB", 0) or 0)
                free = float(d.get("FreeGB", 0) or 0)
                used = max(0, round(size - free, 1))
                pct = round(used / size * 100, 1) if size > 0 else 0
                result.append({
                    "name": d.get("DeviceID", "?"),
                    "mount": d.get("DeviceID", "?") + "\\",
                    "fstype": d.get("FileSystem", "NTFS"),
                    "total_gb": size,
                    "used_gb": used,
                    "free_gb": free,
                    "percent": pct,
                })
            return result
        except:
            return []


    def _detect_ssh(self) -> dict:
        computer_name = self._run_ssh('hostname')

        os_type = self._run_ssh('cat /etc/os-release 2>/dev/null | grep "^PRETTY_NAME" | cut -d= -f2 | tr -d \'"\'')
        if not os_type:
            os_type = self._run_ssh('cat /etc/redhat-release 2>/dev/null').strip()

        os_version = self._run_ssh('uname -r')

        cpu_raw = self._run_ssh('nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo')
        cpu_model = self._run_ssh('cat /proc/cpuinfo 2>/dev/null | grep "model name" | head -1 | cut -d: -f2 | sed "s/^ *//"')
        try:
            cpu_cores = int(cpu_raw.strip())
        except:
            cpu_cores = 0

        mem_raw = self._run_ssh("free -g 2>/dev/null | awk '/^Mem:/{print $2}'")
        try:
            total_memory_gb = float(mem_raw.strip())
        except:
            total_memory_gb = 0.0

        disk_raw = self._run_ssh(
            "df -hT -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | tail -n +2 | "
            "awk '{printf \"{\\\"name\\\":\\\"%s\\\",\\\"fstype\\\":\\\"%s\\\",\\\"mount\\\":\\\"%s\\\","
            "\\\"total_gb\\\":%.1f,\\\"used_gb\\\":%.1f,\\\"free_gb\\\":%.1f,\\\"percent\\\":%s},\\n\", "
            "$1,$2,$7,$3,$4,$5,substr($6,1,length($6)-1)}'"
        )
        disk_partitions = self._parse_ssh_disks(disk_raw)

        return {
            "computer_name": computer_name,
            "os_type": os_type,
            "os_version": os_version,
            "cpu_cores": cpu_cores,
            "cpu_model": cpu_model,
            "total_memory_gb": total_memory_gb,
            "disk_partitions": disk_partitions,
        }

    def _parse_ssh_disks(self, raw: str) -> list:
        if not raw:
            return []
        try:
            result = []
            for line in raw.strip().split('\n'):
                line = line.rstrip(',')
                try:
                    d = json.loads(line)
                    result.append(d)
                except:
                    pass
            return result
        except:
            return []

    def close(self):
        """Close the connection."""
        try:
            if self.server.protocol == "SSH" and self.session:
                self.session.close()
        except:
            pass


def _win_ver_to_name(version: str, build: str = "", caption_hint: str = "") -> str:
    v = version.split(".")
    if len(v) < 2:
        return f"Windows {version}"
    b = int(build) if build else 0
    if v[0] != "10":
        return f"Windows {version}"
    is_server = "server" in caption_hint.lower()
    # Windows 11 (build >= 22000, client only)
    if b >= 26100:
        return "Windows Server 2025" if is_server else f"Windows 11 (Build {build})"
    if b >= 22000:
        return f"Windows 11 (Build {build})"
    # Build 20348-21999: Server 2022 or Win10 preview
    if b >= 20348:
        return "Windows Server 2022"
    # Build 19041-20347: Win10 2004+ or Win10 21H2/22H2 or Server SAC
    if b >= 19045:
        return f"Windows 10 22H2 (Build {build})"
    if b >= 19041:
        return f"Windows 10 21H2 (Build {build})"
    if b >= 17763:
        return "Windows Server 2019"
    if b >= 14393:
        return "Windows Server 2016"
    return f"Windows 10 (Build {build})" if build else "Windows 10/11"

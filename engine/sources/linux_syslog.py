from __future__ import annotations

import random
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource, TransportName
from utils.faker_helpers import random_linux_host, random_internal_ip

_KERNEL_MSGS = [
    "kernel: [UFW BLOCK] IN=eth0 OUT= MAC={mac} SRC={src} DST={dst} LEN=40 TOS=0x00 PREC=0x00 TTL=238 ID=53540 PROTO=TCP SPT={sport} DPT={dport} WINDOW=1024 RES=0x00 SYN URGP=0",
    "kernel: EXT4-fs (sda1): mounted filesystem with ordered data mode",
    "kernel: Out of memory: Kill process {pid} ({proc}) score {score} or sacrifice child",
    "kernel: device eth0 entered promiscuous mode",
    "kernel: nf_conntrack: table full, dropping packet",
]

_CRON_MSGS = [
    "CRON[{pid}]: (root) CMD (/usr/sbin/ntpdate -u pool.ntp.org)",
    "CRON[{pid}]: (backup) CMD (/opt/backup/run_backup.sh)",
    "CRON[{pid}]: (www-data) CMD (find /tmp -mtime +7 -delete)",
    "CRON[{pid}]: ({user}) CMD (/home/{user}/scripts/report.sh)",
]

_DAEMON_MSGS = [
    "systemd[1]: Started {svc}.service.",
    "systemd[1]: Stopped {svc}.service.",
    "systemd[1]: {svc}.service: Main process exited, code=exited, status=1/FAILURE",
    "ntpd[{pid}]: synchronized to {ip}, stratum 3",
    "rsyslogd: [origin software='rsyslogd' swVersion='8.2312.0' x-pid='{pid}'] start",
    "postfix/smtpd[{pid}]: connect from unknown[{ip}]",
]

_PROCS = ["apache2", "nginx", "sshd", "crond", "docker", "kubelet", "mysqld"]
_SERVICES = ["apache2", "nginx", "mysql", "postgresql", "redis", "docker", "sshd", "rsyslog"]
_FACILITIES = [0, 3, 9, 10, 16, 17]  # kern, daemon, cron, auth, local0, local1


class LinuxSyslogSource(LogSource):
    id = "linux_syslog"
    display_name = "Linux Syslog"
    description = "Generic Linux syslog — kernel, cron, daemon messages"
    default_transport: TransportName = "syslog"
    supported_transports = ["syslog"]
    default_eps = 5.0
    tags = ["linux", "system", "syslog"]

    async def generate(self) -> LogEvent:
        host = random_linux_host()
        ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        pid = random.randint(100, 99999)
        ip = random_internal_ip()
        user = random.choice(["root", "deploy", "backup", "www-data"])
        svc = random.choice(_SERVICES)
        proc = random.choice(_PROCS)
        src = random_internal_ip()
        dst = random_internal_ip()
        mac = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
        sport = random.randint(1024, 65535)
        dport = random.choice([22, 80, 443, 3306, 5432, 8080])

        template_pool = _KERNEL_MSGS + _CRON_MSGS + _DAEMON_MSGS
        template = random.choice(template_pool)
        msg = template.format(
            pid=pid, ip=ip, user=user, svc=svc, proc=proc,
            src=src, dst=dst, mac=mac, sport=sport, dport=dport,
            score=random.randint(0, 1000),
        )

        facility = random.choice(_FACILITIES)
        severity = random.choice([3, 4, 5, 6, 7])
        priority = facility * 8 + severity
        raw = f"<{priority}>{ts} {host} {msg}"

        return LogEvent(
            raw=raw,
            structured={
                "host": host,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "message": msg,
                "facility": facility,
                "severity": severity,
                "vendor": "linux",
            },
            format="syslog_rfc3164",
            source_id=self.id,
        )

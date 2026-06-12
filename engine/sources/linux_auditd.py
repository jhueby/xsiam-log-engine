from __future__ import annotations

import random
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource
from utils.faker_helpers import random_linux_host, random_user, random_internal_ip

_SYSCALLS = ["execve", "open", "openat", "unlink", "chmod", "chown", "setuid", "ptrace", "socket", "connect"]
_AUDIT_TYPES = ["SYSCALL", "USER_LOGIN", "USER_AUTH", "USER_CMD", "AVC", "CRED_ACQ", "PATH", "SOCKADDR"]
_TYPE_WEIGHTS = [25, 15, 15, 10, 15, 5, 10, 5]

_AVC_DENIALS = [
    "avc: denied {{ read }} for pid={pid} comm=\"{proc}\" path=\"/etc/shadow\" dev=\"sda1\" ino=131073 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file",
    "avc: denied {{ execute }} for pid={pid} comm=\"{proc}\" path=\"/tmp/malware\" dev=\"sda1\" ino=999999 scontext=system_u:system_r:container_t:s0 tcontext=unconfined_u:object_r:user_tmp_t:s0 tclass=file",
    "avc: denied {{ write }} for pid={pid} comm=\"{proc}\" path=\"/etc/cron.d/evil\" dev=\"sda1\" ino=654321 scontext=system_u:system_r:mysqld_t:s0 tcontext=system_u:object_r:cron_spool_t:s0 tclass=file",
]

_PROCS = ["bash", "python3", "curl", "wget", "nc", "nmap", "sshd", "httpd", "nginx", "mysqld"]


class LinuxAuditdSource(LogSource):
    id = "linux_auditd"
    display_name = "Linux Auditd"
    description = "Linux auditd — AVC denials, syscall events, user login audit records"
    default_transport: str = "syslog"
    supported_transports = ["syslog"]
    default_eps = 5.0
    tags = ["linux", "audit", "security"]

    async def generate(self) -> LogEvent:
        host = random_linux_host()
        audit_type = random.choices(_AUDIT_TYPES, weights=_TYPE_WEIGHTS)[0]
        ts_epoch = f"{__import__('time').time():.3f}"
        serial = random.randint(1000, 999999)
        pid = random.randint(100, 65535)
        uid = random.randint(0, 60000)
        user = random_user()
        proc = random.choice(_PROCS)
        syscall = random.choice(_SYSCALLS)

        if audit_type == "SYSCALL":
            msg = (f"type=SYSCALL msg=audit({ts_epoch}:{serial}): arch=c000003e syscall={syscall} "
                   f"success=yes exit=0 a0=7f1234567 a1=0 a2=0 a3=0 items=1 ppid={random.randint(100,9999)} "
                   f"pid={pid} auid={uid} uid={uid} gid={uid} euid={uid} suid={uid} fsuid={uid} "
                   f"egid={uid} sgid={uid} fsgid={uid} tty=pts0 ses={random.randint(1,100)} "
                   f"comm=\"{proc}\" exe=\"/usr/bin/{proc}\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=\"exec_cmds\"")
        elif audit_type == "AVC":
            template = random.choice(_AVC_DENIALS)
            inner = template.format(pid=pid, proc=proc)
            msg = f"type=AVC msg=audit({ts_epoch}:{serial}): {inner}"
        elif audit_type == "USER_LOGIN":
            ip = random_internal_ip()
            result = random.choice(["success", "failed"])
            msg = (f"type=USER_LOGIN msg=audit({ts_epoch}:{serial}): pid={pid} uid={uid} "
                   f"auid={uid} ses={random.randint(1,100)} subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 "
                   f"msg='op=login acct=\"{user}\" exe=\"/usr/sbin/sshd\" hostname={ip} "
                   f"addr={ip} terminal=ssh res={result}'")
        elif audit_type == "USER_CMD":
            cmd = random.choice(["/bin/bash -i", "/usr/bin/python3 -c import pty", "sudo su -", "chmod 777 /etc/passwd"])
            msg = (f"type=USER_CMD msg=audit({ts_epoch}:{serial}): pid={pid} uid={uid} "
                   f"auid={uid} ses={random.randint(1,100)} subj=unconfined_u:unconfined_r:unconfined_t:s0 "
                   f"msg='cwd=\"/home/{user}\" cmd=\"{cmd}\" terminal=pts/0 res=success'")
        else:
            msg = (f"type={audit_type} msg=audit({ts_epoch}:{serial}): pid={pid} uid={uid} "
                   f"auid={uid} ses={random.randint(1,100)} "
                   f"msg='op={audit_type.lower()} acct=\"{user}\" exe=\"/usr/bin/{proc}\" "
                   f"hostname=? addr=? terminal=? res=success'")

        priority = 13 * 8 + 6  # security/audit, informational
        ts_str = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        raw = f"<{priority}>{ts_str} {host} kernel: {msg}"

        return LogEvent(
            raw=raw,
            structured={
                "host": host,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "audit_type": audit_type,
                "message": msg,
                "pid": pid,
                "uid": uid,
                "process": proc,
                "vendor": "linux",
            },
            format="syslog_audit",
            source_id=self.id,
        )

from __future__ import annotations

import random
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource
from utils.faker_helpers import random_linux_host, random_internal_ip, random_external_ip, random_user, weighted_choice

_EVENTS = [
    # (template, weight)
    ("sshd[{pid}]: Accepted {method} for {user} from {ip} port {port} ssh2", 25),
    ("sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2", 10),
    ("sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2", 5),
    ("sshd[{pid}]: Disconnected from authenticating user {user} {ip} port {port}: Too many authentication failures", 3),
    ("sshd[{pid}]: Connection closed by {ip} port {port} [preauth]", 8),
    ("sudo: {user} : TTY=pts/{tty} ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}", 15),
    ("sudo: pam_unix(sudo:auth): authentication failure; logname={user} uid={uid} euid=0 tty=/dev/pts/{tty} ruser={user} rhost= user={user}", 3),
    ("su[{pid}]: Successful su for root by {user}", 5),
    ("useradd[{pid}]: new user: name={newuser}, UID={uid}, GID={uid}, home=/home/{newuser}, shell=/bin/bash", 2),
    ("usermod[{pid}]: change user '{user}' information", 2),
    ("passwd[{pid}]: pam_unix(passwd:chauthtok): password changed for {user}", 3),
    ("pam_unix(login:session): session opened for user {user} by LOGIN(uid=0)", 10),
    ("pam_unix(login:session): session closed for user {user}", 9),
]

_SUDO_CMDS = [
    "/usr/bin/apt-get install openssh-server",
    "/usr/sbin/service nginx restart",
    "/bin/systemctl restart docker",
    "/usr/bin/vi /etc/passwd",
    "/bin/cat /etc/shadow",
    "/usr/bin/id",
    "/bin/bash",
]


class LinuxAuthSource(LogSource):
    id = "linux_auth"
    display_name = "Linux Auth"
    description = "Linux auth/PAM/sudo/sshd events"
    default_transport: str = "syslog"
    supported_transports = ["syslog"]
    default_eps = 2.0
    tags = ["linux", "authentication", "syslog"]

    async def generate(self) -> LogEvent:
        template, _ = weighted_choice(_EVENTS, [w for _, w in _EVENTS])
        host = random_linux_host()
        ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        user = random_user()
        pid = random.randint(1000, 65535)
        ip = random.choice([random_internal_ip(), random_external_ip()])
        port = random.randint(1024, 65535)
        uid = random.randint(1000, 60000)
        tty = random.randint(0, 9)
        newuser = random_user()
        method = random.choice(["password", "publickey", "keyboard-interactive"])
        cmd = random.choice(_SUDO_CMDS)

        msg = template.format(
            pid=pid, user=user, ip=ip, port=port, uid=uid,
            tty=tty, newuser=newuser, method=method, cmd=cmd,
        )

        priority = 10 * 8 + 6  # auth facility, informational
        raw = f"<{priority}>{ts} {host} {msg}"

        return LogEvent(
            raw=raw,
            structured={
                "host": host,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "message": msg,
                "user": user,
                "src_ip": ip,
                "vendor": "linux",
            },
            format="syslog_rfc3164",
            source_id=self.id,
        )

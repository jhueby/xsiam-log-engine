from __future__ import annotations

import random
from faker import Faker

fake = Faker()
Faker.seed(0)

INTERNAL_SUBNETS = [
    "10.0.{}.{}",
    "10.1.{}.{}",
    "10.10.{}.{}",
    "192.168.1.{}",
    "192.168.10.{}",
    "172.16.{}.{}",
]

EXTERNAL_IPS = [fake.ipv4_public() for _ in range(200)]

HOSTNAMES_WINDOWS = [f"WIN-{fake.lexify('??????').upper()}" for _ in range(50)]
HOSTNAMES_LINUX = [f"{random.choice(['web','app','db','proxy','mail','dns'])}{i:02d}.corp.local" for i in range(1, 30)]
HOSTNAMES_NETWORK = [f"{random.choice(['fw','sw','rt','vpn'])}{i:02d}.corp.local" for i in range(1, 20)]

DOMAIN = "corp.local"
DOMAIN_USERS = [fake.user_name() for _ in range(100)]
SERVICE_ACCOUNTS = [f"svc_{name}" for name in ["backup", "monitor", "deploy", "scan", "ldap", "sql", "web"]]
ALL_USERS = DOMAIN_USERS + SERVICE_ACCOUNTS

PROCESSES_WINDOWS = [
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "explorer.exe",
    "taskhostw.exe", "dwm.exe", "spoolsv.exe", "msiexec.exe", "powershell.exe",
    "cmd.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe",
    "wermgr.exe", "SearchIndexer.exe", "MsMpEng.exe", "OneDrive.exe", "Teams.exe",
]

PROCESSES_LINUX = [
    "sshd", "systemd", "cron", "rsyslog", "nginx", "apache2", "mysqld",
    "postgres", "docker", "containerd", "kubelet", "python3", "bash", "sudo",
]

AWS_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "us-east-2"]
AWS_ACCOUNT_IDS = [str(random.randint(100000000000, 999999999999)) for _ in range(5)]
AWS_SERVICES = ["ec2", "s3", "iam", "rds", "lambda", "eks", "cloudfront", "elb"]


def random_internal_ip() -> str:
    template = random.choice(INTERNAL_SUBNETS)
    count = template.count("{}")
    if count == 2:
        return template.format(random.randint(0, 255), random.randint(1, 254))
    return template.format(random.randint(1, 254))


def random_external_ip() -> str:
    return random.choice(EXTERNAL_IPS)


def random_windows_host() -> str:
    return random.choice(HOSTNAMES_WINDOWS)


def random_linux_host() -> str:
    return random.choice(HOSTNAMES_LINUX)


def random_network_device() -> str:
    return random.choice(HOSTNAMES_NETWORK)


def random_user(include_service: bool = False) -> str:
    pool = ALL_USERS if include_service else DOMAIN_USERS
    return random.choice(pool)


def random_domain_user() -> str:
    return f"{random.choice(DOMAIN_USERS)}@{DOMAIN}"


def random_process_windows() -> str:
    return random.choice(PROCESSES_WINDOWS)


def random_process_linux() -> str:
    return random.choice(PROCESSES_LINUX)


def random_port() -> int:
    return random.randint(1024, 65535)


def random_well_known_port() -> int:
    return random.choice([80, 443, 22, 21, 25, 53, 110, 143, 389, 636, 3389, 445, 139, 8080, 8443])


def weighted_choice(choices: list, weights: list):
    return random.choices(choices, weights=weights, k=1)[0]

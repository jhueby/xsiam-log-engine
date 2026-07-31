from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource, ScenarioEntities, TransportName
from utils.faker_helpers import random_external_ip, random_internal_ip, weighted_choice

# GuardDuty finding types are a fixed vocabulary, which is exactly why this
# source is useful: detection content can key on the type string rather than
# having to interpret raw API calls the way CloudTrail requires.
# (type, resource_kind, severity, title)
_FINDINGS = [
    ("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", "AccessKey", 8.0,
     "Credentials created exclusively for an EC2 instance are being used from an external IP address."),
    ("CryptoCurrency:EC2/BitcoinTool.B!DNS", "Instance", 8.0,
     "EC2 instance is querying a domain name associated with cryptocurrency activity."),
    ("Backdoor:EC2/C&CActivity.B!DNS", "Instance", 8.0,
     "EC2 instance is querying a domain name associated with a known command and control server."),
    ("Trojan:EC2/DNSDataExfiltration", "Instance", 7.0,
     "EC2 instance is exfiltrating data through DNS queries."),
    ("Recon:IAMUser/MaliciousIPCaller.Custom", "AccessKey", 5.0,
     "An API commonly used to discover resources was invoked from an IP address on a custom threat list."),
    ("Persistence:IAMUser/NetworkPermissions", "AccessKey", 5.0,
     "An IAM entity invoked an API commonly used to change network access permissions."),
    ("Policy:IAMUser/RootCredentialUsage", "AccessKey", 5.0,
     "An API was invoked using root credentials."),
    ("Discovery:S3/MaliciousIPCaller", "S3Bucket", 5.0,
     "An S3 API commonly used to discover objects was invoked from a known malicious IP address."),
    ("Exfiltration:S3/ObjectRead.Unusual", "S3Bucket", 5.0,
     "An IAM entity invoked an S3 API in a suspicious way."),
    ("UnauthorizedAccess:EC2/SSHBruteForce", "Instance", 2.0,
     "EC2 instance has been involved in SSH brute force attacks."),
    ("Impact:EC2/AbusedDomainRequest.Reputation", "Instance", 5.0,
     "EC2 instance is querying a low reputation domain name."),
]
_FINDING_WEIGHTS = [6, 9, 8, 5, 12, 8, 4, 10, 7, 18, 13]

_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-2"]
_ACCOUNT = "481516234211"
_INSTANCE_TYPES = ["t3.medium", "m5.large", "c5.xlarge", "t3.micro"]
_BUCKETS = ["corp-finance-exports", "corp-backups-prod", "corp-datalake-raw"]


def _resource(kind: str, *, principal: str, internal_ip: str, external_ip: str, region: str) -> dict:
    if kind == "Instance":
        return {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": f"i-{uuid.uuid4().hex[:17]}",
                "instanceType": random.choice(_INSTANCE_TYPES),
                "launchTime": datetime.now(timezone.utc).isoformat(),
                "availabilityZone": f"{region}a",
                "imageId": f"ami-{uuid.uuid4().hex[:17]}",
                "iamInstanceProfile": {
                    "arn": f"arn:aws:iam::{_ACCOUNT}:instance-profile/app-server-role",
                    "id": f"AIPA{uuid.uuid4().hex[:16].upper()}",
                },
                "networkInterfaces": [{
                    "privateIpAddress": internal_ip,
                    "publicIp": external_ip,
                    "subnetId": f"subnet-{uuid.uuid4().hex[:17]}",
                    "vpcId": f"vpc-{uuid.uuid4().hex[:17]}",
                    "securityGroups": [{"groupName": "app-sg", "groupId": f"sg-{uuid.uuid4().hex[:17]}"}],
                }],
                "tags": [{"key": "Env", "value": "prod"}, {"key": "Owner", "value": "platform"}],
            },
        }
    if kind == "S3Bucket":
        return {
            "resourceType": "S3Bucket",
            "s3BucketDetails": [{
                "arn": f"arn:aws:s3:::{random.choice(_BUCKETS)}",
                "name": random.choice(_BUCKETS),
                "type": "Destination",
                "createdAt": "2025-03-11T09:12:00.000Z",
                "owner": {"id": uuid.uuid4().hex},
                "defaultServerSideEncryption": {"encryptionType": "SSEAlgorithm.AES256"},
                "publicAccess": {"effectivePermission": "NOT_PUBLIC"},
            }],
        }
    return {
        "resourceType": "AccessKey",
        "accessKeyDetails": {
            "accessKeyId": f"ASIA{uuid.uuid4().hex[:16].upper()}",
            "principalId": f"AROA{uuid.uuid4().hex[:16].upper()}:{principal}",
            "userType": "AssumedRole",
            "userName": principal,
        },
    }


def _build(*, finding: tuple, principal: str, internal_ip: str, external_ip: str) -> dict:
    finding_type, kind, severity, description = finding
    now = datetime.now(timezone.utc)
    region = random.choice(_REGIONS)
    count = random.randint(1, 40)

    return {
        "schemaVersion": "2.0",
        "accountId": _ACCOUNT,
        "region": region,
        "partition": "aws",
        "id": uuid.uuid4().hex,
        "arn": f"arn:aws:guardduty:{region}:{_ACCOUNT}:detector/{uuid.uuid4().hex}/finding/{uuid.uuid4().hex}",
        "type": finding_type,
        "resource": _resource(kind, principal=principal, internal_ip=internal_ip,
                              external_ip=external_ip, region=region),
        "service": {
            "serviceName": "guardduty",
            "detectorId": uuid.uuid4().hex,
            "action": {
                "actionType": "AWS_API_CALL" if kind == "AccessKey" else "DNS_REQUEST",
                "awsApiCallAction": {
                    "api": random.choice(["DescribeInstances", "ListBuckets", "GetObject",
                                          "AuthorizeSecurityGroupIngress", "CreateAccessKey"]),
                    "serviceName": random.choice(["ec2.amazonaws.com", "s3.amazonaws.com", "iam.amazonaws.com"]),
                    "callerType": "Remote IP",
                    "remoteIpDetails": {
                        "ipAddressV4": external_ip,
                        "organization": {"asn": str(random.randint(1000, 65000)), "org": "Hosting Provider"},
                        "country": {"countryName": random.choice(["Morocco", "Netherlands", "Brazil", "Singapore"])},
                        "city": {"cityName": "Unknown"},
                    },
                } if kind == "AccessKey" else None,
                "dnsRequestAction": None if kind == "AccessKey" else {
                    "domain": random.choice(["pool.minexmr.com", "c2.example.top", "exfil.example.io"]),
                    "protocol": "UDP",
                    "blocked": random.random() < 0.4,
                },
            },
            "resourceRole": "TARGET" if kind == "S3Bucket" else "ACTOR",
            "additionalInfo": {"threatListName": "ProofPoint", "sample": False},
            "eventFirstSeen": now.isoformat(),
            "eventLastSeen": now.isoformat(),
            "archived": False,
            "count": count,
        },
        "severity": severity,
        "createdAt": now.isoformat(),
        "updatedAt": now.isoformat(),
        "title": finding_type.split("/")[-1].replace(".", " "),
        "description": description,
    }


class AWSGuardDutySource(LogSource):
    id = "aws_guardduty"
    display_name = "AWS GuardDuty"
    description = "AWS GuardDuty findings — credential exfiltration, crypto mining, C2 DNS, S3 discovery"
    default_transport: TransportName = "http"
    supported_transports = ["http"]
    default_eps = 1.0
    tags = ["cloud", "aws", "detection", "threat"]
    xsiam_dataset: str = "amazon_guardduty_raw"

    async def generate(self) -> LogEvent:
        event = _build(
            finding=weighted_choice(_FINDINGS, _FINDING_WEIGHTS),
            principal=random.choice(["app-server-role", "ci-deploy", "analyst-readonly"]),
            internal_ip=random_internal_ip(),
            external_ip=random_external_ip(),
        )
        return LogEvent(raw=json.dumps(event), structured=event, format="json", source_id=self.id)

    async def generate_with_entities(
        self, entities: ScenarioEntities, overrides: dict | None = None
    ) -> LogEvent:
        """Scenario mode: attribute the finding to the run's identity and IPs,
        so a cloud detection lines up with the CloudTrail calls that caused it.

        Recognized overrides: finding_type, internal_ip, external_ip.
        """
        overrides = overrides or {}
        # .get(key, default) -- not `or` -- so an explicit falsy override
        # (e.g. "") is honored instead of silently replaced by random data.
        wanted = overrides.get("finding_type")
        finding = next((f for f in _FINDINGS if f[0] == wanted), None) if wanted else None
        if wanted and finding is None:
            # Honor an unlisted finding type rather than silently swapping in
            # a different detection than the scenario described.
            finding = (wanted, "AccessKey", 5.0, "Finding reported by GuardDuty.")

        event = _build(
            finding=finding or weighted_choice(_FINDINGS, _FINDING_WEIGHTS),
            principal=entities.username,
            internal_ip=overrides.get("internal_ip", entities.internal_ip),
            external_ip=overrides.get("external_ip", entities.external_ip),
        )
        return LogEvent(raw=json.dumps(event), structured=event, format="json", source_id=self.id)

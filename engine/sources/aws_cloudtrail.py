from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone
from faker import Faker

from sources.base_source import LogEvent, LogSource, TransportName
from utils.faker_helpers import (
    AWS_REGIONS, AWS_ACCOUNT_IDS, AWS_SERVICES,
    random_external_ip, random_user, weighted_choice,
)

fake = Faker()

_EVENT_NAMES = [
    ("ConsoleLogin", 15),
    ("AssumeRole", 20),
    ("GetObject", 25),
    ("PutObject", 10),
    ("DeleteObject", 3),
    ("DescribeInstances", 8),
    ("CreateUser", 2),
    ("AttachUserPolicy", 2),
    ("DeleteUser", 1),
    ("CreateAccessKey", 2),
    ("ListBuckets", 8),
    ("InvokeFunction", 4),
]

_ERROR_CODES = {
    "AccessDenied": "User is not authorized to perform this action",
    "InvalidToken": "The security token included in the request is expired",
    "NoSuchBucket": "The specified bucket does not exist",
    "NoSuchKey": "The specified key does not exist",
}


class AWSCloudTrailSource(LogSource):
    id = "aws_cloudtrail"
    display_name = "AWS CloudTrail"
    description = "AWS CloudTrail — CloudTrail JSON record format"
    default_transport: TransportName = "http"
    supported_transports = ["http"]
    default_eps = 5.0
    tags = ["cloud", "aws", "audit"]
    xsiam_dataset: str = "aws_cloudtrail_raw"

    async def generate(self) -> LogEvent:
        event_name, _ = weighted_choice(_EVENT_NAMES, [w for _, w in _EVENT_NAMES])
        region = random.choice(AWS_REGIONS)
        account_id = random.choice(AWS_ACCOUNT_IDS)
        now = datetime.now(timezone.utc)
        user = random_user()
        source_ip = random.choice([random_external_ip(), "AWS Internal"])
        is_error = random.random() < 0.08
        error_code = random.choice(list(_ERROR_CODES.keys())) if is_error else None

        user_identity: dict = {}
        if event_name == "ConsoleLogin":
            user_identity = {
                "type": "IAMUser",
                "principalId": user.upper(),
                "arn": f"arn:aws:iam::{account_id}:user/{user}",
                "accountId": account_id,
                "accessKeyId": "",
                "userName": user,
            }
        elif event_name == "AssumeRole":
            role = random.choice(["EC2InstanceRole", "LambdaExecutionRole", "AdminRole", "ReadOnlyRole"])
            user_identity = {
                "type": "AssumedRole",
                "principalId": f"AROA{uuid.uuid4().hex[:12].upper()}:{user}",
                "arn": f"arn:aws:sts::{account_id}:assumed-role/{role}/{user}",
                "accountId": account_id,
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": f"AROA{uuid.uuid4().hex[:12].upper()}",
                        "arn": f"arn:aws:iam::{account_id}:role/{role}",
                        "accountId": account_id,
                        "userName": role,
                    },
                    "attributes": {
                        "creationDate": now.isoformat(),
                        "mfaAuthenticated": str(random.random() < 0.7).lower(),
                    },
                },
                "accessKeyId": f"ASIA{uuid.uuid4().hex[:12].upper()}",
            }
        else:
            user_identity = {
                "type": "IAMUser",
                "principalId": user.upper(),
                "arn": f"arn:aws:iam::{account_id}:user/{user}",
                "accountId": account_id,
                "accessKeyId": f"AKIA{uuid.uuid4().hex[:12].upper()}",
                "userName": user,
            }

        request_params: dict = {}
        response_elements: dict | None = None
        service = random.choice(AWS_SERVICES)

        if event_name in ("GetObject", "PutObject", "DeleteObject"):
            bucket = f"{fake.word()}-{fake.word()}-{random.choice(['data','logs','backup','archive'])}"
            key = f"{fake.file_path(depth=3)}"
            request_params = {"bucketName": bucket, "key": key}
            if event_name == "GetObject":
                response_elements = None
            elif event_name == "PutObject":
                response_elements = {"x-amz-expiration": "", "x-amz-server-side-encryption": "AES256"}
        elif event_name == "ListBuckets":
            request_params = {}
        elif event_name == "DescribeInstances":
            request_params = {"filterSet": {}, "instancesSet": {"items": [{"instanceId": f"i-{uuid.uuid4().hex[:8]}"}]}}
        elif event_name == "CreateUser":
            new_user = random_user()
            request_params = {"userName": new_user}
            response_elements = {"user": {"path": "/", "userName": new_user, "userId": f"AIDA{uuid.uuid4().hex[:12].upper()}", "arn": f"arn:aws:iam::{account_id}:user/{new_user}", "createDate": now.isoformat()}}
        elif event_name == "AttachUserPolicy":
            request_params = {"userName": random_user(), "policyArn": f"arn:aws:iam::aws:policy/{random.choice(['ReadOnlyAccess','AmazonS3FullAccess','AdministratorAccess'])}"}

        event = {
            "eventVersion": "1.08",
            "userIdentity": user_identity,
            "eventTime": now.isoformat(),
            "eventSource": f"{service}.amazonaws.com",
            "eventName": event_name,
            "awsRegion": region,
            "sourceIPAddress": source_ip,
            "userAgent": random.choice([
                "aws-cli/2.15.0 Python/3.11.7",
                "Boto3/1.34.0 Python/3.11",
                "console.amazonaws.com",
                "signin.amazonaws.com",
            ]),
            "requestParameters": request_params,
            "responseElements": response_elements,
            "requestID": str(uuid.uuid4()),
            "eventID": str(uuid.uuid4()),
            "readOnly": event_name in ("GetObject", "DescribeInstances", "ListBuckets", "ConsoleLogin"),
            "eventType": "AwsApiCall" if event_name != "ConsoleLogin" else "AwsConsoleSignIn",
            "managementEvent": event_name in ("CreateUser", "DeleteUser", "AttachUserPolicy", "AssumeRole"),
            "recipientAccountId": account_id,
            "eventCategory": "Management" if event_name in ("CreateUser", "AttachUserPolicy") else "Data",
            "tlsDetails": {
                "tlsVersion": "TLSv1.3",
                "cipherSuite": "TLS_AES_128_GCM_SHA256",
                "clientProvidedHostHeader": f"{service}.{region}.amazonaws.com",
            },
        }

        if is_error and error_code:
            event["errorCode"] = error_code
            event["errorMessage"] = _ERROR_CODES[error_code]

        return LogEvent(
            raw=json.dumps(event),
            structured=event,
            format="json",
            source_id=self.id,
        )

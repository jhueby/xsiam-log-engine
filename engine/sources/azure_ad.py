from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone
from faker import Faker

from sources.base_source import LogEvent, LogSource
from utils.faker_helpers import random_domain_user, random_external_ip, random_internal_ip

fake = Faker()

_LOG_TYPES = ["SignInLogs", "AuditLogs"]
_TYPE_WEIGHTS = [70, 30]

_RESULT_TYPES = ["0", "50074", "50076", "50126", "70011", "90023", "53003"]
_RESULT_WEIGHTS = [70, 5, 8, 5, 3, 5, 4]
_RESULT_DESCS = {
    "0": "Success",
    "50074": "User account requires a password change",
    "50076": "User is required to use multi-factor authentication",
    "50126": "Invalid username or password",
    "70011": "Invalid scope requested",
    "90023": "Blocked by Conditional Access - Risk-Based Policy",
    "53003": "Access blocked by Conditional Access policies",
}

_APPS = ["Microsoft Office 365", "Microsoft Teams", "Azure Portal",
         "Microsoft 365 Admin Center", "Azure Active Directory PowerShell",
         "My Apps", "SharePoint Online"]
_CA_POLICIES = ["MFA Required for All Users", "Block Legacy Auth", "Require Compliant Device"]
_AUDIT_OPERATIONS = [
    "Add user", "Update user", "Delete user",
    "Add member to group", "Remove member from group",
    "Update group", "Reset user password",
    "Add app role assignment to user",
    "Add service principal",
    "Update application",
]


class AzureADSource(LogSource):
    id = "azure_ad"
    display_name = "Azure AD / Entra ID"
    description = "Azure Active Directory — SignInLogs and AuditLogs (Azure Monitor format)"
    default_transport: str = "http"
    supported_transports = ["http"]
    default_eps = 3.0
    tags = ["identity", "cloud", "azure", "microsoft"]
    xsiam_dataset: str = "msft_azure_ad_raw"

    async def generate(self) -> LogEvent:
        log_type = random.choices(_LOG_TYPES, weights=_TYPE_WEIGHTS)[0]
        now = datetime.now(timezone.utc)
        user = random_domain_user()
        ip = random.choice([random_external_ip(), random_internal_ip()])
        tenant_id = str(uuid.uuid4())

        if log_type == "SignInLogs":
            result_type = random.choices(_RESULT_TYPES, weights=_RESULT_WEIGHTS)[0]
            result_desc = _RESULT_DESCS.get(result_type, "Unknown error")
            app = random.choice(_APPS)
            mfa_detail = {}
            if random.random() < 0.6:
                mfa_detail = {
                    "authDetail": random.choice(["MFA completed in Azure AD", "MFA denied; fraud reported", "MFA requirement satisfied by claim in the token"]),
                    "authMethod": random.choice(["Mobile app notification", "Phone call", "Authenticator App", "OATH hardware token"]),
                }

            event = {
                "time": now.isoformat(),
                "resourceId": f"/tenants/{tenant_id}/providers/Microsoft.aadiam",
                "operationName": "Sign-in activity",
                "operationVersion": "1.0",
                "category": "SignInLogs",
                "tenantId": tenant_id,
                "resultType": result_type,
                "resultSignature": "None",
                "resultDescription": result_desc,
                "durationMs": random.randint(50, 5000),
                "callerIpAddress": ip,
                "correlationId": str(uuid.uuid4()),
                "Level": "4",
                "location": fake.country_code(),
                "properties": {
                    "id": str(uuid.uuid4()),
                    "createdDateTime": now.isoformat(),
                    "userDisplayName": fake.name(),
                    "userPrincipalName": user,
                    "userId": str(uuid.uuid4()),
                    "appId": str(uuid.uuid4()),
                    "appDisplayName": app,
                    "ipAddress": ip,
                    "clientAppUsed": random.choice(["Browser", "Mobile Apps and Desktop clients", "Exchange ActiveSync clients"]),
                    "userAgent": fake.user_agent(),
                    "correlationId": str(uuid.uuid4()),
                    "conditionalAccessStatus": random.choice(["success", "failure", "notApplied"]),
                    "appliedConditionalAccessPolicies": [
                        {"id": str(uuid.uuid4()), "displayName": p, "enforcedGrantControls": [], "result": "success"}
                        for p in random.sample(_CA_POLICIES, k=random.randint(0, 2))
                    ],
                    "authenticationDetails": [
                        {
                            "authenticationStepDateTime": now.isoformat(),
                            "authenticationMethod": random.choice(["Password", "Multi-factor authentication"]),
                            "authenticationMethodDetail": random.choice(["Password in the cloud", "Phone app notification"]),
                            "succeeded": result_type == "0",
                            "resultDetail": result_desc,
                        }
                    ],
                    "mfaDetail": mfa_detail,
                    "networkLocationDetails": [],
                    "deviceDetail": {
                        "deviceId": str(uuid.uuid4()),
                        "displayName": fake.hostname(),
                        "operatingSystem": random.choice(["Windows 11", "macOS 14", "iOS 17", "Android 13"]),
                        "browser": random.choice(["Chrome 124.0", "Firefox 126.0", "Safari 17.0", "Edge 124.0"]),
                        "isCompliant": random.random() < 0.8,
                        "trustType": random.choice(["Azure AD joined", "Hybrid Azure AD joined", "Registered"]),
                    },
                    "location": {
                        "city": fake.city(),
                        "state": fake.state(),
                        "countryOrRegion": fake.country_code(),
                        "geoCoordinates": {"latitude": float(fake.latitude()), "longitude": float(fake.longitude())},
                    },
                    "status": {"errorCode": int(result_type), "failureReason": result_desc if result_type != "0" else None},
                    "riskDetail": "none",
                    "riskLevelAggregated": random.choice(["none", "low", "medium", "high"]),
                    "riskLevelDuringSignIn": random.choice(["none", "low", "medium"]),
                    "riskState": random.choice(["none", "confirmedSafe", "remediated", "atRisk"]),
                },
            }
        else:
            op = random.choice(_AUDIT_OPERATIONS)
            target_user = random_domain_user()
            event = {
                "time": now.isoformat(),
                "resourceId": f"/tenants/{tenant_id}/providers/Microsoft.aadiam",
                "operationName": op,
                "operationVersion": "1.0",
                "category": "AuditLogs",
                "tenantId": tenant_id,
                "resultType": "0",
                "resultSignature": "None",
                "resultDescription": "None",
                "durationMs": random.randint(10, 500),
                "callerIpAddress": ip,
                "correlationId": str(uuid.uuid4()),
                "Level": "4",
                "location": fake.country_code(),
                "properties": {
                    "id": str(uuid.uuid4()),
                    "category": "UserManagement",
                    "correlationId": str(uuid.uuid4()),
                    "result": "success",
                    "resultReason": "",
                    "activityDisplayName": op,
                    "activityDateTime": now.isoformat(),
                    "loggedByService": "Core Directory",
                    "operationType": random.choice(["Add", "Update", "Delete"]),
                    "initiatedBy": {
                        "user": {
                            "id": str(uuid.uuid4()),
                            "displayName": fake.name(),
                            "userPrincipalName": user,
                            "ipAddress": ip,
                        }
                    },
                    "targetResources": [
                        {
                            "id": str(uuid.uuid4()),
                            "displayName": fake.name(),
                            "type": "User",
                            "userPrincipalName": target_user,
                        }
                    ],
                    "additionalDetails": [],
                },
            }

        return LogEvent(
            raw=json.dumps(event),
            structured=event,
            format="json",
            source_id=self.id,
        )

from __future__ import annotations

import json
import random
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource
from utils.faker_helpers import DOMAIN, random_windows_host, random_user, weighted_choice

_EVENTS = {
    4662: "An operation was performed on an object.",
    4728: "A member was added to a security-enabled global group.",
    4729: "A member was removed from a security-enabled global group.",
    4756: "A member was added to a security-enabled universal group.",
    4769: "A Kerberos service ticket was requested.",
    5136: "A directory service object was modified.",
    5137: "A directory service object was created.",
    5139: "A directory service object was moved.",
    5141: "A directory service object was deleted.",
}
_EID_LIST = list(_EVENTS.keys())
_EID_WEIGHTS = [15, 20, 15, 10, 15, 10, 5, 5, 5]

_GROUPS = ["Domain Admins", "Enterprise Admins", "Backup Operators", "Remote Desktop Users",
           "Account Operators", "Schema Admins"]
_LDAP_CLASSES = ["user", "group", "computer", "organizationalUnit", "contact"]


class MicrosoftADSource(LogSource):
    id = "microsoft_ad"
    display_name = "Microsoft Active Directory"
    description = "Active Directory — Kerberos, LDAP bind, group membership changes"
    default_transport: str = "wec"
    supported_transports = ["wec", "syslog"]
    default_eps = 3.0
    tags = ["windows", "identity", "active-directory"]

    async def generate(self) -> LogEvent:
        event_id = weighted_choice(_EID_LIST, _EID_WEIGHTS)
        user = random_user()
        domain = DOMAIN.split(".")[0].upper()
        host = random_windows_host()
        ts = datetime.now(timezone.utc).isoformat()

        if event_id in (4728, 4729, 4756):
            group = random.choice(_GROUPS)
            event_data = {
                "MemberName": f"CN={user},OU=Users,DC=corp,DC=local",
                "MemberSid": f"S-1-5-21-{random.randint(1000000,9999999)}-{random.randint(1000,9999)}",
                "TargetUserName": group,
                "TargetDomainName": domain,
                "TargetSid": f"S-1-5-21-{random.randint(1000000,9999999)}-512",
                "SubjectUserName": random_user(),
                "SubjectDomainName": domain,
                "SubjectLogonId": f"0x{random.randint(0,0xFFFFFF):x}",
                "PrivilegeList": "-",
            }
        elif event_id in (5136, 5137, 5139, 5141):
            obj_class = random.choice(_LDAP_CLASSES)
            event_data = {
                "OpCorrelationID": f"{{{random.randint(0, 0xFFFFFFFF):08x}}}",
                "AppCorrelationID": "-",
                "SubjectUserName": user,
                "SubjectDomainName": domain,
                "SubjectLogonId": f"0x{random.randint(0,0xFFFFFF):x}",
                "DSName": DOMAIN,
                "DSType": "Active Directory Domain Services",
                "ObjectDN": f"CN={user},OU=Users,DC=corp,DC=local",
                "ObjectGUID": f"{{{random.randint(0,0xFFFFFFFF):08x}}}",
                "ObjectClass": obj_class,
                "AttributeLDAPDisplayName": random.choice(["member", "userAccountControl", "description", "mail"]),
                "AttributeSyntaxOID": "2.5.5.7",
                "AttributeValue": f"CN={random_user()},OU=Users,DC=corp,DC=local",
                "OperationType": random.choice(["%%14674", "%%14675", "%%14676"]),
            }
        else:
            event_data = {
                "SubjectUserName": user,
                "SubjectDomainName": domain,
                "SubjectLogonId": f"0x{random.randint(0,0xFFFFFF):x}",
                "TargetUserName": random_user(),
                "ServiceName": random.choice(["ldap", "LDAP/corp.local", "krbtgt"]),
            }

        structured = {
            "EventID": event_id,
            "TimeCreated": ts,
            "Channel": "Security",
            "Computer": host,
            "Provider": "Microsoft-Windows-Security-Auditing",
            "ProviderGuid": "54849625-5478-4994-A5BA-3E3B0328C30D",
            "Level": 0,
            "Task": 14080,
            "Keywords": "0x8020000000000000",
            "EventRecordID": random.randint(100000, 9999999),
            "ProcessID": 4,
            "ThreadID": random.randint(8, 1000),
            "SecurityUserID": "S-1-5-18",
            "EventData": event_data,
            "Message": _EVENTS[event_id],
        }

        return LogEvent(
            raw=json.dumps(structured),
            structured=structured,
            format="windows_evtx",
            source_id=self.id,
        )

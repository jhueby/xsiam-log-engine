from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource, ScenarioEntities, TransportName
from utils.faker_helpers import random_external_ip

# (methodName, serviceName, resource type, permission) — the shapes that
# actually show up in Cloud Audit Logs. Admin Activity entries are always
# written; Data Access entries only when explicitly enabled, which is why
# storage.objects.get is weighted lower than a real read-heavy project.
_METHODS = [
    ("storage.objects.get", "storage.googleapis.com", "gcs_bucket", "storage.objects.get"),
    ("storage.objects.list", "storage.googleapis.com", "gcs_bucket", "storage.objects.list"),
    ("storage.buckets.setIamPolicy", "storage.googleapis.com", "gcs_bucket", "storage.buckets.setIamPolicy"),
    ("SetIamPolicy", "cloudresourcemanager.googleapis.com", "project", "resourcemanager.projects.setIamPolicy"),
    ("google.iam.admin.v1.CreateServiceAccountKey", "iam.googleapis.com", "service_account", "iam.serviceAccountKeys.create"),
    ("google.iam.admin.v1.CreateServiceAccount", "iam.googleapis.com", "service_account", "iam.serviceAccounts.create"),
    ("v1.compute.instances.insert", "compute.googleapis.com", "gce_instance", "compute.instances.create"),
    ("v1.compute.instances.delete", "compute.googleapis.com", "gce_instance", "compute.instances.delete"),
    ("v1.compute.firewalls.insert", "compute.googleapis.com", "gce_firewall_rule", "compute.firewalls.create"),
    ("google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
     "secretmanager.googleapis.com", "audited_resource", "secretmanager.versions.access"),
    ("cloudsql.instances.update", "sqladmin.googleapis.com", "cloudsql_database", "cloudsql.instances.update"),
]
_METHOD_WEIGHTS = [22, 14, 3, 5, 4, 3, 10, 4, 4, 6, 5]

_PROJECTS = ["corp-prod-1428", "corp-data-9931", "corp-sandbox-2210"]
_REGIONS = ["us-central1-a", "us-east1-b", "europe-west1-c"]
_SERVICE_ACCOUNTS = [
    "terraform-deploy@corp-prod-1428.iam.gserviceaccount.com",
    "gke-node-sa@corp-prod-1428.iam.gserviceaccount.com",
    "backup-runner@corp-data-9931.iam.gserviceaccount.com",
]
_STATUS = [None, None, None, {"code": 7, "message": "PERMISSION_DENIED"}, {"code": 5, "message": "NOT_FOUND"}]


def _build(*, method: tuple, principal: str, caller_ip: str) -> dict:
    method_name, service_name, resource_type, permission = method
    now = datetime.now(timezone.utc)
    project = random.choice(_PROJECTS)
    status = random.choice(_STATUS)
    is_data_access = method_name.startswith("storage.objects.") or "AccessSecretVersion" in method_name

    payload: dict = {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "authenticationInfo": {"principalEmail": principal},
        "authorizationInfo": [{
            "resource": f"projects/{project}",
            "permission": permission,
            "granted": status is None,
        }],
        "methodName": method_name,
        "requestMetadata": {
            "callerIp": caller_ip,
            "callerSuppliedUserAgent": random.choice([
                "google-cloud-sdk gcloud/458.0.1", "Terraform/1.7.2", "google-api-go-client/0.5",
                "Mozilla/5.0 (compatible; Google-Cloud-Console)",
            ]),
            "requestAttributes": {"time": now.isoformat(), "auth": {}},
            "destinationAttributes": {},
        },
        "resourceName": f"projects/{project}/resource/{uuid.uuid4().hex[:12]}",
        "serviceName": service_name,
    }
    if status is not None:
        payload["status"] = status

    return {
        "protoPayload": payload,
        "insertId": uuid.uuid4().hex[:16],
        "resource": {
            "type": resource_type,
            "labels": {"project_id": project, "location": random.choice(_REGIONS)},
        },
        "timestamp": now.isoformat(),
        "severity": "ERROR" if status is not None else "NOTICE",
        "logName": (
            f"projects/{project}/logs/cloudaudit.googleapis.com%2F"
            f"{'data_access' if is_data_access else 'activity'}"
        ),
        "receiveTimestamp": now.isoformat(),
    }


class GCPAuditSource(LogSource):
    id = "gcp_audit"
    display_name = "GCP Cloud Audit Logs"
    description = "Google Cloud Audit Logs — Admin Activity and Data Access (IAM, GCS, Compute, Secret Manager)"
    default_transport: TransportName = "http"
    supported_transports = ["http"]
    default_eps = 4.0
    tags = ["cloud", "gcp", "google", "audit"]

    async def generate(self) -> LogEvent:
        # Service accounts do most of the work in a real project, so they
        # dominate the principal mix rather than human users.
        principal = (random.choice(_SERVICE_ACCOUNTS) if random.random() < 0.65
                     else f"{random.choice(['jsmith', 'akhan', 'mchen'])}@corp.local")
        event = _build(
            method=random.choices(_METHODS, weights=_METHOD_WEIGHTS)[0],
            principal=principal,
            caller_ip=random_external_ip(),
        )
        return LogEvent(raw=json.dumps(event), structured=event, format="json", source_id=self.id)

    async def generate_with_entities(
        self, entities: ScenarioEntities, overrides: dict | None = None
    ) -> LogEvent:
        """Scenario mode: attribute the cloud API call to the run's identity.

        Recognized overrides: method_name, caller_ip.
        """
        overrides = overrides or {}
        # .get(key, default) -- not `or` -- so an explicit falsy override
        # (e.g. "") is honored instead of silently replaced by random data.
        wanted = overrides.get("method_name")
        method = next((m for m in _METHODS if m[0] == wanted), None) if wanted else None
        if method is None:
            method = random.choices(_METHODS, weights=_METHOD_WEIGHTS)[0]
            if wanted:
                # Honor an unrecognized method name rather than silently
                # substituting a different call than the scenario asked for.
                method = (wanted, method[1], method[2], method[3])

        event = _build(
            method=method,
            principal=entities.domain_user,
            caller_ip=overrides.get("caller_ip", entities.external_ip),
        )
        return LogEvent(raw=json.dumps(event), structured=event, format="json", source_id=self.id)

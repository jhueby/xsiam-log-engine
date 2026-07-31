from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone

from sources.base_source import LogEvent, LogSource, ScenarioEntities, TransportName
from utils.faker_helpers import random_internal_ip

# (verb, resource, subresource) triples the API server actually records.
# pods/exec and secrets reads are the ones detection content cares about;
# the list/watch traffic is what buries them in a real cluster.
_ACTIONS = [
    ("list", "pods", None),
    ("watch", "pods", None),
    ("get", "pods", None),
    ("create", "pods", None),
    ("delete", "pods", None),
    ("create", "pods", "exec"),
    ("get", "secrets", None),
    ("list", "secrets", None),
    ("create", "secrets", None),
    ("create", "clusterrolebindings", None),
    ("create", "rolebindings", None),
    ("create", "serviceaccounts", None),
    ("patch", "deployments", None),
    ("create", "jobs", None),
]
_ACTION_WEIGHTS = [20, 18, 12, 6, 4, 3, 5, 3, 2, 2, 2, 2, 12, 9]

_NAMESPACES = ["default", "kube-system", "prod-payments", "prod-web", "data-eng"]
_POD_PREFIXES = ["web", "api", "worker", "etl", "redis", "ingress-nginx-controller"]
_SERVICE_ACCOUNT_USERS = [
    "system:serviceaccount:kube-system:daemon-set-controller",
    "system:serviceaccount:prod-web:deploy-bot",
    "system:node:ip-10-42-1-88.ec2.internal",
]
_USER_AGENTS = ["kubectl/v1.29.2 (linux/amd64)", "kube-controller-manager/v1.29.2",
                "Go-http-client/2.0", "helm/v3.14.0"]

_RESPONSE_CODES = [200, 200, 200, 201, 403, 404]


def _build(*, verb: str, resource: str, subresource: str | None,
           username: str, source_ip: str, groups: list[str]) -> dict:
    now = datetime.now(timezone.utc)
    namespace = random.choice(_NAMESPACES)
    name = f"{random.choice(_POD_PREFIXES)}-{uuid.uuid4().hex[:9]}"
    code = random.choice(_RESPONSE_CODES)
    # A denied request is the interesting case; make its status coherent
    # rather than a 403 paired with a success body.
    stage = "ResponseComplete"

    object_ref: dict = {
        "resource": resource,
        "apiVersion": "v1",
        "name": name,
    }
    if resource not in ("clusterrolebindings",):
        object_ref["namespace"] = namespace
    if subresource:
        object_ref["subresource"] = subresource

    uri = f"/api/v1/namespaces/{namespace}/{resource}/{name}"
    if subresource:
        uri += f"/{subresource}"
    if verb in ("list", "watch"):
        uri = f"/api/v1/namespaces/{namespace}/{resource}?limit=500"

    event: dict = {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": "RequestResponse" if resource == "secrets" else "Metadata",
        "auditID": str(uuid.uuid4()),
        "stage": stage,
        "requestURI": uri,
        "verb": verb,
        "user": {"username": username, "groups": groups},
        "sourceIPs": [source_ip],
        "userAgent": random.choice(_USER_AGENTS),
        "objectRef": object_ref,
        "responseStatus": {"code": code},
        "requestReceivedTimestamp": now.isoformat(),
        "stageTimestamp": now.isoformat(),
        "annotations": {
            "authorization.k8s.io/decision": "forbid" if code == 403 else "allow",
            "authorization.k8s.io/reason": (
                "" if code != 403 else f'no RBAC policy matched for user "{username}"'
            ),
        },
    }
    if code == 403:
        event["responseStatus"].update({"metadata": {}, "status": "Failure", "reason": "Forbidden"})
    if subresource == "exec":
        # The command is the whole point of an exec audit record.
        event["requestObject"] = {
            "kind": "PodExecOptions",
            "apiVersion": "v1",
            "stdin": True,
            "stdout": True,
            "tty": True,
            "container": random.choice(["app", "sidecar", "nginx"]),
            "command": random.choice([
                ["/bin/sh"], ["/bin/bash"], ["sh", "-c", "cat /var/run/secrets/kubernetes.io/serviceaccount/token"],
                ["env"], ["cat", "/etc/shadow"],
            ]),
        }
    return event


class KubernetesAuditSource(LogSource):
    id = "kubernetes_audit"
    display_name = "Kubernetes Audit"
    description = "Kubernetes API server audit log — pod exec, secret access, RBAC changes"
    default_transport: TransportName = "http"
    supported_transports = ["http"]
    default_eps = 6.0
    tags = ["cloud", "kubernetes", "container", "audit"]

    async def generate(self) -> LogEvent:
        verb, resource, subresource = random.choices(_ACTIONS, weights=_ACTION_WEIGHTS)[0]
        # Most API traffic in a real cluster is controllers and kubelets, not
        # humans — so service accounts dominate the caller mix.
        if random.random() < 0.7:
            username = random.choice(_SERVICE_ACCOUNT_USERS)
            groups = ["system:serviceaccounts", "system:authenticated"]
        else:
            username = f"{random.choice(['jsmith', 'akhan', 'mchen'])}@corp.local"
            groups = ["system:authenticated", "corp:developers"]

        event = _build(verb=verb, resource=resource, subresource=subresource,
                       username=username, source_ip=random_internal_ip(), groups=groups)
        return LogEvent(raw=json.dumps(event), structured=event, format="json", source_id=self.id)

    async def generate_with_entities(
        self, entities: ScenarioEntities, overrides: dict | None = None
    ) -> LogEvent:
        """Scenario mode: attribute the API call to the run's identity.

        Recognized overrides: verb, resource, subresource, source_ip.
        """
        overrides = overrides or {}
        # .get(key, default) -- not `or` -- so an explicit falsy override
        # (e.g. "") is honored instead of silently replaced by random data.
        default = random.choices(_ACTIONS, weights=_ACTION_WEIGHTS)[0]
        event = _build(
            verb=overrides.get("verb", default[0]),
            resource=overrides.get("resource", default[1]),
            subresource=overrides.get("subresource", default[2]),
            username=entities.domain_user,
            source_ip=overrides.get("source_ip", entities.internal_ip),
            groups=["system:authenticated", "corp:developers"],
        )
        return LogEvent(raw=json.dumps(event), structured=event, format="json", source_id=self.id)

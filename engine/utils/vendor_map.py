"""Canonical vendor/product per source, and the dataset they imply.

This engine exists to fill empty XSIAM tenants with realistic traffic, so
events should land in the datasets a real deployment of that product would
use — that is what makes the tenant's built-in parsers, XDM mappings,
dashboards and marketplace content packs work without any custom wiring.

XSIAM names ingest datasets `{vendor}_{product}_raw`, which is why a single
map can drive both the Cribl `vendor`/`product` headers and each source's
target dataset. The values below were checked against a live tenant's
dataset inventory rather than guessed: `okta_sso_raw` (not
okta_system_log_raw), `amazon_aws_raw` (not aws_cloudtrail_raw),
`google_cloud_logging_raw` (not google_cloud_audit_raw),
`msft_o365_general_raw` (not msft_o365_audit_raw).

Sources whose product has no dataset on that tenant follow the same
convention using the marketplace pack's vendor/product.
"""
from __future__ import annotations

# source_id -> (vendor, product)
VENDOR_PRODUCT: dict[str, tuple[str, str]] = {
    # Windows event log channels. One content pack covers Security, System,
    # Application, PowerShell, Firewall and TaskScheduler, so they share a
    # vendor/product and land together rather than splitting per channel.
    "windows_security": ("microsoft", "windows"),
    "windows_system": ("microsoft", "windows"),
    "windows_application": ("microsoft", "windows"),
    "windows_powershell": ("microsoft", "windows"),
    # Directory Service events arrive on the same Windows channels.
    "microsoft_ad": ("microsoft", "windows"),
    # These ship as their own packs with their own datasets.
    "sysmon": ("microsoft", "sysmon"),
    "windows_amsi": ("microsoft", "amsi"),
    "microsoft_dns": ("microsoft", "dns"),
    "microsoft_dhcp": ("microsoft", "dhcp"),
    "microsoft_defender": ("microsoft", "defender"),

    # Identity / SaaS
    "okta": ("okta", "sso"),
    "azure_ad": ("msft", "azure_ad"),
    "m365_audit": ("msft", "o365_general"),
    "duo_mfa": ("cisco", "duo"),

    # Cloud
    "aws_cloudtrail": ("amazon", "aws"),
    "aws_guardduty": ("amazon", "guardduty"),
    "aws_vpc_flow": ("amazon", "vpcflow"),
    "gcp_audit": ("google", "cloud_logging"),
    "kubernetes_audit": ("kubernetes", "audit"),

    # Endpoint / email
    "crowdstrike_falcon": ("crowdstrike", "falcon"),
    "proofpoint_tap": ("proofpoint", "tap"),

    # Network / firewall / proxy
    "palo_alto_ngfw": ("paloaltonetworks", "ngfw"),
    "globalprotect_vpn": ("paloaltonetworks", "globalprotect"),
    "cisco_asa": ("cisco", "asa"),
    "cisco_meraki": ("cisco", "meraki"),
    "fortinet_fortigate": ("fortinet", "firewall"),
    "netflow": ("cisco", "netflow"),
    "proxy_bluecoat": ("bluecoat", "proxysg"),
    "proxy_zscaler": ("zscaler", "internet_access"),
    "zeek": ("zeek", "network"),
    "suricata": ("oisf", "suricata"),

    # Linux
    "linux_syslog": ("linux", "linux"),
    "linux_auth": ("linux", "linux"),
    "linux_auditd": ("linux", "auditd"),
}


def base_vendor_product(source_id: str) -> tuple[str, str]:
    """The real vendor/product for a source, ignoring simulation mode.

    Falls back to splitting the id on its first underscore for anything not
    listed (e.g. a locally added source).
    """
    mapped = VENDOR_PRODUCT.get(source_id)
    if mapped:
        return mapped
    vendor, _, product = source_id.partition("_")
    return vendor or source_id, product or source_id


def vendor_product(source_id: str) -> tuple[str, str]:
    """Vendor/product as actually sent, honouring simulation mode.

    The suffix goes on the *product*, not the vendor, so the pair still reads
    as that vendor's data and the derived dataset stays inside XSIAM's
    {vendor}_{product}_raw convention -- okta/sso becomes okta/sso_sim, i.e.
    okta_sso_sim_raw.

    Trade-off worth knowing: a suffixed product no longer matches the tenant's
    built-in parser for that source, so simulated data lands unparsed. That is
    the price of leaving the real dataset untouched, and is exactly why
    simulation mode is opt-in rather than the default.
    """
    # Imported here rather than at module scope: settings is mutated live by
    # PUT /api/config, so the value has to be read per call, not bound once.
    from config.settings import settings

    vendor, product = base_vendor_product(source_id)
    if settings.simulation_mode:
        suffix = (settings.simulation_suffix or "sim").strip("_")
        if suffix and not product.endswith(f"_{suffix}"):
            product = f"{product}_{suffix}"
    return vendor, product


def canonical_dataset(source_id: str) -> str:
    """The XSIAM ingest dataset this source's events belong in."""
    vendor, product = vendor_product(source_id)
    return f"{vendor}_{product}_raw"


def effective_dataset(source) -> str:
    """The dataset a source's events belong in.

    An explicit per-source `xsiam_dataset` still wins (so a locally added
    source can pin its own), but normally this resolves through the map so a
    source's dataset and its Cribl vendor/product headers cannot disagree.

    Simulation mode applies to overrides too: a source that pinned its own
    dataset must still be diverted, or the toggle would silently leak that
    one source's events into a real dataset.
    """
    from config.settings import settings

    override = getattr(source, "xsiam_dataset", "")
    if not override:
        return canonical_dataset(getattr(source, "id", ""))

    if not settings.simulation_mode:
        return override
    suffix = (settings.simulation_suffix or "sim").strip("_")
    if not suffix or f"_{suffix}_" in override or override.endswith(f"_{suffix}"):
        return override
    # Keep the trailing _raw last so the name still reads as an ingest dataset.
    stem, sep, tail = override.rpartition("_raw")
    return f"{stem}_{suffix}_raw" if sep else f"{override}_{suffix}"

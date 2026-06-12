from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path

from sources.base_source import LogSource

_registry: dict[str, LogSource] = {}


def _auto_discover() -> None:
    package_dir = Path(__file__).parent
    for module_info in pkgutil.iter_modules([str(package_dir)]):
        if module_info.name in ("base_source", "__init__"):
            continue
        module = importlib.import_module(f"sources.{module_info.name}")
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, LogSource)
                and obj is not LogSource
                and hasattr(obj, "id")
                and obj.id
            ):
                instance = obj()
                _registry[instance.id] = instance


def get_registry() -> dict[str, LogSource]:
    if not _registry:
        _auto_discover()
    return _registry


def get_source(source_id: str) -> LogSource | None:
    return get_registry().get(source_id)

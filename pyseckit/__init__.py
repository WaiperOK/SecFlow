"""SecFlow core package exports.

This module keeps imports lightweight so users can import core components
without pulling optional integrations (web, Elasticsearch, notifications).
"""

from __future__ import annotations

__version__ = "1.1.0"
__author__ = "SecFlow Contributors"
__email__ = "team@secflow.dev"

from .core.config import Config
from .core.exceptions import ConfigurationException, PySecKitException, ScannerException
from .core.scanner import ScanResult, Scanner, ScannerManager
from .sast import BanditScanner, SafetyScanner, SemgrepScanner

__all__ = [
    "Config",
    "ConfigurationException",
    "PySecKitException",
    "ScannerException",
    "Scanner",
    "ScanResult",
    "ScannerManager",
    "BanditScanner",
    "SemgrepScanner",
    "SafetyScanner",
]

# Optional modules are exported only when their dependencies are available.
try:
    from .reporting.manager import ReportManager

    __all__.append("ReportManager")
except Exception:  # pragma: no cover - optional dependency surface
    pass

try:
    from .dast import ZapScanner

    __all__.append("ZapScanner")
except Exception:  # pragma: no cover - optional dependency surface
    pass

try:
    from .secret_scan import GitleaksScanner, TruffleHogScanner

    __all__.extend(["GitleaksScanner", "TruffleHogScanner"])
except Exception:  # pragma: no cover - optional dependency surface
    pass

try:
    from .cloud import CheckovScanner

    __all__.append("CheckovScanner")
except Exception:  # pragma: no cover - optional dependency surface
    pass

try:
    from .threat_model import AdvancedThreatModelGenerator, ThreatModelGenerator

    __all__.extend(["ThreatModelGenerator", "AdvancedThreatModelGenerator"])
except Exception:  # pragma: no cover - optional dependency surface
    pass

try:
    from .ci_cd.manager import CICDManager

    __all__.append("CICDManager")
except Exception:  # pragma: no cover - optional dependency surface
    pass

try:
    from .integrations import (
        ElasticsearchIntegration,
        NotificationManager,
        SlackNotifier,
        TeamsNotifier,
    )

    __all__.extend(
        [
            "ElasticsearchIntegration",
            "NotificationManager",
            "SlackNotifier",
            "TeamsNotifier",
        ]
    )
except Exception:  # pragma: no cover - optional dependency surface
    pass

try:
    from .plugins import PluginBase, PluginRegistry, ScannerPlugin

    __all__.extend(["PluginRegistry", "PluginBase", "ScannerPlugin"])
except Exception:  # pragma: no cover - optional dependency surface
    pass

try:
    from .web import api_bp, create_app, dashboard_bp

    __all__.extend(["create_app", "api_bp", "dashboard_bp"])
except Exception:  # pragma: no cover - optional dependency surface
    pass

VERSION = __version__

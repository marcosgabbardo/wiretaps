"""
wiretaps - See what your AI agents are sending to LLMs.

A transparent MitM proxy for auditing AI agent traffic.
"""

__version__ = "0.1.0"
__author__ = "Marcos Gabbardo"
__email__ = "mgabbardo@protonmail.com"

from wiretaps.proxy import WiretapsProxy
from wiretaps.pii import PIIDetector
from wiretaps.storage import Storage

__all__ = ["WiretapsProxy", "PIIDetector", "Storage", "__version__"]

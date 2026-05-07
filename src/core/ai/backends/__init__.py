"""Concrete provider backends.

Backends register themselves with :class:`ProviderFactory` via
``register_default_backends()`` (called from
``src/core/ai/__init__.py`` at import time). Each backend module
documents which canonical provider names it serves and which
provider settings it understands.
"""

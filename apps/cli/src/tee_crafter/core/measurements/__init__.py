"""Per-image TEE launch-measurement registry + capture helpers.

``bake-ami`` captures the launch measurement of a freshly baked image and
stores it under ``measurements/<platform>/<image_id>.json`` (shipped inside
the package).  ``deploy`` looks it up by ``(platform, image_id)`` and uses it
as the pinned baseline for the client verifier and the BYOK / sealed-``.env``
release policy -- so there is no manual "capture the measurement" step for the
operator (the security posture decision in the secure-env plan).
"""
from tee_crafter.core.measurements.registry import (
    PLATFORM_MEASUREMENT_FIELD,
    lookup,
    measurement_value,
    measurement_values,
    records_for_platform,
    registry_dir,
    store,
    store_many,
)

__all__ = [
    "PLATFORM_MEASUREMENT_FIELD",
    "lookup",
    "measurement_value",
    "measurement_values",
    "records_for_platform",
    "registry_dir",
    "store",
    "store_many",
]

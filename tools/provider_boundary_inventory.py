"""Exact reviewed process source inventory and unchanged fail-closed predicates.

The fixed packaged receiver is registered as a real process boundary with its
source hashes; it is not exempted from the existing strict launch/source audit.
"""

from __future__ import annotations

from collections.abc import Mapping

from tools.provider_gate_common import TRUSTED_PROCESS_BOUNDARY_PATHS, _sha256_bytes

_REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES = {
    "bluefire/runner_client.py": "sha256:19d8340d9c77f3e4591e457e0441e56812f599af76be6503ae35154db59f57b2",
    "bluefire/runner_bootstrap.py": "sha256:3868a90688d0010b0241b460d8be90dc44b0b7b6b025a9a6a076ec04e0024883",
    "bluefire/runner_darwin_containment.py": "sha256:f02533a6cba3c29bc95d5aef5fbd4bfc0e30a830af4005fb6c1bf76a0b57353c",
    "bluefire/runner_windows_containment.py": "sha256:63e749dc00fdf6bdf0d2ed6246fc050cb7dac2d665de30a65452520bc4548979",
    "bluefire/runner_linux_containment.py": "sha256:7b0f3cf3cd36304ba3c400439586efba98f682d34aa4053a12f478ef02eaea3a",
    "bluefire/runner_lifecycle.py": "sha256:69c3f77db8ab720365888c46f2344f5754957e41e30fbaadadbe7efedd455045",
    "bluefire/runner_parent_death.py": "sha256:7a0443b986e18025a748775e18a3fc6cc539713c2cfbb0cc04cce44e3eb277df",
    "bluefire/runner_trust.py": "sha256:d8f422bdc47425a2bf655f723848dc44cbb04c1a5aba85851743e5a1321a2d4d",
    "bluefire/runner_watchdog.py": "sha256:e2a416f14814d1c93bc5b9ab5e213b08068d27dc8e37a663d2281f8d449384e3",
    "bluefire/receiver_session.py": "sha256:168e4e2765d0a5031d1ee238faba29f531966d29c2da10e9c62f40d9aa6e1f0e",
    "bluefire/receiver_session_worker.py": "sha256:a90d4d9e67ac580b79c242bbeea93d580cf915a0b650f8e2804d354c8dcc9a81",
    "bluefire/ai_transport.py": "sha256:b806740e5ab11b6d10d771b57a08230d666483115782b30ced443f5cec0be507",
    "bluefire/_ai_transport_worker.py": "sha256:a1dda3899825c66ac27e572fdfa2f80c6bda08b0fd66a31c65acfa76e47bbf21",
    "bluefire/prepared_lab.py": "sha256:107dacdffc546dec2def8a8773509a13e11cf3493a601c755923cfc20c19f631",
    "bluefire/prepared_lab_guest.py": "sha256:0057a9a92c5908109da7953cf04c423b6aaa1c61a0aba97ac02cdbd29f5c2a8a",
    "bluefire/prepared_lab_runtime.py": "sha256:7acc6e0dd3e67834c9d6ec26dc828859eecf32388fdec3137492214586b2905e",
    "bluefire/prepared_lab_install.py": "sha256:aa660ad7e03b63c9124bce32436dd5e550271f7f7ae412f909aad2adbf976028",
    "bluefire/prepared_lab_broker.py": "sha256:0ac888a425f7ab2a8f09758641788590d8b9db619275b3eeafd8aa777f02824a",
    "bluefire/prepared_lab_ui_bootstrap.py": "sha256:7de08b08b2dbf7120e679f5cc1c81446a125dcddc205b69f244b0c6d4ed50b4c",
    "bluefire/prepared_lab_product.py": "sha256:3a5e38cfa1eb8c7b23c88fe2d8ab89f98cbeb00f27357c7af21c61fa95df7ea9",
    "bluefire/prepared_lab_file_access.py": "sha256:700d4e1a148b440d9a837488db333513260667d2ad3871ea7ad28323d7078b04",
    "bluefire/browser_launch.py": "sha256:54d7a77e43821254841f895aedd516321523c7287d9571df2fa9a52e1253c72f",
    "bluefire/runner_python_environment.py": "sha256:9928d6a53b5fd2dc9bf6036c4a2d9ec9715c97de1f9f89519e99055b21b2f25e",
    "bluefire/ad_smb_worker_process.py": "sha256:13aabb6ead58e491894e1e7dccecbcf1f8f035d1c5392a2163bdb533cabd2168",
}
_REVIEWED_RUST_PROCESS_BOUNDARY_SOURCES = (
    "runner/src/cancellation_witness.rs",
    "runner/src/process.rs",
    "runner/src/atomic_gzip.rs",
    "runner/src/s3_worker_process.rs",
)


def _trusted_process_boundary_inventory_is_fixed() -> bool:
    reviewed_paths = (
        *_REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES,
        *_REVIEWED_RUST_PROCESS_BOUNDARY_SOURCES,
    )
    return (
        len(TRUSTED_PROCESS_BOUNDARY_PATHS) == len(set(TRUSTED_PROCESS_BOUNDARY_PATHS))
        and TRUSTED_PROCESS_BOUNDARY_PATHS == reviewed_paths
    )


def _reviewed_python_process_boundary_sources(texts: Mapping[str, str]) -> bool:
    return {
        name: _sha256_bytes(text.encode("utf-8")) for name, text in texts.items()
    } == _REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES

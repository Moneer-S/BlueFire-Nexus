"""Exact reviewed process source inventory and unchanged fail-closed predicates.

The fixed packaged receiver is registered as a real process boundary with its
source hashes; it is not exempted from the existing strict launch/source audit.
"""

from __future__ import annotations

from collections.abc import Mapping

from tools.provider_gate_common import TRUSTED_PROCESS_BOUNDARY_PATHS, _sha256_bytes

_REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES = {
    "bluefire/runner_client.py": "sha256:e2df9e0df8a3d480f5dc1b30fba60a313fda438b8f29f74394810f0fe55aae7a",
    "bluefire/runner_bootstrap.py": "sha256:2d2ffffec138fdf76587649170b91cc04d2e5fedb6d1768d85b725c7ba809cdf",
    "bluefire/runner_darwin_containment.py": "sha256:f02533a6cba3c29bc95d5aef5fbd4bfc0e30a830af4005fb6c1bf76a0b57353c",
    "bluefire/runner_windows_containment.py": "sha256:937456440a3c2dce94d24af695951ce19ca682b7752aa7437a5fae1f86bfb733",
    "bluefire/runner_linux_containment.py": "sha256:7b0f3cf3cd36304ba3c400439586efba98f682d34aa4053a12f478ef02eaea3a",
    "bluefire/runner_lifecycle.py": "sha256:7d1a167fcccc8336cbb6f41ce3eda290301347ae610e2305903d4326df10dcc3",
    "bluefire/runner_parent_death.py": "sha256:7a0443b986e18025a748775e18a3fc6cc539713c2cfbb0cc04cce44e3eb277df",
    "bluefire/runner_trust.py": "sha256:fc8811d61e0684b480ceb0a88a1124d0b8829363d5c10caa3513febfbb697c67",
    "bluefire/runner_watchdog.py": "sha256:9e6d4b9e4c4b3d64e17b0b138fc8a1b7910aed48a7849563f15ed8abe3fca542",
    "bluefire/receiver_session.py": "sha256:06f5587707cbddb40aa5a310be24ec1fd89375b89a82e60d966b9c6af6451a37",
    "bluefire/receiver_session_worker.py": "sha256:015594b6309e52de966bc09258638551ae23f70f451bd88ef3903a361b2f1b09",
    "bluefire/ai_transport.py": "sha256:b806740e5ab11b6d10d771b57a08230d666483115782b30ced443f5cec0be507",
    "bluefire/_ai_transport_worker.py": "sha256:812f45cf12dfba5f4d125e1b0a629a0ebace4c6c4b24dedee937ae466dd26d7a",
    "bluefire/prepared_lab.py": "sha256:1da8bc6a72ed2681d00045499619266a13e44436e8a886f60b4314151ebb09dc",
    "bluefire/prepared_lab_guest.py": "sha256:db87ca32a31a34d12761a033369991774c90c044c268e1ec5e85aa3b6c67318f",
    "bluefire/prepared_lab_runtime.py": "sha256:c2aea180c4a89c2a4234eda9bcb350e53e4e6d109ac23479437c28d6b9bc7a66",
    "bluefire/prepared_lab_install.py": "sha256:aa660ad7e03b63c9124bce32436dd5e550271f7f7ae412f909aad2adbf976028",
    "bluefire/prepared_lab_broker.py": "sha256:970191f6782403857cc4d3860547cc1e1c7c1de10a15cfd9b1be653ab8c7087b",
    "bluefire/prepared_lab_ui_bootstrap.py": "sha256:7de08b08b2dbf7120e679f5cc1c81446a125dcddc205b69f244b0c6d4ed50b4c",
    "bluefire/prepared_lab_product.py": "sha256:3a5e38cfa1eb8c7b23c88fe2d8ab89f98cbeb00f27357c7af21c61fa95df7ea9",
    "bluefire/browser_launch.py": "sha256:c19b3d5ebfe9b51378d77ce5fd285ada78cc43898690699477d04f4c0862dbf1",
}
_REVIEWED_RUST_PROCESS_BOUNDARY_SOURCES = (
    "runner/src/cancellation_witness.rs",
    "runner/src/process.rs",
    "runner/src/atomic_gzip.rs",
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

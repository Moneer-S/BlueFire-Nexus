"""New fixture intents use the same original-task recovery, never write replay."""

from copy import deepcopy

import pytest

from bluefire.s3_access_contract import S3AccessError
from bluefire.s3_access_host_config import public_environments
from bluefire.s3_access_recovery import validate_recovery_context
from bluefire.s3_access_wire import S3WorkerRequest
from tests_platform.test_s3_access_executor import configured as configured
from tests_platform.test_s3_access_recovery import dispatched
from tests_platform.test_s3_fixture_admission import configured_fixture


def fixture_context(configured):
    value = configured_fixture()
    configured.row["environment"] = public_environments(value["configuration"])[0]
    configured.request = S3WorkerRequest.from_mapping(value["manifest"]["params"]["worker_request"])
    configured.approval = value["manifest"]["params"]["workflow_approval"]
    return dispatched(configured)


def test_fixture_context_is_retained_and_recovers_original_without_discovery(configured):
    context, execution = fixture_context(configured)
    assert validate_recovery_context(configured.request, context) == context
    configured.client.s3_access_environments = lambda: pytest.fail("new discovery")
    configured.client.execute_task = lambda *args, **kwargs: pytest.fail("write replay")
    assert configured.executor.recover_original(configured.request, context) == {
        "status": "finalized",
        "execution": execution,
    }
    assert len(configured.client.calls) == 1


@pytest.mark.parametrize("key", ["fixture_authority_digest", "fixture_intent_id"])
def test_original_fixture_context_rejects_changed_intent_or_authority(configured, key):
    context, _ = fixture_context(configured)
    changed = deepcopy(context)
    changed["manifest"]["params"]["workflow_approval"][key] = "0" * 64
    with pytest.raises(S3AccessError):
        validate_recovery_context(configured.request, changed)

"""Domain aliases preserve producer identity without reconstructing authority."""

from __future__ import annotations

import pytest

from bluefire import product_store_windows_correction as journal
from bluefire import product_store_windows_correction_retest as retest
from bluefire import windows_file_access_correction_child as child
from bluefire import windows_file_access_correction_contract as contract
from bluefire import windows_file_access_correction_control_process as control
from bluefire import windows_file_access_correction_observation as observation
from bluefire.product_store_errors import ProductStoreError
from tests_platform import test_windows_file_access_correction_journal as journal_fake
from tests_platform.test_windows_file_access_baseline_publication import saved as saved
from tests_platform.test_windows_file_access_correction_credential import correction as correction
from tests_platform.test_windows_file_access_correction_journal import retained as retained
from tests_platform.test_windows_file_access_enrollment import observed_setup as observed_setup
from tests_platform.test_windows_file_access_pair_observation import pair_observed as pair_observed
from tests_platform.test_windows_file_access_pair_provenance import paired as paired
from tests_platform.test_windows_file_access_setup_lifecycle import lifecycle as lifecycle


@pytest.mark.parametrize(
    "module,name",
    [
        (observation, "CorrectionObservationInput"),
        (observation, "VerifiedWindowsCorrectionPostimage"),
        (observation, "checked_provenance"),
        (observation, "observation_input"),
        (observation, "_validated"),
        (control, "OwnedCorrectionControlReceipt"),
        (control, "validate_retained_control_receipt"),
        (control, "RECEIPT_SCHEMA"),
        (child, "validate_terminal"),
        (child, "RESULT_SCHEMA"),
        (child, "OUTPUT_MAX"),
    ],
)
def test_public_aliases_are_the_single_domain_definition(module, name):
    assert getattr(module, name) is getattr(contract, name)
    assert retest.observation is contract


@pytest.mark.parametrize(
    "producer",
    [contract.VerifiedWindowsCorrectionPostimage, contract.OwnedCorrectionControlReceipt],
)
def test_opaque_evidence_has_no_caller_or_serialized_constructor(producer):
    with pytest.raises(TypeError):
        producer()
    with pytest.raises(TypeError):
        producer({"process_cleanup": "verified"})
    with pytest.raises(TypeError):
        producer(_raw=b"{}", _binding=b"{}")


def test_concrete_observer_still_mints_the_same_frozen_type(correction):
    c = correction
    assert type(c.checked) is contract.VerifiedWindowsCorrectionPostimage
    assert type(c.checked) is observation.VerifiedWindowsCorrectionPostimage
    assert contract.checked_provenance(c.checked) == observation.checked_provenance(c.checked)
    value = contract.observation_input(c.checked)
    assert type(value) is observation.CorrectionObservationInput
    with pytest.raises((AttributeError, TypeError)):
        c.checked._binding = b"{}"
    with pytest.raises(contract.contract.NativeWireError):
        contract.checked_provenance({"_binding": value.binding_bytes})


def test_historical_receipt_validation_cannot_supply_the_store_producer(retained):
    v = retained
    journal_fake.begin(v)
    produced = journal_fake.receipt(v)
    assert type(produced) is contract.OwnedCorrectionControlReceipt
    assert type(produced) is control.OwnedCorrectionControlReceipt
    historical = contract.validate_retained_control_receipt(
        produced.document(), v.prepared["binding"]
    )
    assert type(historical) is dict and historical["process_cleanup"] == "verified"
    with pytest.raises(ProductStoreError):
        journal.record_control_closure(v.store, v.job, historical)
    assert set(journal.control_evidence(v.store, v.job)) == {"dispatch"}
    journal.record_control_closure(v.store, v.job, produced)
    assert set(journal.control_evidence(v.store, v.job)) == {"dispatch", "closure"}

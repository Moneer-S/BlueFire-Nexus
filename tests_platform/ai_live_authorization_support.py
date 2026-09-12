"""Explicit authored consent for connected software fixtures, never live-provider evidence."""

from urllib.parse import urlsplit

from bluefire.ai_live_authorization import PURPOSES, create_authorization


def authorization_request(provider, *, purposes=None):
    return {
        "provider": provider.to_dict(),
        "purposes": sorted(PURPOSES if purposes is None else purposes),
        "data_scope": "reviewed_lab_context",
        "limits": {
            "max_requests": 64,
            "max_request_bytes": 16_777_216,
            "max_reserved_output_tokens": 1_048_576,
        },
        "expires_in_seconds": 900,
        "approved_by": "authored-software-test-operator",
        "usage_authorized": True,
        "local_endpoint_authorized": urlsplit(str(provider.endpoint)).hostname
        in {"localhost", "127.0.0.1", "::1"},
    }


def authorize_service(service, provider, *, purposes=None):
    return service.authorize_ai(authorization_request(provider, purposes=purposes))


def authorize_broker(access, provider):
    enrollment = access.enrollment
    grant = create_authorization(
        authorization_request(provider, purposes=[name for name, _ in enrollment.schemas]),
        {
            "kind": "broker",
            "binding_digest": enrollment.digest,
            "provider": provider.to_dict(),
            "expires_at_ms": enrollment.expires_at_ms,
        },
    )
    access.authorize_live(grant)

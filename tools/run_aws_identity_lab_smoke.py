"""Manual, credential-value-free AWS identity-lab smoke entry point."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from bluefire.cloud_identity_pack import (
    MANUAL_CONFIRMATION,
    AwsManualSmokeError,
    AwsManualSmokeRequest,
    run_aws_identity_lab_smoke,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run one approved reversible IAM role-tag action using a named AWS profile. "
            "Credential values are not accepted."
        )
    )
    parser.add_argument("--credential-profile", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--role-name", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--approval-id", required=True)
    parser.add_argument("--approve-account-id", required=True)
    parser.add_argument("--approve-role-name", required=True)
    parser.add_argument(
        "--confirm-action",
        required=True,
        help=f"must equal {MANUAL_CONFIRMATION}",
    )
    parser.add_argument("--timeout-seconds", type=int, default=20)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        request = AwsManualSmokeRequest(
            credential_profile=arguments.credential_profile,
            account_id=arguments.account_id,
            role_name=arguments.role_name,
            region=arguments.region,
            approval_id=arguments.approval_id,
            approved_account_id=arguments.approve_account_id,
            approved_role_name=arguments.approve_role_name,
            confirmation=arguments.confirm_action,
            timeout_seconds=arguments.timeout_seconds,
        )
        report = run_aws_identity_lab_smoke(request)
    except AwsManualSmokeError as exc:
        print(f"AWS identity-lab smoke refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

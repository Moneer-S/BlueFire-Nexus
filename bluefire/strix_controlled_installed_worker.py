"""Fixed installed entrypoint: protected material -> RPC -> controlled bootstrap.

Invoke with an isolated interpreter, never a source-tree script or caller
module name. The daemon must verify installed wheel identities and enforce
worker filesystem/network isolation before supplying the launch file path.
"""

from __future__ import annotations

import os
import sys

from . import strix_controlled_bootstrap as bootstrap
from . import strix_controlled_worker_launch as launch
from . import strix_controlled_worker_rpc as rpc


def main() -> object:
    """No argv, ambient credential, configurable import, or fixture selection."""
    rpc.require_linux()
    if (
        len(sys.argv) != 1
        or sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or sys.flags.no_user_site != 1
        or sys.flags.dont_write_bytecode != 1
        or sys.flags.utf8_mode != 1
        or getattr(sys.flags, "safe_path", False) is not True
    ):
        raise rpc._refuse()
    path = launch.validate_process_environment(os.environ)
    material = launch.read_launch_material(path)
    original_environment_object = os.environ
    original_environment = dict(original_environment_object)
    original_argv = sys.argv
    original_cwd = os.getcwd()
    pinned_inputs = material.invocation.pin_installed_inputs(mode=material.installed_input_mode)
    transport: rpc.SocketControlledControllerTransport | None = None
    try:
        connected = launch.connect_worker(material)
        transport = connected.transport
        bootstrap_environment = dict(material.environment)
        environment = pinned_inputs.runtime_environment(
            material.invocation.runtime_environment(bootstrap_environment)
        )
        environment["LLM_API_KEY"] = connected.model_gateway_token
        identities = {item.package: item for item in material.package_identities}
        original_environment_object.clear()
        original_environment_object.update(environment)
        sys.argv = list(pinned_inputs.argv)
        os.chdir(pinned_inputs.cwd)
        return bootstrap.main(
            transport=transport,
            environment=bootstrap_environment,
            identity_getter=identities.__getitem__,
        )
    finally:
        try:
            if transport is not None:
                transport.close()
        finally:
            try:
                original_environment_object.pop("LLM_API_KEY", None)
                original_environment_object.clear()
                original_environment_object.update(original_environment)
                sys.argv = original_argv
                os.chdir(original_cwd)
            finally:
                pinned_inputs.close()


def entrypoint() -> object:
    """Sanitize every third-party failure at the installed process boundary."""
    try:
        return main()
    except SystemExit as error:
        code = error.code
        if code is None or type(code) is int and 0 <= code <= 255:
            raise
        raise SystemExit(2) from None
    except BaseException:
        raise SystemExit(2) from None


if __name__ == "__main__":
    entrypoint()

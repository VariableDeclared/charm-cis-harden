#!/usr/bin/env python3
# Copyright 2024 pjds
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm CIS Hardening

Refer to the following tutorial that will help you
develop a new k8s charm using the Operator Framework:

https://juju.is/docs/sdk/create-a-minimal-kubernetes-charm
"""

import logging
from typing import cast
import tempfile
import base64
import subprocess
import ops

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)

VALID_LOG_LEVELS = ["info", "debug", "warning", "error", "critical"]


class CharmCisHardeningCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        # framework.observe(self.on.config_changed, self._on_config_changed)
        framework.observe(self.on.execute_cis_action, self._cis_harden_action)
        framework.observe(self.on.install, self._on_install)
        framework.observe(self.on.execute_audit_action, self._on_audit_action)

    def _on_install(self, event):
        self.unit.status = ops.ActiveStatus("Ready to execute CIS hardening.")
        if self.model.config["auto-harden"]:
            self.cis_harden()

    def _on_audit_action(self, event):
        self.audit("/tmp/audit.results")

    def audit(self, results_file):
        return subprocess.check_output(f"usg audit --tailoring-file {results_file}".split(" ")).decode('utf-8')

    def cis_harden(self):
        config = self.model.config
        tailoring_file = config.get("tailoring-file", "")
        if not tailoring_file.strip():
            logger.error("Tailoring-file is not set")
            self.unit.status = ops.BlockedStatus("tailoring file is not set. Check juju config")
            return True
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(base64.b64decode(tailoring_file).decode('utf-8'))
            fh.flush()
            return subprocess.check_output(f"usg fix --tailoring-file {fh.name}".split(" ")).decode('utf-8')

    def execute_pre_hardening_script(self):
        """
        Execute bash commands from pre-hardening-script config
        Bash commands need to be run in some cases, before the hardening, in order to remediate some rules
        """
        config = self.model.config
        bash_content = config.get("pre-hardening-script", "")
        if not bash_content.strip():
            return False
        self.unit.status = ops.MaintenanceStatus("Executing pre-hardening script")
        try:
            # Using subprocess.run to be able to log stdout and stderr
            result = subprocess.run(
                bash_content, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                shell=True, executable="/bin/bash", text=True
            )

            if result.stdout:
                logger.info(f"Pre-hardening script output: {result.stdout}")
            if result.stderr:
                logger.error(f"Pre-hardening script error output: {result.stderr}")

            if result.returncode == 0:
                logger.info("Pre-hardening script executed successfully.")
            else:
                self.unit.status = ops.BlockedStatus(f"Pre-hardening script failed with code {result.returncode}. Check juju debug-log")
                logger.error(f"Pre-hardening script failed with code {result.returncode}")
                logger.error(result.stderr)
            return result.returncode

        except subprocess.SubprocessError as e:
            logger.error(f"An error occurred while executing the pre-hardening script: {e}")
            self.unit.status = ops.BlockedStatus("Pre-hardening script failed due to an exception. Check juju debug-log")
            return 1

    def _cis_harden_action(self, event):
        return_code = self.execute_pre_hardening_script()
        if return_code:
            event.fail(
                "Failed to run pre-hardening logs. Check juju debug-log"
            )
            return
        self.unit.status = ops.MaintenanceStatus("Executing hardening...")
        output = self.cis_harden()
        if output:
            event.fail(
                "Failed to run CIS hardening. Check juju-debug-log"
            )
            return
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(output)
            event.set_results({"Result": "Complete!", "Results file": fh.name})
        self.unit.status = ops.ActiveStatus("Hardening complete.")


if __name__ == "__main__":  # pragma: nocover
    ops.main(CharmCisHardeningCharm)  # type: ignore

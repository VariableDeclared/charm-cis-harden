#!/usr/bin/env python3
# Copyright 2024 pjds
# See LICENSE file for licensing details.

import base64
import unittest
from unittest.mock import MagicMock, patch

import ops
import ops.testing

from charm import CharmCisHardeningCharm


class TestCharmCisHardening(unittest.TestCase):

    def setUp(self):
        self.harness = ops.testing.Harness(CharmCisHardeningCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        # Sample base64 encoded content for testing
        self.test_tailoring = base64.b64encode(b"test content").decode("utf-8")

    def test_is_configuration_set(self):
        """Test configuration validation."""
        # Test empty config
        self.assertFalse(self.harness.charm.is_configuration_set("tailoring-file"))

        # Test with whitespace
        self.harness.update_config({"tailoring-file": "   "})
        self.assertFalse(self.harness.charm.is_configuration_set("tailoring-file"))

        # Test with valid content
        self.harness.update_config({"tailoring-file": self.test_tailoring})
        self.assertTrue(self.harness.charm.is_configuration_set("tailoring-file"))

    @patch("charmhelpers.fetch.apt_update")
    @patch("charmhelpers.fetch.apt_install")
    def test_install_default(self, mock_apt_install, mock_apt_update):
        """Test default installation without auto-hardening."""
        self.harness.update_config({"auto-harden": False, "tailoring-file": self.test_tailoring})

        self.harness.charm.on.install.emit()

        mock_apt_update.assert_called_once()
        mock_apt_install.assert_called_once_with(["usg"], fatal=True)
        self.assertIsInstance(self.harness.model.unit.status, ops.ActiveStatus)
        self.assertEqual(
            self.harness.model.unit.status.message, "Ready for CIS hardening. Run 'harden' action"
        )

    @patch("subprocess.check_output")
    @patch("charmhelpers.fetch.apt_install")
    @patch("charmhelpers.fetch.apt_update")
    def test_install_with_auto_harden(self, mock_apt_update, mock_apt_install, mock_check_output):
        """Test installation with auto-hardening enabled."""
        self.harness.update_config({"auto-harden": True, "tailoring-file": self.test_tailoring})
        mock_check_output.return_value = ""

        self.harness.charm.on.install.emit()

        mock_apt_update.assert_called_once()
        mock_apt_install.assert_called_once_with(["usg"], fatal=True)
        self.assertTrue(mock_check_output.call_args[0][0][0:2] == ["usg", "fix"])

    @patch("subprocess.check_output")
    def test_execute_cis_action_success(self, mock_check_output):
        """Test successful CIS hardening action."""
        self.harness.update_config({"tailoring-file": self.test_tailoring})
        mock_check_output.return_value = ""

        action_event = MagicMock()
        self.harness.charm._on_hardening_action(action_event)

        mock_check_output.assert_called()
        self.assertIsInstance(self.harness.model.unit.status, ops.BlockedStatus)
        self.assertTrue("Hardening complete" in str(self.harness.model.unit.status))
        self.assertTrue(self.harness.charm._stored.hardening_status)
        action_event.set_results.assert_called()

    def test_execute_cis_action_no_config(self):
        """Test CIS hardening action without tailoring file."""
        action_event = MagicMock()
        self.harness.charm._on_hardening_action(action_event)

        action_event.fail.assert_called_with("Tailoring-file is not set")
        self.assertIsInstance(self.harness.model.unit.status, ops.BlockedStatus)
        self.assertEqual(
            self.harness.model.unit.status.message,
            "Cannot run hardening. Please configure a tailoring-file",
        )

    @patch("subprocess.check_output")
    def test_execute_audit_action_success(self, mock_check_output):
        """Test successful audit action."""
        self.harness.update_config({"tailoring-file": self.test_tailoring})
        mock_check_output.return_value = "Audit output"

        action_event = MagicMock()
        self.harness.charm._on_audit_action(action_event)

        mock_check_output.assert_called()
        self.assertIsInstance(self.harness.model.unit.status, ops.ActiveStatus)
        self.assertTrue("Audit finished" in str(self.harness.model.unit.status))
        action_event.set_results.assert_called()

    def test_execute_audit_action_no_config(self):
        """Test audit action without tailoring file."""
        action_event = MagicMock()
        self.harness.charm._on_audit_action(action_event)

        action_event.fail.assert_called_with("Tailoring-file is not set")
        self.assertIsInstance(self.harness.model.unit.status, ops.BlockedStatus)
        self.assertEqual(
            self.harness.model.unit.status.message,
            "Cannot run hardening. Please configure a tailoring-file",
        )

    @patch("subprocess.run")
    def test_execute_pre_hardening_script_success(self, mock_run):
        """Test successful pre-hardening script execution."""
        mock_run.return_value = MagicMock(returncode=0, stdout="Success", stderr="")

        self.harness.update_config({"pre-hardening-script": "echo 'test'"})

        result = self.harness.charm.execute_pre_hardening_script()
        self.assertEqual(result, 0)
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_execute_pre_hardening_script_failure(self, mock_run):
        """Test failed pre-hardening script execution."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Error")

        self.harness.update_config({"pre-hardening-script": "invalid_command"})

        result = self.harness.charm.execute_pre_hardening_script()
        self.assertEqual(result, 1)
        self.assertIsInstance(self.harness.model.unit.status, ops.BlockedStatus)
        self.assertTrue("Pre-hardening script failed" in str(self.harness.model.unit.status))

    @patch("subprocess.check_output")
    def test_start_hardened(self, mock_check_output):
        """Test start hook when unit is hardened."""
        mock_check_output.return_value = b"sysctl output"
        self.harness.charm._stored.hardening_status = True
        self.harness.charm.on.start.emit()

        mock_check_output.assert_called_once_with("sysctl --system".split(" "))
        self.assertIsInstance(self.harness.model.unit.status, ops.ActiveStatus)
        self.assertEqual(
            self.harness.model.unit.status.message,
            "Unit is hardened. Use 'audit' action to check compliance",
        )

    @patch("subprocess.check_output")
    def test_start_not_hardened(self, mock_check_output):
        """Test start hook when unit is not hardened."""
        mock_check_output.return_value = b"sysctl output"
        self.harness.update_config({"tailoring-file": self.test_tailoring})
        self.harness.charm._stored.hardening_status = False
        self.harness.charm.on.start.emit()

        mock_check_output.assert_called_once_with("sysctl --system".split(" "))
        self.assertIsInstance(self.harness.model.unit.status, ops.ActiveStatus)
        self.assertEqual(
            self.harness.model.unit.status.message, "Ready for CIS hardening. Run 'harden' action"
        )

    def test_get_status_action(self):
        """Test get-status action returns correct stored state information."""
        action_event = MagicMock()
        self.harness.update_config({"tailoring-file": self.test_tailoring})
        self.harness.charm._on_get_status_action(action_event)

        expected_initial_results = {
            "result": {
                "hardened": False,
                "last-harden-time": None,
                "audited": False,
                "last-audit-time": None,
                "last-audit-result": None,
                "last-audit-files": [],
            }
        }
        action_event.set_results.assert_called_with(expected_initial_results)

        test_time = "2024-03-11T10:30:00"
        test_audit_files = ["/tmp/audit.results.xml", "/tmp/audit.results.html"]
        test_audit_result = "99%"

        self.harness.charm._stored.hardening_status = True
        self.harness.charm._stored.audit_status = True
        self.harness.charm._stored.last_hardening_timestamp = test_time
        self.harness.charm._stored.last_audit_timestamp = test_time
        self.harness.charm._stored.last_audit_files = test_audit_files
        self.harness.charm._stored.test_audit_result = test_audit_result

        # Reset mock to clear previous calls
        action_event.reset_mock()

        # Test get-status again
        self.harness.charm._on_get_status_action(action_event)

        expected_results = {
            "result": {
                "hardened": True,
                "last-harden-time": test_time,
                "audited": True,
                "last-audit-time": test_time,
                "last-audit-result": test_audit_result,
                "last-audit-files": test_audit_files,
            }
        }
        results = action_event.set_results.call_args[0][0]["result"]
        self.assertTrue(results["hardened"])
        self.assertIsNotNone(results["last-harden-time"])
        self.assertTrue(results["audited"])
        self.assertIsNotNone(results["last-audit-time"])
        # self.assertIsNotNone(results["last-audit-result"])
        self.assertTrue(len(results["last-audit-files"]) > 0)

        self.assertIsInstance(self.harness.model.unit.status, ops.ActiveStatus)
        self.assertEqual(
            self.harness.model.unit.status.message,
            "Audit finished. Result file: /tmp/audit.results.html",
        )


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest.mock import Mock, patch

from gateway import connect_upstream
from mock_s3 import access_key_from_auth
from victim_service import LabDatabase, resolve_mock_target


class GatewaySocketTests(unittest.TestCase):
    def test_upstream_connect_timeout_is_cleared_for_idle_streaming(self):
        upstream = Mock()
        with patch("gateway.socket.create_connection", return_value=upstream) as connect:
            self.assertIs(connect_upstream("attacker-kali", 7681), upstream)
        connect.assert_called_once_with(("attacker-kali", 7681), timeout=5)
        upstream.settimeout.assert_called_once_with(None)


class SSRFMappingTests(unittest.TestCase):
    def test_capital_one_metadata_url_is_mapped_to_private_mock_service(self):
        self.assertEqual(
            resolve_mock_target(
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            ),
            ("/latest/meta-data/iam/security-credentials/", None),
        )

    def test_role_credentials_url_is_mapped_to_the_same_private_mock_service(self):
        self.assertEqual(
            resolve_mock_target(
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/waf-demo-role"
            ),
            ("/latest/meta-data/iam/security-credentials/waf-demo-role", None),
        )

    def test_external_targets_are_rejected_without_resolution(self):
        for url in (
            "https://example.com/",
            "http://127.0.0.1/",
            "http://169.254.169.254:8080/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/../user-data",
            "http://user@169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.256/latest/meta-data/iam/security-credentials/",
        ):
            with self.subTest(url=url):
                self.assertIsNone(resolve_mock_target(url))


class VictimAccountTests(unittest.TestCase):
    def setUp(self):
        self.db = LabDatabase()
        self.email = "redteam-test@example.invalid"
        self.password = "NorthstarDemo-UnitTest!"

    def test_synthetic_account_can_log_in_and_session_resolves_to_account(self):
        account = self.db.register_account(
            "Red Team Demo", self.email, self.password, "172.23.0.4"
        )
        user, token = self.db.login(self.email, self.password, "172.23.0.4")
        self.assertEqual(user["user_id"], account["user_id"])
        self.assertTrue(token)
        self.assertEqual(self.db.session_user(token)["email"], self.email)
        self.assertEqual(
            [e["event_type"] for e in self.db.events()],
            ["ACCOUNT_CREATED", "LOGIN_SUCCESS"],
        )

    def test_rejects_non_demo_email_short_password_and_duplicate_email(self):
        for name, email, password in (
            ("Bad Domain", "real@example.com", self.password),
            ("Short Password", "short@example.invalid", "too-short"),
        ):
            with self.subTest(email=email):
                with self.assertRaises(ValueError):
                    self.db.register_account(name, email, password, "127.0.0.1")
        self.db.register_account("First", self.email, self.password, "127.0.0.1")
        with self.assertRaises(ValueError):
            self.db.register_account("Duplicate", self.email, self.password, "127.0.0.1")

    def test_login_failure_is_audited_without_storing_password(self):
        self.db.register_account("Red Team Demo", self.email, self.password, "172.23.0.4")
        user, token = self.db.login(self.email, "wrong-password", "172.23.0.4")
        self.assertIsNone(user)
        self.assertIsNone(token)
        self.assertEqual(self.db.events()[-1]["event_type"], "LOGIN_FAILED")
        self.assertNotIn(self.password, repr(self.db.events()))


class MockS3AuthTests(unittest.TestCase):
    def test_accepts_only_expected_synthetic_access_key_in_sigv4_header(self):
        self.assertEqual(
            access_key_from_auth(
                "AWS4-HMAC-SHA256 Credential=SIMAKIA-NORTHSTAR-DEMO/20261028/us-east-1/s3/aws4_request, "
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=" + "0" * 64
            ),
            "SIMAKIA-NORTHSTAR-DEMO",
        )

    def test_accepts_sts_scope_only_for_caller_identity_validation(self):
        sts_header = (
            "AWS4-HMAC-SHA256 Credential=SIMAKIA-NORTHSTAR-DEMO/20261028/us-east-1/sts/aws4_request, "
            "SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=" + "1" * 64
        )
        self.assertEqual(access_key_from_auth(sts_header, service="sts"), "SIMAKIA-NORTHSTAR-DEMO")
        self.assertIsNone(access_key_from_auth(sts_header, service="s3"))

    def test_rejects_unknown_key_and_malformed_authorization(self):
        for header in (
            "AWS4-HMAC-SHA256 Credential=REALKEY/20261028/us-east-1/s3/aws4_request, "
            "SignedHeaders=host, Signature=deadbeef",
            "Basic Zm9vOmJhcg==",
            "AWS4-HMAC-SHA256 Credential=SIMAKIA-NORTHSTAR-DEMO/20261028/us-east-1/s3/aws4_request, SignedHeaders=host",
        ):
            with self.subTest(header=header):
                self.assertIsNone(access_key_from_auth(header))


if __name__ == "__main__":
    unittest.main()

"""Keep public asset exceptions away from credential-bearing API responses."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('verify_deployment', Path(__file__).resolve().parents[1] / 'scripts/verify_deployment.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DeploymentPolicyTests(unittest.TestCase):
    def setUp(self):
        self.headers = {'content-type': 'text/html', 'cache-control': 'public, max-age=0, must-revalidate', 'x-content-type-options': 'nosniff'}
        self.html = b'<form id="login-form"><input id="secret"></form><div id="app" hidden></div>'

    def test_public_shell_revalidates_but_api_must_not_cache(self):
        module.check_response_policy(200, self.headers, self.html, public_dashboard=True)
        with self.assertRaises(AssertionError):
            module.check_response_policy(200, self.headers, self.html)

    def test_public_shell_rejects_credentials_and_stale_cache(self):
        for changes in ({'set-cookie': 'session=private'}, {'cache-control': 'public, max-age=3600'}, {'cache-control': ''}):
            with self.subTest(changes=changes), self.assertRaises(AssertionError):
                module.check_response_policy(200, self.headers | changes, self.html, public_dashboard=True)
        with self.assertRaises(AssertionError):
            module.check_response_policy(200, self.headers, b'private dashboard', public_dashboard=True)

    def test_only_empty_exact_canonical_redirect_is_allowed(self):
        headers = {'location': '/dashboard/', 'x-content-type-options': 'nosniff'}
        module.check_response_policy(307, headers, b'', public_dashboard=True)
        for location in ('https://other.test/dashboard/', '//other.test/dashboard/', '/admin/session', '/dashboard/?token=private'):
            with self.subTest(location=location), self.assertRaises(AssertionError):
                module.check_response_policy(307, headers | {'location': location}, b'', public_dashboard=True)
        with self.assertRaises(AssertionError):
            module.check_response_policy(307, headers, b'private', public_dashboard=True)
        with self.assertRaises(AssertionError):
            module.check_response_policy(307, headers, b'')


if __name__ == '__main__':
    unittest.main()

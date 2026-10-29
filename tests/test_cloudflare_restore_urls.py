"""R2 download request targets, isolated from credentials and all network I/O."""
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'verify_cloudflare_restore', ROOT / 'scripts/verify_cloudflare_restore.py')
restore = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore)


class R2ObjectRequestTargets(unittest.TestCase):
    def download(self, key):
        response = io.BytesIO(b'\x00synthetic backup bytes\xff')
        response.headers = {'Content-Type': 'application/octet-stream'}
        with patch.object(restore.urllib.request, 'urlopen', return_value=response) as opened:
            payload, headers = restore.cf_get_object(
                'test-account', 'synthetic-token', 'test-bucket', key)
        opened.assert_called_once()
        request = opened.call_args.args[0]
        self.assertEqual(request.get_method(), 'GET')
        self.assertEqual(opened.call_args.kwargs, {'timeout': 60})
        self.assertEqual(payload, b'\x00synthetic backup bytes\xff')
        self.assertEqual(headers['Content-Type'], 'application/octet-stream')
        return request.full_url

    def test_multisegment_spaces_unicode_and_reserved_characters(self):
        cases = [
            ('spaces/s1/blobs/b1', 'spaces/s1/blobs/b1'),
            ('folder name/report final.txt', 'folder%20name/report%20final.txt'),
            ('folder/a?#&=+;:@!$(),[]%.bin',
             'folder/a%3F%23%26%3D%2B%3B%3A%40%21%24%28%29%2C%5B%5D%25.bin'),
            ('资料/报告 1.txt', '%E8%B5%84%E6%96%99/%E6%8A%A5%E5%91%8A%201.txt'),
            ('/leading//nested/trailing/', '/leading//nested/trailing/'),
            ('folder/back\\slash', 'folder/back%5Cslash'),
        ]
        prefix = 'https://api.cloudflare.com/client/v4/accounts/test-account/r2/buckets/test-bucket/objects/'
        for key, encoded in cases:
            with self.subTest(key=key):
                url = self.download(key)
                self.assertEqual(url, prefix + encoded)
                parts = urlsplit(url)
                self.assertEqual(parts.query, '')
                self.assertEqual(parts.fragment, '')
                self.assertEqual(unquote(url[len(prefix):]), key)

    def test_literal_percent_escape_is_distinct_from_path_separator(self):
        slash = self.download('folder/a/b')
        escaped = self.download('folder/a%2Fb')
        self.assertTrue(slash.endswith('/objects/folder/a/b'))
        self.assertTrue(escaped.endswith('/objects/folder/a%252Fb'))
        self.assertNotEqual(slash, escaped)

    def test_slashes_do_not_turn_key_into_another_host_or_query(self):
        url = self.download('//other.example/path?download=1#fragment')
        parts = urlsplit(url)
        self.assertEqual(parts.netloc, 'api.cloudflare.com')
        self.assertEqual(parts.query, '')
        self.assertEqual(parts.fragment, '')
        self.assertTrue(parts.path.endswith('/objects///other.example/path%3Fdownload%3D1%23fragment'))


if __name__ == '__main__':
    unittest.main()

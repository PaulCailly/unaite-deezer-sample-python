import unittest
from unittest.mock import patch
from media import fetch_media, valid_media, NoRedirect

URL = 'https://cdnt-stream.dzcdn.net/media/1/1/a/audio.mp3?hdnea=test'


class MediaTests(unittest.TestCase):
    def test_range_only_and_response_headers_allowlist(self):
        with patch('media.build_opener') as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.status = 206
            response.headers = {'Content-Type': 'audio/mpeg', 'Content-Range': 'bytes 0-2/100', 'Set-Cookie': 'secret'}
            response.read.return_value = b'abc'
            status, body, headers = fetch_media(URL, 'bytes=0-2')
            self.assertEqual((status, body), (206, b'abc'))
            self.assertNotIn('Set-Cookie', headers)
            req = opener.return_value.open.call_args.args[0]
            self.assertEqual(dict(req.header_items()), {'Range': 'bytes=0-2'})
            self.assertIsNone(NoRedirect().redirect_request(None, None, 302, None, None, 'https://evil.invalid'))

    def test_invalid_url_is_rejected_before_network(self):
        with patch('media.build_opener') as opener:
            with self.assertRaises(ValueError):
                fetch_media('https://localhost/')
            opener.assert_not_called()
        for byte_range in ('bytes=2-1', 'bytes=0-1,2-3', 'bytes=-10', 'oops'):
            self.assertFalse(valid_media(URL, byte_range))

    def test_bad_status_type_and_oversized_body_fail(self):
        for status, mime, size in ((302, 'audio/mpeg', 0), (200, 'text/html', 3), (200, 'audio/mpeg', 32*1024*1024+1)):
            with self.subTest(status=status, mime=mime, size=size), patch('media.build_opener') as opener:
                response = opener.return_value.open.return_value.__enter__.return_value
                response.status = status
                response.headers = {'Content-Type': mime}
                response.read.return_value = b'x' * size
                with self.assertRaises(ValueError):
                    fetch_media(URL)

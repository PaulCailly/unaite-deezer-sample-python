"""Bounded relay for signed MP3 files on the official audio CDN only."""
import re
from urllib.parse import urlsplit, parse_qs
from urllib.request import Request, build_opener, HTTPRedirectHandler


def valid_media(url, byte_range=''):
    if not isinstance(url, str) or len(url) > 8192 or not isinstance(byte_range, str):
        return False
    if byte_range and not re.fullmatch(r'bytes=\d{1,12}-\d{0,12}', byte_range):
        return False
    if byte_range:
        first, last = byte_range[6:].split('-')
        if last and int(last) < int(first):
            return False
    try:
        u = urlsplit(url)
        query = parse_qs(u.query, keep_blank_values=True)
        return (u.scheme == 'https' and u.hostname == 'cdnt-stream.dzcdn.net'
                and u.port in (None, 443) and u.username is None and u.password is None and not u.fragment
                and bool(re.fullmatch(r'/media/[A-Za-z0-9/_-]+\.mp3', u.path))
                and set(query) == {'hdnea'} and len(query['hdnea']) == 1 and bool(query['hdnea'][0]))
    except ValueError:
        return False


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch_media(url, byte_range=''):
    if not valid_media(url, byte_range):
        raise ValueError('invalid_media')
    # No cookies, OAuth credentials or caller-provided headers go upstream.
    req = Request(url, headers={'Range': byte_range} if byte_range else {})
    with build_opener(NoRedirect()).open(req, timeout=30) as r:
        media_type = r.headers.get('Content-Type', '').split(';')[0]
        if r.status not in (200, 206) or media_type not in ('audio/mpeg', 'audio/mp3', 'application/octet-stream'):
            raise ValueError('media_failed')
        body = r.read(32 * 1024 * 1024 + 1)
        if len(body) > 32 * 1024 * 1024:
            raise ValueError('media_too_large')
        headers = {'Content-Type': media_type}
        content_range = r.headers.get('Content-Range', '')
        if re.fullmatch(r'bytes \d+-\d+/\d+', content_range):
            headers['Content-Range'] = content_range
        return r.status, body, headers

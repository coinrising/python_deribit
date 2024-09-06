import hashlib
import hmac
import logging
import time
import urllib.parse as _urlencode

import requests

LIVE_URL = 'https://www.deribit.com'


def milliseconds():
    return int(time.time() * 1000)


def urlencode(params={}, doseq=False):
    for key, value in params.items():
        if isinstance(value, bool):
            params[key] = 'true' if value else 'false'
    return _urlencode.urlencode(params, doseq)


def encode(string):
    return string.encode('latin-1')


def hmac_hashing(secret, payload):
    m = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256)
    return m.hexdigest()


def clean_none_value(d) -> dict:
    out = {}
    for k in d.keys():
        if d[k] is not None:
            out[k] = d[k]
    return out


class DeribitAPI:
    version = 'v2'

    def __init__(self, api_key, api_secret, base_url):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = base_url if base_url else LIVE_URL

        self.timeout = None
        self.proxies = None
        self.show_header = False
        self.show_limit_usage = False

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Content-Type": "application/json;charset=utf-8",
                "User-Agent": "deribit",
                "X-MBX-APIKEY": api_key,
            }
        )
        self.logger = logging.getLogger("python_deribit")

    @staticmethod
    def nonce():
        return milliseconds()

    def sign(self, path, method='GET', params={}, headers=None, body=None):
        request = '/' + 'api/' + self.version + path
        if path.startswith('/public'):
            if params:
                request += '?' + urlencode(params)
        elif path.startswith('/private'):
            nonce = str(self.nonce())
            timestamp = str(milliseconds())
            request_body = ''
            if params:
                request += '?' + urlencode(params)
            request_data = method + "\n" + request + "\n" + request_body + "\n"  # eslint-disable-line quotes
            auth = timestamp + "\n" + nonce + "\n" + request_data  # eslint-disable-line quotes
            signature = hmac_hashing(self.api_secret, auth, )
            headers = {
                'Authorization': 'deri-hmac-sha256 id=' + self.api_key + ',ts=' + timestamp + ',sig=' + signature + ',' + 'nonce=' + nonce,
            }
        url = self.base_url + request
        return {'url': url, 'method': method, 'body': body, 'headers': headers}

    def send_request(self, url, method, body=None, headers=False):
        if body is None:
            body = {}
        self.logger.debug("url: " + url)
        params = clean_none_value(
            {
                "url": url,
                "params": None,
                "timeout": self.timeout,
                "proxies": self.proxies,
                'headers': headers,
            }
        )
        response = self._dispatch_request(method)(**params)
        logging.debug("raw response from server:" + response.text)

        try:
            data = response.json()
        except ValueError:
            data = response.text
        result = {}

        if self.show_limit_usage or True:
            limit_usage = {}
            for key in response.headers.keys():
                key = key.lower()
                if (
                        key.startswith("x-mbx-used-weight")
                        or key.startswith("x-mbx-order-count")
                        or key.startswith("x-sapi-used")
                ):
                    limit_usage[key] = response.headers[key]
            # result["limit_usage"] = limit_usage
            self.logger.debug(limit_usage)

        if self.show_header:
            # result["header"] = response.headers
            self.logger.debug(response.headers)

        if len(result) != 0:
            result["data"] = data
            return result

        return data

    def _dispatch_request(self, http_method):
        return {
            "GET": self.session.get,
            "DELETE": self.session.delete,
            "PUT": self.session.put,
            "POST": self.session.post,
        }.get(http_method, self.session.get)

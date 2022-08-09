# Cloudflare V1

import re
import sys
import time

from copy import deepcopy
from collections import OrderedDict

# ------------------------------------------------------------------------------- #

try:
    from HTMLParser import HTMLParser
except ImportError:
    if sys.version_info >= (3, 4):
        import html
    else:
        from html.parser import HTMLParser

try:
    from urlparse import urlparse, urljoin
except ImportError:
    from urllib.parse import urlparse, urljoin

# ------------------------------------------------------------------------------- #

from .exceptions import (
    CloudflareCode1020,
    CloudflareIUAMError,
    CloudflareSolveError,
    CloudflareChallengeError,
    CloudflareCaptchaError,
    CloudflareCaptchaProvider
)

# ------------------------------------------------------------------------------- #

class Cloudflare():

    def __init__(self, cloudscraper):
        self.cloudscraper = cloudscraper

    # ------------------------------------------------------------------------------- #
    # Unescape / decode html entities
    # ------------------------------------------------------------------------------- #

    @staticmethod
    def unescape(html_text):
        if sys.version_info >= (3, 0):
            if sys.version_info >= (3, 4):
                return html.unescape(html_text)

            return HTMLParser().unescape(html_text)

        return HTMLParser().unescape(html_text)

    # ------------------------------------------------------------------------------- #
    # check if the response contains a valid Cloudflare challenge
    # ------------------------------------------------------------------------------- #

    @staticmethod
    def is_IUAM_Challenge(resp):
        try:
            return (
                resp.headers.get('Server', '').startswith('cloudflare')
                and resp.status_code in [429, 503]
                and re.search(
                    r'<form .*?="challenge-form" action="/.*?__cf_chl_jschl_tk__=\S+"',
                    resp.text,
                    re.M | re.S
                )
            )
        except AttributeError:
            pass

        return False

    # ------------------------------------------------------------------------------- #
    # check if the response contains new Cloudflare challenge
    # ------------------------------------------------------------------------------- #

    @staticmethod
    def is_New_IUAM_Challenge(resp):
        try:
            return (
                resp.headers.get('Server', '').startswith('cloudflare')
                and resp.status_code in [429, 503]
                and re.search(
                    r'cpo.src\s*=\s*"/cdn-cgi/challenge-platform/\S+orchestrate/jsch/v1',
                    resp.text,
                    re.M | re.S
                )
                and re.search(r'window._cf_chl_enter\s*[\(=]', resp.text, re.M | re.S)
            )
        except AttributeError:
            pass

        return False

    # ------------------------------------------------------------------------------- #
    # check if the response contains a v2 hCaptcha Cloudflare challenge
    # ------------------------------------------------------------------------------- #

    def is_New_Captcha_Challenge(self, resp):
        try:
            return (
                self.is_Captcha_Challenge(resp)
                and re.search(
                    r'cpo.src\s*=\s*"/cdn-cgi/challenge-platform/\S+orchestrate/(captcha|managed)/v1',
                    resp.text,
                    re.M | re.S
                )
                and re.search(r'\s*id="trk_captcha_js"', resp.text, re.M | re.S)
            )
        except AttributeError:
            pass

        return False

    # ------------------------------------------------------------------------------- #
    # check if the response contains a Cloudflare hCaptcha challenge
    # ------------------------------------------------------------------------------- #

    @staticmethod
    def is_Captcha_Challenge(resp):
        try:
            return (
                resp.headers.get('Server', '').startswith('cloudflare')
                and resp.status_code == 403
                and re.search(
                    r'action="/\S+__cf_chl_captcha_tk__=\S+',
                    resp.text,
                    re.M | re.DOTALL
                )
            )
        except AttributeError:
            pass

        return False

    # ------------------------------------------------------------------------------- #
    # check if the response contains Firewall 1020 Error
    # ------------------------------------------------------------------------------- #

    @staticmethod
    def is_Firewall_Blocked(resp):
        try:
            return (
                resp.headers.get('Server', '').startswith('cloudflare')
                and resp.status_code == 403
                and re.search(
                    r'<span class="cf-error-code">1020</span>',
                    resp.text,
                    re.M | re.DOTALL
                )
            )
        except AttributeError:
            pass

        return False

    # ------------------------------------------------------------------------------- #
    # Wrapper for is_Captcha_Challenge, is_IUAM_Challenge, is_Firewall_Blocked
    # ------------------------------------------------------------------------------- #

    def is_Challenge_Request(self, resp):
        if self.is_Firewall_Blocked(resp):
            self.cloudscraper.simpleException(
                CloudflareCode1020,
                'Cloudflare has blocked this request (Code 1020 Detected).'
            )

        if self.is_New_Captcha_Challenge(resp):
            self.cloudscraper.simpleException(
                CloudflareChallengeError,
                'Detected a Cloudflare version 2 Captcha challenge, This feature is not available in the opensource (free) version.'
            )

        if self.is_New_IUAM_Challenge(resp):
            self.cloudscraper.simpleException(
                CloudflareChallengeError,
                'Detected a Cloudflare version 2 challenge, This feature is not available in the opensource (free) version.'
            )

        if self.is_Captcha_Challenge(resp) or self.is_IUAM_Challenge(resp):
            self.cloudscraper.simpleException(
                CloudflareChallengeError,
                'Detected a Cloudflare version 1 challenge.'
            )

        return False
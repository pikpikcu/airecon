from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("airecon.proxy.agent.auth_manager")

_AUTH_PATTERNS_FILE = Path(__file__).parent.parent / "data" / "verification_patterns.json"


def _load_auth_patterns():
    try:
        if _AUTH_PATTERNS_FILE.exists():
            data = json.loads(_AUTH_PATTERNS_FILE.read_text(encoding="utf-8"))
            auth_failure = data.get("auth_failure_patterns", {})
            login_form = data.get("login_form_patterns", {})
            return {
                k: re.compile(v, re.I) for k, v in auth_failure.items()
            }, {
                k: re.compile(v, re.I) for k, v in login_form.items()
            }
    except Exception as e:
        logger.warning("Failed to load auth patterns from JSON, using defaults: %s", e)
    return {
        "401_unauthorized": re.compile(r"401|unauthorized|authentication required", re.I),
        "403_forbidden": re.compile(r"403|forbidden|access denied", re.I),
        "session_expired": re.compile(r"session expired|session timeout|logged out", re.I),
        "csrf_token": re.compile(r"csrf|xsrf|token mismatch", re.I),
        "login_required": re.compile(r"login required|sign in|please log", re.I),
    }, {
        "username": re.compile(r'name=["\']?(username|user|email|login)["\']?', re.I),
        "password": re.compile(r'name=["\']?(password|pass|pwd)["\']?', re.I),
        "csrf": re.compile(r'name=["\']?(csrf|_token|authenticity_token)["\']?', re.I),
    }


_AUTH_FAILURE_PATTERNS, _LOGIN_FORM_PATTERNS = _load_auth_patterns()


class AuthManager: 
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

        self.credentials: dict[str, Any] = {}

        self.auth_cookies: list[dict] = []
        self.auth_tokens: dict[str, str] = {}
        self.last_auth_attempt: float = 0
        self.auth_failures: int = 0

    async def close(self) -> None:
        await self.client.aclose()

    async def __aenter__(self) -> "AuthManager":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    def detect_auth_failure(self, response: httpx.Response) -> tuple[bool, str]:
        if response.status_code == 401:
            return True, "401_unauthorized"

        if response.status_code == 403:
            return True, "403_forbidden"

        body_text = response.text

        for failure_type, pattern in _AUTH_FAILURE_PATTERNS.items():
            if pattern.search(body_text):
                logger.info(f"Auth failure detected: {failure_type}")
                return True, failure_type

        return False, ""

    def _validate_login_url(self, login_url: str, target_url: str) -> bool:
        try:
            login_host = urlparse(login_url).hostname
            if not login_host:
                return False
            if "://" not in target_url:
                target_host = urlparse(f"https://{target_url}").hostname
            else:
                target_host = urlparse(target_url).hostname
            if not target_host:
                return False
            if login_host == target_host:
                return True
            if login_host.endswith(f".{target_host}"):
                return True
            if target_host.endswith(f".{login_host}"):
                return True
            logger.warning(
                "Auth domain mismatch: login=%s vs target=%s — skipping reauth to prevent credential leak",
                login_host,
                target_host,
            )
            return False
        except Exception as e:
            logger.error("Login URL validation error: %s — blocking reauth", e)
            return False

    async def handle_auth_failure(
        self,
        response: httpx.Response,
        target_url: str,
    ) -> bool:
        is_failure, failure_type = self.detect_auth_failure(response)

        if not is_failure:
            return True

        logger.info(f"Handling auth failure: {failure_type} on {target_url}")

        if not self.credentials:
            logger.warning("No credentials stored - cannot auto-reauth")
            return False

        if failure_type in ("401_unauthorized", "session_expired", "login_required"):
            return await self.auto_reauth(target_url)

        if failure_type == "csrf_token":
            return await self.handle_csrf_failure(target_url)

        if failure_type == "403_forbidden":
            return await self.auto_reauth(target_url)

        return False

    async def auto_reauth(self, login_url: str) -> bool:
        try:
            target_host = self._safe_target_host if hasattr(self, '_safe_target_host') else None
            if target_host:
                if not self._validate_login_url(login_url, target_host):
                    return False
            logger.info(f"Fetching login page: {login_url}")
            response = await self.client.get(login_url)

            csrf_token = self._extract_csrf_token(response.text)

            login_data = {
                "username": self.credentials.get("username", ""),
                "password": self.credentials.get("password", ""),
            }

            for field, value in self.credentials.items():
                if field in {"username", "password"}:
                    continue
                if value is None:
                    continue
                login_data[str(field)] = str(value)

            if csrf_token:
                csrf_fields = ("csrf_token", "csrf", "_token", "authenticity_token")
                applied = False
                for field_name in csrf_fields:
                    if field_name in login_data:
                        login_data[field_name] = csrf_token
                        applied = True
                if not applied:
                    login_data["csrf_token"] = csrf_token
                logger.info("CSRF token extracted and added to login")

            login_response = await self.client.post(login_url, data=login_data)

            if self._is_login_successful(login_response):
                logger.info("Re-authentication successful")

                self._store_session_cookies(login_response.cookies)

                return True
            else:
                logger.warning("Re-authentication failed - invalid credentials?")
                self.auth_failures += 1
                return False

        except Exception as e:
            logger.error(f"Re-authentication error: {e}")
            return False

    async def handle_csrf_failure(self, target_url: str) -> bool:
        try:
            response = await self.client.get(target_url)
            csrf_token = self._extract_csrf_token(response.text)

            if csrf_token:
                logger.info("Fresh CSRF token obtained")

                return True
            else:
                logger.warning("No CSRF token found on page")
                return False

        except Exception as e:
            logger.error(f"CSRF handling error: {e}")
            return False

    async def handle_oauth(
        self,
        oauth_url: str,
        client_id: str | None = None,
        redirect_uri: str | None = None,
    ) -> dict[str, Any]:
        try:
            params = {}
            if client_id:
                params["client_id"] = client_id
            if redirect_uri:
                params["redirect_uri"] = redirect_uri
            params["response_type"] = "code"

            logger.info(f"Starting OAuth flow: {oauth_url}")
            response = await self.client.get(oauth_url, params=params)

            return {
                "success": True,
                "message": "OAuth flow initiated (manual completion required)",
                "authorization_url": str(response.url),
            }

        except Exception as e:
            logger.error(f"OAuth flow error: {e}")
            return {
                "success": False,
                "error": str(e),
            }

    def set_credentials(
        self,
        username: str,
        password: str,
        extra_fields: dict[str, str] | None = None,
        target_url: str | None = None,
    ) -> None:
        self.credentials = {
            "username": username,
            "password": password,
        }

        if extra_fields:
            self.credentials.update(extra_fields)

        if target_url:
            self._safe_target_host = target_url

        logger.info("Credentials stored for auto-reauth")

    def _extract_csrf_token(self, html: str) -> str | None:
        patterns = [
            r'name=["\']?csrf_token["\']?\s+value=["\']?([^"\'>\s]+)["\']?',
            r'name=["\']?_token["\']?\s+value=["\']?([^"\'>\s]+)["\']?',
            r'name=["\']?authenticity_token["\']?\s+value=["\']?([^"\'>\s]+)["\']?',
            r'name=["\']?csrf["\']?\s+value=["\']?([^"\'>\s]+)["\']?',
        ]

        for pattern in patterns:
            match = re.search(pattern, html, re.I)
            if match:
                return match.group(1)

        return None

    def _is_login_successful(self, response: httpx.Response) -> bool:
        if response.status_code in (401, 403):
            return False

        body_lower = response.text.lower()

        failure_indicators = (
            "invalid credentials",
            "incorrect password",
            "login failed",
            "authentication failed",
            "wrong username",
            "login required",
            "please sign in",
            "sign in",
        )
        for indicator in failure_indicators:
            if indicator in body_lower:
                return False

        success_indicators = (
            "welcome",
            "logged in",
            "dashboard",
            "logout",
        )
        for indicator in success_indicators:
            if indicator in body_lower:
                return True

        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("location", "").lower()
            if any(token in location for token in ("login", "signin", "sign-in", "auth")):
                return False
            return True

        session_cookie_markers = (
            "session", "sessionid", "sess", "auth", "token", "jwt", "remember"
        )
        if any(
            any(marker in cookie.name.lower() for marker in session_cookie_markers)
            for cookie in response.cookies
        ):
            return True

        return False

    def _store_session_cookies(self, cookies: httpx.Cookies) -> None:
        session_cookie_names = (
            "session",
            "sessionid",
            "sess",
            "phpsessid",
            "jsessionid",
            "asp.net_sessionid",
            "remember",
            "auth",
            "jwt",
        )

        cookie_iterable = getattr(cookies, "jar", cookies)
        for cookie in cookie_iterable:
            if hasattr(cookie, "name"):
                cookie_name = str(cookie.name)
                cookie_value = str(cookie.value)
                cookie_domain = str(getattr(cookie, "domain", ""))
                cookie_path = str(getattr(cookie, "path", "/"))
            else:
                cookie_name = str(cookie)
                cookie_value = str(cookies.get(cookie_name, ""))
                cookie_domain = ""
                cookie_path = "/"

            cookie_lower = cookie_name.lower()
            if any(name in cookie_lower for name in session_cookie_names):
                self.auth_cookies.append({
                    "name": cookie_name,
                    "value": cookie_value,
                    "domain": cookie_domain,
                    "path": cookie_path,
                })
                logger.info(f"Session cookie stored: {cookie_name}")

        self.client.cookies.update(cookies)

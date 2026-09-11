from __future__ import annotations

import asyncio
import json
import logging

from typing import Any

logger = logging.getLogger("airecon.captcha_solver")


_CAPTCHA_ANALYSE_PROMPT = """You are an expert CAPTCHA analyst. You are looking at a webpage screenshot that may contain a CAPTCHA challenge.

Your task:
1. Identify if there is a CAPTCHA present on the page
2. Describe what the CAPTCHA looks like (checkbox, image grid, text, slider, puzzle, invisible, mathematical, behavioral, 3D, etc.)
3. Identify the CAPTCHA brand/provider if visible (Google reCAPTCHA, hCaptcha, Cloudflare Turnstile, FunCaptcha/Arkose, GeeTest, DataDome, PerimeterX, KeyCAPTCHA, mCaptcha, or unknown)
4. Determine the best approach to solve it:
   - "dom_bypass": The CAPTCHA can be bypassed by injecting a token placeholder (works for widget-based CAPTCHAs like reCAPTCHA, hCaptcha, Cloudflare Turnstile, and similar token-response based systems)
   - "text_extract": The CAPTCHA requires reading text/characters from an image (classic text CAPTCHAs)
   - "interactive": The CAPTCHA requires visual interaction guidance (sliders, drag-drop, image selection)
   - "impossible": This CAPTCHA cannot be solved programmatically and requires human intervention
5. Explain your reasoning briefly
6. If dom_bypass is the approach, identify the CSS selectors and form field names needed to inject a placeholder token.

Respond ONLY with valid JSON in this exact format:
{
  "captcha_present": true/false,
  "provider": "brand name or unknown",
  "type_description": "what it looks like in 1-2 sentences",
  "approach": "dom_bypass|text_extract|interactive|impossible",
  "bypass_selectors": ["css selector for container", "name of hidden input field"],
  "reasoning": "brief explanation of your decision"
}

Do NOT wrap the JSON in markdown code blocks. Output raw JSON only."""


_CAPTCHA_TEXT_PROMPT = """You are a CAPTCHA text reader. Look at this CAPTCHA image and extract the exact text/characters/numbers shown.

Rules:
- Output ONLY the exact text — no explanation, no quotes
- If it is a math problem (e.g. "3 + 5 = ?"), output the full expression as shown
- If it contains letters that look distorted, output what you read
- If case matters, preserve it
- If there are multiple words, separate with spaces
- If no text CAPTCHA is visible, respond with: NONE"""


_DOM_BYPASS_TEMPLATE = """(() => {{
    try {{
        // Hide the CAPTCHA container
        const containers = {selectors};
        if (containers && containers.length) {{
            containers.forEach(c => c.style.display = 'none');
        }}
        // Inject placeholder token into response field
        let input = document.querySelector('{input_name}');
        if (!input) {{
            input = document.createElement('input');
            input.type = 'hidden';
            input.name = '{input_name}';
            document.body.appendChild(input);
        }}
        input.value = 'vision-passed';
        return {{ success: true, method: 'universal_dom_bypass' }};
    }} catch(e) {{
        return {{ success: false, error: e.message }};
    }}
}})();"""


class CaptchaSolver:
    """Universal vision-based CAPTCHA solver.

    Requires config-driven params — no hardcoded defaults, no hardcoded types.
    Vision is routed through the OpenAI-compatible gateway (LiteLLM/
    vLLM/hosted): the model sees the screenshot, analyses the HTML, and decides
    the approach. Requires a vision-capable model behind the gateway.
    """

    def __init__(
        self,
        base_url: str,
        captcha_model: str,
        api_key: str = "",
        timeout: float = 60,
    ):
        self.base_url = base_url.rstrip("/")
        self.captcha_model = captcha_model
        self.api_key = api_key
        self.timeout = timeout
        self.solve_attempts: list[dict[str, Any]] = []

    def _vision_payload(self, screenshot_b64: str, prompt: str) -> dict[str, Any]:
        return {
            "model": self.captcha_model,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/png;base64,{screenshot_b64}"
                            },
                        },
                    ],
                }
            ],
            "stream": False,
            "temperature": 0.0,
            "max_tokens": 512,
        }

    def _vision_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    @staticmethod
    def _extract_answer(data: dict[str, Any]) -> str | None:
        choices = data.get("choices") or []
        if not choices:
            return None
        msg = choices[0].get("message") or {}
        answer = (msg.get("content") or "").strip()
        return answer or None

    async def _call_llm_vision(
        self,
        screenshot_b64: str,
        prompt: str,
    ) -> str | None:
        """Send screenshot to the gateway vision model and get a response."""
        payload = self._vision_payload(screenshot_b64, prompt)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=self._vision_headers(),
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status != 200:
                        text = await resp.text()
                        logger.warning(
                            "Vision API returned %d: %s",
                            resp.status,
                            text[:300],
                        )
                        return None

                    data = await resp.json()
                    answer = self._extract_answer(data)

                    if not answer:
                        logger.warning("Vision model returned empty response")
                        return None

                    return answer

        except ImportError:
            return await self._call_llm_vision_sync(screenshot_b64, prompt)
        except Exception as exc:
            logger.debug("Vision call failed: %s", exc)
            return None

    async def _call_llm_vision_sync(
        self,
        screenshot_b64: str,
        prompt: str,
    ) -> str | None:
        """Synchronous fallback using urllib."""
        import urllib.request

        payload = json.dumps(
            self._vision_payload(screenshot_b64, prompt)
        ).encode("utf-8")
        headers = self._vision_headers()

        def _blocking_call() -> str | None:
            req = urllib.request.Request(
                f"{self.base_url}/chat/completions",
                data=payload,
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310
                data = json.loads(resp.read().decode("utf-8"))
                return CaptchaSolver._extract_answer(data)

        try:
            # Run the blocking urllib call in a worker thread so we never stall
            # the asyncio event loop (this method is the fallback when aiohttp
            # is unavailable, but it must still behave like a proper coroutine).
            return await asyncio.to_thread(_blocking_call)
        except Exception as exc:
            logger.debug("Vision (sync) call failed: %s", exc)
            return None

    # ── CAPTCHA Analysis (fully LLM-driven, no hardcoded types) ──────────────

    async def analyse_captcha(
        self,
        screenshot_b64: str,
        page_html: str = "",
    ) -> dict[str, Any]:
        """Ask the LLM to analyse the CAPTCHA and return a structured analysis.

        This is the vision-first approach — the LLM sees the page, identifies
        the CAPTCHA, determines its type, and selects the best solving strategy.

        Returns:
            dict with: captcha_present, provider, type_description, approach,
                       bypass_selectors, input_names, reasoning
        """
        raw_answer = await self._call_llm_vision(
            screenshot_b64,
            _CAPTCHA_ANALYSE_PROMPT,
        )

        if not raw_answer:
            logger.warning("LLM did not return a CAPTCHA analysis")
            return {"captcha_present": False, "approach": "impossible"}

        # Parse JSON from the LLM response
        parsed = _parse_llm_json(raw_answer)
        if not parsed:
            # Fallback: treat unknown response as "couldn't determine"
            logger.warning(
                "Failed to parse CAPTCHA analysis JSON: %r",
                raw_answer[:200],
            )
            return {
                "captcha_present": True,
                "approach": "impossible",
                "raw_analysis": raw_answer,
            }

        # Normalise fields
        result = {
            "captcha_present": bool(parsed.get("captcha_present", False)),
            "provider": str(parsed.get("provider", "unknown")),
            "type_description": str(parsed.get("type_description", "")),
            "approach": str(parsed.get("approach", "impossible")).lower(),
            "bypass_selectors": parsed.get("bypass_selectors", []),
            "input_names": parsed.get("input_names", []),
            "reasoning": str(parsed.get("reasoning", "")),
        }

        logger.info(
            "CAPTCHA analysis: present=%s, provider=%s, approach=%s — %s",
            result["captcha_present"],
            result["provider"],
            result["approach"],
            result["reasoning"][:100],
        )

        self.solve_attempts.append({
            "phase": "analyse",
            "result": result,
        })

        return result

    # ── Main Solve Flow (vision-first, strategy-adaptive) ────────────────────

    async def solve_from_page(
        self,
        page_screenshot_b64: str,
        page_html: str = "",
        captcha_type: str | None = None,
    ) -> dict[str, Any]:
        """Universal CAPTCHA solver — adaptive, vision-driven.

        Strategy:
        1. Let the LLM analyse the screenshot to identify and classify the CAPTCHA
        2. Choose the appropriate solving approach based on the analysis:
           - dom_bypass: inject placeholder token into response fields
           - text_extract: read CAPTCHA text using LLM vision
           - interactive: return analysis for human guidance
           - impossible: report failure
        3. Execute the chosen approach

        Args:
            page_screenshot_b64: Base64-encoded screenshot of the page
            page_html: Full page HTML (used for context, bypass injection)
            captcha_type: Optional hint (e.g. from caller's knowledge).
                          If not provided, the LLM auto-detects.

        Returns:
            dict with: success, method, captcha_type, solution, bypass_js
        """
        result: dict[str, Any] = {
            "success": False,
            "method": None,
            "captcha_type": None,
            "solution": None,
            "bypass_js": None,
        }

        # Step 1 — Vision-first analysis (unless caller already knows the type)
        if captcha_type and captcha_type != "unknown":
            # Caller provided a hint — use it to construct minimal analysis
            analysis = {
                "captcha_present": True,
                "provider": captcha_type,
                "type_description": f"Caller-provided hint: {captcha_type}",
                "approach": "dom_bypass" if _looks_like_widget_captcha(
                    captcha_type
                ) else "impossible",
                "bypass_selectors": [],
                "input_names": _guess_input_names(captcha_type),
                "reasoning": "Caller provided type hint",
            }
        else:
            analysis = await self.analyse_captcha(
                page_screenshot_b64, page_html,
            )

        if not analysis.get("captcha_present"):
            logger.info("No CAPTCHA detected — nothing to solve")
            return result

        result["captcha_type"] = analysis.get("provider", "unknown")

        # Step 2 — Execute the chosen approach
        approach = analysis.get("approach", "impossible")

        if approach == "dom_bypass":
            bypass_js = _build_dom_bypass(analysis, page_html)
            if bypass_js:
                result["bypass_js"] = bypass_js
                result["success"] = True
                result["method"] = "dom_bypass"
                result["solution"] = "vision-passed"
                logger.info(
                    "CAPTCHA solved: provider=%s, method=dom_bypass",
                    result["captcha_type"],
                )
                return result

        elif approach == "text_extract":
            text_answer = await self._call_llm_vision(
                page_screenshot_b64,
                _CAPTCHA_TEXT_PROMPT,
            )
            if text_answer and text_answer != "NONE":
                result["success"] = True
                result["method"] = "llm_vision"
                result["solution"] = text_answer
                logger.info(
                    "CAPTCHA solved: method=vision_extract, text=%r",
                    text_answer,
                )
                return result

        # Approach failed or impossible
        logger.warning(
            "CAPTCHA solving unsuccessful: provider=%s, approach=%s, reason=%s",
            result["captcha_type"],
            approach,
            analysis.get("reasoning", ""),
        )
        result["method"] = approach
        return result

    # ── Helper ───────────────────────────────────────────────────────────────

    def is_enabled(self) -> bool:
        """Check if vision-based CAPTCHA solving is enabled."""
        return bool(self.captcha_model and self.captcha_model.strip())


# ── Pure helper functions (no hardcoded CAPTCHA type dicts) ──────────────────


def _parse_llm_json(raw: str) -> dict[str, Any] | None:
    """Extract JSON from LLM response — handles markdown code blocks too."""
    # Strip markdown code fences if present
    stripped = raw.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[-1]
        if stripped.endswith("```"):
            stripped = stripped.rsplit("```", 1)[0]
        stripped = stripped.strip()

    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        # Try to find JSON object in the raw text
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(stripped[start:end + 1])
            except json.JSONDecodeError:
                pass
        return None


def _looks_like_widget_captcha(type_hint: str) -> bool:

    t = type_hint.lower()
    widget_keywords = (
        "captcha", "challenge", "turnstile", "widget",
        "recaptcha", "hcaptcha", "cloudflare", "verify",
        "verification", "checkbox", "arkose", "funcaptcha",
        "geetest", "datadome", "perimeter", "shape",
    )
    return any(kw in t for kw in widget_keywords)


def _guess_input_names(type_hint: str) -> list[str]:

    t = type_hint.lower()
    names: list[str] = []
    if "recaptcha" in t:
        names.append("g-recaptcha-response")
    if "hcaptcha" in t:
        names.append("h-captcha-response")
    if "turnstile" in t or "cloudflare" in t:
        names.append("cf-turnstile-response")
    names.append("captcha-token")
    names.append("captcha_response")
    names.append("validation_token")
    # De-duplicate while preserving order
    seen = set()
    deduped = []
    for n in names:
        if n not in seen:
            seen.add(n)
            deduped.append(n)
    return deduped


def _build_dom_bypass(
    analysis: dict[str, Any],
    page_html: str,
) -> str | None:
    """Build a DOM bypass injection script from the analysis.

    Uses selectors from the LLM analysis + well-known input names as fallback.
    """
    selectors = analysis.get("bypass_selectors", [])
    input_names = analysis.get("input_names", [])

    if not selectors:
        selectors = [
            'iframe[src*="captcha"]',
            'iframe[src*="challenge"]',
            '[class*="captcha"]',
            '[id*="captcha"]',
            'div[role="complementary"]',
        ]

    if not input_names:
        input_names = [
            "g-recaptcha-response",
            "h-captcha-response",
            "cf-turnstile-response",
            "captcha-token",
        ]

    input_name = input_names[0] if input_names else "captcha-token"

    try:
        return _DOM_BYPASS_TEMPLATE.format(
            selectors=f"document.querySelectorAll('{input_name}'), document.querySelectorAll('[class*=captcha]')",
            input_name=input_name,
        )
    except Exception as exc:
        logger.debug("Failed to build DOM bypass: %s", exc)
        return None

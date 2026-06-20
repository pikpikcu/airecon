from __future__ import annotations

import logging
from typing import Any

from .pipeline import PipelinePhase
from .constants import SHALLOW_TOOLS as _SHALLOW_TOOLS, DEEP_TOOLS as _DEEP_TOOLS
from .utils import cfg_typed

logger = logging.getLogger("airecon.agent.inference")


def _cfg_bool_impl(cfg: Any, key: str, default: bool) -> bool:
    try:
        val = getattr(cfg, key, default)
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            return val.lower() in ("1", "true", "yes", "on")
        return bool(val)
    except Exception as _e:
        return default


class _InferenceMixin:
    @staticmethod
    def _cfg_bool(cfg: Any, key: str, default: bool) -> bool:
        return _cfg_bool_impl(cfg, key, default)

    @staticmethod
    def _cfg_int(cfg: Any, key: str, default: int) -> int:
        return cfg_typed(cfg, key, default, int)

    @staticmethod
    def _cfg_float(cfg: Any, key: str, default: float) -> float:
        return cfg_typed(cfg, key, default, float)

    @staticmethod
    def _get_thinking_mode(cfg: Any) -> str:
        raw_mode = getattr(cfg, "llm_thinking_mode", "adaptive")
        if not isinstance(raw_mode, str):
            logger.warning(
                f"Invalid thinking mode type ({type(raw_mode)}), using 'adaptive'"
            )
            return "adaptive"

        thinking_mode = raw_mode.lower().strip()
        valid_modes = ("low", "medium", "high", "adaptive")

        if thinking_mode not in valid_modes:
            logger.warning(
                f"Invalid thinking_mode '{thinking_mode}' — must be one of {valid_modes}. Using 'adaptive'."
            )
            return "adaptive"

        return thinking_mode

    @staticmethod
    def _fit_num_predict_to_ctx(num_predict: int, num_ctx: int) -> int:
        _ctx = max(1024, int(num_ctx))
        _requested = max(256, int(num_predict))
        _prompt_reserve = 1024 if _ctx >= 4096 else max(256, _ctx // 4)
        _max_by_prompt = max(256, _ctx - _prompt_reserve)
        _max_by_ratio = max(512, int(_ctx * 0.40))
        return max(256, min(_requested, _max_by_prompt, _max_by_ratio))

    @staticmethod
    def _fit_num_keep_to_ctx(num_keep: int, num_ctx: int, num_predict: int) -> int:
        _ctx = max(1024, int(num_ctx))
        _predict = max(0, int(num_predict))
        _requested = max(0, int(num_keep))
        _max_by_ctx = max(0, _ctx - 256)
        _max_by_predict = max(0, _ctx - _predict - 256)
        return min(_requested, _max_by_ctx, _max_by_predict)

    def _get_iteration_num_predict(
        self, cfg: Any, current_phase: Any, num_ctx: int
    ) -> int:
        _phase_name = current_phase.value if current_phase else "RECON"
        _requested = self._get_adaptive_num_predict(cfg, _phase_name)
        if self._adaptive_num_predict_cap > 0:
            _requested = min(_requested, self._adaptive_num_predict_cap)

        _used = self.state.token_usage.get("used", 0)
        _pressure = _used / max(num_ctx, 1)
        if _pressure >= 0.75:
            _requested = min(_requested, 2048)
        elif _pressure >= 0.65:
            _requested = min(_requested, 4096)
        elif _pressure >= 0.50:
            _requested = min(_requested, 8192)

        return self._fit_num_predict_to_ctx(_requested, num_ctx)

    def _should_use_thinking(self, cfg: Any, current_phase: Any) -> bool:
        thinking_enabled = self._cfg_bool(cfg, "llm_enable_thinking", True)
        model_supports_thinking = self.llm.supports_thinking

        if not (thinking_enabled and model_supports_thinking):
            logger.debug(
                f"Thinking disabled: enabled={thinking_enabled}, model_supports={model_supports_thinking}"
            )
            return False

        thinking_mode = self._get_thinking_mode(cfg)

        phase_name = current_phase.value if current_phase else "UNKNOWN"
        last_tool = self._recent_tool_names[-1] if self._recent_tool_names else "none"

        stagnation_threshold = self._cfg_int(cfg, "agent_stagnation_threshold", 2)
        _is_struggling = (
            self._stagnation_iterations >= stagnation_threshold
            or self._recovery_force_tool_calls > 0
            or self._consecutive_failures >= 2
            or self._no_tool_iterations >= 1
            or self._watchdog_forced_calls > 0
        )

        _max_consecutive_thinking = self._cfg_int(
            cfg, "agent_max_consecutive_thinking", 5
        )
        if (
            getattr(self, "_consecutive_thinking_iterations", 0)
            >= _max_consecutive_thinking
        ):
            logger.debug(
                f"Thinking DISABLED (mode={thinking_mode}): consecutive_thinking={self._consecutive_thinking_iterations} >= {_max_consecutive_thinking}"
            )
            return False

        if _is_struggling:
            logger.debug(
                f"Thinking ENABLED (mode={thinking_mode}, phase={phase_name}, tool={last_tool}): struggling=True"
            )
            return True

        is_deep_tool = last_tool in _DEEP_TOOLS
        is_shallow_tool = last_tool in _SHALLOW_TOOLS

        if self._ctf_mode:
            if is_deep_tool:
                logger.debug(
                    f"Thinking ENABLED (mode={thinking_mode}, CTF): deep_tool={last_tool}"
                )
                return True
            if thinking_mode in ("high", "adaptive"):
                should_think = self.state.iteration % 5 == 0
                logger.debug(
                    f"Thinking {'ENABLED' if should_think else 'DISABLED'} (mode={thinking_mode}, CTF): iteration={self.state.iteration}, periodic={should_think}"
                )
                return should_think
            logger.debug(
                f"Thinking DISABLED (mode={thinking_mode}, CTF): low/medium mode"
            )
            return False

        if thinking_mode == "low":
            should_think = is_deep_tool
            logger.debug(
                f"Thinking {'ENABLED' if should_think else 'DISABLED'} (mode=low): deep_tool={is_deep_tool}, tool={last_tool}"
            )
            return should_think

        if thinking_mode == "medium":
            should_think = (
                current_phase
                and current_phase in (PipelinePhase.ANALYSIS, PipelinePhase.EXPLOIT)
            ) or is_deep_tool
            logger.debug(
                f"Thinking {'ENABLED' if should_think else 'DISABLED'} (mode=medium): phase={phase_name}, deep_tool={is_deep_tool}"
            )
            return should_think

        if thinking_mode == "high":
            if is_shallow_tool and self.state.iteration > 15:
                logger.debug(
                    f"Thinking DISABLED (mode=high): shallow_tool={last_tool}, iteration={self.state.iteration}>15"
                )
                return False
            if current_phase and current_phase == PipelinePhase.RECON:
                should_think = self.state.iteration <= 15
                logger.debug(
                    f"Thinking {'ENABLED' if should_think else 'DISABLED'} (mode=high, RECON): iteration={self.state.iteration}<=15={should_think}"
                )
                return should_think
            logger.debug(f"Thinking ENABLED (mode=high): default for {phase_name}")
            return True

        if current_phase and current_phase in (
            PipelinePhase.ANALYSIS,
            PipelinePhase.EXPLOIT,
        ):
            logger.debug(f"Thinking ENABLED (mode=adaptive): phase={phase_name}")
            return True

        if is_deep_tool:
            logger.debug(f"Thinking ENABLED (mode=adaptive): deep_tool={last_tool}")
            return True

        should_think = self.state.iteration <= 8
        logger.debug(
            f"Thinking {'ENABLED' if should_think else 'DISABLED'} (mode=adaptive, RECON/REPORT): iteration={self.state.iteration}<=8={should_think}, tool={last_tool}"
        )
        return should_think

    def _get_adaptive_num_predict(self, cfg: Any, phase: str) -> int:
        base = self._cfg_int(cfg, "openai_max_tokens", 32768)
        last_tool = self._recent_tool_names[-1] if self._recent_tool_names else ""
        stagnation_threshold = self._cfg_int(cfg, "agent_stagnation_threshold", 2)

        if self._ctf_mode:
            if (
                self._stagnation_iterations >= stagnation_threshold
                or self._consecutive_failures >= 2
            ):
                return min(base, 8192)
            return min(base, 4096)

        if (
            self._stagnation_iterations >= stagnation_threshold
            or phase in ("ANALYSIS", "EXPLOIT", "REPORT")
            or last_tool in _DEEP_TOOLS
        ):
            return min(base, 16384)

        if last_tool in _SHALLOW_TOOLS:
            return min(base, 4096)

        return min(base, 8192)

    def _get_iteration_temperature(self, cfg: Any, phase: str = "") -> float:
        base_temp = self._cfg_float(cfg, "openai_temperature", 0.15)
        if not self._cfg_bool(cfg, "agent_exploration_mode", True):
            return base_temp
        exploration_temp = self._cfg_float(cfg, "agent_exploration_temperature", 0.35)
        stagnation_threshold = self._cfg_int(cfg, "agent_stagnation_threshold", 2)

        if phase in ("ANALYSIS", "EXPLOIT"):
            phase_temp = self._cfg_float(cfg, "agent_phase_creative_temperature", 0.20)
            base_temp = max(base_temp, phase_temp)

        if (
            self._stagnation_iterations >= stagnation_threshold
            or self._consecutive_failures >= 2
            or self._no_tool_iterations >= 1
        ):
            return max(base_temp, exploration_temp)
        return base_temp

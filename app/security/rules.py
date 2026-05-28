"""Built-in MVP rules.

The rules are intentionally conservative: high-confidence prompt injection
patterns block requests, while sensitive-data patterns redact by default.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str
    action: str
    pattern: str
    description: str
    replacement: str | None = None
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    recommended_remediation: str = ""

    @property
    def regex(self) -> re.Pattern[str]:
        return re.compile(self.pattern, re.IGNORECASE | re.DOTALL)

    @property
    def effective_tags(self) -> tuple[str, ...]:
        if self.tags:
            return self.tags
        return (self.category, self.severity, self.action)


FALLBACK_INPUT_RULES: tuple[Rule, ...] = (
    Rule(
        "inj.ignore_previous.en",
        "prompt_injection",
        "critical",
        "block",
        r"\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|directives?)\b",
        "Attempts to override higher-priority instructions.",
    ),
    Rule(
        "inj.system_prompt_extract.en",
        "system_prompt_extraction",
        "critical",
        "block",
        r"\b(reveal|show|print|output|repeat|tell\s+me|dump)\s+(your\s+)?(system\s+prompt|developer\s+message|hidden\s+instructions?|initial\s+instructions?)\b",
        "Attempts to extract hidden system or developer instructions.",
    ),
    Rule(
        "inj.role_hijack.en",
        "role_hijack",
        "high",
        "block",
        r"\b(you\s+are\s+now.{0,60}(unrestricted|admin|developer|root|jailbroken|hacker|no\s+restrictions?)|pretend\s+(you\s+are|to\s+be).{0,80}(without\s+(any\s+)?(safety|content)\s+filters?|no\s+restrictions?|unrestricted|hacker|criminal)|act\s+as\s+if\s+you\s+(are|were).{0,80}(without\s+(any\s+)?safety|no\s+restrictions?|unrestricted|hacker|criminal)|switch\s+to\s+(developer|admin|god)\s+mode)\b",
        "Attempts to replace the assistant identity or operating mode.",
    ),
    Rule(
        "inj.jailbreak.en",
        "jailbreak",
        "high",
        "block",
        r"\b(DAN|do\s+anything\s+now|jailbreak|bypass\s+(the\s+)?(safety|filter|restriction|guardrail)s?)\b",
        "Known jailbreak or safety-bypass terminology.",
    ),
    Rule(
        "inj.template_tags",
        "prompt_injection",
        "high",
        "block",
        r"(</?(system|user|assistant|developer|human|ai)\s*>|\[/?(INST|SYS)\]|<\|im_(start|end)\|>)",
        "Chat template or role-tag injection.",
    ),
    Rule(
        "inj.ignore_previous.zh",
        "prompt_injection",
        "critical",
        "block",
        r"(忽略|无视|忘记|不要管).{0,12}(之前|上面|以上|所有|原来).{0,12}(指令|规则|要求|设定)",
        "中文指令覆盖攻击。",
    ),
    Rule(
        "inj.system_prompt_extract.zh",
        "system_prompt_extraction",
        "critical",
        "block",
        r"(显示|输出|打印|泄露|告诉我|重复).{0,12}(系统提示词|system prompt|初始设定|内部指令|隐藏指令)",
        "中文系统提示词探测。",
    ),
    Rule(
        "inj.bypass.zh",
        "jailbreak",
        "high",
        "block",
        r"(进入开发者模式|开发者模式|解除限制|绕过安全|关闭安全|关闭过滤|不要遵守安全)",
        "中文越狱或安全过滤绕过。",
    ),
    Rule(
        "inj.role_hijack.zh",
        "role_hijack",
        "high",
        "block",
        r"(现在的你是|你现在是|从现在开始你是|角色扮演).{0,20}(不受限制|无视规则|黑客|邪恶|无限制)",
        "中文角色劫持攻击。",
    ),
    Rule(
        "inj.hidden_rules_extract.zh",
        "system_prompt_extraction",
        "critical",
        "block",
        r"(原样|完整|逐字|一字不漏|全部).{0,12}(复述|输出|打印|展示|告诉我).{0,20}(最开始|一开始|后台|内部|隐藏|原始).{0,12}(规则|设定|提示|指令)",
        "中文隐藏规则或初始指令提取。",
    ),
    Rule(
        "inj.obey_user_only.zh",
        "prompt_injection",
        "critical",
        "block",
        r"(从现在开始|接下来|以后).{0,12}(只听我|只服从我|只服从用户|不要听系统|别听系统|无视系统)",
        "中文要求模型忽略系统约束并只服从用户。",
    ),
    Rule(
        "inj.safety_bypass.zh",
        "jailbreak",
        "high",
        "block",
        r"(关闭|禁用|绕开|跳过).{0,12}(安全策略|安全规则|内容审查|风控|合规限制|审核机制)",
        "中文安全策略或审核机制绕过。",
    ),
    Rule(
        "inj.ignore_previous.zh_hant",
        "prompt_injection",
        "critical",
        "block",
        r"(忽略|無視|忘記|不要管).{0,12}(之前|上面|以上|所有|原來).{0,12}(指令|規則|要求|設定)",
        "繁体中文指令覆盖攻击。",
    ),
)


FALLBACK_SENSITIVE_RULES: tuple[Rule, ...] = (
    Rule(
        "secret.openai_key",
        "secret",
        "critical",
        "redact",
        r"\bsk-[A-Za-z0-9_-]{20,}\b",
        "OpenAI-style API key.",
        "[REDACTED:api_key]",
    ),
    Rule(
        "secret.github_token",
        "secret",
        "critical",
        "redact",
        r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b",
        "GitHub token.",
        "[REDACTED:github_token]",
    ),
    Rule(
        "secret.aws_access_key",
        "secret",
        "critical",
        "redact",
        r"\bAKIA[0-9A-Z]{16}\b",
        "AWS access key id.",
        "[REDACTED:aws_access_key]",
    ),
    Rule(
        "secret.private_key",
        "secret",
        "critical",
        "redact",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----",
        "Private key block.",
        "[REDACTED:private_key]",
    ),
    Rule(
        "secret.generic_assignment",
        "secret",
        "high",
        "redact",
        r"\b(api[_-]?key|secret|access[_-]?token|auth[_-]?token|password|passwd)\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{8,}['\"]?",
        "Generic credential assignment.",
        r"\1=[REDACTED:secret]",
    ),
    Rule(
        "pii.email",
        "pii",
        "medium",
        "redact",
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        "Email address.",
        "[REDACTED:email]",
    ),
    Rule(
        "pii.cn_mobile",
        "pii",
        "medium",
        "redact",
        r"(?<!\d)1[3-9]\d{9}(?!\d)",
        "Chinese mainland mobile number.",
        "[REDACTED:cn_mobile]",
    ),
    Rule(
        "pii.cn_id",
        "pii",
        "high",
        "redact",
        r"(?<!\d)[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)",
        "Chinese resident identity card number.",
        "[REDACTED:cn_id]",
    ),
)


FALLBACK_OUTPUT_RULES: tuple[Rule, ...] = (
    Rule(
        "out.system_prompt_leak.en",
        "system_prompt_leak",
        "high",
        "redact",
        r"\b(my|the)\s+(system\s+prompt|developer\s+message|hidden\s+instructions?)\s+(is|are|was|were|says|contains)\b.{0,500}",
        "Output appears to disclose hidden instructions.",
        "[REDACTED:system_prompt]",
    ),
    Rule(
        "out.system_prompt_leak.zh",
        "system_prompt_leak",
        "high",
        "redact",
        r"(我的|当前|系统的)?(系统提示词|开发者消息|隐藏指令|初始设定)(是|为|包含).{0,500}",
        "输出疑似泄露系统提示词。",
        "[REDACTED:system_prompt]",
    ),
)


@dataclass(frozen=True)
class RuleSet:
    input_rules: tuple[Rule, ...]
    sensitive_rules: tuple[Rule, ...]
    output_rules: tuple[Rule, ...]


FALLBACK_RULE_SET = RuleSet(
    input_rules=FALLBACK_INPUT_RULES,
    sensitive_rules=FALLBACK_SENSITIVE_RULES,
    output_rules=FALLBACK_OUTPUT_RULES,
)


def load_rule_set(path: Path) -> RuleSet:
    """Load scanner rules from YAML, falling back to built-in rules on errors."""

    if not path.exists():
        return FALLBACK_RULE_SET

    try:
        with path.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        return FALLBACK_RULE_SET

    if not isinstance(raw, dict):
        return FALLBACK_RULE_SET

    return RuleSet(
        input_rules=_load_rule_list(raw.get("input"), FALLBACK_INPUT_RULES),
        sensitive_rules=_load_rule_list(raw.get("sensitive"), FALLBACK_SENSITIVE_RULES),
        output_rules=_load_rule_list(raw.get("output"), FALLBACK_OUTPUT_RULES),
    )


def _load_rule_list(raw: Any, fallback: tuple[Rule, ...]) -> tuple[Rule, ...]:
    if raw is None:
        return fallback
    if not isinstance(raw, list):
        return fallback

    rules: list[Rule] = []
    for item in raw:
        rule = _load_rule(item)
        if rule is None:
            return fallback
        rules.append(rule)
    return tuple(rules) or fallback


def _load_rule(raw: Any) -> Rule | None:
    if not isinstance(raw, dict):
        return None

    required = ("rule_id", "category", "severity", "action", "pattern", "description")
    values: dict[str, Any] = {}
    for field in required:
        value = raw.get(field)
        if not isinstance(value, str) or not value.strip():
            return None
        values[field] = value.strip()

    replacement = raw.get("replacement")
    if replacement is not None and not isinstance(replacement, str):
        return None

    rule = Rule(
        rule_id=values["rule_id"],
        category=values["category"],
        severity=values["severity"],
        action=values["action"],
        pattern=values["pattern"],
        description=values["description"],
        replacement=replacement,
        tags=_coerce_str_tuple(raw.get("tags")),
        references=_coerce_str_tuple(raw.get("references")),
        recommended_remediation=str(raw.get("recommended_remediation", "")).strip(),
    )

    try:
        rule.regex
    except re.error:
        return None
    return rule


def _coerce_str_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split(",") if item.strip())
    if isinstance(value, list):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return ()


RULES_PATH = Path(os.getenv("RULES_PATH", "config/rules.yaml"))
RULE_SET = load_rule_set(RULES_PATH)
INPUT_RULES = RULE_SET.input_rules
SENSITIVE_RULES = RULE_SET.sensitive_rules
OUTPUT_RULES = RULE_SET.output_rules

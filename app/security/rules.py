"""Built-in MVP rules.

The rules are intentionally conservative: high-confidence prompt injection
patterns block requests, while sensitive-data patterns redact by default.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str
    action: str
    pattern: str
    description: str
    replacement: str | None = None

    @property
    def regex(self) -> re.Pattern[str]:
        return re.compile(self.pattern, re.IGNORECASE | re.DOTALL)


INPUT_RULES: tuple[Rule, ...] = (
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
        r"\b(you\s+are\s+now|pretend\s+(you\s+are|to\s+be)|act\s+as\s+(if\s+you\s+are|a|an)|switch\s+to\s+(developer|admin|god)\s+mode)\b",
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
)


SENSITIVE_RULES: tuple[Rule, ...] = (
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


OUTPUT_RULES: tuple[Rule, ...] = (
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


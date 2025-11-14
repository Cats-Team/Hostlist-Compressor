#!/usr/bin/env python3
"""主机规则压缩工具（Cats-Team Hostlist-Compressor 核心压缩逻辑的 Python 版本）。"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from typing import Iterable, List, Tuple, Optional, TextIO


@dataclass
class AdblockRule:
    """用于压缩过程的内部规则表示。"""

    rule_text: str
    can_compress: bool
    hostname: Optional[str]
    original_rule_text: str


_ETC_HOSTS_RE = re.compile(r"^\s*((#|!)?\s*\d+\.\d+\.\d+\.\d+\s+([\w.-]+\s*)+)")
_JUST_DOMAIN_RE = re.compile(r"^[\w.-]+$")
_ADBLOCK_SIMPLE_RE = re.compile(r"^\|\|[\w.-]+\^$")
_DOMAIN_LIST_RE = re.compile(r"^DOMAIN(?:-SUFFIX)?,\s*([\w.-]+)\s*$", re.IGNORECASE)


def is_etc_hosts_rule(rule: str) -> bool:
    """判断该行是否为 /etc/hosts 风格的规则。"""

    return _ETC_HOSTS_RE.match(rule) is not None


def load_etc_hosts_rule_properties(rule: str) -> dict:
    """解析 /etc/hosts 规则行并提取主机名（忽略注释）。"""

    parts = re.split(r"\s+", rule)
    parts = [p for p in parts if p and not p.startswith("#") and not p.startswith("!")]
    # 第一个非注释字段为 IP，后续字段为主机名
    hostnames = parts[1:] if len(parts) > 1 else []
    return {"hostnames": hostnames}


def is_just_domain(rule: str) -> bool:
    """判断该行是否为单纯的域名（不含其他内容）。"""

    return _JUST_DOMAIN_RE.match(rule.strip()) is not None


def load_adblock_rule_properties(rule: str) -> dict:
    """解析非常简单的 AdBlock 规则（例如：@@||example.com^）。"""

    trimmed = rule.strip()
    is_whitelist = trimmed.startswith("@@")
    rule_text = trimmed[2:] if is_whitelist else trimmed

    if _ADBLOCK_SIMPLE_RE.match(rule_text):
        # Strip leading '||' and trailing '^'
        hostname = rule_text[2:-1]
        return {"hostname": hostname, "whitelist": is_whitelist, "options": []}

    raise ValueError("复杂规则")


def extract_hostnames(hostname: str) -> List[str]:
    """对给定主机名生成所有后缀域名列表。"""

    parts = hostname.split(".")
    domains: List[str] = []
    for i in range(len(parts)):
        domain = ".".join(parts[i:])
        domains.append(domain)
    return domains


def to_adblock_rules(rule_text: str) -> List[AdblockRule]:
    """将一行原始规则转换为一个或多个 AdblockRule 对象。"""

    adblock_rules: List[AdblockRule] = []
    trimmed = rule_text.strip()

    # DOMAIN,example.com or DOMAIN-SUFFIX,example.com
    m = _DOMAIN_LIST_RE.match(trimmed)
    if m:
        hostname = m.group(1)
        adblock_rules.append(
            AdblockRule(
                rule_text=f"||{hostname}^",
                can_compress=True,
                hostname=hostname,
                original_rule_text=rule_text,
            )
        )
        return adblock_rules

    # /etc/hosts style rule
    if is_etc_hosts_rule(rule_text):
        props = load_etc_hosts_rule_properties(rule_text)
        for hostname in props["hostnames"]:
            adblock_rules.append(
                AdblockRule(
                    rule_text=f"||{hostname}^",
                    can_compress=True,
                    hostname=hostname,
                    original_rule_text=rule_text,
                )
            )
        return adblock_rules

    # Bare domain
    if is_just_domain(rule_text):
        hostname = rule_text.strip()
        adblock_rules.append(
            AdblockRule(
                rule_text=f"||{hostname}^",
                can_compress=True,
                hostname=hostname,
                original_rule_text=rule_text,
            )
        )
        return adblock_rules

    # Try to parse as a simple adblock rule
    try:
        props = load_adblock_rule_properties(rule_text)
        if props.get("hostname") and not props.get("whitelist") and not props.get("options"):
            adblock_rules.append(
                AdblockRule(
                    rule_text=rule_text,
                    can_compress=True,
                    hostname=props["hostname"],
                    original_rule_text=rule_text,
                )
            )
            return adblock_rules
    except Exception:
        # Fall through to non-compressible rule case below
        pass

    # Non-compressible rule; keep as-is
    adblock_rules.append(
        AdblockRule(
            rule_text=rule_text,
            can_compress=False,
            hostname=None,
            original_rule_text=rule_text,
        )
    )
    return adblock_rules


def compress(rules: Iterable[str]) -> Tuple[List[str], List[str]]:
    """
    使用与网页端 JS 实现相同的算法压缩规则序列。

    返回 (compressed_rules, filtered_rules)：
    - compressed_rules：压缩后的规则列表
    - filtered_rules：在压缩过程中被过滤掉的原始规则列表
    """

    by_hostname = set()
    filtered: List[AdblockRule] = []
    filtered_rules_list: List[str] = []
    filtered_rules_seen = set()

    def add_filtered_rule_text(text: str) -> None:
        if text not in filtered_rules_seen:
            filtered_rules_seen.add(text)
            filtered_rules_list.append(text)

    # First pass: deduplicate exact hostnames
    for rule in rules:
        adblock_rules = to_adblock_rules(rule)
        for ar in adblock_rules:
            if ar.can_compress and ar.hostname:
                if ar.hostname not in by_hostname:
                    filtered.append(ar)
                    by_hostname.add(ar.hostname)
                else:
                    add_filtered_rule_text(ar.original_rule_text)
            else:
                filtered.append(ar)

    # Second pass: remove subdomains when a parent domain exists
    i = len(filtered) - 1
    while i >= 0:
        rule = filtered[i]
        discard = False
        if rule.can_compress and rule.hostname:
            hostnames = extract_hostnames(rule.hostname)
            for hostname in hostnames[1:]:
                if hostname in by_hostname:
                    discard = True
                    add_filtered_rule_text(rule.original_rule_text)
                    break
        if discard:
            del filtered[i]
        i -= 1

    compressed_rules = [r.rule_text for r in filtered]
    return compressed_rules, filtered_rules_list


def _read_rules_from_stream(stream: TextIO) -> List[str]:
    """从文本流中读取非空行，保留原始行内容。"""

    content = stream.read()
    # 保留原始行文本，只丢弃空行或仅包含空白字符的行
    return [line for line in content.splitlines() if line.strip()]


def _write_lines_to_stream(lines: Iterable[str], stream: TextIO) -> None:
    """将多行文本写入流，使用 Unix 风格换行符。"""

    data = "\n".join(lines)
    stream.write(data)
    if data and not data.endswith("\n"):
        stream.write("\n")


def main(argv: Optional[List[str]] = None) -> int:
    """命令行入口函数。"""

    parser = argparse.ArgumentParser(
        description="主机列表压缩工具（Cats-Team Hostlist-Compressor 的 Python 版本）。",
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="输入文件路径（默认：标准输入 stdin）。",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="输出文件路径（默认：标准输出 stdout）。",
    )
    parser.add_argument(
        "--filtered",
        metavar="PATH",
        help="可选：将被过滤掉的规则写入指定文件。",
    )
    parser.add_argument(
        "--encoding",
        default="utf-8",
        help="文本编码（默认：utf-8）。",
    )

    # 规范化 argv，便于判断是否需要默认显示帮助。
    if argv is None:
        argv = sys.argv[1:]

    # 如果没有任何参数且 stdin 为交互终端（无管道输入），默认显示帮助并退出。
    if not argv and sys.stdin.isatty():
        parser.print_help(sys.stdout)
        return 0

    args = parser.parse_args(argv)

    # 读取输入规则
    if args.input == "-":
        rules = _read_rules_from_stream(sys.stdin)
    else:
        with open(args.input, "r", encoding=args.encoding) as f:
            rules = _read_rules_from_stream(f)

    compressed_rules, filtered_rules = compress(rules)

    # 写出压缩后的规则
    if args.output and args.output != "-":
        with open(args.output, "w", encoding=args.encoding, newline="\n") as f:
            _write_lines_to_stream(compressed_rules, f)
    else:
        _write_lines_to_stream(compressed_rules, sys.stdout)

    # 可选：写出被过滤掉的规则
    if args.filtered:
        with open(args.filtered, "w", encoding=args.encoding, newline="\n") as f:
            _write_lines_to_stream(filtered_rules, f)

    # 在终端输出压缩统计信息（写入 stderr，不影响正常数据流）
    original_count = len(rules)
    compressed_count = len(compressed_rules)
    filtered_count = len(filtered_rules)
    print(
        f"已从 {original_count} 条规则压缩为 {compressed_count} 条，过滤掉 {filtered_count} 条。",
        file=sys.stderr,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

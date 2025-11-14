#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from typing import Iterable, List, Tuple, Optional, TextIO


@dataclass
class AdblockRule:
    """内部表示：用于表示一条转换后的 Adblock 风格规则及其元数据。"""

    rule_text: str
    can_compress: bool
    hostname: Optional[str]
    original_rule_text: str


# 正则：/etc/hosts 风格、纯域名、简单 adblock 和 DOMAIN 列表识别
_ETC_HOSTS_RE = re.compile(r"^\s*((#|!)?\s*\d+\.\d+\.\d+\.\d+\s+([\w.-]+\s*)+)")
_JUST_DOMAIN_RE = re.compile(r"^[\w.-]+$")
_ADBLOCK_SIMPLE_RE = re.compile(r"^\|\|[\w.-]+\^$")
_DOMAIN_LIST_RE = re.compile(r"^DOMAIN(?:-SUFFIX)?,\s*([\w.-]+)\s*$", re.IGNORECASE)


def is_etc_hosts_rule(rule: str) -> bool:
    """判断是否为 /etc/hosts 风格的行（以 IP 开头，后面跟主机名）。"""
    return _ETC_HOSTS_RE.match(rule) is not None


def load_etc_hosts_rule_properties(rule: str) -> dict:
    """解析 /etc/hosts 行并返回主机名列表（忽略行内注释）。"""
    parts = re.split(r"\s+", rule)
    parts = [p for p in parts if p and not p.startswith("#") and not p.startswith("!")]
    hostnames = parts[1:] if len(parts) > 1 else []
    return {"hostnames": hostnames}


def is_just_domain(rule: str) -> bool:
    """判断该行是否仅为一个裸域名（例如 example.com）。"""
    return _JUST_DOMAIN_RE.match(rule.strip()) is not None


def load_adblock_rule_properties(rule: str) -> dict:
    """解析简单的 adblock 规则（支持白名单前缀 @@）。若规则复杂则抛出异常。"""
    trimmed = rule.strip()
    is_whitelist = trimmed.startswith("@@")
    rule_text = trimmed[2:] if is_whitelist else trimmed
    if _ADBLOCK_SIMPLE_RE.match(rule_text):
        hostname = rule_text[2:-1]
        return {"hostname": hostname, "whitelist": is_whitelist, "options": []}
    raise ValueError("复杂规则")


def extract_hostnames(hostname: str) -> List[str]:
    """生成主机名的各级后缀（从最具体到最通用），用于判断子域/父域关系。"""
    parts = hostname.split(".")
    domains: List[str] = []
    for i in range(len(parts)):
        domain = ".".join(parts[i:])
        domains.append(domain)
    return domains


def to_adblock_rules(rule_text: str) -> List[AdblockRule]:
    """将一条原始输入规则转换为 0 个或多个 AdblockRule 对象（供后续压缩使用）。"""
    adblock_rules: List[AdblockRule] = []
    trimmed = rule_text.strip()
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
        pass

    # 非可压缩或复杂规则，作为不可压缩项返回
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
    主压缩算法：
    - 尝试将输入规则转换为简单的 `||hostname^` 形式
    - 去重并移除被上级域名覆盖的子域名
    - 返回 (compressed_rules, filtered_rules)
    """
    by_hostname = set()
    filtered: List[AdblockRule] = []
    filtered_rules_list: List[str] = []
    filtered_rules_seen = set()

    def add_filtered_rule_text(text: str) -> None:
        """记录被过滤掉的原始规则，保持唯一性和出现顺序。"""
        if text not in filtered_rules_seen:
            filtered_rules_seen.add(text)
            filtered_rules_list.append(text)

    # 第一遍：将可压缩规则收集，非可压缩或重复的记录为被过滤
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
                add_filtered_rule_text(ar.original_rule_text)

    # 第二遍：移除被父域覆盖的子域规则（从后往前遍历以保留第一次出现的父域）
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

    final_compressed: List[str] = []
    for r in filtered:
        if _ADBLOCK_SIMPLE_RE.match(r.rule_text):
            final_compressed.append(r.rule_text)
        else:
            add_filtered_rule_text(r.original_rule_text)

    return final_compressed, filtered_rules_list


def _read_rules_from_stream(stream: TextIO) -> List[str]:
    """从文本流读取非空行（保持原始行文本）。"""
    content = stream.read()
    return [line for line in content.splitlines() if line.strip()]


def _write_lines_to_stream(lines: Iterable[str], stream: TextIO) -> None:
    """将多行文本写入流，使用 LF 换行并确保以换行结尾。"""
    data = "\n".join(lines)
    stream.write(data)
    if data and not data.endswith("\n"):
        stream.write("\n")


def main(argv: Optional[List[str]] = None) -> int:
    """命令行入口：解析参数、读取输入、运行压缩并写出结果。"""
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

    if argv is None:
        argv = sys.argv[1:]

    if not argv and sys.stdin.isatty():
        parser.print_help(sys.stdout)
        return 0

    args = parser.parse_args(argv)

    if args.input == "-":
        rules = _read_rules_from_stream(sys.stdin)
    else:
        with open(args.input, "r", encoding=args.encoding) as f:
            rules = _read_rules_from_stream(f)

    compressed_rules, filtered_rules = compress(rules)

    if args.output and args.output != "-":
        with open(args.output, "w", encoding=args.encoding, newline="\n") as f:
            _write_lines_to_stream(compressed_rules, f)
    else:
        _write_lines_to_stream(compressed_rules, sys.stdout)

    if args.filtered:
        with open(args.filtered, "w", encoding=args.encoding, newline="\n") as f:
            _write_lines_to_stream(filtered_rules, f)

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

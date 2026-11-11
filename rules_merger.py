import yaml
import json
import subprocess
import tempfile
import requests
import os
import logging
import re
import ipaddress
import shutil
import threading
from datetime import datetime
from functools import lru_cache
from typing import List, Dict, Optional, Any, Tuple, Union
from contextlib import contextmanager
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

DOMAIN_PATTERN = re.compile(
    r"^(?:\.?(\*|[a-zA-Z0-9*](?:[a-zA-Z0-9*-]*[a-zA-Z0-9*])?))"
    r"(?:\.(?:\*|[a-zA-Z0-9*](?:[a-zA-Z0-9*-]*[a-zA-Z0-9*])?))*$"
)
PORT_PATTERN = re.compile(r"^\d+(?:-\d+)?$")
JSON_COMMENT_PATTERN = re.compile(
    r'//.*?$|/\*.*?\*/|"(?:\\.|[^\\"])*"',
    re.DOTALL | re.MULTILINE
)

MIHOMO_PATH = "mihomo"
SING_BOX_PATH = "sing-box"
SING_BOX_RULESET_VERSION = 5
SING_BOX_LIST_FIELDS = (
    "domain", "domain_suffix", "domain_keyword",
    "domain_regex", "ip_cidr", "port", "port_range", "network"
)
CLASSICAL_TO_SB = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "DOMAIN-REGEX": "domain_regex",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
    "DST-PORT": "port",
    "NETWORK": "network"
}


class RulesMerger:
    def __init__(self, config_path: str, max_workers: int = 64):
        raw_config = self._load_config(config_path)
        if isinstance(raw_config, list):
            self.rulesets = raw_config
            self.push_config = {}
            self.output_dir = "output"
        elif isinstance(raw_config, dict):
            self.rulesets = raw_config.get("rulesets", [])
            self.push_config = raw_config.get("push", {})
            self.output_dir = raw_config.get("output_dir", "output")
        else:
            self.rulesets = []
            self.push_config = {}
            self.output_dir = "output"

        self.mihomo_path = MIHOMO_PATH
        self.sing_box_path = SING_BOX_PATH
        self.max_workers = max(1, int(max_workers))

        # 外层规则集线程和所有内层源线程共享总线程预算。
        # 每个规则集拥有独立的源线程池，因此按最坏情况计算总线程数。
        self.ruleset_workers = 1
        self.source_workers = max(1, self.max_workers - 1)

        # requests.Session 不保证跨线程共享安全；每个工作线程复用自己的 Session。
        self._session_local = threading.local()
        self._http_retries = Retry(
            total=5,
            connect=5,
            read=5,
            status=5,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=frozenset(["GET", "HEAD"]),
            respect_retry_after_header=True
        )
        os.makedirs(self.output_dir, exist_ok=True)

        self._transformers = {
            ("classical", "ipcidr"): self._classical_to_ipcidr,
            ("classical", "domain"): self._classical_to_domain,
            ("ipcidr", "classical"): self._ipcidr_to_classical,
            ("domain", "classical"): self._domain_to_classical,
            ("classical", "sing-box"): self._classical_to_sing_box,
            ("domain", "sing-box"): self._domain_to_sing_box,
            ("ipcidr", "sing-box"): self._ipcidr_to_sing_box,
            ("sing-box", "classical"): self._sing_box_to_classical,
            ("sing-box", "domain"): self._sing_box_to_domain,
            ("sing-box", "ipcidr"): self._sing_box_to_ipcidr
        }

        self.push_enabled = self.push_config.get("enabled", False)
        self.push_remote = self.push_config.get("remote", "origin")
        self.push_branch = self.push_config.get("branch", None)

    @staticmethod
    def _normalize_behavior(behavior: Optional[str]) -> str:
        if not behavior:
            return "classical"
        value = behavior.strip().lower()
        return "sing-box" if value in ("singbox", "sing-box") else value

    def _get_session(self) -> requests.Session:
        """获取当前线程专用的 HTTP Session，并在该线程内复用连接。"""
        session = getattr(self._session_local, "session", None)
        if session is None:
            session = requests.Session()
            adapter = HTTPAdapter(
                max_retries=self._http_retries,
                pool_connections=4,
                pool_maxsize=1,
                pool_block=False
            )
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            self._session_local.session = session
        return session

    @staticmethod
    def _load_config(path: str) -> Any:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    @contextmanager
    def _temp_file(self, suffix: str):
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        try:
            yield path
        finally:
            if os.path.exists(path):
                try:
                    os.unlink(path)
                except OSError:
                    pass

    @staticmethod
    def _as_list(value: Any) -> List[Any]:
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    @staticmethod
    def _clean_rule(rule: str) -> str:
        rule = rule.strip()
        if not rule or rule.startswith("#"):
            return ""
        return rule.split(" #", 1)[0].strip()

    @staticmethod
    def _clean_json_text(text: str) -> str:
        if not text:
            return ""
        text = text.lstrip("\ufeff")
        def replace(match):
            value = match.group(0)
            return "" if value.startswith("/") else value

        return JSON_COMMENT_PATTERN.sub(replace, text)

    @staticmethod
    @lru_cache(maxsize=65536)
    def _parse_ip_network(rule: str) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        if not rule or not isinstance(rule, str):
            return None
        value = rule.strip()
        if not value:
            return None
        if "," in value:
            parts = [part.strip() for part in value.split(",")]
            if parts[0].upper() in ("IP-CIDR", "IP-CIDR6"):
                value = parts[1] if len(parts) > 1 else ""
            else:
                value = parts[0]
        if not value:
            return None
        try:
            return ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None

    @classmethod
    def _get_ipcidr_version(cls, rule: str) -> Optional[int]:
        network = cls._parse_ip_network(rule)
        return network.version if network else None

    def _validate_ipcidr_rule(self, rule: str) -> Optional[str]:
        network = self._parse_ip_network(rule)
        return network.with_prefixlen if network else None

    def _validate_domain_rule(self, rule: str) -> Optional[str]:
        # Accept valid exact, suffix and wildcard domain-list entries.
        # _normalize_domain_value rejects malformed repeated prefixes.
        return rule if self._normalize_domain_value(rule) else None

    def _validate_classical_rule(self, rule: str) -> Optional[str]:
        try:
            parts = [part.strip() for part in rule.split(",")]
            if not parts or not parts[0]:
                return None
            prefix = parts[0].upper()

            if prefix in ("DOMAIN", "DOMAIN-SUFFIX"):
                return rule if len(parts) >= 2 and self._validate_domain_rule(parts[1]) else None
            if prefix in ("DOMAIN-KEYWORD", "DOMAIN-REGEX"):
                return rule if len(parts) >= 2 and parts[1] else None
            if prefix == "IP-CIDR":
                return rule if len(parts) >= 2 and self._get_ipcidr_version(parts[1]) == 4 else None
            if prefix == "IP-CIDR6":
                return rule if len(parts) >= 2 and self._get_ipcidr_version(parts[1]) == 6 else None
            if prefix == "DST-PORT":
                values = [p.strip() for p in parts[1].split("/") if p.strip()] if len(parts) >= 2 else []
                return rule if values and all(PORT_PATTERN.fullmatch(p) for p in values) else None
            if prefix == "NETWORK":
                return rule if len(parts) >= 2 and parts[1].lower() in ("tcp", "udp") else None
            if self._parse_ip_network(parts[0]) is not None:
                return rule
            return None
        except Exception:
            return None

    def _normalize_domain_value(self, value: Any, suffix_hint: bool = False) -> Optional[str]:
        """Return exact domain or +.suffix; reject malformed repeated prefixes."""
        if not isinstance(value, str):
            return None
        domain = value.strip()
        if not domain or "," in domain or "/" in domain or "\\" in domain:
            return None

        is_suffix = suffix_hint
        if domain.startswith("+."):
            is_suffix = True
            domain = domain[2:]
        elif domain.startswith("*."):
            is_suffix = True
            domain = domain[2:]
        elif domain.startswith("."):
            is_suffix = True
            domain = domain[1:]

        # A second prefix indicates malformed input; do not silently strip it.
        if not domain or domain.startswith(("+", ".")) or domain == "*":
            return None

        domain = domain.rstrip(".").lower()
        if not domain:
            return None
        try:
            ipaddress.ip_address(domain)
            return None
        except ValueError:
            pass
        if not DOMAIN_PATTERN.fullmatch(domain):
            return None
        return f"+.{domain}" if is_suffix else domain

    def _normalize_rule_signature(self, rule: Any) -> str:
        if isinstance(rule, dict):
            canonical = {}
            for key, value in rule.items():
                values = self._as_list(value)
                if key in ("domain", "domain_suffix"):
                    canonical[key] = sorted({str(x).lower().strip(".") for x in values})
                elif key in ("domain_keyword", "domain_regex"):
                    canonical[key] = sorted(set(str(x) for x in values))
                elif key == "ip_cidr":
                    normalized = []
                    for item in values:
                        network = self._parse_ip_network(str(item))
                        normalized.append(network.with_prefixlen if network else str(item).strip())
                    canonical[key] = sorted(set(normalized))
                elif key == "network":
                    canonical[key] = sorted({str(x).lower() for x in values})
                elif key in ("port", "port_range"):
                    canonical[key] = sorted(values, key=str)
                else:
                    canonical[key] = value
            return json.dumps(canonical, ensure_ascii=False, sort_keys=True)

        if isinstance(rule, str):
            value = rule.strip().lower()
            if value.startswith("ip-cidr6,"):
                value = "ip-cidr," + value[9:]
            if "," in value:
                parts = [part.strip() for part in value.split(",")]
                prefix = parts[0]
                item = parts[1] if len(parts) > 1 else ""
                clean = item.strip(".")
                if prefix in ("domain", "domain-suffix", "domain-keyword", "domain-regex"):
                    value = f"{prefix},{clean}"
                elif prefix in ("ip-cidr", "ip-cidr6"):
                    network = self._parse_ip_network(item)
                    if network:
                        value = f"ip-cidr,{network.with_prefixlen}"
                elif prefix == "network":
                    value = f"network,{clean.lower()}"
            else:
                network = self._parse_ip_network(value)
                if network:
                    value = f"ip-cidr,{network.with_prefixlen}"
            return value
        return str(rule)

    @staticmethod
    def _merge_port_items(items: List[str]) -> List[str]:
        ranges = []
        for item in set(items):
            value = str(item).strip()
            if not value:
                continue
            try:
                if "-" in value:
                    start, end = map(int, value.split("-", 1))
                else:
                    start = end = int(value)
                if 1 <= start <= end <= 65535:
                    ranges.append([start, end])
            except ValueError:
                continue
        if not ranges:
            return []
        ranges.sort(key=lambda pair: pair[0])
        merged = [ranges[0]]
        for start, end in ranges[1:]:
            last = merged[-1]
            if start <= last[1] + 1:
                last[1] = max(last[1], end)
            else:
                merged.append([start, end])
        return [str(start) if start == end else f"{start}-{end}" for start, end in merged]

    @staticmethod
    def _wildcard_to_domain_regex(domain: str) -> Optional[str]:
        if not domain:
            return None
        value = domain.strip()
        if value.startswith("+."):
            value = value[2:]
        elif value.startswith("."):
            value = value[1:]
        value = value.strip(".")
        if not value or value == "*":
            return None
        body = ".*".join(re.escape(part) for part in value.split("*"))
        return f"(^|\\.){body}$"

    def _unified_domain_deduplication(
        self, exact_domains: List[str], suffix_domains: List[str]
    ) -> Tuple[List[str], List[str]]:
        domain_types: Dict[str, int] = {}
        for domain in exact_domains:
            value = str(domain).strip().lower().strip(".")
            if value and "*" not in value:
                domain_types[value] = 0
        for domain in suffix_domains:
            value = str(domain).strip().lower().strip(".")
            if value and "*" not in value:
                domain_types[value] = 1
        if not domain_types:
            return [], []

        reversed_list = sorted((tuple(domain.split("."))[::-1], domain) for domain in domain_types)
        result_domains = []
        last_parent = None
        last_len = 0
        for labels, original in reversed_list:
            if last_parent and len(labels) > last_len and labels[:last_len] == last_parent:
                parent = ".".join(last_parent[::-1])
                domain_types[parent] = 1
                continue
            result_domains.append(original)
            last_parent = labels
            last_len = len(labels)

        exact, suffix = [], []
        for domain in result_domains:
            if domain_types[domain] == 1:
                suffix.append(domain)
            else:
                exact.append(domain)
        return exact, suffix

    @staticmethod
    def _prune_networks(networks):
        """删除被已保留父网段覆盖的子网，不合并相邻网段。"""
        if not networks:
            return []

        networks = sorted(
            set(networks),
            key=lambda n: (n.version, n.prefixlen, int(n.network_address))
        )
        kept = []
        kept_set = set()

        for network in networks:
            covered = False
            # 父网段的前缀长度一定小于当前网段；只需检查至多 32/128 个祖先。
            for prefix in range(network.prefixlen):
                parent = network.supernet(new_prefix=prefix)
                if parent in kept_set:
                    covered = True
                    break
            if not covered:
                kept.append(network)
                kept_set.add(network)

        return kept

    def _merge_ip_rules(self, rules: List[str]) -> List[str]:
        ipv4_networks, ipv6_networks = [], []
        other, seen_other = [], set()
        for rule in rules:
            value = rule.strip()
            if not value:
                continue
            network = self._parse_ip_network(value)
            if network:
                (ipv4_networks if network.version == 4 else ipv6_networks).append(network)
                continue
            signature = self._normalize_rule_signature(value)
            if signature not in seen_other:
                seen_other.add(signature)
                other.append(value)

        result = [f"IP-CIDR,{n.with_prefixlen}" for n in self._prune_networks(ipv4_networks)]
        result.extend(f"IP-CIDR6,{n.with_prefixlen}" for n in self._prune_networks(ipv6_networks))
        result.extend(other)
        return result

    # -------------------- Source fetching and parsing --------------------

    def _fetch_source(self, source: Dict) -> Tuple[List[Any], str, str]:
        rule_format = source.get("format", "yaml")
        default_behavior = "sing-box" if rule_format in ("json", "srs") else "classical"
        behavior = self._normalize_behavior(source.get("behavior", default_behavior))
        label = source.get("url") or source.get("path") or "unknown"
        source_type = source.get("type")

        try:
            if source_type == "http":
                url = source.get("url", "")
                logger.info("下载源: %s", url)
                with self._get_session().get(url, timeout=(5, 15)) as response:
                    response.raise_for_status()
                    content = response.content
            elif source_type == "file":
                path = source.get("path", "")
                logger.info("读取本地源: %s", path)
                with open(path, "rb") as f:
                    content = f.read()
            else:
                raise ValueError(f"不支持的源类型: {source_type}")

            rules = self._parse_source_content(content, rule_format, behavior)
            logger.info("源读取完成: %s → %s 条规则", label, len(rules))
            return rules, behavior, label
        except Exception as exc:
            logger.error("获取源失败 %s: %s", label, exc)
            return [], behavior, label

    def _parse_source_content(self, content_bytes: bytes, rule_format: str, behavior: str) -> List[Any]:
        if not content_bytes:
            return []
        if rule_format == "srs":
            with self._temp_file(".srs") as temp_srs:
                with open(temp_srs, "wb") as f:
                    f.write(content_bytes)
                return self._parse_sing_box_source_to_list(self._decompile_srs_to_json_str(temp_srs))
        if rule_format == "mrs":
            with self._temp_file(".mrs") as temp_mrs:
                with open(temp_mrs, "wb") as f:
                    f.write(content_bytes)
                return self._read_mrs_file(temp_mrs, behavior)

        text = content_bytes.decode("utf-8", errors="ignore")
        if rule_format == "json":
            return self._parse_sing_box_source_to_list(text)
        if rule_format == "yaml":
            return self._extract_yaml_rules(yaml.safe_load(text))
        if "payload:" in text[:200]:
            return self._extract_yaml_rules(yaml.safe_load(text))
        return text.splitlines()

    def _parse_sing_box_source_to_list(self, content: str) -> List[Any]:
        if not content or not content.strip():
            return []
        cleaned = self._clean_json_text(content)
        try:
            data = json.loads(cleaned)
            if isinstance(data, dict):
                if isinstance(data.get("rules"), list):
                    return data["rules"]
                if isinstance(data.get("payload"), list):
                    return data["payload"]
                return [data]
            if isinstance(data, list):
                return data
            return []
        except json.JSONDecodeError as exc:
            logger.error("解析 JSON 规则源失败: %s", exc)
            return []

    @staticmethod
    def _extract_yaml_rules(data: Any) -> List[Any]:
        if isinstance(data, dict):
            payload = data.get("payload")
            return payload if isinstance(payload, list) else []
        return data if isinstance(data, list) else []

    # -------------------- Conversion engine --------------------

    def _transform(self, rule: Any, source_behavior: str, target_behavior: str) -> List[Any]:
        if isinstance(rule, dict):
            if target_behavior == "sing-box":
                return [rule]
            transformer = self._transformers.get(("sing-box", target_behavior))
            if transformer:
                result = transformer(rule)
                return result if isinstance(result, list) else [result] if result else []
            return []

        if source_behavior == target_behavior:
            if target_behavior == "domain":
                normalized = self._normalize_domain_value(rule)
                return [normalized] if normalized else []
            if target_behavior == "ipcidr":
                normalized = self._validate_ipcidr_rule(rule)
                return [normalized] if normalized else []
            if target_behavior == "classical":
                return [rule] if self._validate_classical_rule(rule) else []
            return [rule]

        transformer = self._transformers.get((source_behavior, target_behavior))
        if transformer:
            result = transformer(rule)
            if result:
                return result if isinstance(result, list) else [result]
        return []

    def _classical_to_ipcidr(self, rule: str) -> Optional[str]:
        return self._validate_ipcidr_rule(rule)

    def _classical_to_domain(self, rule: str) -> Optional[str]:
        parts = rule.split(",", 1)
        if len(parts) != 2:
            return None
        prefix, domain = parts[0].strip().upper(), parts[1].strip()
        if prefix not in ("DOMAIN", "DOMAIN-SUFFIX"):
            return None
        return self._normalize_domain_value(
            domain,
            suffix_hint=(prefix == "DOMAIN-SUFFIX")
        )

    def _ipcidr_to_classical(self, rule: str) -> Optional[str]:
        network = self._parse_ip_network(rule)
        if network:
            prefix = "IP-CIDR6" if network.version == 6 else "IP-CIDR"
            return f"{prefix},{network.with_prefixlen}"
        return None

    def _domain_to_classical(self, rule: str) -> Optional[str]:
        normalized = self._normalize_domain_value(rule)
        if not normalized:
            return None
        if normalized.startswith("+."):
            return f"DOMAIN-SUFFIX,{normalized[2:]}"
        return f"DOMAIN,{normalized}"

    def _classical_to_sing_box(self, rule: str) -> Optional[str]:
        parts = [part.strip() for part in rule.split(",")]
        if not parts or not parts[0]:
            return None
        prefix = parts[0].upper()

        if prefix == "DST-PORT" and len(parts) >= 2:
            if not self._validate_classical_rule(rule):
                return None
            items = [item.strip() for item in parts[1].split("/") if item.strip()]
            ports, ranges = [], []
            for item in self._merge_port_items(items):
                if "-" in item:
                    ranges.append(item.replace("-", ":"))
                else:
                    ports.append(int(item))
            result = {}
            if ports:
                result["port"] = ports
            if ranges:
                result["port_range"] = ranges
            return json.dumps(result) if result else None

        item = self._to_sing_box_item(rule, "classical")
        if item:
            return json.dumps({item[0]: [item[1]]})
        return None

    def _domain_to_sing_box(self, rule: str) -> Optional[str]:
        item = self._to_sing_box_item(rule, "domain")
        return json.dumps({item[0]: [item[1]]}) if item else None

    def _ipcidr_to_sing_box(self, rule: str) -> Optional[str]:
        item = self._to_sing_box_item(rule, "ipcidr")
        return json.dumps({item[0]: [item[1]]}) if item else None

    def _to_sing_box_item(self, rule: str, behavior: str) -> Optional[tuple]:
        if not isinstance(rule, str) or not rule.strip():
            return None
        value = rule.strip()
        try:
            if behavior == "domain":
                normalized = self._normalize_domain_value(value)
                if not normalized:
                    return None
                if "*" in normalized:
                    regex_value = self._wildcard_to_domain_regex(normalized)
                    return ("domain_regex", regex_value) if regex_value else None
                if normalized.startswith("+."):
                    return "domain_suffix", normalized[2:]
                return "domain", normalized

            if behavior == "ipcidr":
                network = self._parse_ip_network(value)
                return ("ip_cidr", network.with_prefixlen) if network else None

            parts = [part.strip() for part in value.split(",")]
            if not parts or not parts[0]:
                return None
            prefix = parts[0].upper()
            field = CLASSICAL_TO_SB.get(prefix)
            if field:
                if len(parts) < 2:
                    return None
                item = parts[1]
                if field == "ip_cidr":
                    network = self._parse_ip_network(item)
                    return ("ip_cidr", network.with_prefixlen) if network else None
                if field in ("domain_keyword", "domain_regex"):
                    return (field, item) if item else None
                if field in ("domain", "domain_suffix"):
                    normalized = self._normalize_domain_value(
                        item, suffix_hint=(field == "domain_suffix")
                    )
                    if not normalized:
                        return None
                    if "*" in normalized:
                        regex_value = self._wildcard_to_domain_regex(normalized)
                        return ("domain_regex", regex_value) if regex_value else None
                    if normalized.startswith("+."):
                        return "domain_suffix", normalized[2:]
                    return field, normalized
                if field == "network":
                    return field, item.lower()
            network = self._parse_ip_network(parts[0])
            if network:
                return "ip_cidr", network.with_prefixlen
        except Exception as exc:
            logger.debug("解析规则条目异常 [%s]: %s", rule, exc)
        return None

    def _parse_sing_box_rule(self, rule_input: Any) -> Optional[Dict[str, Any]]:
        if isinstance(rule_input, dict):
            return rule_input
        if isinstance(rule_input, str):
            try:
                parsed = json.loads(self._clean_json_text(rule_input))
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                return None
        return None

    def _iter_sing_box_rules(self, rule: Any) -> List[Dict[str, Any]]:
        parsed = self._parse_sing_box_rule(rule)
        if not parsed:
            return []
        result = [parsed]
        if parsed.get("type") == "logical":
            for nested in self._as_list(parsed.get("rules")):
                result.extend(self._iter_sing_box_rules(nested))
        return result

    def _sing_box_to_domain(self, rule: Union[Dict, str]) -> List[str]:
        result = []
        for item in self._iter_sing_box_rules(rule):
            for domain in self._as_list(item.get("domain")):
                normalized = self._normalize_domain_value(str(domain))
                if normalized:
                    result.append(normalized)
            for suffix in self._as_list(item.get("domain_suffix")):
                normalized = self._normalize_domain_value(str(suffix), suffix_hint=True)
                if normalized:
                    result.append(normalized)
        return result

    def _sing_box_to_ipcidr(self, rule: Union[Dict, str]) -> List[str]:
        result = []
        for item in self._iter_sing_box_rules(rule):
            for value in self._as_list(item.get("ip_cidr")):
                network = self._parse_ip_network(str(value))
                if network:
                    result.append(network.with_prefixlen)
        return result

    def _sing_box_to_classical(self, rule: Union[Dict, str]) -> List[str]:
        result = []
        for item in self._iter_sing_box_rules(rule):
            result.extend(f"DOMAIN,{value}" for value in self._as_list(item.get("domain")))
            result.extend(f"DOMAIN-SUFFIX,{str(value).lstrip('.')}" for value in self._as_list(item.get("domain_suffix")))
            result.extend(f"DOMAIN-KEYWORD,{value}" for value in self._as_list(item.get("domain_keyword")))
            result.extend(f"DOMAIN-REGEX,{value}" for value in self._as_list(item.get("domain_regex")))
            for value in self._as_list(item.get("ip_cidr")):
                network = self._parse_ip_network(str(value))
                if network:
                    prefix = "IP-CIDR6" if network.version == 6 else "IP-CIDR"
                    result.append(f"{prefix},{network.with_prefixlen}")
            result.extend(f"NETWORK,{str(value).lower()}" for value in self._as_list(item.get("network")))

            port_items = (
                [str(value) for value in self._as_list(item.get("port"))]
                + [str(value).replace(":", "-") for value in self._as_list(item.get("port_range"))]
            )
            if port_items:
                merged = self._merge_port_items(port_items)
                if merged:
                    result.append(f"DST-PORT,{'/'.join(merged)}")
        return result

    # -------------------- Independent aggregation pipelines --------------------

    def _deduplicate_and_merge_domain(self, rules: List[Any]) -> List[str]:
        exact, suffix, wildcard = [], [], []
        for raw in rules:
            if not isinstance(raw, str):
                continue
            rule = self._clean_rule(raw)
            if not rule:
                continue

            suffix_hint = False
            if "," in rule:
                parts = [part.strip() for part in rule.split(",", 1)]
                if len(parts) != 2:
                    continue
                prefix, value = parts[0].upper(), parts[1]
                if prefix == "DOMAIN":
                    pass
                elif prefix == "DOMAIN-SUFFIX":
                    suffix_hint = True
                else:
                    continue
                normalized = self._normalize_domain_value(value, suffix_hint)
            else:
                normalized = self._normalize_domain_value(rule)

            if not normalized:
                continue
            if "*" in normalized:
                wildcard.append(normalized)
            elif normalized.startswith("+."):
                suffix.append(normalized[2:])
            else:
                exact.append(normalized)

        exact, suffix = self._unified_domain_deduplication(exact, suffix)
        result = [*exact, *(f"+.{value}" for value in suffix)]
        result.extend(sorted(set(wildcard)))
        return result

    def _deduplicate_and_merge_ipcidr(self, rules: List[Any]) -> List[str]:
        ipv4, ipv6 = [], []
        for raw in rules:
            if not isinstance(raw, str):
                continue
            network = self._parse_ip_network(raw)
            if network:
                (ipv4 if network.version == 4 else ipv6).append(network)
        return [n.with_prefixlen for n in self._prune_networks(ipv4)] + [
            n.with_prefixlen for n in self._prune_networks(ipv6)
        ]

    def _deduplicate_and_merge_classical(self, rules: List[str], target_behavior: str = "classical") -> List[str]:
        buckets = {
            "DOMAIN": [], "DOMAIN-SUFFIX": [], "DOMAIN-KEYWORD": [],
            "DOMAIN-REGEX": [], "IP-CIDR": [], "DST-PORT": [],
            "NETWORK": [], "OTHER": []
        }
        for rule in rules:
            if not rule:
                continue
            prefix = rule.split(",", 1)[0].strip().upper()
            if prefix in buckets:
                buckets[prefix].append(rule)
            elif prefix == "IP-CIDR6":
                buckets["IP-CIDR"].append(rule)
            elif self._parse_ip_network(rule):
                buckets["IP-CIDR"].append(rule)
            else:
                buckets["OTHER"].append(rule)

        exact = [r.split(",", 1)[1].strip() for r in buckets["DOMAIN"] if "," in r]
        suffix = [r.split(",", 1)[1].strip() for r in buckets["DOMAIN-SUFFIX"] if "," in r]
        final_exact, final_suffix = self._unified_domain_deduplication(exact, suffix)

        def simple_dedup(items):
            seen, result = set(), []
            for item in items:
                signature = self._normalize_rule_signature(item)
                if signature not in seen:
                    seen.add(signature)
                    result.append(item)
            return result

        merged_ip = self._merge_ip_rules(buckets["IP-CIDR"])
        result = (
            [f"DOMAIN,{value}" for value in final_exact]
            + [f"DOMAIN-SUFFIX,{value}" for value in final_suffix]
            + simple_dedup(buckets["DOMAIN-KEYWORD"])
            + simple_dedup(buckets["DOMAIN-REGEX"])
            + merged_ip
        )
        if merged_ports := self._merge_dst_port_rules(buckets["DST-PORT"]):
            result.append(merged_ports)
        result.extend(simple_dedup(buckets["NETWORK"]))
        result.extend(simple_dedup(buckets["OTHER"]))
        return result

    def _merge_dst_port_rules(self, rules: List[str]) -> Optional[str]:
        all_items = []
        for rule in rules:
            parts = rule.split(",", 1)
            if len(parts) == 2:
                all_items.extend(item.strip() for item in parts[1].split("/") if item.strip())
        merged = self._merge_port_items(all_items)
        return f"DST-PORT,{'/'.join(merged)}" if merged else None

    def _compile_final_sing_box_list(self, rules: List[Dict]) -> List[Dict]:
        # Sets remove duplicates as values arrive, avoiding large duplicate-heavy lists.
        bucket = {key: set() for key in SING_BOX_LIST_FIELDS}
        passthrough = []

        for rule in rules:
            if self._can_compact_sing_box_rule(rule):
                for key, raw_values in rule.items():
                    values = self._as_list(raw_values)
                    if key == "port":
                        bucket[key].update(int(v) if str(v).isdigit() else v for v in values)
                    elif key == "network":
                        bucket[key].update(str(v).lower() for v in values)
                    elif key in ("domain", "domain_suffix"):
                        bucket[key].update(str(v).lower().strip(".") for v in values)
                    elif key in ("domain_keyword", "domain_regex"):
                        bucket[key].update(str(v) for v in values)
                    else:
                        bucket[key].update(values)
            else:
                passthrough.append(rule)

        if bucket["domain"] or bucket["domain_suffix"]:
            bucket["domain"], bucket["domain_suffix"] = self._unified_domain_deduplication(
                [str(value) for value in bucket["domain"]],
                [str(value) for value in bucket["domain_suffix"]]
            )

        for key in ("domain", "domain_suffix"):
            remaining = set()
            for value in bucket[key]:
                text = str(value)
                if "*" in text:
                    wildcard = text if key == "domain" else f"+.{text}"
                    regex_value = self._wildcard_to_domain_regex(wildcard)
                    if regex_value:
                        bucket["domain_regex"].add(regex_value)
                        continue
                remaining.add(value)
            bucket[key] = remaining

        if bucket["domain_regex"]:
            bucket["domain_regex"] = {str(value).strip() for value in bucket["domain_regex"]}

        if bucket["ip_cidr"]:
            ipv4, ipv6 = [], []
            for value in bucket["ip_cidr"]:
                network = self._parse_ip_network(str(value))
                if network:
                    (ipv4 if network.version == 4 else ipv6).append(network)
            bucket["ip_cidr"] = {
                network.with_prefixlen
                for network in self._prune_networks(ipv4) + self._prune_networks(ipv6)
            }

        if bucket["port"] or bucket["port_range"]:
            merged = self._merge_port_items(
                [str(value) for value in bucket["port"]]
                + [str(value).replace(":", "-") for value in bucket["port_range"]]
            )
            bucket["port"], bucket["port_range"] = set(), set()
            for value in merged:
                if "-" in value:
                    bucket["port_range"].add(value.replace("-", ":"))
                else:
                    bucket["port"].add(int(value))

        compacted = []
        for key in SING_BOX_LIST_FIELDS:
            if values := bucket.get(key):
                unique = sorted(values) if key == "port" else sorted(values, key=str)
                compacted.append({key: unique})

        seen, final = set(), []
        for rule in compacted + passthrough:
            signature = self._normalize_rule_signature(rule)
            if signature not in seen:
                seen.add(signature)
                final.append(rule)
        return final

    def _can_compact_sing_box_rule(self, rule: Dict[str, Any]) -> bool:
        if rule.get("type") == "logical":
            return False
        return all(
            key in SING_BOX_LIST_FIELDS
            and all(isinstance(value, (str, int)) for value in self._as_list(values))
            for key, values in rule.items()
        )

    # -------------------- Main processing workflow --------------------

    def merge_rules(self) -> None:
        configs = [
            cfg for cfg in self.rulesets
            if isinstance(cfg, dict) and "upstream" in cfg and cfg.get("path")
        ]
        if not configs:
            logger.warning("没有有效的规则集配置")
            return

        if self.max_workers == 1:
            self.ruleset_workers = 1
            self.source_workers = 1
        else:
            self.ruleset_workers = min(8, max(1, self.max_workers // 2), len(configs))
            self.source_workers = max(
                1, (self.max_workers - self.ruleset_workers) // self.ruleset_workers
            )
        logger.info(
            "共 %s 个规则集，开始并行处理 (规则集线程=%s, 每个规则集上游线程上限=%s, 总并发预算=%s)...",
            len(configs), self.ruleset_workers, self.source_workers, self.max_workers
        )
        if self.max_workers == 1:
            for cfg in configs:
                try:
                    self._process_one_ruleset(cfg)
                except Exception as exc:
                    logger.error("规则集处理抛出未捕获的异常: %s", exc)
        else:
            with ThreadPoolExecutor(max_workers=self.ruleset_workers) as executor:
                futures = [executor.submit(self._process_one_ruleset, cfg) for cfg in configs]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as exc:
                        logger.error("规则集处理抛出未捕获的异常: %s", exc)

        logger.info("全部规则集处理完毕。")
        if self.push_enabled:
            self._force_push()

    def _process_one_source(self, source: Dict, target_behavior: str, path: str) -> Tuple[List[Any], int, int]:
        label = source.get("url") or source.get("path") or "unknown"
        try:
            raw_rules, source_behavior, _ = self._fetch_source(source)
        except Exception as exc:
            logger.error("[%s] 源 %s 抓取失败: %s", path, label, exc)
            return [], 0, 0

        total_raw, dropped = len(raw_rules), 0
        converted = []
        transform_cache = {}
        for rule in raw_rules:
            if rule is None or rule == "":
                continue
            if isinstance(rule, str):
                rule = self._clean_rule(rule)
                if not rule or rule in ("*", "+.*", ".*", "+.", "."):
                    dropped += 1
                    continue
                if rule.startswith("*."):
                    rule = "+." + rule[2:]
                elif rule.startswith(".") and not rule.startswith(".."):
                    rule = "+." + rule[1:]

                cached = transform_cache.get(rule)
                if cached is None:
                    transformed = self._transform(rule, source_behavior, target_behavior)
                    cached = tuple(transformed) if transformed else ()
                    # Bound cache growth for very large feeds containing mostly unique rules.
                    if len(transform_cache) < 65536:
                        transform_cache[rule] = cached
                transformed = cached
            else:
                transformed = self._transform(rule, source_behavior, target_behavior)

            if transformed:
                converted.extend(transformed)
            else:
                dropped += 1

        logger.info(
            "[%s] 源 %s 处理完成: 原始 %s 条 -> 有效 %s 条, 丢弃 %s 条",
            path, label, total_raw, len(converted), dropped
        )
        return converted, total_raw, dropped

    def _process_one_ruleset(self, cfg: Dict) -> None:
        path = cfg["path"]
        target_format = cfg.get("format", "yaml")
        target_behavior = self._normalize_behavior(
            cfg.get("behavior", "sing-box" if target_format in ("json", "srs") else "classical")
        )
        version = cfg.get("version", SING_BOX_RULESET_VERSION)
        sources = list(cfg["upstream"].values())

        try:
            all_converted = []
            total_raw = total_dropped = 0
            if sources:
                workers = max(1, min(self.source_workers, len(sources)))
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = [
                        executor.submit(self._process_one_source, source, target_behavior, path)
                        for source in sources
                    ]
                    for future in as_completed(futures):
                        try:
                            converted, raw_count, dropped_count = future.result()
                            all_converted.extend(converted)
                            total_raw += raw_count
                            total_dropped += dropped_count
                        except Exception as exc:
                            logger.error("[%s] 源流水线单元异常: %s", path, exc)

            logger.info(
                "[%s] 全部源处理完成: 原始 %s 条 -> 有效 %s 条, 丢弃 %s 条",
                path, total_raw, len(all_converted), total_dropped
            )

            if target_behavior == "sing-box":
                dict_rules = []
                for rule in all_converted:
                    if isinstance(rule, dict):
                        dict_rules.append(rule)
                    elif isinstance(rule, str):
                        parsed = self._parse_sing_box_rule(rule)
                        if parsed:
                            dict_rules.append(parsed)
                final_rules = self._compile_final_sing_box_list(dict_rules)
            elif target_behavior == "domain":
                final_rules = self._deduplicate_and_merge_domain(all_converted)
            elif target_behavior == "ipcidr":
                final_rules = self._deduplicate_and_merge_ipcidr(all_converted)
            elif target_behavior == "classical":
                final_rules = self._deduplicate_and_merge_classical(
                    [str(rule) for rule in all_converted if rule is not None]
                )
            else:
                raise ValueError(f"不支持的目标 behavior: {target_behavior}")

            logger.info("[%s] 聚合去重完成，最终规则数=%s，正在写入...", path, len(final_rules))
            if os.path.isabs(path) or os.path.dirname(path):
                output_path = path
            else:
                output_path = os.path.join(self.output_dir, os.path.basename(path))
            self._write_rules(output_path, final_rules, target_format, target_behavior, version)

        except Exception as exc:
            logger.exception("[%s] 规则集生成失败: %s", path, exc)

    # -------------------- Output preparation and writing --------------------

    def _prepare_rules_for_mrs(self, rules: List[Any], behavior: str) -> List[str]:
        cleaned = []
        for rule in rules:
            if rule is None:
                continue
            value = str(rule).strip()
            if not value or value.startswith("#"):
                continue

            if behavior == "ipcidr":
                network = self._parse_ip_network(value)
                if network:
                    cleaned.append(network.with_prefixlen)
            elif behavior == "domain":
                normalized = self._normalize_domain_value(value)
                if normalized:
                    cleaned.append(normalized)
            else:
                cleaned.append(value)
        return list(dict.fromkeys(cleaned))

    def _write_rules(self, output_path: str, rules: List[Any], rule_format: str, behavior: str, version: int) -> None:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        try:
            if rule_format == "mrs":
                mrs_rules = self._prepare_rules_for_mrs(rules, behavior)
                if not mrs_rules:
                    logger.error("[%s] 没有可用于 MRS 编译的有效规则，取消写盘", output_path)
                    return
                with self._temp_file(".txt") as temp_txt:
                    with open(temp_txt, "w", encoding="utf-8") as f:
                        f.write("\n".join(mrs_rules) + "\n")
                    success = self._convert_to_binary(
                        self.mihomo_path,
                        ["convert-ruleset", behavior, "text", temp_txt, output_path],
                        "MRS"
                    )
                if not success:
                    logger.error("[%s] MRS 编译失败，未生成文件", output_path)
                    return

            elif rule_format == "srs":
                with self._temp_file(".json") as temp_json:
                    with open(temp_json, "w", encoding="utf-8") as f:
                        json.dump({"version": version, "rules": rules}, f, ensure_ascii=False, indent=2)
                    success = self._convert_to_binary(
                        self.sing_box_path,
                        ["rule-set", "compile", "--output", output_path, temp_json],
                        "SRS"
                    )
                if not success:
                    logger.error("[%s] SRS 编译失败，未生成文件", output_path)
                    return

            elif rule_format == "json":
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump({"version": version, "rules": rules}, f, ensure_ascii=False, indent=2)

            elif rule_format == "yaml":
                with open(output_path, "w", encoding="utf-8") as f:
                    yaml.dump({"payload": rules}, f, allow_unicode=True, sort_keys=False)

            else:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(f"# Update: {datetime.now():%Y-%m-%d %H:%M:%S} | Total: {len(rules)}\n")
                    f.write("\n".join(str(rule) for rule in rules) + "\n")

            logger.info("[%s] 规则集写入完成，最终规则数: %s", output_path, len(rules))
        except Exception as exc:
            logger.exception("[%s] 写入失败: %s", output_path, exc)

    # -------------------- Binary tool support --------------------

    def _read_mrs_file(self, input_path: str, behavior: str) -> List[str]:
        if not self.mihomo_path:
            return []
        with self._temp_file(".txt") as temp_txt:
            command = [self.mihomo_path, "convert-ruleset", behavior, "mrs", input_path, temp_txt]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                with open(temp_txt, "r", encoding="utf-8") as f:
                    return f.read().splitlines()
            logger.error("读取 MRS 失败: %s", (result.stderr or result.stdout).strip())
        return []

    def _decompile_srs_to_json_str(self, input_path: str) -> str:
        if not self.sing_box_path:
            return "{}"
        with self._temp_file(".json") as temp_json:
            command = [self.sing_box_path, "rule-set", "decompile", "--output", temp_json, input_path]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                with open(temp_json, "r", encoding="utf-8") as f:
                    return f.read()
            logger.error("反编译 SRS 失败: %s", (result.stderr or result.stdout).strip())
        return "{}"

    def _convert_to_binary(self, binary_path: str, args: List[str], name: str) -> bool:
        if not binary_path:
            logger.error("未配置工具路径，无法编译 %s", name)
            return False
        try:
            result = subprocess.run(
                [binary_path] + args,
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "未明确原因").strip()
                logger.error("编译 %s 失败 (退出码 %s): %s", name, result.returncode, detail)
                return False
            return True
        except Exception as exc:
            logger.error("调用编译器 %s 异常: %s", binary_path, exc)
            return False

    # -------------------- Git push --------------------

    def _force_push(self) -> None:
        if not shutil.which("git"):
            logger.error("未找到 git 命令，跳过推送")
            return
        try:
            subprocess.run(
                ["git", "add", self.output_dir],
                check=True, capture_output=True, text=True
            )
            status = subprocess.run(
                ["git", "status", "--porcelain", self.output_dir],
                capture_output=True, text=True, check=True
            )
            if not status.stdout.strip():
                logger.info("规则文件无变更，跳过推送")
                return

            commit_message = f"Update rules {datetime.now():%Y-%m-%d %H:%M:%S}"
            subprocess.run(
                ["git", "commit", "-m", commit_message],
                check=True, capture_output=True, text=True
            )
            push_command = ["git", "push", "--force", self.push_remote]
            if self.push_branch:
                push_command.append(self.push_branch)
            result = subprocess.run(
                push_command, capture_output=True, text=True, check=True
            )
            logger.info("推送成功: %s", result.stdout.strip())
        except subprocess.CalledProcessError as exc:
            logger.error("Git 操作失败: %s", exc.stderr.strip() if exc.stderr else exc)
        except Exception as exc:
            logger.exception("推送过程异常: %s", exc)


def main():
    merger = RulesMerger("config.yaml", max_workers=64)
    merger.merge_rules()


if __name__ == "__main__":
    main()

"""SMB file share enumeration and assessment module.

Discovers accessible shares, checks permissions, and identifies sensitive data exposure.
"""

from __future__ import annotations

import logging
from typing import Any

from iescan.config import ScanConfig
from iescan.core.scanner import (
    BaseModule,
    Finding,
    FindingCategory,
    ModuleResult,
    Severity,
)

logger = logging.getLogger(__name__)

# Sensitive file patterns to look for in shares
SENSITIVE_PATTERNS = [
    "password", "passwd", "credential", "secret",
    ".kdbx", ".key", ".pem", ".pfx", ".p12",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "web.config", "appsettings.json", "connectionstrings",
    ".env", "vault", "token",
    "unattend.xml", "sysprep.xml", "autounattend.xml",
    "groups.xml", "services.xml", "scheduledtasks.xml",
]

# Common admin/sensitive shares
ADMIN_SHARES = ["C$", "ADMIN$", "IPC$"]
SENSITIVE_SHARE_NAMES = [
    "backup", "backups", "it", "admin", "finance",
    "hr", "legal", "confidential", "secret", "passwords",
    "sysvol", "netlogon", "software", "deploy",
]


class ShareEnumerationModule(BaseModule):
    """Enumerate and assess SMB file shares for access control issues."""

    name = "share_enumeration"
    description = "Enumerate SMB shares, check permissions, and identify sensitive data exposure"

    def run(self, target: str, **kwargs: Any) -> ModuleResult:
        result = self._make_result(target)

        try:
            from smb.SMBConnection import SMBConnection

            username = self.config.credentials.username
            password = self.config.credentials.password
            domain = self.config.credentials.domain

            conn = SMBConnection(
                username,
                password,
                "iescan",
                target,
                domain=domain,
                use_ntlm_v2=True,
                is_direct_tcp=True,
            )

            connected = conn.connect(target, 445, timeout=self.config.timeout)
            if not connected:
                result.errors.append(f"Failed to connect to SMB on {target}")
                result.success = False
                return result

            try:
                shares = conn.listShares()
                share_list = []

                for share in shares:
                    share_info = self._assess_share(conn, share, target, result)
                    share_list.append(share_info)

                result.data["shares"] = share_list
                result.data["share_count"] = len(share_list)

                # Check for null session access
                self._check_null_session(target, result)

            finally:
                conn.close()

        except ImportError:
            result.errors.append("pysmb not available - using impacket fallback")
            self._enum_with_impacket(target, result)
        except Exception as e:
            result.errors.append(f"SMB error: {e}")
            result.success = False

        return result

    def _assess_share(
        self, conn: Any, share: Any, target: str, result: ModuleResult
    ) -> dict[str, Any]:
        """Assess a single SMB share."""
        share_name = share.name
        share_info: dict[str, Any] = {
            "name": share_name,
            "type": str(share.type),
            "comments": share.comments or "",
            "accessible": False,
            "readable": False,
            "writable": False,
            "files_found": 0,
            "sensitive_files": [],
        }

        # Check if it's an admin share
        if share_name in ADMIN_SHARES:
            try:
                conn.listPath(share_name, "/")
                share_info["accessible"] = True
                share_info["readable"] = True
                result.findings.append(
                    Finding(
                        title=f"Administrative Share {share_name} Accessible on {target}",
                        severity=Severity.HIGH,
                        category=FindingCategory.SMB_SHARE,
                        description=(
                            f"Administrative share {share_name} is accessible with the "
                            "provided credentials. Admin shares provide access to the "
                            "entire file system and can be used for lateral movement."
                        ),
                        target=target,
                        remediation=(
                            "Restrict administrative share access. Disable admin shares "
                            "if not needed via LocalAccountTokenFilterPolicy."
                        ),
                    )
                )
            except Exception:
                pass
            return share_info

        # Check read access
        try:
            files = conn.listPath(share_name, "/")
            share_info["accessible"] = True
            share_info["readable"] = True
            share_info["files_found"] = len(files)

            # Check for sensitive files
            sensitive = self._find_sensitive_files(conn, share_name, "/", depth=0)
            share_info["sensitive_files"] = sensitive

            if sensitive:
                result.findings.append(
                    Finding(
                        title=f"Sensitive Files Found in \\\\{target}\\{share_name}",
                        severity=Severity.HIGH,
                        category=FindingCategory.CREDENTIAL,
                        description=(
                            f"Found {len(sensitive)} potentially sensitive files in the "
                            f"{share_name} share that may contain credentials or secrets."
                        ),
                        target=target,
                        evidence="\n".join(sensitive[:20]),
                        remediation=(
                            "Review and restrict access to sensitive files. "
                            "Move credentials to a secrets management solution."
                        ),
                    )
                )

        except Exception:
            pass

        # Check write access
        try:
            test_file = "__iescan_write_test__.tmp"
            from io import BytesIO

            test_data = BytesIO(b"iescan write test")
            conn.storeFile(share_name, f"/{test_file}", test_data)
            # Clean up test file immediately
            conn.deleteFiles(share_name, f"/{test_file}")
            share_info["writable"] = True

            if share_name not in ADMIN_SHARES:
                result.findings.append(
                    Finding(
                        title=f"Writable Share \\\\{target}\\{share_name}",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.SMB_SHARE,
                        description=(
                            f"Share {share_name} is writable with the provided credentials. "
                            "Writable shares can be used for planting malicious files or "
                            "modifying legitimate ones."
                        ),
                        target=target,
                        remediation=(
                            "Review share permissions and apply least-privilege access. "
                            "Ensure only authorized users have write access."
                        ),
                    )
                )
        except Exception:
            pass

        # Check for sensitive share names
        if any(s in share_name.lower() for s in SENSITIVE_SHARE_NAMES):
            if share_info["accessible"]:
                result.findings.append(
                    Finding(
                        title=f"Sensitive Share \\\\{target}\\{share_name} Accessible",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.SMB_SHARE,
                        description=(
                            f"Share '{share_name}' appears to contain sensitive data based "
                            "on its name and is accessible with the provided credentials."
                        ),
                        target=target,
                        remediation=(
                            "Review access control on this share. Ensure only authorized "
                            "personnel have access to sensitive data."
                        ),
                    )
                )

        return share_info

    def _find_sensitive_files(
        self, conn: Any, share: str, path: str, depth: int, max_depth: int = 2
    ) -> list[str]:
        """Recursively search for sensitive files (limited depth)."""
        if depth >= max_depth:
            return []

        sensitive_found: list[str] = []
        try:
            files = conn.listPath(share, path)
            for f in files:
                if f.filename in (".", ".."):
                    continue
                full_path = f"{path}{f.filename}" if path == "/" else f"{path}/{f.filename}"
                name_lower = f.filename.lower()

                # Check file name against sensitive patterns
                for pattern in SENSITIVE_PATTERNS:
                    if pattern in name_lower:
                        sensitive_found.append(full_path)
                        break

                # Recurse into directories
                if f.isDirectory and depth < max_depth:
                    sensitive_found.extend(
                        self._find_sensitive_files(conn, share, full_path, depth + 1)
                    )
        except Exception:
            pass

        return sensitive_found

    def _check_null_session(self, target: str, result: ModuleResult) -> None:
        """Check if null session (anonymous) access is possible."""
        try:
            from smb.SMBConnection import SMBConnection

            null_conn = SMBConnection(
                "", "", "iescan", target,
                use_ntlm_v2=True, is_direct_tcp=True,
            )
            if null_conn.connect(target, 445, timeout=self.config.timeout):
                try:
                    shares = null_conn.listShares()
                    if shares:
                        result.findings.append(
                            Finding(
                                title=f"Null Session Access Allowed on {target}",
                                severity=Severity.HIGH,
                                category=FindingCategory.SMB_SHARE,
                                description=(
                                    "The server allows null session (anonymous) access to "
                                    "enumerate shares. This can leak information about the "
                                    "system and network to unauthenticated attackers."
                                ),
                                target=target,
                                evidence=(
                                    "Shares visible via null session: "
                                    + ", ".join(s.name for s in shares)
                                ),
                                remediation=(
                                    "Disable null session access by setting "
                                    "RestrictAnonymous=1 in registry and restricting "
                                    "anonymous access in security policy."
                                ),
                            )
                        )
                finally:
                    null_conn.close()
        except Exception:
            pass

    def _enum_with_impacket(self, target: str, result: ModuleResult) -> None:
        """Fallback share enumeration using impacket."""
        try:
            from impacket.smbconnection import SMBConnection

            smb = SMBConnection(target, target, timeout=self.config.timeout)
            smb.login(
                self.config.credentials.username,
                self.config.credentials.password,
                self.config.credentials.domain,
            )

            shares = smb.listShares()
            share_list = []
            for share in shares:
                share_name = share["shi1_netname"][:-1]  # Remove null terminator
                share_list.append({
                    "name": share_name,
                    "type": str(share["shi1_type"]),
                    "comments": share["shi1_remark"][:-1] if share["shi1_remark"] else "",
                })

            result.data["shares"] = share_list
            result.data["share_count"] = len(share_list)
            smb.close()

        except Exception as e:
            result.errors.append(f"Impacket SMB error: {e}")

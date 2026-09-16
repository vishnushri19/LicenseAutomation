#!/usr/bin/env python3
"""Standalone BIG-IP licensing through iControl REST and the F5 Activation Service."""

from __future__ import annotations

import argparse
import base64
import getpass
import html
import os
import re
import sys
import xml.etree.ElementTree as ET
from typing import Iterable, Optional

import requests


ACTIVATION_URL = (
    os.getenv(
        "F5_ACTIVATION_URL",
        "https://activate.f5.com/license/services/",
    )
    + "urn:com.f5.license.v5b.ActivationService"
)


class BigIPClient:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        verify_tls: bool,
        timeout: int,
    ) -> None:
        self.base_url = f"https://{host}"
        self.auth = (username, password)
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.token: Optional[str] = None
        self._login()

    def _login(self) -> None:
        response = requests.post(
            self.base_url + "/mgmt/shared/authn/login",
            json={
                "username": self.auth[0],
                "password": self.auth[1],
                "loginProviderName": "tmos",
            },
            verify=self.verify_tls,
            timeout=self.timeout,
        )
        if response.ok:
            token = response.json().get("token", {}).get("token")
            if token:
                self.token = str(token)

    def post(
        self,
        path: str,
        payload: dict,
        timeout: Optional[int] = None,
    ) -> dict:
        headers = {"X-F5-Auth-Token": self.token} if self.token else {}
        response = requests.post(
            self.base_url + path,
            json=payload,
            auth=None if self.token else self.auth,
            headers=headers,
            verify=self.verify_tls,
            timeout=timeout or self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def get(self, path: str) -> dict:
        headers = {"X-F5-Auth-Token": self.token} if self.token else {}
        response = requests.get(
            self.base_url + path,
            auth=None if self.token else self.auth,
            headers=headers,
            verify=self.verify_tls,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def run_bash(self, command: str, timeout: int) -> str:
        response = self.post(
            "/mgmt/tm/util/bash",
            {
                "command": "run",
                "utilCmdArgs": f"-c '{command}'",
            },
            timeout=timeout,
        )
        return str(response.get("commandResult", "")).strip()


def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ValueError(f"Missing required environment variable: {name}")
    return value


def get_password() -> str:
    password = os.getenv("BIGIP_PASS", "").strip()
    if password:
        return password
    if not sys.stdin.isatty():
        raise ValueError("BIGIP_PASS is required in non-interactive mode.")
    return getpass.getpass("Enter BIG-IP Password: ")


def validate_registration_key(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9-]+", value):
        raise ValueError(
            "F5_REGISTRATION_KEY may contain only letters, numbers, and hyphens."
        )
    return value


def xml_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def parse_xml(payload: str) -> ET.Element:
    try:
        return ET.fromstring(payload)
    except ET.ParseError as exc:
        raise RuntimeError(
            "F5 Activation Service returned invalid XML."
        ) from exc


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _multi_ref_values(root: ET.Element, names: set[str]) -> list[str]:
    by_id = {
        element.get("id"): element
        for element in root.iter()
        if element.get("id")
    }

    def value(element: ET.Element, seen: set[str]) -> str:
        href = element.get("href", "").lstrip("#")
        if href and href in by_id and href not in seen:
            return value(by_id[href], seen | {href})
        return " ".join(
            part.strip()
            for part in element.itertext()
            if part.strip()
        )

    values = []
    for element in root.iter():
        if _local_name(element.tag) in names:
            text = value(element, set()).strip()
            if text:
                values.append(text)
    return values


def soap_request(
    action: str,
    body: str,
    verify_tls: bool,
    timeout: int,
) -> str:
    envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope '
        'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:act="urn:com.f5.license.v5b.ActivationService">'
        "<soapenv:Body>"
        f"{body}"
        "</soapenv:Body>"
        "</soapenv:Envelope>"
    )
    response = requests.post(
        ACTIVATION_URL,
        data=envelope.encode("utf-8"),
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": (
                "urn:com.f5.license.v5b.ActivationService#"
                f"{action}"
            ),
        },
        verify=verify_tls,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.text


def raise_for_soap_fault(payload: str) -> None:
    root = parse_xml(payload)
    faults = [
        " ".join(part.strip() for part in element.itertext() if part.strip())
        for element in root.iter()
        if xml_name(element.tag) == "faultstring"
    ]
    if faults:
        raise RuntimeError(f"F5 Activation Service fault: {faults[0]}")


def text_candidates(root: ET.Element) -> Iterable[str]:
    for element in root.iter():
        text = " ".join(
            part.strip()
            for part in element.itertext()
            if part.strip()
        )
        if text:
            yield text


def get_eula(
    dossier: str,
    verify_tls: bool,
    timeout: int,
) -> str:
    response = soap_request(
        "getEULA",
        (
            "<act:getEULA><dossier>"
            f"{html.escape(dossier)}"
            "</dossier></act:getEULA>"
        ),
        verify_tls,
        timeout,
    )
    raise_for_soap_fault(response)
    root = parse_xml(response)
    values = _multi_ref_values(root, {"eula", "eulareturn"})
    if not values:
        values = list(text_candidates(root))
    eula = max(values, key=len, default="")
    if not eula:
        raise RuntimeError("F5 Activation Service returned no EULA text.")
    return eula


def activate(
    dossier: str,
    verify_tls: bool,
    timeout: int,
) -> str:
    response = soap_request(
        "activate",
        (
            "<act:activate><dossier>"
            f"{html.escape(dossier)}"
            "</dossier><eula_accepted>true</eula_accepted>"
            "</act:activate>"
        ),
        verify_tls,
        timeout,
    )
    raise_for_soap_fault(response)
    root = parse_xml(response)
    candidates = _multi_ref_values(
        root,
        {"license", "licensetext", "licensefile", "licensereturn"},
    )
    if not candidates:
        candidates = [
            value
            for value in text_candidates(root)
            if "license" in value.lower()
        ]
    license_text = max(candidates, key=len, default="")
    if not license_text:
        raise RuntimeError(
            "F5 Activation Service returned no signed license text."
        )
    return license_text


def generate_dossier(client: BigIPClient, registration_key: str) -> str:
    result = client.run_bash(
        f'get_dossier -b "{registration_key}"',
        timeout=180,
    )
    if not result:
        raise RuntimeError("BIG-IP returned an empty dossier.")
    return result


def apply_license(client: BigIPClient, license_text: str) -> None:
    encoded = base64.b64encode(license_text.encode("utf-8")).decode("ascii")
    write_result = client.run_bash(
        f"echo {encoded} | base64 -d > /config/bigip.license",
        timeout=120,
    )
    if "error" in write_result.lower():
        raise RuntimeError(
            f"Could not write /config/bigip.license: {write_result}"
        )

    reload_result = client.run_bash("/usr/bin/reloadlic", timeout=180)
    if "error" in reload_result.lower():
        raise RuntimeError(f"reloadlic failed: {reload_result}")


def verify_license(client: BigIPClient, registration_key: str) -> None:
    payload = client.get("/mgmt/tm/sys/license")
    if not payload:
        raise RuntimeError("BIG-IP returned an empty license response.")
    entries = payload.get("entries", [])
    if not entries:
        raise RuntimeError("BIG-IP license response contains no entries.")
    keys = {
        str(value).strip()
        for element in entries
        if isinstance(element, dict)
        for name, value in element.items()
        if name.lower() == "registrationkey" and value
    }
    if keys and registration_key not in keys:
        raise RuntimeError(
            "BIG-IP license verification returned a different registration key."
        )
    print("License verification: PASS")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Standalone BIG-IP license dossier and activation utility."
    )
    parser.add_argument(
        "--activate",
        action="store_true",
        help="Retrieve the EULA, activate, apply, and verify the license.",
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify BIG-IP and F5 Activation Service TLS certificates.",
    )
    args = parser.parse_args()

    try:
        host = required_env("BIGIP_HOST")
        username = required_env("BIGIP_USER")
        registration_key = validate_registration_key(
            required_env("F5_REGISTRATION_KEY")
        )
        password = get_password()
        timeout = int(os.getenv("BIGIP_TIMEOUT", "60"))
        client = BigIPClient(
            host,
            username,
            password,
            args.verify_tls,
            timeout,
        )

        print(f"Generating dossier on {host}...")
        dossier = generate_dossier(client, registration_key)
        print("Dossier generated successfully.")

        if not args.activate:
            print(
                "No activation requested. The license was not sent, changed, "
                "or reloaded."
            )
            return 0

        print("Requesting EULA from F5 Activation Service...")
        eula = get_eula(dossier, args.verify_tls, timeout)
        print(f"EULA received ({len(eula)} characters).")
        if not sys.stdin.isatty():
            raise RuntimeError(
                "EULA acceptance requires an interactive terminal."
            )
        answer = input(
            "Accept the F5 EULA and activate this license? (y/N): "
        ).strip().lower()
        if answer not in {"y", "yes"}:
            print("Activation cancelled. No license was changed.")
            return 0

        print("Activating through F5 Activation Service...")
        license_text = activate(dossier, args.verify_tls, timeout)
        print("Signed license received. Applying license to BIG-IP...")
        apply_license(client, license_text)
        verify_license(client, registration_key)
        print("BIG-IP license activation completed successfully.")
        return 0
    except (ValueError, RuntimeError, requests.RequestException) as exc:
        print(f"License automation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

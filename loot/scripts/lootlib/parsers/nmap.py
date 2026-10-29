"""nmap ``-oX`` XML (and masscan and naabu, which write the same schema) to hosts and services.

An attribute nmap did not emit is a field that is not set: no defaults, no guesses.
masscan writes each banner as its own ``<host>``; its ``<service name>`` is the banner's type.
"""

from __future__ import annotations

from typing import Any

from lootlib import records
from lootlib.parsers import Input, ParserError
from lootlib.parsers.xmlspan import XmlElement, XmlSpanError
from lootlib.parsers.xmlspan import parse as parse_xml
from lootlib.prov import TOOL, cite

NAME = "nmap"
IP_TYPES = ("ipv4", "ipv6")


def sniff(data: bytes, hint: str | None = None) -> bool:
    head = data[:4096]
    return b"<nmaprun" in head and b"<?xml" in head[:64]


def parse(raw: Input) -> list[dict[str, Any]]:
    try:
        root = parse_xml(raw.data)
    except XmlSpanError as err:
        raise ParserError(f"{raw.source or raw.blob} is not readable nmap XML: {err}") from err
    if root.tag != "nmaprun":
        raise ParserError(f"expected a <nmaprun> document, found <{root.tag}>")
    masscan = root.get("scanner") == "masscan"
    out: list[dict[str, Any]] = []
    services: dict[str, dict[str, Any]] = {}
    for host_el in root.all("host"):
        for rec in _host(host_el, raw, masscan):
            if rec["type"] != "service" or not masscan:
                out.append(rec)
            elif records.make_id(rec) in services:
                _add_banners(services[records.make_id(rec)], rec)
            else:
                services[records.make_id(rec)] = rec
                out.append(rec)
    return out


def _add_banners(held: dict[str, Any], rec: dict[str, Any]) -> None:
    """Fold a later masscan banner record for the same port into the service already read."""
    if "banner" in rec and "banner" not in held:
        records.set_field(held, "banner", rec["banner"], rec["prov"]["banner"])
    for banner in rec["ext"].get("banners", []):
        if banner not in held["ext"].setdefault("banners", []):
            held["ext"]["banners"].append(banner)


def _citer(raw: Input):
    def at(element: XmlElement, attribute: str) -> dict[str, Any]:
        located = element.attr_span(attribute, raw.data)
        if located is None:
            raise ParserError(f"<{element.tag}> at byte {element.start} has no {attribute!r} to cite")
        return cite(raw.blob, raw.data, *located, TOOL, raw.source)
    return at


def _host(host_el: XmlElement, raw: Input, masscan: bool) -> list[dict[str, Any]]:
    address = next((a for a in host_el.all("address") if a.get("addrtype") in IP_TYPES), None)
    if address is None:
        return []
    at = _citer(raw)
    host = records.new("host")
    ip_ref = at(address, "addr")
    records.set_field(host, "ip", address.attrs["addr"], ip_ref)

    status = host_el.find("status")
    if status is not None and status.get("state"):
        records.set_field(host, "state", status.attrs["state"], at(status, "state"))

    names, refs = [], []
    container = host_el.find("hostnames")
    for hostname in container.all("hostname") if container is not None else []:
        if hostname.get("name"):
            names.append(hostname.attrs["name"])
            refs.append(at(hostname, "name"))
    if names:
        records.set_field(host, "hostnames", names, refs)

    os_el = host_el.find("os")
    matches = os_el.all("osmatch") if os_el is not None else []
    if matches and matches[0].get("name"):
        records.set_field(host, "os", matches[0].attrs["name"], at(matches[0], "name"))
        if matches[0].get("accuracy"):
            host["ext"]["os_accuracy"] = matches[0].attrs["accuracy"]

    mac = next((a for a in host_el.all("address") if a.get("addrtype") == "mac"), None)
    if mac is not None:
        host["ext"]["mac"] = mac.attrs.get("addr")
        if mac.get("vendor"):
            host["ext"]["mac_vendor"] = mac.attrs["vendor"]

    out = [host]
    ports = host_el.find("ports")
    for port_el in ports.all("port") if ports is not None else []:
        out.append(_service(port_el, host, ip_ref, raw, masscan))
    return out


def _service(port_el: XmlElement, host: dict[str, Any], ip_ref: dict[str, Any], raw: Input,
             masscan: bool) -> dict[str, Any]:
    at = _citer(raw)
    portid, protocol = port_el.get("portid"), port_el.get("protocol")
    if portid is None or not portid.isdigit():
        raise ParserError(f"<port> without a numeric portid at byte {port_el.start}")
    if not protocol:
        raise ParserError(f"<port> without a protocol at byte {port_el.start}")
    svc = records.new("service")
    records.set_field(svc, "host_id", f"host:{host['ip']}", ip_ref)
    records.set_field(svc, "port", int(portid), at(port_el, "portid"))
    records.set_field(svc, "protocol", protocol, at(port_el, "protocol"))

    state_el = port_el.find("state")
    if state_el is not None and state_el.get("state"):
        records.set_field(svc, "state", state_el.attrs["state"], at(state_el, "state"))

    service_el = port_el.find("service")
    if service_el is not None and masscan:
        if service_el.get("banner"):
            records.set_field(svc, "banner", service_el.attrs["banner"], at(service_el, "banner"))
            svc["ext"]["banners"] = [f"{service_el.get('name') or 'unknown'}: {service_el.attrs['banner']}"]
    elif service_el is not None:
        for name in ("name", "product", "version"):
            if service_el.get(name):
                records.set_field(svc, name, service_el.attrs[name], at(service_el, name))
        for extra in ("extrainfo", "method", "conf", "ostype", "tunnel"):
            if service_el.get(extra):
                svc["ext"][extra] = service_el.attrs[extra]
    return svc

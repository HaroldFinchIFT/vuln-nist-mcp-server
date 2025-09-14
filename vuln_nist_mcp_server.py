"""vuln-nist-mcp-server MCP server"""
import asyncio
import os
import sys
import logging
from datetime import datetime, timedelta, timezone
from typing import cast
import re

import httpx
import traceback

from mcp.server.fastmcp import FastMCP

__version__ = "1.0.0"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("vuln-nist-mcp-server")

mcp = FastMCP("vuln-nist-mcp-server")

# Configuration
NVD_BASE = os.environ.get("NVD_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves")
NVD_VERSION = os.environ.get("NVD_VERSION", "/2.0")
API_TIMEOUT = int(os.environ.get("NVD_API_TIMEOUT", "10"))

# Utility helpers
def _safe_str(s):
    """Return safe stripped string"""
    try:
        return "" if s is None else str(s).strip()
    except Exception:
        return ""

def _int_or_default(s, default=20):
    """Convert string to int or default"""
    try:
        return int(str(s).strip()) if str(s).strip() != "" else default
    except Exception:
        return default

def _short_desc_from_vuln(v):
    """Return a short description for a vuln object"""
    try:
        cve = v.get("cve", {})
        descs = cve.get("descriptions", []) or []
        for d in descs:
            if d.get("lang") == "en" and d.get("value"):
                txt = d.get("value")
                return txt if len(txt) <= 240 else txt[:237] + "..."
        if descs:
            txt = descs[0].get("value", "")
            return txt if len(txt) <= 240 else txt[:237] + "..."
    except Exception:
        pass
    return "(no description)"

def _format_vuln_entry(v):
    """Format a single vulnerability entry for output"""
    try:
        cve = v.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        published = _safe_str(cve.get("published"))
        desc = _short_desc_from_vuln(v)
        return f"- {cve_id} | published: {published} | {desc}"
    except Exception:
        return "- (malformed entry)"

# === MCP TOOLS ===

@mcp.tool()
async def search_cves(keyword: str = "", resultsPerPage: int = 20,
                      startIndex: int = 0, recent_days: int = 30) -> str:
    """
    Search CVEs by keyword in description, optionally filtering by recent days.
    If recent_days > 120, the period is chunked into multiple queries (max 120 days each)
    and results are aggregated. Queries are executed in parallel.
    """
    keyword = _safe_str(keyword)
    if not keyword:
        return "❌ Error: keyword parameter is required"

    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=recent_days)

    url = f"{NVD_BASE}/cves{NVD_VERSION}"

    async def fetch_chunk(chunk_start, chunk_end):
        pubStartDate = chunk_start.strftime("%Y-%m-%dT%H:%M:%S.000")
        pubEndDate = chunk_end.strftime("%Y-%m-%dT%H:%M:%S.000")

        query = (
            f"?keywordSearch={keyword}"
            f"&resultsPerPage={resultsPerPage}"
            f"&startIndex={startIndex}"
            f"&pubStartDate={pubStartDate}"
            f"&pubEndDate={pubEndDate}"
        )
        full_url = url + query
        logger.info(f"search_cves chunk: full_url={full_url}")

        async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
            resp = await client.get(full_url)
            resp.raise_for_status()
            return resp.json()

    try:
        chunk_size = timedelta(days=120)
        chunks = []
        chunk_start = start_date
        while chunk_start < end_date:
            chunk_end = min(chunk_start + chunk_size, end_date)
            chunks.append((chunk_start, chunk_end))
            chunk_start = chunk_end

        tasks = [fetch_chunk(cs, ce) for cs, ce in chunks]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        total = 0
        results = []

        for resp in responses:
            if isinstance(resp, Exception):
                logger.error(f"Chunk failed: {resp}")
                continue

            data = cast(dict, resp)
            total += data.get("totalResults", 0)
            results.extend(data.get("vulnerabilities", []) or [])

        lines = [f"🔍 Search results for \"{keyword}\" - total matches: {total}"]
        if not results:
            lines.append("⚠️ No vulnerabilities returned for the given params.")
        else:
            for v in results:
                lines.append(_format_vuln_entry(v))

        lines.append(
            f"📄 Aggregated across {len(chunks)} chunk(s) "
            f"(parallelized), period={recent_days} days, resultsPerPage={resultsPerPage}"
        )
        return "\n".join(lines)

    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error in search_cves: {e.response.status_code} - {e.response.text}")
        return f"❌ API Error: {e.response.status_code}"
    except Exception as e:
        logger.error("Exception in search_cves: " + str(e))
        logger.debug(traceback.format_exc())
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_cve_by_id(cve_id: str = "") -> str:
    """Retrieve a CVE by its CVE-ID"""
    cve_id = _safe_str(cve_id)
    if not cve_id:
        return "❌ Error: cve_id parameter is required"
    url = f"{NVD_BASE}/cves{NVD_VERSION}"
    params = {"cveId": cve_id}
    logger.info(f"get_cve_by_id: cveId={cve_id}")
    try:
        async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
        vulns = data.get("vulnerabilities", []) or []
        if not vulns:
            return f"⚠️ No CVE found for {cve_id}"
        v = vulns[0]
        cve = v.get("cve", {})
        desc = _short_desc_from_vuln(v)
        published = _safe_str(cve.get("published"))
        lastmod = _safe_str(cve.get("lastModified"))
        tags = cve.get("cveTags", []) or []
        tag_names = ", ".join([t.get("tag", "") for t in tags]) if tags else "none"
        out = [
            f"✅ CVE: {cve_id}",
            f"- Published: {published}",
            f"- Last Modified: {lastmod}",
            f"- Tags: {tag_names}",
            f"- Description: {desc}",
        ]
        refs = v.get("references", []) or []
        if refs:
            out.append(f"- References ({len(refs)}):")
            for r in refs[:5]:
                rtype = r.get("type", "ref")
                urlr = r.get("url", "")
                out.append(f"  - [{rtype}] {urlr}")
            if len(refs) > 5:
                out.append(f"  - ... and {len(refs)-5} more")
        return "\n".join(out)
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error in get_cve_by_id: {e.response.status_code}")
        return f"❌ API Error: {e.response.status_code}"
    except Exception as e:
        logger.error("Exception in get_cve_by_id: " + str(e))
        logger.debug(traceback.format_exc())
        return f"❌ Error: {str(e)}"

CPE_REGEX = re.compile(
    r"^cpe:(?P<version>2\.3):"
    r"(?P<part>[aho]):"
    r"(?P<vendor>[^:]*):"
    r"(?P<product>[^:]*):"
    r"(?P<version_field>[^:]*):"
    r"(?P<update>[^:]*):"
    r"(?P<edition>[^:]*):"
    r"(?P<language>[^:]*):"
    r"(?P<sw_edition>[^:]*):"
    r"(?P<target_sw>[^:]*):"
    r"(?P<target_hw>[^:]*):"
    r"(?P<other>[^:]*)$"
)

@mcp.tool()
async def cves_by_cpe(cpe_name: str = "", is_vulnerable: str = "") -> str:
    """List CVEs associated with a specific CPE"""
    cpe_name = _safe_str(cpe_name)
    if not cpe_name:
        return "❌ Error: cpe_name parameter is required"

    if not CPE_REGEX.match(cpe_name):
        return ("❌ Error: cpe_name must be provided in full CPE 2.3 format, e.g. "
                "cpe:2.3:a:vendor:product:version:update:edition:language:"
                "sw_edition:target_sw:target_hw:other - eventually use the wildcard *, e.g.: cpe:2.3:a:ntp:ntp:4.2.8:p3:*:*:*:*:*:*")

    url = f"{NVD_BASE}/cves{NVD_VERSION}"
    params = {"cpeName": cpe_name}
    if _safe_str(is_vulnerable).lower() in ("1", "true", "yes"):
        params["isVulnerable"] = ""
    logger.info(f"cves_by_cpe: cpeName={cpe_name} isVulnerable={_safe_str(is_vulnerable)}")
    try:
        async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
        total = data.get("totalResults", 0)
        vulns = data.get("vulnerabilities", []) or []
        lines = [f"🌐 CVEs for CPE \"{cpe_name}\" - total matches: {total}"]
        if not vulns:
            lines.append("⚠️ No vulnerabilities returned for the given CPE.")
        else:
            for v in vulns[:50]:
                lines.append(_format_vuln_entry(v))
            if total > len(vulns):
                lines.append(f"📄 Partial list: returned {len(vulns)} of {total}")
        return "\n".join(lines)
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error in cves_by_cpe: {e.response.status_code}")
        return f"❌ API Error: {e.response.status_code}"
    except Exception as e:
        logger.error("Exception in cves_by_cpe: " + str(e))
        logger.debug(traceback.format_exc())
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def kevs_between(
    kevStartDate: str = "",
    kevEndDate: str = "",
    resultsPerPage: str = "20",
    startIndex: str = "0"
) -> str:
    """
    List CVEs added to CISA KEV catalog in a date window.
    If the requested window exceeds 90 days, the query is automatically
    split into multiple chunks (max 90 days each) and results are aggregated.
    """
    kevStartDate = _safe_str(kevStartDate)
    kevEndDate = _safe_str(kevEndDate)
    if not kevStartDate or not kevEndDate:
        return "❌ Error: kevStartDate and kevEndDate parameters are required and must be ISO-8601"

    rpp = _int_or_default(resultsPerPage, 20)
    sidx = _int_or_default(startIndex, 0)

    try:
        dt_start = datetime.fromisoformat(kevStartDate.replace("Z", "+00:00"))
        dt_end = datetime.fromisoformat(kevEndDate.replace("Z", "+00:00"))

        if dt_end <= dt_start:
            return "❌ Error: kevEndDate must be after kevStartDate"

        chunk_size = timedelta(days=90)
        chunks = []
        chunk_start = dt_start
        while chunk_start < dt_end:
            chunk_end = min(chunk_start + chunk_size, dt_end)
            chunks.append((chunk_start, chunk_end))
            chunk_start = chunk_end

        async def fetch_chunk(cs, ce):
            params = {
                "hasKev": "",
                "kevStartDate": cs.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "kevEndDate": ce.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": str(rpp),
                "startIndex": str(sidx),
            }
            url = f"{NVD_BASE}/cves{NVD_VERSION}"
            logger.info(f"kevs_between chunk: {params['kevStartDate']} -> {params['kevEndDate']}")
            async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                resp = await client.get(url, params=params)
                resp.raise_for_status()
                return resp.json()

        tasks = [fetch_chunk(cs, ce) for cs, ce in chunks]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        total = 0
        vulns = []

        for resp in responses:
            if isinstance(resp, Exception):
                logger.error(f"KEV chunk failed: {resp}")
                continue
            data = cast(dict, resp)
            total += data.get("totalResults", 0)
            vulns.extend(data.get("vulnerabilities", []) or [])

        lines = [
            f"🔥 KEV CVEs added between {kevStartDate} and {kevEndDate} - total matches (aggregated): {total}"
        ]
        if not vulns:
            lines.append("⚠️ No KEV CVEs returned for the given window.")
        else:
            for v in vulns:
                lines.append(_format_vuln_entry(v))
        lines.append(f"📄 Aggregated across {len(chunks)} chunk(s), resultsPerPage={rpp} startIndex={sidx}")

        return "\n".join(lines)

    except ValueError:
        return "❌ Error: kevStartDate and kevEndDate must be valid ISO-8601 timestamps"
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error in kevs_between: {e.response.status_code}")
        return f"❌ API Error: {e.response.status_code}"
    except Exception as e:
        logger.error("Exception in kevs_between: " + str(e))
        logger.debug(traceback.format_exc())
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def cve_change_history(
    cve_id: str = "",
    changeStartDate: str = "",
    changeEndDate: str = "",
    resultsPerPage: str = "20",
    startIndex: str = "0"
) -> str:
    """
    Retrieve change history for a CVE or a time window.
    If no cve_id is provided and the date range exceeds 120 days,
    the query is split into multiple chunks (max 120 days each) and results aggregated.
    """
    cve_id = _safe_str(cve_id)
    rpp = _int_or_default(resultsPerPage, 20)
    sidx = _int_or_default(startIndex, 0)
    url = f"{NVD_BASE}/cvehistory{NVD_VERSION}"

    try:
        chunks = []

        if cve_id:
            params = {"cveId": cve_id, "resultsPerPage": str(rpp), "startIndex": str(sidx)}
            logger.info(f"cve_change_history: cveId={cve_id}")
            async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                resp = await client.get(url, params=params)
                resp.raise_for_status()
                data = resp.json()
            changes = data.get("cveChanges", []) or []
            total = data.get("totalResults", 0)
        else:
            changeStartDate = _safe_str(changeStartDate)
            changeEndDate = _safe_str(changeEndDate)
            if not changeStartDate or not changeEndDate:
                return "❌ Error: either cve_id or both changeStartDate and changeEndDate are required"

            dt_start = datetime.fromisoformat(changeStartDate.replace("Z", "+00:00"))
            dt_end = datetime.fromisoformat(changeEndDate.replace("Z", "+00:00"))

            if dt_end <= dt_start:
                return "❌ Error: changeEndDate must be after changeStartDate"

            chunk_size = timedelta(days=120)
            chunks = []
            chunk_start = dt_start
            while chunk_start < dt_end:
                chunk_end = min(chunk_start + chunk_size, dt_end)
                chunks.append((chunk_start, chunk_end))
                chunk_start = chunk_end

            async def fetch_chunk(cs, ce):
                params = {
                    "changeStartDate": cs.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "changeEndDate": ce.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "resultsPerPage": str(rpp),
                    "startIndex": str(sidx)
                }
                logger.info(f"cve_change_history chunk: {params['changeStartDate']} -> {params['changeEndDate']}")
                async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                    resp = await client.get(url, params=params)
                    resp.raise_for_status()
                    return resp.json()

            tasks = [fetch_chunk(cs, ce) for cs, ce in chunks]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            changes = []
            total = 0
            for resp in responses:
                if isinstance(resp, Exception):
                    logger.error(f"CVE change chunk failed: {resp}")
                    continue
                data = cast(dict, resp)
                total += data.get("totalResults", 0)
                changes.extend(data.get("cveChanges", []) or [])

        lines = [f"🕘 CVE Change History - total events: {total}"]
        if not changes:
            lines.append("⚠️ No change events returned for the given query.")
        else:
            for ch in changes[:50]:
                try:
                    change = ch.get("change", {})
                    cid = change.get("cveId", "UNKNOWN")
                    event = change.get("eventName", "EVENT")
                    created = change.get("created", "")
                    lines.append(f"- {cid} | event: {event} | at: {created}")
                except Exception:
                    lines.append("- (malformed change event)")
            if total > len(changes):
                lines.append(f"📄 Partial list: returned {len(changes)} of {total}")
        if not cve_id and len(chunks) > 1:
            lines.append(f"📄 Aggregated across {len(chunks)} chunk(s), resultsPerPage={rpp} startIndex={sidx}")

        return "\n".join(lines)

    except ValueError:
        return "❌ Error: changeStartDate and changeEndDate must be valid ISO-8601 timestamps"
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error in cve_change_history: {e.response.status_code}")
        return f"❌ API Error: {e.response.status_code}"
    except Exception as e:
        logger.error("Exception in cve_change_history: " + str(e))
        logger.debug(traceback.format_exc())
        return f"❌ Error: {str(e)}"

# === SERVER STARTUP ===

def main():
    """Main entry point"""
    logger.info(f"Starting NIST Vulnerability MCP server v{__version__}...")
    try:
        mcp.run(transport="stdio")
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()

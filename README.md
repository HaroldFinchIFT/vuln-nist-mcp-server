# vuln-nist-mcp-server

A Model Context Protocol (MCP) server for querying NIST National Vulnerability Database (NVD) API endpoints.

## Purpose

This MCP server exposes tools to query the NVD/CVE REST API and return formatted text results suitable for LLM consumption via the MCP protocol. It includes automatic query chunking for large date ranges and parallel processing for improved performance.

Base API docs: https://nvd.nist.gov/developers/vulnerabilities

## Features

### Available Tools

- **`get_temporal_context`** - Get current date and temporal context for time-relative queries
  - Essential for queries like "this year", "last year", "6 months ago"
  - Provides current date mappings and examples for date parameter construction
  - **USAGE**: Call this tool FIRST when user asks time-relative questions

- **`search_cves`** - Search CVE descriptions by keyword with flexible date filtering
  - Parameters: `keyword`, `resultsPerPage` (default: 20), `startIndex` (default: 0), `last_days` (`recent_days` has been deprecated), `start_date`, `end_date`
  - **New in v1.1.0**: Support for absolute date ranges with `start_date` and `end_date` parameters
  - **Date filtering priority**: `start_date`/`end_date` → `last_days` → default 30 days
  - Auto-chunks queries > 120 days into parallel requests
  - Results sorted by publication date (newest first)

- **`get_cve_by_id`** - Retrieve detailed information for a specific CVE
  - Parameters: `cve_id`
  - Returns: CVE details, references, tags, and publication dates

- **`cves_by_cpe`** - List CVEs associated with a Common Platform Enumeration (CPE)
  - Parameters: `cpe_name` (full CPE 2.3 format required), `is_vulnerable` (optional)
  - Validates CPE format before querying

- **`kevs_between`** - Find CVEs added to CISA KEV catalog within a date range
  - Parameters: `kevStartDate`, `kevEndDate`, `resultsPerPage` (default: 20), `startIndex` (default: 0)
  - Auto-chunks queries > 90 days into parallel requests
  - Results sorted by publication date (newest first)

- **`cve_change_history`** - Retrieve change history for CVEs
  - Parameters: `cve_id` OR (`changeStartDate` + `changeEndDate`), `resultsPerPage` (default: 20), `startIndex` (default: 0)
  - Auto-chunks date range queries > 120 days into parallel requests
  - Results sorted by change creation date (newest first)

### Key Features

- **Temporal Awareness**: New `get_temporal_context` tool for accurate time-relative queries
- **Flexible Date Filtering**: Support for both relative (`last_days`) and absolute (`start_date`/`end_date`) date ranges
- **Improved Result Ordering**: All results sorted chronologically (newest first) for better relevance
- **Parallel Processing**: Large date ranges are automatically split into chunks and processed concurrently
- **Input Validation**: CPE format validation, date parsing, parameter sanitization
- **Emoji Indicators**: Clear visual feedback (✅ success, ❌ error, ⚠️ warning, 🔍 search, 🔥 KEV, 🌐 CPE, 🕘 history, 📅 temporal)
- **Comprehensive Logging**: Detailed stderr logging for debugging
- **Error Handling**: Graceful handling of API errors, timeouts, and malformed responses

## Prerequisites

- Docker (recommended) or Python 3.11+
- Network access to NVD endpoints (`services.nvd.nist.gov`)
- MCP-compatible client (e.g., Claude Desktop)

## Quick Start

### Using Docker (Recommended)

```bash
# Clone and build
git clone https://github.com/HaroldFinchIFT/vuln-nist-mcp-server
cd vuln-nist-mcp-server
docker build -t vuln-nist-mcp-server .

# Run
docker run --rm -it vuln-nist-mcp-server
```

## Configuration

Environment variables:

- `NVD_BASE_URL`: Base URL for NVD API (default: `https://services.nvd.nist.gov/rest/json`)
- `NVD_VERSION`: API version (default: `/2.0`)
- `NVD_API_TIMEOUT`: Request timeout in seconds (default: `10`)

## Usage Examples

### With Claude Desktop or MCP Client

**Get temporal context for time-relative queries:**
```
Tool: get_temporal_context
Params: {}
```

**Search recent CVEs (relative time):**
```
Tool: search_cves
Params: {
  "keyword": "Microsoft Exchange",
  "resultsPerPage": 10,
  "last_days": 7
}
```

**Search CVEs with absolute date range:**
```
Tool: search_cves
Params: {
  "keyword": "buffer overflow",
  "start_date": "2024-01-01T00:00:00",
  "end_date": "2024-03-31T23:59:59"
}
```

**Search CVEs for "this year" (use get_temporal_context first):**
```
# First, get temporal context
Tool: get_temporal_context

# Then use the provided date mappings
Tool: search_cves
Params: {
  "keyword": "remote code execution",
  "start_date": "2025-01-01T00:00:00",
  "end_date": "2025-09-17T12:00:00"
}
```

**Get CVE details:**
```
Tool: get_cve_by_id
Params: {"cve_id": "CVE-2024-21413"}
```

**Check CPE vulnerabilities:**
```
Tool: cves_by_cpe
Params: {
  "cpe_name": "cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*",
  "is_vulnerable": "true"
}
```

**Find recent KEV additions:**
```
Tool: kevs_between
Params: {
  "kevStartDate": "2024-01-01T00:00:00.000Z",
  "kevEndDate": "2024-03-31T23:59:59.000Z"
}
```

## Performance Notes

- Queries with date ranges > 90-120 days are automatically chunked for better performance
- Parallel processing reduces total query time for large date ranges
- Results are automatically sorted by publication date (newest first) across all chunks

## Development

### File Structure

```
vuln-nist-mcp-server/
├── Dockerfile
├── LICENSE
├── nvd_logo.png
├── README.md
├── requirements.txt
├── SECURITY.md 
└── vuln_nist_mcp_server.py
```

## Security Considerations

- No API key required (public NVD endpoints)
- Container runs as non-root user (`mcpuser`)
- Input validation prevents injection attacks
- No persistent storage of sensitive data
- Network capabilities added only when required via Docker flags

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test locally
5. Submit a pull request

## License

MIT - see LICENSE file for details

## Changelog

### v1.1.0
- **NEW**: Added `get_temporal_context` tool for temporal awareness and time-relative queries
- **ENHANCED**: `search_cves` now supports absolute date ranges with `start_date` and `end_date` parameters
- **ENHANCED**: Improved date filtering logic with priority: absolute dates → relative days → default 30 days
- **ENHANCED**: All tools now return results sorted chronologically (newest first) for better relevance
- **IMPROVED**: Better error handling for ISO-8601 date parsing
- **DEPRECATED**: `recent_days` parameter in `search_cves` (use `last_days` instead)
- **UPDATED**: Logo and visual improvements

### v1.0.0
- Initial release
- Support for all major NVD API endpoints
- Automatic query chunking and parallel processing
- CPE format validation
- Comprehensive error handling
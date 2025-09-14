# vuln-nist-mcp-server

A Model Context Protocol (MCP) server for querying NIST National Vulnerability Database (NVD) API endpoints.

## Purpose

This MCP server exposes tools to query the NVD/CVE REST API and return formatted text results suitable for LLM consumption via the MCP protocol. It includes automatic query chunking for large date ranges and parallel processing for improved performance.

Base API docs: https://nvd.nist.gov/developers/vulnerabilities

## Features

### Available Tools

- **`search_cves`** - Search CVE descriptions by keyword with optional date filtering
  - Parameters: `keyword`, `resultsPerPage` (default: 20), `startIndex` (default: 0), `recent_days` (default: 30)
  - Auto-chunks queries > 120 days into parallel requests

- **`get_cve_by_id`** - Retrieve detailed information for a specific CVE
  - Parameters: `cve_id`
  - Returns: CVE details, references, tags, and publication dates

- **`cves_by_cpe`** - List CVEs associated with a Common Platform Enumeration (CPE)
  - Parameters: `cpe_name` (full CPE 2.3 format required), `is_vulnerable` (optional)
  - Validates CPE format before querying

- **`kevs_between`** - Find CVEs added to CISA KEV catalog within a date range
  - Parameters: `kevStartDate`, `kevEndDate`, `resultsPerPage` (default: 20), `startIndex` (default: 0)
  - Auto-chunks queries > 90 days into parallel requests

- **`cve_change_history`** - Retrieve change history for CVEs
  - Parameters: `cve_id` OR (`changeStartDate` + `changeEndDate`), `resultsPerPage` (default: 20), `startIndex` (default: 0)
  - Auto-chunks date range queries > 120 days into parallel requests

### Key Features

- **Parallel Processing**: Large date ranges are automatically split into chunks and processed concurrently
- **Input Validation**: CPE format validation, date parsing, parameter sanitization
- **Emoji Indicators**: Clear visual feedback (✅ success, ❌ error, ⚠️ warning, 🔍 search, 🔥 KEV, 🌐 CPE, 🕘 history)
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

**Search recent CVEs:**
```
Tool: search_cves
Params: {
  "keyword": "Microsoft Exchange",
  "resultsPerPage": "10",
  "recent_days": "7"
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

## Development

### File Structure

```
vuln-nist-mcp-server/
├── Dockerfile
├── LICENSE
├── README.md
├── requirements.txt
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

### v1.0.0
- Initial release
- Support for all major NVD API endpoints
- Automatic query chunking and parallel processing
- CPE format validation
- Comprehensive error handling
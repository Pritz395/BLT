# Issue: Enhance CVE Integration with Caching, Search, Filtering, and Autocomplete

## Problem Statement

The current BLT codebase has basic CVE (Common Vulnerabilities and Exposures) functionality, but it lacks several critical features that limit its usability and performance:

### 1. **No Caching Layer - Performance Issue**

- **Current State**: Every CVE score lookup makes a direct API call to NVD (National Vulnerability Database)
- **Problem**:
  - NVD API has rate limits (429 errors) that cause failures under load
  - Repeated lookups for the same CVE waste API quota
  - Slow response times for users when fetching CVE scores
  - No protection against concurrent duplicate API calls (race conditions)
- **Impact**: Users experience timeouts and errors when creating issues with CVE IDs, especially during high-traffic periods

### 2. **No Search Functionality**

- **Current State**: Users cannot search for issues by CVE ID
- **Problem**: Security researchers and developers need to find all issues related to a specific CVE (e.g., "CVE-2024-1234") but have no way to search for them
- **Impact**: Users must manually browse through all issues to find CVE-related vulnerabilities, making it impossible to track all instances of a specific vulnerability

### 3. **No Filtering Capabilities**

- **Current State**: API endpoints do not support filtering by CVE ID or CVSS score
- **Problem**:
  - Cannot filter issues by CVE ID via API (`/api/v1/issues/?cve_id=CVE-2024-1234`)
  - Cannot filter by CVSS score range (e.g., high-severity CVEs with score >= 7.0)
  - Cannot combine CVE filters with other filters (status, domain, etc.)
- **Impact**: API consumers cannot programmatically query CVE-related issues, limiting integration possibilities

### 4. **No Autocomplete for CVE IDs**

- **Current State**: Users must manually type CVE IDs when reporting issues
- **Problem**:
  - Typo-prone manual entry leads to invalid CVE IDs
  - Users don't know which CVE IDs already exist in the system
  - No suggestions for similar/related CVE IDs
- **Impact**: Data quality issues, user frustration, and potential duplicate entries with typos

### 5. **Database Schema Limitations**

- **Current State**: `cve_score` field has `max_digits=2`, limiting scores to 0.0-9.9
- **Problem**: CVSS v3.1 scores can be 10.0 (critical severity), but the database cannot store this value
- **Impact**: Critical vulnerabilities with CVSS 10.0 scores cannot be properly stored or filtered

### 6. **Missing Database Indexes**

- **Current State**: No indexes on `cve_id` or `cve_score` fields
- **Problem**: Queries filtering by CVE ID or score are slow on large datasets
- **Impact**: Poor performance when searching or filtering CVE-related issues

### 7. **CVE Score Not Persisted**

- **Current State**: `cve_score` is computed on-the-fly but never saved to the database
- **Problem**:
  - Filtering by `cve_score` doesn't work because the field is always NULL
  - Every page load recalculates scores, wasting resources
- **Impact**: CVE score filtering is completely broken, and performance is degraded

### 8. **Case Sensitivity Issues**

- **Current State**: CVE IDs are stored without normalization (mixed case)
- **Problem**:
  - "CVE-2024-1234" and "cve-2024-1234" are treated as different values
  - Search and filtering fail when case doesn't match exactly
- **Impact**: Users cannot find issues if they use different casing than what's stored

## Proposed Solution

Implement a comprehensive CVE enhancement that addresses all the above issues:

1. **CVE Caching Layer**: Add a robust caching system with:

   - 24-hour cache timeout (CVE data rarely changes)
   - Cache-backed locking to prevent duplicate API calls
   - Exponential backoff for rate limit handling (429 errors)
   - Sentinel values to cache "not found" results
   - Prefer CVSS v3.1, then v3.0, then v2.0

2. **CVE Search**: Add `cve:` prefix search (e.g., `cve:CVE-2024-1234`) to the web search interface

3. **CVE Filtering**: Add API query parameters:

   - `cve_id`: Filter by exact CVE ID (case-insensitive)
   - `cve_score_min`: Filter by minimum CVSS score
   - `cve_score_max`: Filter by maximum CVSS score
   - Support combining with existing filters (status, domain, etc.)

4. **CVE Autocomplete**: Add autocomplete functionality:

   - API endpoint `/api/v1/cve/autocomplete/?q=CVE-2024`
   - Client-side autocomplete in the issue reporting form
   - Shows existing CVE IDs from the database
   - Keyboard navigation support (arrow keys, enter, escape)
   - XSS-safe implementation

5. **Database Fixes**:

   - Change `cve_score.max_digits` from 2 to 3 (allow 10.0)
   - Add database indexes on `cve_id` and `cve_score`
   - Populate `cve_score` when issues are created/updated
   - Normalize CVE IDs to uppercase on save

6. **Normalization**: Normalize all CVE IDs to uppercase, trim whitespace, and use case-insensitive matching in queries

## Acceptance Criteria

- [x] CVE scores are cached for 24 hours to reduce API calls
- [x] Cache handles rate limits (429) with exponential backoff
- [x] Cache prevents duplicate API calls with locking mechanism
- [x] Web search supports `cve:` prefix (e.g., `cve:CVE-2024-1234`)
- [x] API supports `cve_id`, `cve_score_min`, and `cve_score_max` query parameters
- [x] CVE filters can be combined with other filters (status, domain)
- [x] Autocomplete endpoint returns existing CVE IDs matching query
- [x] Issue reporting form has autocomplete with keyboard navigation
- [x] Database schema supports CVSS 10.0 scores
- [x] Database indexes exist for `cve_id` and `cve_score`
- [x] `cve_score` is populated when issues are created (all creation paths)
- [x] CVE IDs are normalized to uppercase on save
- [x] All queries use case-insensitive matching
- [x] CVE IDs are read from POST data in hunt submissions
- [x] Autocomplete respects visibility rules (hunt=None, is_hidden)
- [x] Error handling for normalization failures
- [x] Input validation (minimum 8 characters for autocomplete)
- [x] Comprehensive test coverage for all features

## Related Issues/PRs

- Related to: CVE-based tip suggestions (if any existing PRs)
- Part of: CVE integration enhancement initiative

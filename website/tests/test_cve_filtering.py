"""
Tests for CVE filtering and search functionality.
"""

from decimal import Decimal

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from website.models import Domain, Issue

User = get_user_model()


@pytest.fixture
def api_client():
    """API client for testing."""
    return APIClient()


@pytest.fixture
def web_client():
    """Web client for testing."""
    return Client()


@pytest.fixture
def test_user(db):
    """Create a test user."""
    return User.objects.create_user(username="testuser", email="test@example.com", password="testpass123")


@pytest.fixture
def test_domain(db):
    """Create a test domain."""
    return Domain.objects.create(url="https://example.com", name="example.com")


@pytest.fixture
def issues_with_cve(db, test_domain, test_user):
    """Create test issues with CVE data."""
    issues = []
    # Issue with CVE ID and score
    issues.append(
        Issue.objects.create(
            url="https://example.com/vuln1",
            description="Critical vulnerability",
            cve_id="CVE-2024-1234",
            cve_score=Decimal("9.8"),
            domain=test_domain,
            user=test_user,
            is_hidden=False,
        )
    )
    # Issue with different CVE ID and high score
    issues.append(
        Issue.objects.create(
            url="https://example.com/vuln2",
            description="High severity issue",
            cve_id="CVE-2024-5678",
            cve_score=Decimal("8.5"),
            domain=test_domain,
            user=test_user,
            is_hidden=False,
        )
    )
    # Issue with low CVE score
    issues.append(
        Issue.objects.create(
            url="https://example.com/vuln3",
            description="Low severity issue",
            cve_id="CVE-2024-9999",
            cve_score=Decimal("3.2"),
            domain=test_domain,
            user=test_user,
            is_hidden=False,
        )
    )
    # Issue without CVE
    issues.append(
        Issue.objects.create(
            url="https://example.com/normal",
            description="Normal issue",
            cve_id=None,
            cve_score=None,
            domain=test_domain,
            user=test_user,
            is_hidden=False,
        )
    )
    return issues


class TestIssueViewSetCveFiltering:
    """Test CVE filtering in IssueViewSet API."""

    def test_filter_by_cve_id_exact_match(self, api_client, issues_with_cve):
        """Test filtering issues by exact CVE ID match."""
        url = "/api/v1/issues/"
        response = api_client.get(url, {"cve_id": "CVE-2024-1234"})
        assert response.status_code == status.HTTP_200_OK
        assert response.data["count"] == 1
        assert response.data["results"][0]["cve_id"] == "CVE-2024-1234"
        assert response.data["results"][0]["cve_score"] == "9.8"

    def test_filter_by_cve_id_case_insensitive(self, api_client, issues_with_cve):
        """Test that CVE ID filtering is case-insensitive (normalized)."""
        url = "/api/v1/issues/"
        # Test lowercase
        response = api_client.get(url, {"cve_id": "cve-2024-1234"})
        assert response.status_code == status.HTTP_200_OK
        assert response.data["count"] == 1
        # Test with spaces
        response = api_client.get(url, {"cve_id": "  CVE-2024-1234  "})
        assert response.status_code == status.HTTP_200_OK
        assert response.data["count"] == 1

    def test_filter_by_cve_id_no_match(self, api_client, issues_with_cve):
        """Test filtering by non-existent CVE ID returns empty results."""
        url = "/api/v1/issues/"
        response = api_client.get(url, {"cve_id": "CVE-2024-0000"})
        assert response.status_code == status.HTTP_200_OK
        assert response.data["count"] == 0

    def test_filter_by_cve_id_empty_string(self, api_client, issues_with_cve):
        """Test that empty CVE ID filter is ignored."""
        url = "/api/v1/issues/"
        response = api_client.get(url, {"cve_id": ""})
        assert response.status_code == status.HTTP_200_OK
        # Should return all issues (no CVE filter applied)
        assert response.data["count"] >= 4

    def test_filter_by_cve_score_min(self, api_client, issues_with_cve):
        """Test filtering issues by minimum CVE score."""
        url = "/api/v1/issues/"
        response = api_client.get(url, {"cve_score_min": "7.0"})
        assert response.status_code == status.HTTP_200_OK
        assert response.data["count"] == 2
        scores = [float(issue["cve_score"]) for issue in response.data["results"] if issue["cve_score"]]
        assert all(score >= 7.0 for score in scores)

    def test_filter_by_cve_score_max(self, api_client, issues_with_cve):
        """Test filtering issues by maximum CVE score."""
        url = "/api/v1/issues/"
        response = api_client.get(url, {"cve_score_max": "5.0"})
        assert response.status_code == status.HTTP_200_OK
        # Should include issue with score 3.2 and issues without CVE
        scores = [float(issue["cve_score"]) for issue in response.data["results"] if issue["cve_score"] is not None]
        assert all(score <= 5.0 for score in scores)

    def test_filter_by_cve_score_range(self, api_client, issues_with_cve):
        """Test filtering issues by CVE score range."""
        url = "/api/v1/issues/"
        response = api_client.get(url, {"cve_score_min": "5.0", "cve_score_max": "9.0"})
        assert response.status_code == status.HTTP_200_OK
        scores = [float(issue["cve_score"]) for issue in response.data["results"] if issue["cve_score"]]
        assert all(5.0 <= score <= 9.0 for score in scores)
        assert len(scores) == 1  # Only CVE-2024-5678 with score 8.5

    def test_filter_by_cve_score_invalid_min(self, api_client, issues_with_cve):
        """Test that invalid minimum score is ignored."""
        url = "/api/v1/issues/"
        response = api_client.get(url, {"cve_score_min": "invalid"})
        assert response.status_code == status.HTTP_200_OK
        # Should return all issues (invalid filter ignored)
        assert response.data["count"] >= 4

    def test_filter_by_cve_score_invalid_max(self, api_client, issues_with_cve):
        """Test that invalid maximum score is ignored."""
        url = "/api/v1/issues/"
        response = api_client.get(url, {"cve_score_max": "not_a_number"})
        assert response.status_code == status.HTTP_200_OK
        # Should return all issues (invalid filter ignored)
        assert response.data["count"] >= 4

    def test_filter_combines_with_status(self, api_client, issues_with_cve):
        """Test that CVE filtering combines with other filters."""
        url = "/api/v1/issues/"
        response = api_client.get(url, {"cve_id": "CVE-2024-1234", "status": "open"})
        assert response.status_code == status.HTTP_200_OK
        # Verify that filters combine correctly
        assert response.data["count"] > 0
        for item in response.data["results"]:
            assert item["cve_id"] == "CVE-2024-1234"
            assert item["status"] == "open"

    def test_filter_combines_with_domain(self, api_client, issues_with_cve, test_domain):
        """Test that CVE filtering combines with domain filter."""
        url = "/api/v1/issues/"
        response = api_client.get(url, {"cve_id": "CVE-2024-1234", "domain": test_domain.url})
        assert response.status_code == status.HTTP_200_OK
        assert response.data["count"] == 1


class TestWebSearchCve:
    """Test CVE search in web search_issues view."""

    def test_search_by_cve_prefix(self, web_client, issues_with_cve):
        """Test searching issues using cve: prefix."""
        url = reverse("search_issues")
        response = web_client.get(url, {"query": "cve:CVE-2024-1234"})
        assert response.status_code == 200
        data = response.json()
        assert len(data["issues"]) == 1
        assert data["issues"][0]["fields"]["cve_id"] == "CVE-2024-1234"

    def test_search_by_cve_case_insensitive(self, web_client, issues_with_cve):
        """Test that CVE search is case-insensitive (normalized)."""
        url = reverse("search_issues")
        # Test lowercase
        response = web_client.get(url, {"query": "cve:cve-2024-1234"})
        assert response.status_code == 200
        data = response.json()
        assert len(data["issues"]) == 1
        # Test with spaces
        response = web_client.get(url, {"query": "cve:  CVE-2024-1234  "})
        assert response.status_code == 200
        data = response.json()
        assert len(data["issues"]) == 1

    def test_search_by_cve_no_match(self, web_client, issues_with_cve):
        """Test searching for non-existent CVE returns empty results."""
        url = reverse("search_issues")
        response = web_client.get(url, {"query": "cve:CVE-2024-0000"})
        assert response.status_code == 200
        data = response.json()
        assert len(data["issues"]) == 0

    def test_search_by_cve_empty_query(self, web_client, issues_with_cve):
        """Test that empty CVE query returns no results."""
        url = reverse("search_issues")
        response = web_client.get(url, {"query": "cve:"})
        assert response.status_code == 200
        data = response.json()
        assert len(data["issues"]) == 0

    def test_search_by_cve_whitespace_only(self, web_client, issues_with_cve):
        """Test that whitespace-only CVE query returns no results."""
        url = reverse("search_issues")
        response = web_client.get(url, {"query": "cve:   "})
        assert response.status_code == 200
        data = response.json()
        assert len(data["issues"]) == 0

    def test_search_by_cve_respects_hidden_issues(self, web_client, issues_with_cve, test_user):
        """Test that CVE search respects hidden issue visibility rules."""
        # Create a hidden issue with CVE
        hidden_issue = Issue.objects.create(
            url="https://example.com/hidden",
            description="Hidden vulnerability",
            cve_id="CVE-2024-9999",
            cve_score=Decimal("7.0"),
            domain=issues_with_cve[0].domain,
            user=test_user,
            is_hidden=True,
        )
        url = reverse("search_issues")
        response = web_client.get(url, {"query": "cve:CVE-2024-9999"})
        assert response.status_code == 200
        data = response.json()
        issue_ids = [str(issue["pk"]) for issue in data["issues"]]
        # Hidden issue should not appear in results
        assert str(hidden_issue.id) not in issue_ids
        # But the visible issue with this CVE from the fixture should still be present
        visible_ids = {str(issue.id) for issue in issues_with_cve if issue.cve_id == "CVE-2024-9999"}
        assert visible_ids & set(issue_ids), "Visible issues with this CVE should still be returned"

    def test_search_by_cve_orders_by_created_desc(self, web_client, issues_with_cve, test_domain, test_user):
        """Test that CVE search results are ordered by creation date descending."""
        # Create another issue with same CVE ID but newer
        newer_issue = Issue.objects.create(
            url="https://example.com/newer",
            description="Newer issue",
            cve_id="CVE-2024-1234",
            cve_score=Decimal("9.8"),
            domain=test_domain,
            user=test_user,
            is_hidden=False,
        )
        url = reverse("search_issues")
        response = web_client.get(url, {"query": "cve:CVE-2024-1234"})
        assert response.status_code == 200
        data = response.json()
        assert len(data["issues"]) == 2
        # Newer issue should appear first (ordered by -created)
        # JSON serialization returns pk as integer
        assert int(data["issues"][0]["pk"]) == newer_issue.id

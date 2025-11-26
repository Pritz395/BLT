"""
Tests for CVE filtering and search functionality.
"""

from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from website.models import Domain, Issue

User = get_user_model()


class TestIssueViewSetCveFiltering(TestCase):
    """Test CVE filtering in IssueViewSet API."""

    def setUp(self):
        """Set up test data."""
        self.api_client = APIClient()
        self.test_user = User.objects.create_user(username="testuser", email="test@example.com", password="testpass123")
        self.test_domain = Domain.objects.create(url="https://example.com", name="example.com")
        # Issue with CVE ID and score
        self.issue1 = Issue.objects.create(
            url="https://example.com/vuln1",
            description="Critical vulnerability",
            cve_id="CVE-2024-1234",
            cve_score=Decimal("9.8"),
            domain=self.test_domain,
            user=self.test_user,
            is_hidden=False,
        )
        # Issue with different CVE ID and high score
        self.issue2 = Issue.objects.create(
            url="https://example.com/vuln2",
            description="High severity issue",
            cve_id="CVE-2024-5678",
            cve_score=Decimal("8.5"),
            domain=self.test_domain,
            user=self.test_user,
            is_hidden=False,
        )
        # Issue with low CVE score
        self.issue3 = Issue.objects.create(
            url="https://example.com/vuln3",
            description="Low severity issue",
            cve_id="CVE-2024-9999",
            cve_score=Decimal("3.2"),
            domain=self.test_domain,
            user=self.test_user,
            is_hidden=False,
        )
        # Issue without CVE
        self.issue4 = Issue.objects.create(
            url="https://example.com/normal",
            description="Normal issue",
            cve_id=None,
            cve_score=None,
            domain=self.test_domain,
            user=self.test_user,
            is_hidden=False,
        )

    def test_filter_by_cve_id_exact_match(self):
        """Test filtering issues by exact CVE ID match."""
        url = "/api/v1/issues/"
        response = self.api_client.get(url, {"cve_id": "CVE-2024-1234"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["cve_id"], "CVE-2024-1234")
        self.assertEqual(response.data["results"][0]["cve_score"], "9.8")

    def test_filter_by_cve_id_case_insensitive(self):
        """Test that CVE ID filtering is case-insensitive (normalized)."""
        url = "/api/v1/issues/"
        # Test lowercase
        response = self.api_client.get(url, {"cve_id": "cve-2024-1234"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)
        # Test with spaces
        response = self.api_client.get(url, {"cve_id": "  CVE-2024-1234  "})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)

    def test_filter_by_cve_id_no_match(self):
        """Test filtering by non-existent CVE ID returns empty results."""
        url = "/api/v1/issues/"
        response = self.api_client.get(url, {"cve_id": "CVE-2024-0000"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 0)

    def test_filter_by_cve_id_empty_string(self):
        """Test that empty CVE ID filter is ignored."""
        url = "/api/v1/issues/"
        response = self.api_client.get(url, {"cve_id": ""})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should return all issues (no CVE filter applied)
        self.assertGreaterEqual(response.data["count"], 4)

    def test_filter_by_cve_score_min(self):
        """Test filtering issues by minimum CVE score."""
        url = "/api/v1/issues/"
        response = self.api_client.get(url, {"cve_score_min": "7.0"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 2)
        scores = [float(issue["cve_score"]) for issue in response.data["results"] if issue["cve_score"]]
        self.assertTrue(all(score >= 7.0 for score in scores))

    def test_filter_by_cve_score_max(self):
        """Test filtering issues by maximum CVE score."""
        url = "/api/v1/issues/"
        response = self.api_client.get(url, {"cve_score_max": "5.0"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should include issue with score 3.2 and issues without CVE
        scores = [float(issue["cve_score"]) for issue in response.data["results"] if issue["cve_score"] is not None]
        self.assertTrue(all(score <= 5.0 for score in scores))

    def test_filter_by_cve_score_range(self):
        """Test filtering issues by CVE score range."""
        url = "/api/v1/issues/"
        response = self.api_client.get(url, {"cve_score_min": "5.0", "cve_score_max": "9.0"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        scores = [float(issue["cve_score"]) for issue in response.data["results"] if issue["cve_score"]]
        self.assertTrue(all(5.0 <= score <= 9.0 for score in scores))
        self.assertEqual(len(scores), 1)  # Only CVE-2024-5678 with score 8.5

    def test_filter_by_cve_score_invalid_min(self):
        """Test that invalid minimum score is ignored."""
        url = "/api/v1/issues/"
        response = self.api_client.get(url, {"cve_score_min": "invalid"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should return all issues (invalid filter ignored)
        self.assertGreaterEqual(response.data["count"], 4)

    def test_filter_by_cve_score_invalid_max(self):
        """Test that invalid maximum score is ignored."""
        url = "/api/v1/issues/"
        response = self.api_client.get(url, {"cve_score_max": "not_a_number"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should return all issues (invalid filter ignored)
        self.assertGreaterEqual(response.data["count"], 4)

    def test_filter_by_cve_score_invalid_range(self):
        """Test that invalid range (min > max) ignores both filters."""
        url = "/api/v1/issues/"
        # min=9.0, max=5.0 is invalid - both filters should be ignored
        response = self.api_client.get(url, {"cve_score_min": "9.0", "cve_score_max": "5.0"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should return all issues (both filters ignored due to invalid range)
        self.assertGreaterEqual(response.data["count"], 4)
        # Verify that issues with scores outside the invalid range are still returned
        scores = [float(issue["cve_score"]) for issue in response.data["results"] if issue["cve_score"]]
        # Should include issues with scores > 5.0 (like 9.8) since filters were ignored
        self.assertTrue(any(score > 5.0 for score in scores) or len(scores) == 0)

    def test_filter_combines_with_status(self):
        """Test that CVE filtering combines with other filters."""
        url = "/api/v1/issues/"
        response = self.api_client.get(url, {"cve_id": "CVE-2024-1234", "status": "open"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Verify that filters combine correctly
        self.assertGreater(response.data["count"], 0)
        for item in response.data["results"]:
            self.assertEqual(item["cve_id"], "CVE-2024-1234")
            self.assertEqual(item["status"], "open")

    def test_filter_combines_with_domain(self):
        """Test that CVE filtering combines with domain filter."""
        url = "/api/v1/issues/"
        response = self.api_client.get(url, {"cve_id": "CVE-2024-1234", "domain": self.test_domain.url})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)


class TestWebSearchCve(TestCase):
    """Test CVE search in web search_issues view."""

    def setUp(self):
        """Set up test data."""
        self.web_client = Client()
        self.test_user = User.objects.create_user(username="testuser", email="test@example.com", password="testpass123")
        self.test_domain = Domain.objects.create(url="https://example.com", name="example.com")
        # Issue with CVE ID and score
        self.issue1 = Issue.objects.create(
            url="https://example.com/vuln1",
            description="Critical vulnerability",
            cve_id="CVE-2024-1234",
            cve_score=Decimal("9.8"),
            domain=self.test_domain,
            user=self.test_user,
            is_hidden=False,
        )
        # Issue with different CVE ID and high score
        self.issue2 = Issue.objects.create(
            url="https://example.com/vuln2",
            description="High severity issue",
            cve_id="CVE-2024-5678",
            cve_score=Decimal("8.5"),
            domain=self.test_domain,
            user=self.test_user,
            is_hidden=False,
        )
        # Issue with low CVE score
        self.issue3 = Issue.objects.create(
            url="https://example.com/vuln3",
            description="Low severity issue",
            cve_id="CVE-2024-9999",
            cve_score=Decimal("3.2"),
            domain=self.test_domain,
            user=self.test_user,
            is_hidden=False,
        )
        # Issue without CVE
        self.issue4 = Issue.objects.create(
            url="https://example.com/normal",
            description="Normal issue",
            cve_id=None,
            cve_score=None,
            domain=self.test_domain,
            user=self.test_user,
            is_hidden=False,
        )

    def test_search_by_cve_prefix(self):
        """Test searching issues using cve: prefix."""
        url = reverse("search_issues")
        response = self.web_client.get(url, {"query": "cve:CVE-2024-1234"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["issues"]), 1)
        self.assertEqual(data["issues"][0]["fields"]["cve_id"], "CVE-2024-1234")

    def test_search_by_cve_case_insensitive(self):
        """Test that CVE search is case-insensitive (normalized)."""
        url = reverse("search_issues")
        # Test lowercase
        response = self.web_client.get(url, {"query": "cve:cve-2024-1234"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["issues"]), 1)
        # Test with spaces
        response = self.web_client.get(url, {"query": "cve:  CVE-2024-1234  "})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["issues"]), 1)

    def test_search_by_cve_no_match(self):
        """Test searching for non-existent CVE returns empty results."""
        url = reverse("search_issues")
        response = self.web_client.get(url, {"query": "cve:CVE-2024-0000"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["issues"]), 0)

    def test_search_by_cve_empty_query(self):
        """Test that empty CVE query returns no results."""
        url = reverse("search_issues")
        response = self.web_client.get(url, {"query": "cve:"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["issues"]), 0)

    def test_search_by_cve_whitespace_only(self):
        """Test that whitespace-only CVE query returns no results."""
        url = reverse("search_issues")
        response = self.web_client.get(url, {"query": "cve:   "})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["issues"]), 0)

    def test_search_by_cve_respects_hidden_issues(self):
        """Test that CVE search respects hidden issue visibility rules."""
        # Create a hidden issue with CVE
        hidden_issue = Issue.objects.create(
            url="https://example.com/hidden",
            description="Hidden vulnerability",
            cve_id="CVE-2024-9999",
            cve_score=Decimal("7.0"),
            domain=self.issue1.domain,
            user=self.test_user,
            is_hidden=True,
        )
        url = reverse("search_issues")
        response = self.web_client.get(url, {"query": "cve:CVE-2024-9999"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        issue_ids = [str(issue["pk"]) for issue in data["issues"]]
        # Hidden issue should not appear in results
        self.assertNotIn(str(hidden_issue.id), issue_ids)
        # But the visible issue with this CVE from setUp should still be present
        visible_ids = {str(issue.id) for issue in [self.issue3] if issue.cve_id == "CVE-2024-9999"}
        self.assertTrue(visible_ids & set(issue_ids), "Visible issues with this CVE should still be returned")

    def test_search_by_cve_orders_by_created_desc(self):
        """Test that CVE search results are ordered by creation date descending."""
        # Create another issue with same CVE ID but newer
        newer_issue = Issue.objects.create(
            url="https://example.com/newer",
            description="Newer issue",
            cve_id="CVE-2024-1234",
            cve_score=Decimal("9.8"),
            domain=self.test_domain,
            user=self.test_user,
            is_hidden=False,
        )
        url = reverse("search_issues")
        response = self.web_client.get(url, {"query": "cve:CVE-2024-1234"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["issues"]), 2)
        # Newer issue should appear first (ordered by -created)
        # JSON serialization returns pk as integer
        self.assertEqual(int(data["issues"][0]["pk"]), newer_issue.id)

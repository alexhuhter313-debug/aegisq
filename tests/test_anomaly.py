"""Tests for anomaly detection module."""

import pytest
from aegisq.detection.anomaly import AnomalyDetector, AnomalyResult


class TestAnomalyDetector:
    """Test suite for AnomalyDetector."""

    def test_init(self):
        """Test detector initialization."""
        detector = AnomalyDetector(threshold=0.7)
        assert detector.threshold == 0.7
        assert detector.model is not None

    def test_detect_normal_event(self):
        """Test detection of normal event."""
        detector = AnomalyDetector(threshold=0.7)
        event = {
            "privilege_escalation": False,
            "network_anomaly": False,
            "failed_logins": 1,
            "hour": 14,
        }

        result = detector.detect(event)

        assert isinstance(result, AnomalyResult)
        assert result.is_anomaly is False
        assert result.score < 0.7
        assert result.features == event
        assert result.timestamp > 0

    def test_detect_suspicious_event(self):
        """Test detection of suspicious event."""
        detector = AnomalyDetector(threshold=0.7)
        event = {
            "privilege_escalation": True,
            "network_anomaly": True,
            "failed_logins": 10,
            "hour": 3,
        }

        result = detector.detect(event)

        assert isinstance(result, AnomalyResult)
        assert result.is_anomaly is True
        assert result.score >= 0.7
        assert result.score > 0.5

    def test_detect_privilege_escalation(self):
        """Test privilege escalation detection."""
        detector = AnomalyDetector(threshold=0.5)
        event = {"privilege_escalation": True}

        result = detector.detect(event)

        assert result.score >= 0.4
        assert result.is_anomaly is True

    def test_detect_failed_logins(self):
        """Test failed login detection."""
        detector = AnomalyDetector(threshold=0.5)
        event = {"failed_logins": 10}

        result = detector.detect(event)

        assert result.score > 0.0
        assert result.score <= 0.3

    def test_detect_off_hours(self):
        """Test off-hours detection."""
        detector = AnomalyDetector(threshold=0.5)
        event = {"hour": 3}

        result = detector.detect(event)

        assert result.score >= 0.1

    def test_batch_detect(self):
        """Test batch detection."""
        detector = AnomalyDetector(threshold=0.7)
        events = [
            {"privilege_escalation": False, "failed_logins": 1, "hour": 14},
            {"privilege_escalation": True, "failed_logins": 10, "hour": 3},
        ]

        results = detector.batch_detect(events)

        assert len(results) == 2
        assert all(isinstance(r, AnomalyResult) for r in results)
        assert results[0].is_anomaly is False
        assert results[1].is_anomaly is True

    def test_calculate_anomaly_score(self):
        """Test anomaly score calculation."""
        detector = AnomalyDetector()

        # Test empty features
        score = detector._calculate_anomaly_score({})
        assert score == 0.0

        # Test max score
        features = {
            "privilege_escalation": True,
            "network_anomaly": True,
            "failed_logins": 100,
            "hour": 3,
        }
        score = detector._calculate_anomaly_score(features)
        assert score <= 1.0
        assert score >= 0.8

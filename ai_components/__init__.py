"""
AI Components for AI-Augmented DevOps Framework

This package contains the core AI/ML components that implement the intelligent
automation features described in our research paper.

Components:
- cvss_context_model: Neural network for contextual vulnerability prioritization
- anomaly_detection: Multi-modal ensemble for explainable anomaly detection  
- explainable_ai: XAI components for human-readable explanations
- knowledge_extraction: Learning system for continuous improvement
"""

__version__ = "1.0.0"
__author__ = "Akshay Mittal, Krishna Kandi"

from .cvss_context_model import CVSSContextAnalyzer
from .anomaly_detection import ExplainableAnomalyDetector
from .explainable_ai import ExplanationEngine

__all__ = [
    "CVSSContextAnalyzer",
    "ExplainableAnomalyDetector", 
    "ExplanationEngine"
]

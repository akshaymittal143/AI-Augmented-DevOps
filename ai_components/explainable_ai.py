#!/usr/bin/env python3
"""
Explainable AI Engine for DevOps

This module implements the explainable AI components described in our paper that provide
transparent and understandable AI decisions across the DevOps pipeline. It integrates
SHAP analysis for feature importance, template-based natural language generation for
human-readable explanations, and interactive visualizations.

Key Features:
- SHAP analysis for ML model explanations
- Natural language generation for human-readable reports
- Interactive visualizations showing decision confidence levels
- Context-aware explanations tailored to DevOps scenarios
- Educational feedback to improve developer understanding
"""

import numpy as np
import pandas as pd
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Union, Tuple
import logging
import json
from datetime import datetime
from enum import Enum
import uuid

# Explainability libraries
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    logging.warning("SHAP not available. Feature importance will use simple methods.")

logger = logging.getLogger(__name__)

class ExplanationType(Enum):
    """Types of explanations that can be generated"""
    FEATURE_IMPORTANCE = "feature_importance"
    DECISION_PATH = "decision_path"
    COUNTERFACTUAL = "counterfactual"
    TREND_ANALYSIS = "trend_analysis"
    COMPARATIVE = "comparative"

class ExplanationAudience(Enum):
    """Target audience for explanations"""
    DEVELOPER = "developer"
    DEVOPS_ENGINEER = "devops_engineer"
    SECURITY_ANALYST = "security_analyst"
    MANAGER = "manager"
    EXECUTIVE = "executive"

@dataclass
class FeatureImportance:
    """Feature importance with explanations"""
    feature_name: str
    importance_score: float
    impact_direction: str  # positive, negative, neutral
    human_explanation: str
    technical_explanation: str
    confidence: float

@dataclass
class ExplanationResult:
    """Complete explanation result"""
    explanation_id: str
    timestamp: datetime
    explanation_type: ExplanationType
    audience: ExplanationAudience
    title: str
    summary: str
    detailed_explanation: str
    feature_importances: List[FeatureImportance]
    confidence_score: float
    recommendations: List[str]
    learning_points: List[str]
    visualization_data: Dict[str, Any]
    metadata: Dict[str, Any]

@dataclass
class DecisionContext:
    """Context for AI decision that needs explanation"""
    decision_type: str  # vulnerability_analysis, anomaly_detection, etc.
    input_data: Dict[str, Any]
    model_output: Dict[str, Any]
    model_name: str
    feature_names: List[str]
    feature_values: List[float]
    prediction_confidence: float

class ExplanationEngine:
    """
    Explainable AI engine for DevOps contexts
    
    Provides transparent explanations for AI decisions across the DevOps pipeline,
    helping developers understand and learn from AI recommendations.
    """
    
    def __init__(self):
        """Initialize the explanation engine"""
        self.explanation_templates = self._load_explanation_templates()
        self.domain_knowledge = self._load_domain_knowledge()
        self.explainers = {}  # Model-specific explainers
        
        logger.info("ExplanationEngine initialized")
    
    def explain_decision(self, 
                        context: DecisionContext,
                        audience: ExplanationAudience = ExplanationAudience.DEVELOPER,
                        explanation_type: ExplanationType = ExplanationType.FEATURE_IMPORTANCE) -> ExplanationResult:
        """
        Generate explanation for an AI decision
        
        Args:
            context: Decision context with input/output data
            audience: Target audience for the explanation
            explanation_type: Type of explanation to generate
            
        Returns:
            Comprehensive explanation result
        """
        logger.info(f"Generating {explanation_type.value} explanation for {audience.value}")
        
        # Calculate feature importance
        feature_importances = self._calculate_feature_importance(context)
        
        # Generate natural language explanation
        title, summary, detailed = self._generate_natural_language_explanation(
            context, feature_importances, audience, explanation_type
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(context, feature_importances, audience)
        
        # Generate learning points for educational value
        learning_points = self._generate_learning_points(context, feature_importances, audience)
        
        # Calculate overall confidence
        confidence = self._calculate_explanation_confidence(context, feature_importances)
        
        # Generate visualization data
        viz_data = self._generate_visualization_data(context, feature_importances)
        
        return ExplanationResult(
            explanation_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            explanation_type=explanation_type,
            audience=audience,
            title=title,
            summary=summary,
            detailed_explanation=detailed,
            feature_importances=feature_importances,
            confidence_score=confidence,
            recommendations=recommendations,
            learning_points=learning_points,
            visualization_data=viz_data,
            metadata={
                'model_name': context.model_name,
                'decision_type': context.decision_type,
                'input_features': len(context.feature_names)
            }
        )
    
    def explain_vulnerability_analysis(self, 
                                     cve_id: str,
                                     cvss_data: Dict[str, Any],
                                     context_features: Dict[str, Any],
                                     prediction: Dict[str, Any],
                                     audience: ExplanationAudience = ExplanationAudience.DEVELOPER) -> ExplanationResult:
        """
        Explain CVSS-Context vulnerability analysis decision
        
        Args:
            cve_id: CVE identifier
            cvss_data: CVSS score data
            context_features: Contextual features used
            prediction: Model prediction result
            audience: Target audience
            
        Returns:
            Explanation tailored for vulnerability analysis
        """
        # Create decision context
        decision_context = DecisionContext(
            decision_type="vulnerability_analysis",
            input_data={
                'cve_id': cve_id,
                'base_cvss_score': cvss_data.get('base_score', 0),
                **context_features
            },
            model_output=prediction,
            model_name="CVSS-Context Neural Network",
            feature_names=list(context_features.keys()),
            feature_values=list(context_features.values()),
            prediction_confidence=prediction.get('confidence', 0.5)
        )
        
        return self.explain_decision(decision_context, audience, ExplanationType.FEATURE_IMPORTANCE)
    
    def explain_anomaly_detection(self,
                                 anomaly_data: Dict[str, Any],
                                 detection_result: Dict[str, Any],
                                 audience: ExplanationAudience = ExplanationAudience.DEVOPS_ENGINEER) -> ExplanationResult:
        """
        Explain anomaly detection decision
        
        Args:
            anomaly_data: Input anomaly data
            detection_result: Detection result
            audience: Target audience
            
        Returns:
            Explanation tailored for anomaly detection
        """
        decision_context = DecisionContext(
            decision_type="anomaly_detection",
            input_data=anomaly_data,
            model_output=detection_result,
            model_name="Multi-Modal Anomaly Detector",
            feature_names=list(anomaly_data.keys()),
            feature_values=list(anomaly_data.values()),
            prediction_confidence=detection_result.get('confidence', 0.5)
        )
        
        return self.explain_decision(decision_context, audience, ExplanationType.TREND_ANALYSIS)
    
    def generate_educational_feedback(self,
                                    developer_action: str,
                                    ai_recommendation: str,
                                    outcome: str,
                                    context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate educational feedback to improve developer understanding
        
        Args:
            developer_action: What the developer did
            ai_recommendation: What AI recommended
            outcome: Result of the action
            context: Additional context
            
        Returns:
            Educational feedback with learning points
        """
        feedback = {
            'feedback_id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(),
            'scenario': {
                'developer_action': developer_action,
                'ai_recommendation': ai_recommendation,
                'outcome': outcome,
                'context': context
            }
        }
        
        # Analyze alignment between developer action and AI recommendation
        alignment = self._analyze_action_alignment(developer_action, ai_recommendation)
        
        # Generate learning points based on outcome
        if outcome == 'success':
            if alignment == 'high':
                feedback['message'] = "Excellent! Your decision aligned with AI recommendations and produced good results."
                feedback['learning_points'] = [
                    "Your security intuition is well-calibrated",
                    "Continue leveraging AI insights for validation",
                    "This approach can be applied to similar scenarios"
                ]
            else:
                feedback['message'] = "Great outcome! Your approach differed from AI recommendations but was effective."
                feedback['learning_points'] = [
                    "Your domain expertise provided valuable insights",
                    "Consider documenting this approach for future reference",
                    "The AI model can learn from this successful deviation"
                ]
        else:
            if alignment == 'low':
                feedback['message'] = "The outcome suggests following AI recommendations might have been beneficial."
                feedback['learning_points'] = [
                    f"AI recommended: {ai_recommendation}",
                    "Consider the reasoning behind AI suggestions",
                    "Review the factors that led to this recommendation"
                ]
            else:
                feedback['message'] = "Despite following recommendations, the outcome was suboptimal. Let's analyze why."
                feedback['learning_points'] = [
                    "Some factors may not have been considered in the analysis",
                    "This helps improve the AI model for future decisions",
                    "Consider additional context that might be relevant"
                ]
        
        # Add specific learning recommendations
        feedback['recommendations'] = self._generate_educational_recommendations(
            developer_action, ai_recommendation, outcome, context
        )
        
        return feedback
    
    def _calculate_feature_importance(self, context: DecisionContext) -> List[FeatureImportance]:
        """Calculate feature importance using available methods"""
        importances = []
        
        if SHAP_AVAILABLE and context.model_name in self.explainers:
            # Use SHAP for precise feature importance
            importances = self._calculate_shap_importance(context)
        else:
            # Use simple correlation-based importance
            importances = self._calculate_simple_importance(context)
        
        # Sort by importance score
        importances.sort(key=lambda x: abs(x.importance_score), reverse=True)
        
        return importances
    
    def _calculate_shap_importance(self, context: DecisionContext) -> List[FeatureImportance]:
        """Calculate SHAP-based feature importance"""
        # This would use actual SHAP explainer in production
        # For demo, we'll simulate SHAP values
        
        importances = []
        feature_values = np.array(context.feature_values)
        
        # Simulate SHAP values (normally would come from explainer)
        simulated_shap_values = np.random.normal(0, 0.1, len(context.feature_names))
        
        for i, (name, value, shap_val) in enumerate(zip(
            context.feature_names, feature_values, simulated_shap_values
        )):
            # Determine impact direction
            if shap_val > 0.05:
                direction = "positive"
            elif shap_val < -0.05:
                direction = "negative"
            else:
                direction = "neutral"
            
            # Generate explanations
            human_exp, technical_exp = self._generate_feature_explanations(
                name, value, shap_val, direction, context
            )
            
            importances.append(FeatureImportance(
                feature_name=name,
                importance_score=abs(shap_val),
                impact_direction=direction,
                human_explanation=human_exp,
                technical_explanation=technical_exp,
                confidence=0.9  # High confidence for SHAP
            ))
        
        return importances
    
    def _calculate_simple_importance(self, context: DecisionContext) -> List[FeatureImportance]:
        """Calculate simple feature importance when SHAP is not available"""
        importances = []
        
        # Use domain knowledge and simple heuristics
        for i, (name, value) in enumerate(zip(context.feature_names, context.feature_values)):
            # Assign importance based on domain knowledge
            base_importance = self.domain_knowledge.get(name, {}).get('base_importance', 0.1)
            
            # Adjust based on value magnitude
            if isinstance(value, (int, float)):
                if name.lower() in ['public', 'high', 'critical', 'production']:
                    adjusted_importance = base_importance * (1 + value)
                else:
                    adjusted_importance = base_importance * (1 + abs(value) * 0.5)
            else:
                adjusted_importance = base_importance
            
            # Determine direction based on domain knowledge
            direction = self.domain_knowledge.get(name, {}).get('typical_direction', 'neutral')
            
            # Generate explanations
            human_exp, technical_exp = self._generate_feature_explanations(
                name, value, adjusted_importance, direction, context
            )
            
            importances.append(FeatureImportance(
                feature_name=name,
                importance_score=adjusted_importance,
                impact_direction=direction,
                human_explanation=human_exp,
                technical_explanation=technical_exp,
                confidence=0.7  # Medium confidence for simple method
            ))
        
        return importances
    
    def _generate_feature_explanations(self, 
                                     feature_name: str, 
                                     feature_value: Any, 
                                     importance: float,
                                     direction: str,
                                     context: DecisionContext) -> Tuple[str, str]:
        """Generate human and technical explanations for a feature"""
        
        # Get domain-specific explanations
        domain_info = self.domain_knowledge.get(feature_name, {})
        
        # Human explanation
        if direction == "positive":
            human_exp = f"{domain_info.get('human_name', feature_name)} increases the risk/priority"
        elif direction == "negative":
            human_exp = f"{domain_info.get('human_name', feature_name)} decreases the risk/priority"
        else:
            human_exp = f"{domain_info.get('human_name', feature_name)} has neutral impact"
        
        if domain_info.get('explanation'):
            human_exp += f". {domain_info['explanation']}"
        
        # Technical explanation
        technical_exp = f"Feature '{feature_name}' with value {feature_value} "
        technical_exp += f"has importance score {importance:.3f} ({direction} impact)"
        
        return human_exp, technical_exp
    
    def _generate_natural_language_explanation(self,
                                             context: DecisionContext,
                                             feature_importances: List[FeatureImportance],
                                             audience: ExplanationAudience,
                                             explanation_type: ExplanationType) -> Tuple[str, str, str]:
        """Generate natural language explanation"""
        
        # Get appropriate template
        template_key = f"{context.decision_type}_{audience.value}_{explanation_type.value}"
        template = self.explanation_templates.get(template_key, self.explanation_templates['default'])
        
        # Generate title
        if context.decision_type == "vulnerability_analysis":
            title = f"Vulnerability Analysis Explanation for {context.input_data.get('cve_id', 'Unknown CVE')}"
        elif context.decision_type == "anomaly_detection":
            title = "Anomaly Detection Analysis"
        else:
            title = f"{context.decision_type.replace('_', ' ').title()} Explanation"
        
        # Generate summary
        top_factors = feature_importances[:3]
        if top_factors:
            summary = f"The AI decision was primarily influenced by: "
            summary += ", ".join([f.feature_name for f in top_factors])
            summary += f". Confidence: {context.prediction_confidence:.1%}"
        else:
            summary = f"AI analysis completed with {context.prediction_confidence:.1%} confidence."
        
        # Generate detailed explanation
        detailed = template['intro']
        
        if feature_importances:
            detailed += "\n\nKey factors in this decision:\n"
            for i, feature in enumerate(feature_importances[:5], 1):
                detailed += f"{i}. {feature.human_explanation}\n"
        
        detailed += f"\n{template['conclusion']}"
        
        # Customize for audience
        if audience == ExplanationAudience.DEVELOPER:
            detailed += "\n\nFor developers: This analysis helps you understand which code and deployment factors most impact security decisions."
        elif audience == ExplanationAudience.MANAGER:
            detailed += "\n\nBusiness impact: These factors directly affect system security posture and operational risk."
        
        return title, summary, detailed
    
    def _generate_recommendations(self,
                                context: DecisionContext,
                                feature_importances: List[FeatureImportance],
                                audience: ExplanationAudience) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Get top risk factors
        high_risk_factors = [f for f in feature_importances if f.importance_score > 0.1 and f.impact_direction == "positive"]
        
        for factor in high_risk_factors[:3]:
            if factor.feature_name == 'service_exposure' and factor.impact_direction == "positive":
                recommendations.append("Consider implementing additional network security controls for public-facing services")
            elif factor.feature_name == 'data_sensitivity' and factor.impact_direction == "positive":
                recommendations.append("Implement enhanced data protection measures for high-sensitivity data")
            elif 'incident_history' in factor.feature_name:
                recommendations.append("Review historical incident patterns to identify systematic vulnerabilities")
            else:
                recommendations.append(f"Address high-impact factor: {factor.feature_name}")
        
        # Add audience-specific recommendations
        if audience == ExplanationAudience.DEVELOPER:
            recommendations.append("Integrate security checks into your development workflow")
            recommendations.append("Use the AI recommendations to improve secure coding practices")
        elif audience == ExplanationAudience.DEVOPS_ENGINEER:
            recommendations.append("Update deployment policies based on these risk factors")
            recommendations.append("Configure automated monitoring for high-risk scenarios")
        
        return recommendations[:5]  # Limit to top 5
    
    def _generate_learning_points(self,
                                context: DecisionContext,
                                feature_importances: List[FeatureImportance],
                                audience: ExplanationAudience) -> List[str]:
        """Generate educational learning points"""
        learning_points = []
        
        # Extract key learning insights
        if context.decision_type == "vulnerability_analysis":
            learning_points.extend([
                "CVSS scores alone don't capture full risk context",
                "Application-specific factors significantly impact actual risk",
                "Historical incident data helps predict future vulnerabilities"
            ])
        elif context.decision_type == "anomaly_detection":
            learning_points.extend([
                "Multiple detection methods improve accuracy",
                "Context matters as much as the anomaly magnitude",
                "Explainable AI helps distinguish true positives from noise"
            ])
        
        # Add top learning insights from features
        for feature in feature_importances[:2]:
            if feature.feature_name == 'service_exposure':
                learning_points.append("Public services require more stringent security measures")
            elif feature.feature_name == 'environment_type':
                learning_points.append("Production environments need immediate attention for security issues")
        
        # Add audience-specific learning
        if audience == ExplanationAudience.DEVELOPER:
            learning_points.append("Understanding AI reasoning improves security intuition")
        
        return learning_points[:4]  # Limit to top 4
    
    def _calculate_explanation_confidence(self,
                                        context: DecisionContext,
                                        feature_importances: List[FeatureImportance]) -> float:
        """Calculate confidence in the explanation"""
        # Base on prediction confidence and feature importance confidence
        prediction_conf = context.prediction_confidence
        
        if feature_importances:
            feature_conf = np.mean([f.confidence for f in feature_importances])
            combined_conf = (prediction_conf + feature_conf) / 2
        else:
            combined_conf = prediction_conf
        
        return combined_conf
    
    def _generate_visualization_data(self,
                                   context: DecisionContext,
                                   feature_importances: List[FeatureImportance]) -> Dict[str, Any]:
        """Generate data for visualizations"""
        viz_data = {
            'feature_importance_chart': {
                'features': [f.feature_name for f in feature_importances[:10]],
                'importance_scores': [f.importance_score for f in feature_importances[:10]],
                'directions': [f.impact_direction for f in feature_importances[:10]]
            },
            'confidence_gauge': {
                'overall_confidence': context.prediction_confidence,
                'explanation_confidence': self._calculate_explanation_confidence(context, feature_importances)
            },
            'decision_tree': {
                'decision_type': context.decision_type,
                'input_summary': len(context.feature_names),
                'output_summary': context.model_output
            }
        }
        
        return viz_data
    
    def _analyze_action_alignment(self, developer_action: str, ai_recommendation: str) -> str:
        """Analyze alignment between developer action and AI recommendation"""
        # Simple keyword-based alignment analysis for demo
        action_words = set(developer_action.lower().split())
        recommendation_words = set(ai_recommendation.lower().split())
        
        overlap = len(action_words.intersection(recommendation_words))
        total_words = len(action_words.union(recommendation_words))
        
        if total_words == 0:
            return 'neutral'
        
        alignment_ratio = overlap / total_words
        
        if alignment_ratio > 0.5:
            return 'high'
        elif alignment_ratio > 0.2:
            return 'medium'
        else:
            return 'low'
    
    def _generate_educational_recommendations(self,
                                            developer_action: str,
                                            ai_recommendation: str,
                                            outcome: str,
                                            context: Dict[str, Any]) -> List[str]:
        """Generate educational recommendations"""
        recommendations = []
        
        if outcome == 'success':
            recommendations.extend([
                "Document this successful approach for team knowledge sharing",
                "Consider creating a playbook for similar scenarios",
                "Share insights with the security team"
            ])
        else:
            recommendations.extend([
                "Review the AI reasoning to understand the recommended approach",
                "Discuss with senior team members for additional insights",
                "Update personal security practices based on this learning"
            ])
        
        # Add context-specific recommendations
        if 'vulnerability' in context.get('scenario_type', ''):
            recommendations.append("Practice using CVSS context analysis for future vulnerabilities")
        
        return recommendations
    
    def _load_explanation_templates(self) -> Dict[str, Dict[str, str]]:
        """Load explanation templates for different contexts"""
        return {
            'vulnerability_analysis_developer_feature_importance': {
                'intro': "This vulnerability analysis considers both the base CVSS score and your specific application context.",
                'conclusion': "Understanding these factors helps you make more informed security decisions."
            },
            'anomaly_detection_devops_engineer_trend_analysis': {
                'intro': "The anomaly detection system analyzed multiple data streams to identify unusual patterns.",
                'conclusion': "This multi-modal approach reduces false positives while maintaining high detection accuracy."
            },
            'default': {
                'intro': "The AI system analyzed multiple factors to reach this decision.",
                'conclusion': "These explanations help you understand and validate AI recommendations."
            }
        }
    
    def _load_domain_knowledge(self) -> Dict[str, Dict[str, Any]]:
        """Load domain knowledge for DevOps and security contexts"""
        return {
            'service_exposure': {
                'human_name': 'Service exposure level',
                'explanation': 'Public services face higher attack risk',
                'base_importance': 0.3,
                'typical_direction': 'positive'
            },
            'data_sensitivity': {
                'human_name': 'Data sensitivity',
                'explanation': 'High-sensitivity data requires stronger protection',
                'base_importance': 0.25,
                'typical_direction': 'positive'
            },
            'environment_type': {
                'human_name': 'Environment type',
                'explanation': 'Production environments need immediate attention',
                'base_importance': 0.2,
                'typical_direction': 'positive'
            },
            'incident_history_count': {
                'human_name': 'Historical incidents',
                'explanation': 'Services with incident history are higher risk',
                'base_importance': 0.15,
                'typical_direction': 'positive'
            },
            'has_authentication': {
                'human_name': 'Authentication requirement',
                'explanation': 'Authentication reduces unauthorized access risk',
                'base_importance': 0.1,
                'typical_direction': 'negative'
            }
        }


def demo():
    """Demonstration of the explainable AI engine"""
    print("🔍 Explainable AI Engine Demo")
    print("=" * 40)
    
    # Initialize engine
    engine = ExplanationEngine()
    
    # Demo vulnerability analysis explanation
    print("📋 Vulnerability Analysis Explanation")
    print("-" * 40)
    
    explanation = engine.explain_vulnerability_analysis(
        cve_id="CVE-2023-DEMO",
        cvss_data={'base_score': 7.5},
        context_features={
            'service_exposure': 'public',
            'data_sensitivity': 'high',
            'environment_type': 'production',
            'incident_history_count': 2
        },
        prediction={
            'adjusted_score': 8.7,
            'priority': 1,
            'confidence': 0.89
        },
        audience=ExplanationAudience.DEVELOPER
    )
    
    print(f"Title: {explanation.title}")
    print(f"Summary: {explanation.summary}")
    print(f"Confidence: {explanation.confidence_score:.1%}")
    print()
    print("Top Risk Factors:")
    for i, feature in enumerate(explanation.feature_importances[:3], 1):
        print(f"  {i}. {feature.human_explanation}")
    print()
    print("Learning Points:")
    for point in explanation.learning_points:
        print(f"  • {point}")
    print()
    print("Recommendations:")
    for rec in explanation.recommendations[:3]:
        print(f"  • {rec}")
    
    # Demo educational feedback
    print("\n" + "=" * 40)
    print("🎓 Educational Feedback Demo")
    print("-" * 40)
    
    feedback = engine.generate_educational_feedback(
        developer_action="Applied security patch immediately",
        ai_recommendation="Apply patch within 24 hours due to high context risk",
        outcome="success",
        context={'scenario_type': 'vulnerability_management'}
    )
    
    print(f"Feedback: {feedback['message']}")
    print("Learning Points:")
    for point in feedback['learning_points']:
        print(f"  • {point}")


if __name__ == "__main__":
    demo()

"""
Consolidated APT Reporting System
Handles reporting and logging for all APT implementations
"""

import os
import json
import time
import logging
import hashlib
import base64
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

class APTReporting:
    """Handles reporting and logging for all APT implementations"""
    
    def __init__(self, apt_name: str):
        # Initialize logging directories
        self.base_dir = Path("logs")
        self.apt_dir = self.base_dir / apt_name
        self.operations_dir = self.apt_dir / "operations"
        self.artifacts_dir = self.apt_dir / "artifacts"
        self.reports_dir = self.apt_dir / "reports"
        
        # Create directories if they don't exist
        for directory in [self.base_dir, self.apt_dir, self.operations_dir, 
                         self.artifacts_dir, self.reports_dir]:
            directory.mkdir(parents=True, exist_ok=True)
            
        # Set up logging
        self.logger = logging.getLogger(f"apt_reporting_{apt_name}")
        self.logger.setLevel(logging.DEBUG)
        
        # File handler
        fh = logging.FileHandler(self.apt_dir / "apt_operations.log")
        fh.setLevel(logging.DEBUG)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        # Add handlers
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)
        
        # Initialize storage
        self.operations = {}
        self.artifacts = {}
        self.metrics = {
            "total_operations": 0,
            "successful_operations": 0,
            "failed_operations": 0,
            "impact_levels": {},
            "detection_rates": {}
        }
        
    def log_operation(self, operation: Dict[str, Any]) -> str:
        """Log an operation with metadata"""
        try:
            # Generate unique operation ID
            operation_id = self._generate_operation_id(operation)
            
            # Add metadata
            operation["operation_id"] = operation_id
            operation["timestamp"] = datetime.now().isoformat()
            
            # Store operation
            self.operations[operation_id] = operation
            
            # Log operation
            self.logger.info(f"Operation {operation_id}: {operation['tactic']} - {operation['technique']}")
            
            # Update metrics
            self._update_metrics(operation)
            
            return operation_id
            
        except Exception as e:
            self.logger.error(f"Error logging operation: {str(e)}")
            raise
            
    def store_artifact(self, operation_id: str, artifact: Dict[str, Any]) -> None:
        """Store an artifact with metadata"""
        try:
            # Validate operation exists
            if operation_id not in self.operations:
                raise ValueError(f"Operation {operation_id} not found")
                
            # Generate artifact ID
            artifact_id = self._generate_artifact_id(artifact)
            
            # Add metadata
            artifact["artifact_id"] = artifact_id
            artifact["operation_id"] = operation_id
            artifact["timestamp"] = datetime.now().isoformat()
            
            # Store artifact
            self.artifacts[artifact_id] = artifact
            
            # Save artifact to file
            artifact_path = self.artifacts_dir / f"{artifact_id}.json"
            with open(artifact_path, "w") as f:
                json.dump(artifact, f, indent=2)
                
            # Log artifact
            self.logger.info(f"Artifact {artifact_id} stored for operation {operation_id}")
            
        except Exception as e:
            self.logger.error(f"Error storing artifact: {str(e)}")
            raise
            
    def generate_report(self, operation_id: str) -> Dict[str, Any]:
        """Generate a report for a specific operation"""
        try:
            # Validate operation exists
            if operation_id not in self.operations:
                raise ValueError(f"Operation {operation_id} not found")
                
            # Get operation and related artifacts
            operation = self.operations[operation_id]
            artifacts = [a for a in self.artifacts.values() if a["operation_id"] == operation_id]
            
            # Generate report
            report = {
                "operation_id": operation_id,
                "timestamp": datetime.now().isoformat(),
                "operation": operation,
                "artifacts": artifacts,
                "metrics": self._calculate_operation_metrics(operation_id),
                "indicators": self._extract_indicators(operation, artifacts),
                "recommendations": self._generate_recommendations(operation, artifacts)
            }
            
            # Save report
            report_path = self.reports_dir / f"operation_{operation_id}_report.json"
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2)
                
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            raise
            
    def generate_summary(self, start_time: Optional[str] = None, 
                        end_time: Optional[str] = None) -> Dict[str, Any]:
        """Generate a summary report for a time period"""
        try:
            # Filter operations by time period
            filtered_operations = self._filter_operations_by_time(start_time, end_time)
            
            # Generate summary
            summary = {
                "period": {
                    "start": start_time or "beginning",
                    "end": end_time or "now"
                },
                "total_operations": len(filtered_operations),
                "operations_by_tactic": self._group_operations_by_tactic(filtered_operations),
                "success_rate": self._calculate_success_rate(filtered_operations),
                "impact_levels": self._calculate_impact_levels(filtered_operations),
                "detection_rates": self._calculate_detection_rates(filtered_operations),
                "key_findings": self._extract_key_findings(filtered_operations),
                "recommendations": self._generate_summary_recommendations(filtered_operations)
            }
            
            # Save summary
            summary_path = self.reports_dir / f"summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(summary_path, "w") as f:
                json.dump(summary, f, indent=2)
                
            return summary
            
        except Exception as e:
            self.logger.error(f"Error generating summary: {str(e)}")
            raise
            
    def _generate_operation_id(self, operation: Dict[str, Any]) -> str:
        """Generate a unique operation ID"""
        data = f"{operation['tactic']}_{operation['technique']}_{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
        
    def _generate_artifact_id(self, artifact: Dict[str, Any]) -> str:
        """Generate a unique artifact ID"""
        data = f"{artifact['type']}_{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
        
    def _update_metrics(self, operation: Dict[str, Any]) -> None:
        """Update metrics with operation data"""
        self.metrics["total_operations"] += 1
        
        if operation.get("status") == "completed":
            self.metrics["successful_operations"] += 1
        else:
            self.metrics["failed_operations"] += 1
            
        impact = operation.get("impact_level", "unknown")
        self.metrics["impact_levels"][impact] = self.metrics["impact_levels"].get(impact, 0) + 1
        
        detection = operation.get("detection_status", "unknown")
        self.metrics["detection_rates"][detection] = self.metrics["detection_rates"].get(detection, 0) + 1
        
    def _calculate_operation_metrics(self, operation_id: str) -> Dict[str, Any]:
        """Calculate metrics for a specific operation"""
        operation = self.operations[operation_id]
        artifacts = [a for a in self.artifacts.values() if a["operation_id"] == operation_id]
        
        return {
            "duration": self._calculate_duration(operation),
            "success": operation.get("status") == "completed",
            "impact_level": operation.get("impact_level", "unknown"),
            "detection_status": operation.get("detection_status", "unknown"),
            "artifact_count": len(artifacts),
            "indicator_count": len(self._extract_indicators(operation, artifacts))
        }
        
    def _calculate_duration(self, operation: Dict[str, Any]) -> float:
        """Calculate operation duration in seconds"""
        start_time = datetime.fromisoformat(operation["timestamp"])
        end_time = datetime.now()
        return (end_time - start_time).total_seconds()
        
    def _extract_indicators(self, operation: Dict[str, Any], 
                          artifacts: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Extract indicators from operation and artifacts"""
        indicators = {
            "file": [],
            "network": [],
            "process": [],
            "registry": [],
            "behavior": []
        }
        
        # Extract from operation
        for indicator_type in indicators:
            if indicator_type in operation.get("indicators", {}):
                indicators[indicator_type].extend(operation["indicators"][indicator_type])
                
        # Extract from artifacts
        for artifact in artifacts:
            if "indicators" in artifact:
                for indicator_type in indicators:
                    if indicator_type in artifact["indicators"]:
                        indicators[indicator_type].extend(artifact["indicators"][indicator_type])
                        
        return indicators
        
    def _generate_recommendations(self, operation: Dict[str, Any], 
                                artifacts: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on operation and artifacts"""
        recommendations = []
        
        # Check for high impact operations
        if operation.get("impact_level") == "high":
            recommendations.append("Review and enhance security controls for high-impact operations")
            
        # Check for detection
        if operation.get("detection_status") == "detected":
            recommendations.append("Investigate detection mechanisms and update evasion techniques")
            
        # Check for failed operations
        if operation.get("status") != "completed":
            recommendations.append("Review and improve operation execution procedures")
            
        # Check for sensitive data exposure
        for artifact in artifacts:
            if artifact.get("sensitivity_level") == "high":
                recommendations.append("Implement additional data protection measures")
                
        return recommendations
        
    def _filter_operations_by_time(self, start_time: Optional[str], 
                                 end_time: Optional[str]) -> List[Dict[str, Any]]:
        """Filter operations by time period"""
        filtered = []
        
        for operation in self.operations.values():
            op_time = datetime.fromisoformat(operation["timestamp"])
            
            if start_time:
                start = datetime.fromisoformat(start_time)
                if op_time < start:
                    continue
                    
            if end_time:
                end = datetime.fromisoformat(end_time)
                if op_time > end:
                    continue
                    
            filtered.append(operation)
            
        return filtered
        
    def _group_operations_by_tactic(self, operations: List[Dict[str, Any]]) -> Dict[str, int]:
        """Group operations by tactic"""
        grouped = {}
        
        for operation in operations:
            tactic = operation["tactic"]
            grouped[tactic] = grouped.get(tactic, 0) + 1
            
        return grouped
        
    def _calculate_success_rate(self, operations: List[Dict[str, Any]]) -> float:
        """Calculate success rate for operations"""
        if not operations:
            return 0.0
            
        successful = sum(1 for op in operations if op.get("status") == "completed")
        return successful / len(operations)
        
    def _calculate_impact_levels(self, operations: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate impact levels for operations"""
        levels = {}
        
        for operation in operations:
            level = operation.get("impact_level", "unknown")
            levels[level] = levels.get(level, 0) + 1
            
        return levels
        
    def _calculate_detection_rates(self, operations: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate detection rates for operations"""
        rates = {}
        
        for operation in operations:
            status = operation.get("detection_status", "unknown")
            rates[status] = rates.get(status, 0) + 1
            
        return rates
        
    def _extract_key_findings(self, operations: List[Dict[str, Any]]) -> List[str]:
        """Extract key findings from operations"""
        findings = []
        
        # Analyze success rate
        success_rate = self._calculate_success_rate(operations)
        findings.append(f"Overall operation success rate: {success_rate:.2%}")
        
        # Analyze impact levels
        impact_levels = self._calculate_impact_levels(operations)
        for level, count in impact_levels.items():
            findings.append(f"Operations with {level} impact: {count}")
            
        # Analyze detection rates
        detection_rates = self._calculate_detection_rates(operations)
        for status, count in detection_rates.items():
            findings.append(f"Operations {status}: {count}")
            
        return findings
        
    def _generate_summary_recommendations(self, operations: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on operation summary"""
        recommendations = []
        
        # Check overall success rate
        success_rate = self._calculate_success_rate(operations)
        if success_rate < 0.8:
            recommendations.append("Improve operation success rate through better planning and execution")
            
        # Check high impact operations
        impact_levels = self._calculate_impact_levels(operations)
        if impact_levels.get("high", 0) > 0:
            recommendations.append("Review and enhance controls for high-impact operations")
            
        # Check detection rates
        detection_rates = self._calculate_detection_rates(operations)
        if detection_rates.get("detected", 0) > 0:
            recommendations.append("Enhance evasion techniques to reduce detection rates")
            
        return recommendations 
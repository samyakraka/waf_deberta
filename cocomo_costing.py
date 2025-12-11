#!/usr/bin/env python3
"""
COCOMO (Constructive Cost Model) Cost Estimation for WAF Project
Analyzes the codebase and calculates development effort, time, and cost
Based on COCOMO II model with calibration for AI/ML projects

Author: Generated for WAF DeBERTa Project
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict
import re


@dataclass
class CodeMetrics:
    """Metrics collected from codebase analysis"""
    total_lines: int
    source_lines: int  # Excluding comments and blanks
    comment_lines: int
    blank_lines: int
    files_count: int
    avg_lines_per_file: float
    max_lines_in_file: int
    min_lines_in_file: int


@dataclass
class COCOMOEstimate:
    """COCOMO cost estimation results"""
    model_type: str  # Basic, Intermediate, Detailed
    project_type: str  # Organic, Semi-detached, Embedded
    kloc: float  # Thousands of Lines of Code
    effort_pm: float  # Person-Months
    development_time_months: float
    average_team_size: float
    productivity_loc_per_pm: float
    total_cost_usd: float
    cost_per_loc: float
    maintenance_cost_annual: float


class COCOMOCalculator:
    """
    COCOMO II Calculator for software cost estimation
    
    Project Types:
    - Organic: Small teams, familiar environment (a=2.4, b=1.05)
    - Semi-detached: Medium teams, mixed experience (a=3.0, b=1.12)
    - Embedded: Large teams, tight constraints (a=3.6, b=1.20)
    
    Formulas:
    - Effort = a × (KLOC)^b person-months
    - Time = c × (Effort)^d months
    - Team Size = Effort / Time
    """
    
    # COCOMO coefficients
    COEFFICIENTS = {
        'organic': {'a': 2.4, 'b': 1.05, 'c': 2.5, 'd': 0.38},
        'semi-detached': {'a': 3.0, 'b': 1.12, 'c': 2.5, 'd': 0.35},
        'embedded': {'a': 3.6, 'b': 1.20, 'c': 2.5, 'd': 0.32}
    }
    
    # Cost factors (USD per person-month)
    COST_PER_PM = {
        'junior': 5000,
        'mid': 8000,
        'senior': 12000,
        'lead': 15000
    }
    
    # AI/ML project multipliers (typically higher complexity)
    AI_ML_MULTIPLIER = 1.25
    
    def __init__(self, workspace_path: str):
        """Initialize calculator with workspace path"""
        self.workspace_path = Path(workspace_path)
        self.metrics: CodeMetrics = None
        
    def analyze_codebase(self, exclude_dirs: List[str] = None) -> CodeMetrics:
        """
        Analyze codebase to collect metrics
        
        Args:
            exclude_dirs: Directories to exclude from analysis
            
        Returns:
            CodeMetrics object with collected metrics
        """
        if exclude_dirs is None:
            exclude_dirs = [
                '__pycache__', 'model', 'models', 'models_30k', 'models_out',
                '.git', 'venv', 'env', 'node_modules', '__MACOSX', 'nginx/logs'
            ]
        
        total_lines = 0
        source_lines = 0
        comment_lines = 0
        blank_lines = 0
        files_count = 0
        file_sizes = []
        
        # Find all Python files
        for py_file in self.workspace_path.rglob('*.py'):
            # Skip excluded directories
            if any(excluded in py_file.parts for excluded in exclude_dirs):
                continue
            
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    file_line_count = len(lines)
                    file_sizes.append(file_line_count)
                    files_count += 1
                    
                    in_multiline_comment = False
                    for line in lines:
                        total_lines += 1
                        stripped = line.strip()
                        
                        # Blank line
                        if not stripped:
                            blank_lines += 1
                            continue
                        
                        # Multiline comment (docstring)
                        if '"""' in stripped or "'''" in stripped:
                            comment_lines += 1
                            in_multiline_comment = not in_multiline_comment
                            continue
                        
                        if in_multiline_comment:
                            comment_lines += 1
                            continue
                        
                        # Single line comment
                        if stripped.startswith('#'):
                            comment_lines += 1
                            continue
                        
                        # Source line
                        source_lines += 1
                        
            except Exception as e:
                print(f"Warning: Could not read {py_file}: {e}")
                continue
        
        avg_lines = sum(file_sizes) / len(file_sizes) if file_sizes else 0
        max_lines = max(file_sizes) if file_sizes else 0
        min_lines = min(file_sizes) if file_sizes else 0
        
        self.metrics = CodeMetrics(
            total_lines=total_lines,
            source_lines=source_lines,
            comment_lines=comment_lines,
            blank_lines=blank_lines,
            files_count=files_count,
            avg_lines_per_file=avg_lines,
            max_lines_in_file=max_lines,
            min_lines_in_file=min_lines
        )
        
        return self.metrics
    
    def calculate_cocomo(
        self,
        project_type: str = 'semi-detached',
        developer_level: str = 'mid',
        is_ai_ml_project: bool = True
    ) -> COCOMOEstimate:
        """
        Calculate COCOMO estimates
        
        Args:
            project_type: 'organic', 'semi-detached', or 'embedded'
            developer_level: 'junior', 'mid', 'senior', or 'lead'
            is_ai_ml_project: Apply AI/ML complexity multiplier
            
        Returns:
            COCOMOEstimate object with all calculations
        """
        if self.metrics is None:
            raise ValueError("Must run analyze_codebase() first")
        
        # Get coefficients
        coeff = self.COEFFICIENTS[project_type]
        
        # Calculate KLOC (using source lines only, excluding comments/blanks)
        kloc = self.metrics.source_lines / 1000.0
        
        # Basic COCOMO calculations
        effort_pm = coeff['a'] * (kloc ** coeff['b'])
        
        # Apply AI/ML multiplier if applicable
        if is_ai_ml_project:
            effort_pm *= self.AI_ML_MULTIPLIER
        
        # Development time
        dev_time_months = coeff['c'] * (effort_pm ** coeff['d'])
        
        # Average team size
        avg_team_size = effort_pm / dev_time_months
        
        # Productivity
        productivity = self.metrics.source_lines / effort_pm
        
        # Cost calculations
        cost_per_pm = self.COST_PER_PM[developer_level]
        total_cost = effort_pm * cost_per_pm
        cost_per_loc = total_cost / self.metrics.source_lines if self.metrics.source_lines > 0 else 0
        
        # Maintenance cost (typically 15-20% annually)
        maintenance_cost = total_cost * 0.17
        
        return COCOMOEstimate(
            model_type="COCOMO II Basic",
            project_type=project_type,
            kloc=kloc,
            effort_pm=effort_pm,
            development_time_months=dev_time_months,
            average_team_size=avg_team_size,
            productivity_loc_per_pm=productivity,
            total_cost_usd=total_cost,
            cost_per_loc=cost_per_loc,
            maintenance_cost_annual=maintenance_cost
        )
    
    def calculate_all_scenarios(self) -> Dict[str, COCOMOEstimate]:
        """Calculate estimates for all project types and developer levels"""
        scenarios = {}
        
        for proj_type in ['organic', 'semi-detached', 'embedded']:
            for dev_level in ['junior', 'mid', 'senior']:
                key = f"{proj_type}_{dev_level}"
                scenarios[key] = self.calculate_cocomo(
                    project_type=proj_type,
                    developer_level=dev_level,
                    is_ai_ml_project=True
                )
        
        return scenarios
    
    def generate_report(self, output_file: str = None) -> str:
        """
        Generate comprehensive COCOMO report
        
        Args:
            output_file: Optional file path to save report
            
        Returns:
            Report as string
        """
        if self.metrics is None:
            raise ValueError("Must run analyze_codebase() first")
        
        # Calculate recommended scenario (semi-detached with mid-level developers)
        recommended = self.calculate_cocomo('semi-detached', 'mid', True)
        
        # Calculate all scenarios
        all_scenarios = self.calculate_all_scenarios()
        
        # Generate report
        report = []
        report.append("=" * 80)
        report.append("COCOMO COST ESTIMATION REPORT")
        report.append("WAF DeBERTa Project - AI/ML Security System")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Workspace: {self.workspace_path}")
        report.append("")
        
        # Code Metrics
        report.append("CODE METRICS")
        report.append("-" * 80)
        report.append(f"Total Lines:              {self.metrics.total_lines:,}")
        report.append(f"Source Lines (SLOC):      {self.metrics.source_lines:,}")
        report.append(f"Comment Lines:            {self.metrics.comment_lines:,}")
        report.append(f"Blank Lines:              {self.metrics.blank_lines:,}")
        report.append(f"Python Files:             {self.metrics.files_count}")
        report.append(f"Avg Lines per File:       {self.metrics.avg_lines_per_file:.1f}")
        report.append(f"Largest File:             {self.metrics.max_lines_in_file} lines")
        report.append(f"Smallest File:            {self.metrics.min_lines_in_file} lines")
        report.append(f"Code to Comment Ratio:    {self.metrics.source_lines/max(1, self.metrics.comment_lines):.2f}:1")
        report.append("")
        
        # Recommended Estimate
        report.append("RECOMMENDED ESTIMATE (Semi-Detached, Mid-Level Developers)")
        report.append("-" * 80)
        report.append(f"Model:                    {recommended.model_type}")
        report.append(f"Project Type:             {recommended.project_type.title()}")
        report.append(f"KLOC:                     {recommended.kloc:.2f}")
        report.append(f"")
        report.append(f"Effort Required:          {recommended.effort_pm:.2f} person-months")
        report.append(f"Development Time:         {recommended.development_time_months:.2f} months")
        report.append(f"Average Team Size:        {recommended.average_team_size:.1f} developers")
        report.append(f"Productivity:             {recommended.productivity_loc_per_pm:.0f} LOC/person-month")
        report.append(f"")
        report.append(f"Total Development Cost:   ${recommended.total_cost_usd:,.2f}")
        report.append(f"Cost per LOC:             ${recommended.cost_per_loc:.2f}")
        report.append(f"Annual Maintenance Cost:  ${recommended.maintenance_cost_annual:,.2f}")
        report.append("")
        
        # Alternative Scenarios
        report.append("ALTERNATIVE SCENARIOS")
        report.append("-" * 80)
        report.append(f"{'Scenario':<30} {'Effort (PM)':<15} {'Time (Mo)':<15} {'Cost (USD)':<20}")
        report.append("-" * 80)
        
        for key, estimate in sorted(all_scenarios.items()):
            scenario_name = key.replace('_', ' + ').title()
            report.append(f"{scenario_name:<30} {estimate.effort_pm:<15.2f} {estimate.development_time_months:<15.2f} ${estimate.total_cost_usd:<19,.2f}")
        
        report.append("")
        
        # Project Characteristics
        report.append("PROJECT CHARACTERISTICS")
        report.append("-" * 80)
        report.append("✓ AI/ML Security System (DeBERTa-based WAF)")
        report.append("✓ Complexity Multiplier: 1.25x (AI/ML projects)")
        report.append("✓ Components:")
        report.append("  - Machine Learning Model Training (src/trainer.py)")
        report.append("  - Anomaly Detection Engine (src/detector.py)")
        report.append("  - Real-time WAF Monitoring (waf_integrated_ui.py)")
        report.append("  - Redis Rule Management (src/redis_rules.py)")
        report.append("  - Incremental Learning System (incremental_model.py)")
        report.append("  - Web UI and API Integration (Flask-based)")
        report.append("")
        
        # Assumptions
        report.append("ASSUMPTIONS & NOTES")
        report.append("-" * 80)
        report.append("• COCOMO II Basic Model used for estimation")
        report.append("• AI/ML complexity multiplier: 1.25x")
        report.append("• Cost rates (per person-month):")
        report.append(f"  - Junior Developer: ${self.COST_PER_PM['junior']:,}")
        report.append(f"  - Mid-Level Developer: ${self.COST_PER_PM['mid']:,}")
        report.append(f"  - Senior Developer: ${self.COST_PER_PM['senior']:,}")
        report.append(f"  - Lead Developer: ${self.COST_PER_PM['lead']:,}")
        report.append("• Maintenance cost: 17% of development cost annually")
        report.append("• Excludes: Hardware, infrastructure, training, licenses")
        report.append("")
        
        # Risk Factors
        report.append("RISK & ADJUSTMENT FACTORS")
        report.append("-" * 80)
        report.append("Consider adjusting estimates for:")
        report.append("  • Model training time and compute costs")
        report.append("  • Dataset collection and labeling efforts")
        report.append("  • Security testing and penetration testing")
        report.append("  • Performance optimization and tuning")
        report.append("  • Documentation and deployment guides")
        report.append("  • Integration with existing systems")
        report.append("")
        
        report.append("=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        report_text = "\n".join(report)
        
        # Save to file if specified
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
            print(f"✅ Report saved to: {output_file}")
        
        return report_text
    
    def export_json(self, output_file: str = None) -> Dict:
        """Export metrics and estimates as JSON"""
        if self.metrics is None:
            raise ValueError("Must run analyze_codebase() first")
        
        data = {
            'generated_at': datetime.now().isoformat(),
            'workspace': str(self.workspace_path),
            'metrics': asdict(self.metrics),
            'estimates': {}
        }
        
        # Add all scenarios
        for key, estimate in self.calculate_all_scenarios().items():
            data['estimates'][key] = asdict(estimate)
        
        # Add recommended estimate
        data['recommended'] = asdict(self.calculate_cocomo('semi-detached', 'mid', True))
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"✅ JSON data saved to: {output_file}")
        
        return data


def main():
    """Main execution function"""
    print("=" * 80)
    print("COCOMO Cost Estimation Tool")
    print("WAF DeBERTa Project")
    print("=" * 80)
    print()
    
    # Get workspace path
    workspace_path = Path(__file__).parent
    
    # Initialize calculator
    print(f"📁 Analyzing workspace: {workspace_path}")
    calculator = COCOMOCalculator(workspace_path)
    
    # Analyze codebase
    print("🔍 Scanning Python files...")
    metrics = calculator.analyze_codebase()
    print(f"✅ Found {metrics.files_count} Python files, {metrics.source_lines:,} source lines")
    print()
    
    # Generate report
    print("📊 Generating COCOMO report...")
    report_file = workspace_path / 'cocomo_report.txt'
    json_file = workspace_path / 'cocomo_data.json'
    
    report = calculator.generate_report(str(report_file))
    calculator.export_json(str(json_file))
    
    print()
    print(report)
    print()
    print(f"📄 Full report saved to: {report_file}")
    print(f"📄 JSON data saved to: {json_file}")


if __name__ == "__main__":
    main()

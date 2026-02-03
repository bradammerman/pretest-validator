"""
Report Generation for Pretest Validator
=======================================

This module handles formatting and exporting validation results in
multiple formats: console output, JSON, and Markdown.

Features:
---------
- Rich console output with color-coded status symbols
- JSON export for machine parsing and automation
- Markdown export for documentation and client reports
- Summary statistics with pass/fail counts

Usage:
------
    from pretest_validator.report import ReportGenerator
    from pretest_validator.config import PretestConfig
    
    config = PretestConfig(client="ACME", engagement_id="001")
    results = [...]  # List of ValidationResult objects
    
    report = ReportGenerator(config, results)
    report.print_summary()  # Console output
    report.export_json('report.json')
    report.export_markdown('report.md')
    
    exit_code = report.get_exit_code()  # 0=success, 1=failures

Requirements:
-------------
    - rich>=13.0 (for console formatting)
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from .utils import ValidationResult, ValidationStatus
from .config import PretestConfig


class ReportGenerator:
    """
    Generate validation reports in multiple formats.
    
    This class takes validation results and produces formatted output
    for console display and file export.
    
    Attributes:
        config: PretestConfig with engagement metadata
        results: List of ValidationResult objects to report
        console: Rich Console instance for formatted output
    
    Example:
        report = ReportGenerator(config, results)
        report.print_summary()  # Display to terminal
        report.export_json('results.json')  # Save JSON
        report.export_markdown('results.md')  # Save Markdown
    """
    
    # Color mapping for each status type
    STATUS_COLORS = {
        ValidationStatus.SUCCESS: "green",
        ValidationStatus.FAILURE: "red",
        ValidationStatus.WARNING: "yellow",
        ValidationStatus.SKIPPED: "dim",
        ValidationStatus.ERROR: "red bold",
    }
    
    # Symbol mapping for each status type
    STATUS_SYMBOLS = {
        ValidationStatus.SUCCESS: "✓",
        ValidationStatus.FAILURE: "✗",
        ValidationStatus.WARNING: "⚠",
        ValidationStatus.SKIPPED: "○",
        ValidationStatus.ERROR: "✗",
    }
    
    def __init__(self, config: PretestConfig, results: list[ValidationResult]):
        """
        Initialize the report generator.
        
        Args:
            config: PretestConfig with client/engagement info
            results: List of ValidationResult objects from validators
        """
        self.config = config
        self.results = results
        self.console = Console()
    
    def print_summary(self) -> None:
        """
        Print a formatted summary to the console.
        
        Displays a header panel with engagement info, a table of all
        results with color-coded status, and a summary statistics panel.
        """
        # Print header panel with engagement metadata
        self.console.print()
        self.console.print(Panel(
            f"[bold]Pretest Validation Report[/bold]\n"
            f"Client: {self.config.client}\n"
            f"Engagement: {self.config.engagement_id}\n"
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            title="Pretest Validator",
            border_style="blue",
        ))
        self.console.print()
        
        # Build results table
        table = Table(
            title="Validation Results",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        
        table.add_column("Status", width=3, justify="center")
        table.add_column("Check", min_width=30)
        table.add_column("Result", min_width=40)
        
        # Add each result as a table row
        for result in self.results:
            status_symbol = self.STATUS_SYMBOLS.get(result.status, "?")
            status_color = self.STATUS_COLORS.get(result.status, "white")
            
            table.add_row(
                f"[{status_color}]{status_symbol}[/{status_color}]",
                result.name,
                f"[{status_color}]{result.message}[/{status_color}]",
            )
        
        self.console.print(table)
        self.console.print()
        
        # Print summary statistics
        self._print_statistics()
    
    def _print_statistics(self) -> None:
        """Print summary statistics panel."""
        stats = self._calculate_statistics()
        
        total = stats['total']
        if total == 0:
            self.console.print("[dim]No validation checks performed.[/dim]")
            return
        
        success_pct = (stats['success'] / total) * 100 if total > 0 else 0
        
        # Determine overall status and color based on results
        if stats['failure'] > 0 or stats['error'] > 0:
            overall_color = "red"
            overall_status = "ISSUES FOUND"
        elif stats['warning'] > 0:
            overall_color = "yellow"
            overall_status = "WARNINGS"
        elif stats['success'] > 0:
            overall_color = "green"
            overall_status = "ALL PASSED"
        else:
            overall_color = "dim"
            overall_status = "SKIPPED"
        
        # Build summary text
        summary = Text()
        summary.append("Summary: ", style="bold")
        summary.append(f"{overall_status}", style=f"bold {overall_color}")
        summary.append(f" - {stats['success']}/{total} passed ({success_pct:.0f}%)")
        
        # Append counts for non-zero categories
        if stats['failure'] > 0:
            summary.append(f", {stats['failure']} failed", style="red")
        if stats['warning'] > 0:
            summary.append(f", {stats['warning']} warnings", style="yellow")
        if stats['error'] > 0:
            summary.append(f", {stats['error']} errors", style="red")
        if stats['skipped'] > 0:
            summary.append(f", {stats['skipped']} skipped", style="dim")
        
        self.console.print(Panel(summary, border_style=overall_color))
        self.console.print()
    
    def _calculate_statistics(self) -> dict:
        """
        Calculate result statistics.
        
        Returns:
            Dict with counts: total, success, failure, warning, skipped, error
        """
        stats = {
            'total': len(self.results),
            'success': 0,
            'failure': 0,
            'warning': 0,
            'skipped': 0,
            'error': 0,
        }
        
        for result in self.results:
            if result.status == ValidationStatus.SUCCESS:
                stats['success'] += 1
            elif result.status == ValidationStatus.FAILURE:
                stats['failure'] += 1
            elif result.status == ValidationStatus.WARNING:
                stats['warning'] += 1
            elif result.status == ValidationStatus.SKIPPED:
                stats['skipped'] += 1
            elif result.status == ValidationStatus.ERROR:
                stats['error'] += 1
        
        return stats
    
    def export_json(self, output_path: str | Path) -> None:
        """
        Export results to a JSON file.
        
        Creates a structured JSON file with metadata, statistics,
        and detailed results. Useful for automation and parsing.
        
        Args:
            output_path: Path for the output JSON file
        
        Example output structure:
            {
                "metadata": {"client": "...", "timestamp": "..."},
                "statistics": {"total": 10, "success": 8, ...},
                "results": [{"name": "...", "status": "...", ...}]
            }
        """
        output_path = Path(output_path)
        
        report = {
            'metadata': {
                'client': self.config.client,
                'engagement_id': self.config.engagement_id,
                'timestamp': datetime.now().isoformat(),
                'version': '0.1.0',
            },
            'statistics': self._calculate_statistics(),
            'results': [
                {
                    'name': r.name,
                    'status': r.status.value,
                    'message': r.message,
                    'details': r.details,
                }
                for r in self.results
            ]
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.console.print(f"[green]Report exported to: {output_path}[/green]")
    
    def export_markdown(self, output_path: str | Path) -> None:
        """
        Export results to a Markdown file.
        
        Creates a formatted Markdown report suitable for documentation,
        client deliverables, or engagement records.
        
        Args:
            output_path: Path for the output Markdown file
        """
        output_path = Path(output_path)
        stats = self._calculate_statistics()
        
        lines = [
            f"# Pretest Validation Report",
            f"",
            f"**Client:** {self.config.client}  ",
            f"**Engagement:** {self.config.engagement_id}  ",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"",
            f"## Summary",
            f"",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Total Checks | {stats['total']} |",
            f"| Passed | {stats['success']} |",
            f"| Failed | {stats['failure']} |",
            f"| Warnings | {stats['warning']} |",
            f"| Errors | {stats['error']} |",
            f"| Skipped | {stats['skipped']} |",
            f"",
            f"## Detailed Results",
            f"",
            f"| Status | Check | Result |",
            f"|:------:|-------|--------|",
        ]
        
        # Add each result as a table row
        for result in self.results:
            symbol = self.STATUS_SYMBOLS.get(result.status, "?")
            lines.append(f"| {symbol} | {result.name} | {result.message} |")
        
        lines.append("")
        
        # Add details section for results with extra data
        results_with_details = [r for r in self.results if r.details]
        if results_with_details:
            lines.append("## Details")
            lines.append("")
            
            for result in results_with_details:
                lines.append(f"### {result.name}")
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(result.details, indent=2))
                lines.append("```")
                lines.append("")
        
        with open(output_path, 'w') as f:
            f.write('\n'.join(lines))
        
        self.console.print(f"[green]Markdown report exported to: {output_path}[/green]")
    
    def get_exit_code(self) -> int:
        """
        Determine the appropriate exit code based on results.
        
        Returns:
            0 if all checks passed or only warnings
            1 if any checks failed or errored
        
        Use this for CI/CD integration:
            exit_code = report.get_exit_code()
            sys.exit(exit_code)
        """
        stats = self._calculate_statistics()
        
        # Return non-zero if any failures or errors
        if stats['failure'] > 0 or stats['error'] > 0:
            return 1
        
        # Warnings don't fail the run
        return 0

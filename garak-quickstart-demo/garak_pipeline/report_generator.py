"""
Enhanced HTML Report Generator for Garak Scans.

Generate interactive, visually appealing HTML reports from Garak JSONL output.
"""

import logging
from pathlib import Path
from typing import Optional

from .report_data_processor import parse_garak_report
from .report_templates import generate_html_report

logger = logging.getLogger(__name__)


def generate_enhanced_report(
    jsonl_path: str,
    output_path: Optional[str] = None,
    title: Optional[str] = None,
) -> str:
    """
    Generate enhanced HTML report from Garak JSONL file.
    
    Args:
        jsonl_path: Path to Garak report JSONL file
        output_path: Path to save HTML report (default: same dir as JSONL)
        title: Custom report title (default: auto-generated)
        
    Returns:
        Path to generated HTML report
        
    Example:
        >>> generate_enhanced_report(
        ...     "scan_reports/garak.abc123.report.jsonl",
        ...     "scan_reports/enhanced_report.html",
        ...     "Security Scan - Granite 3.3"
        ... )
    """
    logger.info(f"Generating enhanced report from: {jsonl_path}")
    
    # Parse JSONL data
    try:
        data = parse_garak_report(jsonl_path)
    except Exception as e:
        logger.error(f"Failed to parse report: {e}")
        raise
    
    # Generate title if not provided
    if title is None:
        model_name = data.get("config", {}).get("model_name", "Unknown Model")
        title = f"Garak Security Scan - {model_name}"
    
    # Generate HTML
    try:
        html_content = generate_html_report(data, title)
    except Exception as e:
        logger.error(f"Failed to generate HTML: {e}")
        raise
    
    # Determine output path
    if output_path is None:
        input_path = Path(jsonl_path)
        output_path = input_path.parent / f"{input_path.stem}_enhanced.html"
    
    output_path = Path(output_path)
    
    # Write HTML file
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logger.info(f"Report saved to: {output_path}")
    except Exception as e:
        logger.error(f"Failed to write report: {e}")
        raise
    
    return str(output_path.absolute())


def generate_report_from_s3(
    s3_client,
    bucket: str,
    key: str,
    output_path: str,
    title: Optional[str] = None,
) -> str:
    """
    Generate enhanced HTML report from Garak JSONL file in S3.
    
    Args:
        s3_client: Boto3 S3 client
        bucket: S3 bucket name
        key: S3 object key for JSONL file
        output_path: Local path to save HTML report
        title: Custom report title
        
    Returns:
        Path to generated HTML report
    """
    import tempfile
    
    logger.info(f"Downloading report from s3://{bucket}/{key}")
    
    # Download JSONL to temp file
    with tempfile.NamedTemporaryFile(mode='w+b', suffix='.jsonl', delete=False) as tmp:
        s3_client.download_fileobj(bucket, key, tmp)
        tmp_path = tmp.name
    
    try:
        # Generate report from temp file
        result = generate_enhanced_report(tmp_path, output_path, title)
        return result
    finally:
        # Clean up temp file
        try:
            Path(tmp_path).unlink()
        except:
            pass


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m garak_pipeline.report_generator <jsonl_path> [output_path]")
        sys.exit(1)
    
    jsonl_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    logging.basicConfig(level=logging.INFO)
    
    try:
        result_path = generate_enhanced_report(jsonl_path, output_path)
        print(f"\n✅ Report generated successfully!")
        print(f"📄 Output: {result_path}")
    except Exception as e:
        print(f"\n❌ Error generating report: {e}")
        sys.exit(1)

#!/usr/bin/env python3
"""
AI Security Log Analyzer - Main Entry Point
"""
import asyncio
import argparse
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
from app.api import app
from agents.graph import security_graph
from storage import init_storage
import uvicorn

async def process_logs_cli(log_path: str, window_hours: int = 24):
    """CLI interface for processing logs"""
    print(f"Processing log file: {log_path}")
    print(f"Analysis window: {window_hours} hours")
    
    if not Path(log_path).exists():
        print(f"Error: Log file not found: {log_path}")
        return
    
    # Process through the graph
    result = await security_graph.process_logs(log_path, window_hours)
    
    # Display results
    incidents = result.get("incidents", [])
    metadata = result.get("metadata", {})
    summary = result.get("summary", {})
    
    print(f"\nAnalysis Results:")
    print(f"   Processed logs: {metadata.get('ingested_count', 0)}")
    print(f"   Indexed chunks: {metadata.get('indexed_count', 0)}")
    print(f"   Detected incidents: {len(incidents)}")
    
    if incidents:
        print(f"\nSecurity Incidents Found:")
        for i, incident in enumerate(incidents[:5], 1):  # Show first 5
            print(f"   {i}. [{incident['severity'].upper()}] {incident['type']}")
            print(f"      {incident['summary']}")
            print(f"      Recommendations: {len(incident['recommendations'])}")
            print()
    
    if summary:
        print(f"Incident Summary:")
        severity_breakdown = summary.get('severity_breakdown', {})
        for severity, count in severity_breakdown.items():
            if count > 0:
                print(f"   {severity.capitalize()}: {count}")
    
    print("Analysis complete!")

def start_server(host: str = "0.0.0.0", port: int = 8000, reload: bool = False):
    """Start the FastAPI server"""
    print(f"Starting AI Security Log Analyzer API server")
    print(f"Server will be available at http://{host}:{port}")
    print(f"API documentation at http://{host}:{port}/docs")
    
    uvicorn.run(
        "app.api:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )

def init_system():
    """Initialize the system"""
    print("Initializing AI Security Log Analyzer...")
    init_storage()
    print("System initialized successfully!")

def main():
    parser = argparse.ArgumentParser(description="AI Security Log Analyzer")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Init command
    init_parser = subparsers.add_parser('init', help='Initialize the system')
    
    # Process command
    process_parser = subparsers.add_parser('process', help='Process log files')
    process_parser.add_argument('log_path', help='Path to log file (.log or .jsonl)')
    process_parser.add_argument('--window', type=int, default=24, help='Analysis window in hours (default: 24)')
    
    # Server command
    server_parser = subparsers.add_parser('server', help='Start API server')
    server_parser.add_argument('--host', default='0.0.0.0', help='Host to bind (default: 0.0.0.0)')
    server_parser.add_argument('--port', type=int, default=8000, help='Port to bind (default: 8000)')
    server_parser.add_argument('--reload', action='store_true', help='Enable auto-reload for development')
    
    args = parser.parse_args()
    
    if args.command == 'init':
        init_system()
    
    elif args.command == 'process':
        asyncio.run(process_logs_cli(args.log_path, args.window))
    
    elif args.command == 'server':
        # Initialize storage before starting server
        init_system()
        start_server(args.host, args.port, args.reload)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
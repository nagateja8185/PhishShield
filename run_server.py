#!/usr/bin/env python3
"""
PhishShield Server Startup Script
Entry point for running the PhishShield application
"""

import sys
import os

# Add the project directory to Python path
project_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_dir)

from server.server import create_server


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='PhishShield - AI-Powered Phishing Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python run_server.py              # Start server on default port 8000
  python run_server.py --port 8080  # Start server on port 8080
  python run_server.py --host 127.0.0.1 --port 5000  # Custom host and port
        '''
    )
    
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Host to bind to (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=8000,
        help='Port to bind to (default: 8000)'
    )
    
    args = parser.parse_args()
    
    # Print banner
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║   ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗███████╗██╗     ████████╗   ║
    ║   ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝██║     ██║    ██║  ║
    ║   ██████╔╝███████║██║███████╗███████║█████╗  ██║     ██║    ██║  ║
    ║   ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██╔══╝  ██║     ██║    ██║  ║
    ║   ██║     ██║  ██║██║███████║██║  ██║███████╗╚██████╗████████║    ║
    ║   ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝    ║
    ║                                                                  ║
    ║        AI-Powered Email & URL Phishing Detection                 ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
    
    # Check if models exist
    models_dir = os.path.join(project_dir, 'ml', 'models')
    email_model = os.path.join(models_dir, 'email_model.pkl')
    url_model = os.path.join(models_dir, 'url_model.pkl')
    
    if not os.path.exists(email_model) or not os.path.exists(url_model):
        print("WARNING: ML models not found!")
        print(f"Expected models in: {models_dir}")
        print("\nPlease train the models first by running:")
        print("  python ml/train_models.py")
        print("\nStarting server anyway... (predictions will fail until models are trained)\n")
    
    # Create and start server
    server = create_server(host=args.host, port=args.port)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n\nShutdown requested by user.")
        server.stop()
    except Exception as e:
        print(f"\n\nError starting server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

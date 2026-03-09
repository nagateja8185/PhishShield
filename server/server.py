"""
PhishShield HTTP Server
Main server module that sets up and runs the HTTP server
"""

import os
import sys
import signal
from http.server import HTTPServer

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.request_handler import PhishShieldHandler


class PhishShieldServer:
    """Main server class for PhishShield"""
    
    def __init__(self, host='0.0.0.0', port=8000):
        self.host = host
        self.port = port
        self.server = None
        self.running = False
    
    def start(self):
        """Start the HTTP server"""
        # Initialize the predictor before starting server
        print("Initializing ML models...")
        PhishShieldHandler.initialize_predictor()
        
        # Create server
        self.server = HTTPServer((self.host, self.port), PhishShieldHandler)
        self.running = True
        
        print(f"\n{'='*60}")
        print(f"PhishShield Server Started")
        print(f"{'='*60}")
        print(f"Server running at http://{self.host}:{self.port}")
        print(f"Frontend: http://localhost:{self.port}")
        print(f"\nPress Ctrl+C to stop the server")
        print(f"{'='*60}\n")
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        try:
            while self.running:
                self.server.handle_request()
        except Exception as e:
            if self.running:
                print(f"Server error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the HTTP server"""
        if self.server:
            print("\nShutting down server...")
            self.server.server_close()
            self.running = False
            print("Server stopped.")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print("\nShutdown signal received...")
        self.running = False


def create_server(host='0.0.0.0', port=8000):
    """Factory function to create a server instance"""
    return PhishShieldServer(host, port)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='PhishShield HTTP Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to (default: 8000)')
    
    args = parser.parse_args()
    
    server = create_server(host=args.host, port=args.port)
    server.start()

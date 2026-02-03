#!/usr/bin/env python3
"""
Advanced Password Manager - Application Launcher

This script launches the Advanced Password Manager application.
Works on Windows, macOS, and Linux.

Usage:
    python run.py              # Normal mode
    python run.py --debug      # Debug mode
    python run.py --help       # Show help
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# Add src directory to path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(
        description='Advanced Password Manager - Secure credential storage',
        epilog='For more information, visit: https://github.com/Gorkhali-Aayush/Advance_password_manager'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode with verbose logging'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Advanced Password Manager v1.0.0'
    )
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled")
    
    try:
        # Import the main application
        logger.info("Starting Advanced Password Manager...")
        from src.main import PasswordManagerApp
        
        # Create and run the application
        app = PasswordManagerApp()
        logger.info("Application initialized successfully")
        app.run()
        
    except ImportError as e:
        logger.error(f"Failed to import application modules: {e}")
        print(f"Error: Could not start the application. Missing dependencies.")
        print(f"Please ensure all requirements are installed: pip install -r requirements.txt")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"Application error: {e}", exc_info=True)
        print(f"Error: An unexpected error occurred.")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

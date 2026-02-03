# Running the Advanced Password Manager

This directory contains scripts to easily launch the Advanced Password Manager application.

## Quick Start

### Windows
```bash
# Double-click run.bat
# OR from command line:
run.bat

# With debug mode:
run.bat --debug
```

### Linux / macOS
```bash
# Make script executable (first time only):
chmod +x run.sh

# Run the application:
./run.sh

# With debug mode:
./run.sh --debug
```

### Cross-Platform (Python)
```bash
# On any platform:
python run.py

# With debug mode:
python run.py --debug

# Show help:
python run.py --help
```

## Prerequisites

Before running the application, ensure you have:

1. **Python 3.10 or higher** installed
   ```bash
   python --version  # Check your Python version
   ```

2. **Virtual environment created**
   ```bash
   python -m venv .venv
   ```

3. **Dependencies installed**
   ```bash
   # Activate virtual environment first
   # Windows: .venv\Scripts\activate.bat
   # Linux/macOS: source .venv/bin/activate
   
   # Then install:
   pip install -r requirements.txt
   ```

4. **Database configured**
   - MySQL 5.7+ should be running
   - Database credentials in `.env` file
   - See `.env.example` for configuration template

## Script Details

### run.py
- **Cross-platform** Python launcher
- Works on Windows, Linux, and macOS
- Supports `--debug` and `--help` flags
- Best for development and testing

### run.bat
- **Windows-only** batch script
- Automatically activates virtual environment
- Checks for required dependencies
- Provides error reporting

### run.sh
- **Linux/macOS** shell script
- Automatically activates virtual environment
- Checks for required dependencies
- Provides error reporting

## Troubleshooting

### "Python is not recognized"
- Ensure Python is installed: https://python.org
- Add Python to your PATH environment variable
- Use `python3` instead of `python` on some systems

### "Module not found" error
- Ensure virtual environment is activated
- Run: `pip install -r requirements.txt`
- Check that all packages installed successfully

### "No module named 'tkinter'"
- Windows: Tkinter should be included with Python
- Linux: Install tkinter separately
  ```bash
  sudo apt-get install python3-tk  # Ubuntu/Debian
  sudo dnf install python3-tkinter  # Fedora/RHEL
  ```
- macOS: Usually included with Python

### "Database connection failed"
- Ensure MySQL is running
- Check credentials in `.env` file
- Verify database exists: `password_manager`
- Run database initialization script if needed

### Application crashes on startup
- Enable debug mode: `run.py --debug`
- Check logs for detailed error messages
- Verify all dependencies are installed
- Check `.env` configuration

## Debug Mode

For troubleshooting, use debug mode:

```bash
# Windows
run.bat --debug

# Linux/macOS
./run.sh --debug

# Cross-platform
python run.py --debug
```

Debug mode provides:
- Verbose logging output
- Detailed error messages
- Full stack traces
- Performance information

## Development

For development and testing:

```bash
# Run with debug mode
python run.py --debug

# Run with specific Python version
python3.10 run.py

# Run from source directory
cd src
python -m main
```

## Security Notes

- Never share `.env` files containing credentials
- Keep virtual environment local (don't commit to git)
- Ensure MySQL password is secure
- Use strong master password when creating account
- Regularly backup database

## Support

For issues or questions:
- Check the documentation in `/docs`
- Review error logs in `/backups`
- Visit: https://github.com/Gorkhali-Aayush/Advance_password_manager
- Create an issue on GitHub

## Additional Commands

```bash
# Create admin user
python createAdminUser.py

# Run tests
pytest

# Run with coverage
pytest --cov=src

# Run specific tests
pytest tests/test_crypto.py

# Generate coverage report
pytest --cov=src --cov-report=html
```

## Environment Setup

First-time setup:

```bash
# 1. Clone the repository
git clone https://github.com/Gorkhali-Aayush/Advance_password_manager.git
cd Advance_password_manager/Advance_password_manager

# 2. Create virtual environment
python -m venv .venv

# 3. Activate virtual environment
# Windows:
.venv\Scripts\activate.bat
# Linux/macOS:
source .venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Setup .env file
cp .env.example .env
# Edit .env with your database credentials

# 6. Initialize database (if needed)
# Import the SQL schema from database_queries/password_manager.sql

# 7. Create admin user
python createAdminUser.py

# 8. Run the application
python run.py
```

---

**Enjoy using Advanced Password Manager!** 🔐

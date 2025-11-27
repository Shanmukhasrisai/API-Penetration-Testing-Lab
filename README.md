# API-Penetration-Testing-Lab
A comprehensive API penetration testing lab.

## Installation

### Prerequisites

Before setting up the project, ensure you have the following installed:

- Python 3.7 or higher
- pip (Python package installer)
- Git

### Setup Instructions

#### 1. Clone the Repository

You can clone this repository using HTTPS or SSH:

**Using HTTPS:**
```bash
git clone https://github.com/Shanmukhasrisai/API-Penetration-Testing-Lab.git
```

**Using SSH:**
```bash
git clone git@github.com:Shanmukhasrisai/API-Penetration-Testing-Lab.git
```

**Using GitHub CLI:**
```bash
gh repo clone Shanmukhasrisai/API-Penetration-Testing-Lab
```

#### 2. Navigate to the Project Directory

```bash
cd API-Penetration-Testing-Lab
```

#### 3. Create a Virtual Environment (Recommended)

Creating a virtual environment helps isolate project dependencies:

**On Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**On macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 4. Install Required Dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not available, install the necessary packages manually:
```bash
pip install flask requests
```

#### 5. Run the Application

```bash
python api.py.py
```

#### 6. Access the API

Once the application is running, the API will be available at:
```
http://localhost:5000
```

### Troubleshooting

- **Permission Errors**: Try running commands with `sudo` (Linux/macOS) or as Administrator (Windows)
- **Port Already in Use**: Ensure that port 5000 is not already in use by another application
- **Dependency Installation Fails**: Try upgrading pip first: `pip install --upgrade pip`
- **Virtual Environment Issues**: Make sure you've activated the virtual environment before installing dependencies

### Additional Notes

- This is a lab environment designed for educational purposes only
- Do not use this application in production environments
- Always follow ethical hacking guidelines and obtain proper authorization before conducting any penetration tests
- Review the LICENSE file for usage terms and conditions

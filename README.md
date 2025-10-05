# Hybrid Encryption Web Application

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Django](https://img.shields.io/badge/Django-4.2.13-green.svg)](https://www.djangoproject.com/)
[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)

A robust web-based data encryption and decryption platform that implements hybrid encryption techniques combining symmetric (AES) and asymmetric (RSA) cryptography. This application ensures secure data handling with integrity verification, user authentication, and role-based access control.

## 🌐 Live Demo

The application is hosted at: [https://mis-cyb3rcych0.pythonanywhere.com/](https://mis-cyb3rcych0.pythonanywhere.com/)

## 📋 Table of Contents

- [Features](#features)
- [Technology Stack](#technology-stack)
- [Architecture](#architecture)
- [Security Features](#security-features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [Testing](#testing)
- [License](#license)
- [Authors](#authors)
- [Contact](#contact)

## ✨ Features

### Core Encryption Capabilities
- **Hybrid Encryption**: Combines AES-256 (symmetric) and RSA-2048 (asymmetric) algorithms for optimal security and performance
- **Multi-format Support**: Encrypt and decrypt text data, files, and combined text-file packages
- **Integrity Verification**: SHA-256 hashing ensures data integrity and detects tampering
- **Secure Key Management**: Automatic RSA key pair generation per user with secure storage

### User Management
- **Role-based Access Control**: Standard users can encrypt; only superusers/administrators can decrypt
- **User Authentication**: Secure login and registration system
- **Profile Management**: User-specific encryption key management

### Administrative Features
- **Backend Dashboard**: Comprehensive admin interface for system management
- **Audit Logging**: Detailed decryption activity tracking and reporting
- **User Analytics**: Monitor user activity and case statistics
- **Data Export**: CSV export functionality for encrypted case data

### Advanced Functionality
- **Search & Filter**: Advanced search by case ID, date ranges, and user
- **Bulk Operations**: Handle multiple encryption/decryption operations
- **Responsive Design**: Mobile-friendly Bootstrap-based UI
- **Real-time Feedback**: User notifications for operation status

## 🛠 Technology Stack

### Backend
- **Framework**: Django 4.2.13
- **Database**: MySQL (via PyMySQL)
- **Cryptography**: PyCryptodome 3.20.0
- **Authentication**: Django's built-in authentication system

### Frontend
- **HTML5/CSS3**: Semantic markup and responsive design
- **Bootstrap 5**: Modern UI components and responsive grid
- **JavaScript**: Client-side interactivity and validation

### Infrastructure
- **WSGI Server**: Gunicorn (for production)
- **Database**: MySQL 8.0+
- **Hosting**: PythonAnywhere (current deployment)

### Development Tools
- **Version Control**: Git
- **Code Quality**: Qodana (code analysis)
- **Containerization**: Docker support
- **Environment Management**: python-dotenv

## 🏗 Architecture

The application follows a modular Django architecture:

```
hybrid-encryption-webapp/
├── cwms/                    # Django project settings
├── hybridapp/              # Main application
│   ├── models.py          # Database models (KeyPair, File, Text, etc.)
│   ├── views.py           # Business logic and view handlers
│   ├── forms.py           # Form definitions
│   ├── admin.py           # Django admin configuration
│   ├── templates/         # HTML templates
│   ├── static/            # CSS, JS, images
│   └── migrations/        # Database migrations
├── media/                 # User-uploaded files
├── static/                # Collected static files
└── requirements.txt       # Python dependencies
```

### Data Flow
1. **User Registration**: Automatic RSA key pair generation
2. **Encryption Process**:
   - Generate random AES session key
   - Encrypt data with AES
   - Encrypt AES key with user's RSA public key
   - Store encrypted data and hash for integrity
3. **Decryption Process** (Admin only):
   - Decrypt AES key with RSA private key
   - Decrypt data with AES
   - Verify integrity using stored hash

## 🔒 Security Features

### Cryptographic Security
- **AES-256-GCM**: Industry-standard symmetric encryption with authenticated encryption
- **RSA-2048**: Asymmetric encryption for secure key exchange
- **SHA-256**: Cryptographic hashing for integrity verification
- **OAEP Padding**: Secure padding scheme for RSA encryption

### Application Security
- **CSRF Protection**: Django's built-in CSRF middleware
- **XSS Prevention**: Template escaping and input sanitization
- **SQL Injection Prevention**: Django ORM with parameterized queries
- **Session Security**: Secure session management with cache control
- **Access Control**: Role-based permissions and authentication decorators

### Operational Security
- **Audit Trail**: Complete logging of decryption activities
- **Data Isolation**: User-specific key pairs and encrypted data
- **Secure File Handling**: Safe file upload and storage practices
- **Environment Variables**: Sensitive configuration via environment variables

## 📋 Prerequisites

- Python 3.12 or higher
- MySQL 8.0+ or compatible database
- Git for version control
- Virtual environment tool (venv or virtualenv)

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/cyb3r-cych0/hybrid-encryption-webapp.git
cd hybrid-encryption-webapp
```

### 2. Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Database Setup
```bash
# Apply migrations
python manage.py makemigrations
python manage.py migrate
```

### 5. Create Superuser (Admin)
```bash
python manage.py createsuperuser
```

### 6. Run Development Server
```bash
python manage.py runserver
```

Access the application at: `http://localhost:8000`

## ⚙ Configuration

### Environment Variables
Create a `.env` file in the project root:

```env
DEBUG=True
SECRET_KEY=your-secret-key-here
DATABASE_URL=mysql://user:password@localhost:3306/dbname
ALLOWED_HOSTS=localhost,127.0.0.1
```

### Database Configuration
Update `cwms/settings.py` for database connection:

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'your_database_name',
        'USER': 'your_username',
        'PASSWORD': 'your_password',
        'HOST': 'localhost',
        'PORT': '3306',
    }
}
```

## 📖 Usage

### For Regular Users
1. **Register**: Create account (RSA keys generated automatically)
2. **Login**: Access the encryption dashboard
3. **Encrypt Data**:
   - Upload files or enter text
   - Provide case ID and metadata
   - Submit for encryption
4. **View Cases**: Browse encrypted data in personal dashboard

### For Administrators
1. **Login as Superuser**: Access admin privileges
2. **Decrypt Data**: Select records for decryption
3. **Audit Activities**: Monitor decryption logs
4. **Manage Users**: View user statistics and records
5. **Export Data**: Download record data as CSV

### Key Workflows

#### Encrypting a File
1. Navigate to Encrypt → Upload File
2. Enter rcorde ID
3. Select record to encrypt
4. Submit - record is encrypted and stored

#### Decrypting Data (Admin Only)
1. Access Decrypt dashboard
2. Search for specific record
3. Click decrypt - integrity check performed
4. Download decrypted record

## 🔗 API Endpoints

The application provides RESTful endpoints for programmatic access:

| Method | Endpoint | Description | Access |
|--------|----------|-------------|---------|
| GET | `/` | Frontend landing page | Public |
| GET/POST | `/register/` | User registration | Public |
| GET/POST | `/login/` | User authentication | Public |
| GET | `/encrypt/` | Encryption dashboard | Authenticated |
| POST | `/encrypt/text/` | Encrypt text record | Authenticated |
| POST | `/encrypt/file/` | Encrypt file record | Authenticated |
| GET | `/decrypt/` | Decryption dashboard | Admin Only |
| GET | `/decrypt/{id}/` | Decrypt specific record | Admin Only |

## 🚢 Deployment

### PythonAnywhere Deployment
1. Create PythonAnywhere account
2. Upload project files
3. Configure virtual environment
4. Set up MySQL database
5. Configure WSGI file
6. Set environment variables
7. Reload web app

### Docker Deployment
```bash
# Build image
docker build -t hybrid-encryption .

# Run container
docker run -p 8000:8000 hybrid-encryption
```

### Production Considerations
- Use production-grade WSGI server (Gunicorn)
- Configure HTTPS/SSL
- Set up database backups
- Implement monitoring and logging
- Configure firewall and security groups

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/AmazingFeature`
3. **Commit** changes: `git commit -m 'Add AmazingFeature'`
4. **Push** to branch: `git push origin feature/AmazingFeature`
5. **Open** a Pull Request

### Development Guidelines
- Follow PEP 8 style guidelines
- Write comprehensive tests
- Update documentation
- Ensure security best practices
- Test across different environments

## 🧪 Testing

### Running Tests
```bash
# Run Django tests
python manage.py test

# Run with coverage
coverage run manage.py test
coverage report
```

### Test Coverage
- Unit tests for encryption/decryption functions
- Integration tests for user workflows
- Security tests for access control
- Performance tests for large file handling

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- **@cyb3r-cych0** - *Initial work and development*
  - Email: minigates21@gmail.com
  - GitHub: [@cyb3r-cych0](https://github.com/cyb3r-cych0)

## 📞 Contact

**Project Link**: [https://github.com/cyb3r-cych0/hybrid-encryption-webapp](https://github.com/cyb3r-cych0/hybrid-encryption-webapp)

**Live Application**: [https://mis-cyb3rcych0.pythonanywhere.com/](https://mis-cyb3rcych0.pythonanywhere.com/)

---

**Note**: This application is designed for educational and demonstration purposes. For production use in sensitive environments, additional security audits and compliance checks are recommended.

# Security Policy

## Supported Versions

We take security seriously and actively maintain security updates for the following versions of the Hybrid Encryption Web Application:

| Version | Supported          |
| ------- | ------------------ |
| 1.2.0   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it to us as soon as possible. We appreciate your help in keeping our users safe.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by emailing:

**minigates21@gmail.com**

You can also use the GitHub Security Advisories feature:

1. Go to the Security tab in this repository
2. Click "Report a vulnerability"
3. Fill out the vulnerability report form

### What to Include

When reporting a security vulnerability, please include:

- A clear description of the vulnerability
- Steps to reproduce the issue
- Potential impact and severity
- Any suggested fixes or mitigations (optional)
- Your contact information for follow-up

### Response Timeline

We will acknowledge your report within 48 hours and provide a more detailed response within 7 days indicating our next steps.

We will keep you informed about our progress throughout the process of fixing the vulnerability.

### Disclosure Policy

- We will credit you (if desired) once the vulnerability is fixed and disclosed
- We follow responsible disclosure practices
- We will not disclose vulnerability details until a fix is available
- We may delay disclosure to allow users time to update

## Security Considerations

### Cryptographic Security

This application implements hybrid encryption using:

- **AES-256-GCM**: Symmetric encryption with authenticated encryption
- **RSA-2048**: Asymmetric encryption for key exchange
- **SHA-256**: Cryptographic hashing for integrity verification
- **OAEP Padding**: Secure padding scheme for RSA operations

### Application Security Features

- **Role-based Access Control**: Only administrators can decrypt data
- **CSRF Protection**: Django's built-in CSRF middleware
- **XSS Prevention**: Template escaping and input sanitization
- **SQL Injection Prevention**: Django ORM with parameterized queries
- **Session Security**: Secure session management
- **Audit Logging**: Complete logging of decryption activities

### Best Practices for Users

1. **Use Strong Passwords**: Choose complex passwords for user accounts
2. **Regular Updates**: Keep the application and dependencies updated
3. **Secure Environment**: Deploy in secure environments with proper access controls
4. **Monitor Logs**: Regularly review audit logs for suspicious activity
5. **Backup Data**: Maintain secure backups of encrypted data

### Security Updates

Security updates will be released as patch versions with the following naming convention:

- **Critical**: Immediate release with high priority
- **High**: Release within 7 days
- **Medium**: Release within 30 days
- **Low**: Release with next regular update

## Contact

For security-related questions or concerns:

- Email: minigates21@gmail.com
- Project Repository: https://github.com/cyb3r-cych0/hybrid-encryption-webapp

## Acknowledgments

We appreciate the security research community for their contributions to keeping open source software secure. Security researchers who report vulnerabilities responsibly will be acknowledged in our security advisories (unless they request anonymity).

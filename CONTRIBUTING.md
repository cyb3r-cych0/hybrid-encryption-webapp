# Contributing to Hybrid Encryption Web Application

Thank you for your interest in contributing to the Hybrid Encryption Web Application! We welcome contributions from the community to help improve and expand this project. This document provides guidelines and information to help you get started.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)
- [Security Vulnerabilities](#security-vulnerabilities)

## Code of Conduct

This project adheres to a code of conduct to ensure a welcoming environment for all contributors. By participating, you agree to:

- Be respectful and inclusive
- Focus on constructive feedback
- Accept responsibility for mistakes
- Show empathy towards other contributors
- Help create a positive community

## How Can I Contribute?

### Types of Contributions

- **Bug Fixes**: Identify and fix bugs in the codebase
- **Features**: Implement new features or enhance existing ones
- **Documentation**: Improve documentation, README, or code comments
- **Testing**: Write or improve tests
- **Security**: Report or fix security vulnerabilities
- **UI/UX**: Improve user interface and user experience

### First Time Contributors

If you're new to open source or this project:

1. Look for issues labeled `good first issue` or `beginner-friendly`
2. Read through the codebase and understand the architecture
3. Start with small fixes or documentation improvements
4. Ask questions in issues or discussions

## Development Setup

### Prerequisites

- Python 3.12 or higher
- MySQL 8.0+ or compatible database
- Git
- Virtual environment tool (venv or virtualenv)

### Local Development Environment

1. **Fork and Clone the Repository**
   ```bash
   git clone https://github.com/your-username/hybrid-encryption-webapp.git
   cd hybrid-encryption-webapp
   ```

2. **Create Virtual Environment**
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # Linux/Mac
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Database Setup**
   ```bash
   # Create MySQL database
   # Update settings.py with your database credentials

   # Run migrations
   python manage.py makemigrations
   python manage.py migrate
   ```

5. **Create Superuser**
   ```bash
   python manage.py createsuperuser
   ```

6. **Run Development Server**
   ```bash
   python manage.py runserver
   ```

7. **Access the Application**
   - Frontend: http://localhost:8000
   - Admin: http://localhost:8000/admin

### Additional Setup for Contributors

- Install development dependencies if any
- Set up pre-commit hooks for code quality
- Configure your IDE with Python and Django support

## Development Workflow

### 1. Choose an Issue

- Check existing issues on GitHub
- Comment on the issue to indicate you're working on it
- Create a new issue if you find a bug or have a feature idea

### 2. Create a Branch

```bash
# Create and switch to a new branch
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number-description
```

### 3. Make Changes

- Write clean, readable code
- Follow the coding standards below
- Add tests for new features
- Update documentation as needed

### 4. Test Your Changes

- Run the test suite
- Test manually in the browser
- Ensure no existing functionality is broken

### 5. Commit Changes

```bash
# Stage your changes
git add .

# Commit with a descriptive message
git commit -m "feat: add new encryption feature

- Implement AES-256 encryption
- Add integrity verification
- Update documentation"
```

### 6. Push and Create Pull Request

```bash
# Push your branch
git push origin feature/your-feature-name

# Create a Pull Request on GitHub
```

## Coding Standards

### Python Code Style

- Follow [PEP 8](https://pep8.org/) style guidelines
- Use 4 spaces for indentation
- Maximum line length: 88 characters (Black formatter default)
- Use descriptive variable and function names
- Add docstrings to functions and classes

### Django-Specific Guidelines

- Use Django's class-based views where appropriate
- Follow Django's URL naming conventions
- Use Django's built-in authentication and authorization
- Implement proper error handling and logging

### Security Considerations

- Never commit sensitive information (API keys, passwords)
- Use environment variables for configuration
- Implement proper input validation and sanitization
- Follow OWASP security guidelines

### Commit Message Format

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Testing
- `chore`: Maintenance

## Testing

### Running Tests

```bash
# Run all tests
python manage.py test

# Run specific app tests
python manage.py test hybridapp

# Run with coverage
coverage run manage.py test
coverage report
```

### Writing Tests

- Write unit tests for models, views, and utilities
- Write integration tests for user workflows
- Test both positive and negative scenarios
- Mock external dependencies when necessary

### Test Coverage Goals

- Aim for 80%+ code coverage
- Test critical security functions thoroughly
- Include edge cases and error conditions

## Submitting Changes

### Pull Request Process

1. **Ensure your PR is ready**:
   - All tests pass
   - Code follows style guidelines
   - Documentation is updated
   - No merge conflicts

2. **Create a Pull Request**:
   - Use a clear, descriptive title
   - Provide detailed description of changes
   - Reference related issues
   - Add screenshots for UI changes

3. **PR Template**:
   - **What does this PR do?**
   - **Why is this change needed?**
   - **How was this tested?**
   - **Screenshots (if applicable)**
   - **Checklist**

4. **Review Process**:
   - Maintainers will review your PR
   - Address any feedback or requested changes
   - Once approved, your PR will be merged

### PR Checklist

- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] No security vulnerabilities introduced
- [ ] Migration files included if needed
- [ ] Breaking changes documented

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

- **Description**: Clear description of the issue
- **Steps to Reproduce**: Step-by-step instructions
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Environment**: OS, browser, Python version
- **Screenshots**: If applicable
- **Additional Context**: Any other relevant information

### Feature Requests

For feature requests, please include:

- **Problem**: What's the problem you're trying to solve?
- **Solution**: Describe your proposed solution
- **Alternatives**: Any alternative solutions considered
- **Additional Context**: Screenshots, mockups, or examples

## Security Vulnerabilities

If you discover a security vulnerability, please:

- **DO NOT** create a public issue
- Email the maintainers directly at [minigates21@gmail.com]
- Provide detailed information about the vulnerability
- Allow time for the issue to be resolved before public disclosure

## Getting Help

- **Documentation**: Check the README and docs folder
- **Issues**: Search existing issues on GitHub
- **Discussions**: Use GitHub Discussions for questions
- **Community**: Join our community chat (if available)

## Recognition

Contributors will be recognized in:
- The project's contributors list
- Release notes
- Special mentions in documentation

Thank you for contributing to the Hybrid Encryption Web Application! Your efforts help make this project better for everyone.

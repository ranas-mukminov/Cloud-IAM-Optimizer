# Contributing to Cloud IAM Optimizer

First off, thank you for considering contributing to Cloud IAM Optimizer! 🎉

This is a **public demo version** of the tool. The enterprise version is deployed as part of commercial audits by [run-as-daemon.ru](https://run-as-daemon.ru).

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Description:** Clear description of the issue
- **Steps to reproduce:** How to reproduce the behavior
- **Expected behavior:** What you expected to happen
- **Actual behavior:** What actually happened
- **Environment:** Python version, OS, cloud provider
- **Logs:** Relevant error messages or stack traces

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Use case:** Describe the problem this enhancement would solve
- **Proposed solution:** How you envision the feature working
- **Alternatives:** Alternative solutions you've considered

### Pull Requests

1. Fork the repository
2. Create a new branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Add tests if applicable
5. Run the linter and formatter:
   ```bash
   flake8 src/
   black src/
   mypy src/
   ```
6. Commit your changes: `git commit -m 'Add some feature'`
7. Push to your fork: `git push origin feature/your-feature-name`
8. Open a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/Cloud-IAM-Optimizer.git
cd Cloud-IAM-Optimizer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install pytest black flake8 mypy

# Run tests
pytest tests/

# Run linter
flake8 src/

# Format code
black src/
```

## Code Style

- Follow [PEP 8](https://pep8.org/) style guide
- Use [PEP 257](https://peps.python.org/pep-0257/) for docstrings
- Use type hints (mypy-compatible)
- Keep functions small and focused
- Add comments for complex logic
- Use descriptive variable names

## Commit Message Guidelines

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit first line to 72 characters
- Reference issues and pull requests liberally

Example:
```
Add GCP IAM support for service accounts

- Implement GCP authentication
- Add service account listing
- Add role binding analysis

Closes #123
```

## What We're Looking For

We especially welcome contributions in these areas:

- **New cloud providers:** Azure AD, Yandex Cloud, VK Cloud Solutions
- **Enhanced analysis:** Policy permission analysis, unused permissions detection
- **Integrations:** SIEM systems, monitoring tools, notification channels
- **Documentation:** Guides, tutorials, use cases
- **Localization:** Additional language support

## Code of Conduct

Be respectful and inclusive. We're all here to learn and build something useful together.

## Questions?

Feel free to open an issue or contact us:
- 🌐 **Website:** [run-as-daemon.ru](https://run-as-daemon.ru)
- 💼 **GitHub:** [@ranas-mukminov](https://github.com/ranas-mukminov)

---

**Thank you for contributing!** 🙏

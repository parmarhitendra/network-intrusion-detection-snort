# Contributing to Snort NIDS Project

First off, thank you for considering contributing to this project! This is an educational cybersecurity project, and contributions from learners and experts alike help make it better for everyone.

## Code of Conduct

By participating in this project, you agree to maintain a respectful, inclusive, and collaborative environment. We welcome contributors of all skill levels.

## How Can I Contribute?

### Reporting Bugs or Issues

If you find a bug or issue:

1. Check if the issue already exists in the [Issues](https://github.com/yourusername/snort-nids-project/issues) section
2. If not, create a new issue with:
   - Clear title describing the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Screenshots if applicable
   - Your environment (OS, Snort version, etc.)

### Suggesting Enhancements

We welcome suggestions for:
- New detection rules
- Additional attack simulations
- Improved documentation
- Better visualizations
- Performance optimizations

Submit enhancement suggestions as GitHub issues with the "enhancement" label.

### Contributing Code

#### Custom Rules

If you've written a useful custom Snort rule:

1. Ensure it's well-commented
2. Include test cases showing it works
3. Document what it detects and why
4. Add it to the appropriate rules file

#### Attack Simulation Scripts

When contributing attack simulation scripts:

1. Include clear usage instructions
2. Add safety warnings
3. Document expected Snort alerts
4. Test thoroughly before submitting

#### Documentation

Documentation improvements are always welcome:

- Fix typos or clarify confusing sections
- Add examples or screenshots
- Translate documentation to other languages
- Create tutorials or guides

## Pull Request Process

1. **Fork the repository** and create your branch from `main`
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write clear, commented code
   - Follow existing code style
   - Update documentation as needed

3. **Test your changes**
   - Verify custom rules trigger correctly
   - Test scripts in a safe environment
   - Check documentation renders properly

4. **Commit your changes**
   ```bash
   git commit -m "Add: brief description of your changes"
   ```
   
   Use conventional commit messages:
   - `Add:` for new features
   - `Fix:` for bug fixes
   - `Docs:` for documentation
   - `Update:` for improvements
   - `Remove:` for deletions

5. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Open a Pull Request**
   - Provide a clear description of changes
   - Reference any related issues
   - Include screenshots if relevant
   - Explain testing performed

## Contribution Guidelines

### Custom Snort Rules

```
# Good rule example with proper documentation
# Description: Detects SSH brute force attempts
# Author: Your Name
# Date: 2026-01-31
# Tested: Yes
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; \
flags:S; threshold:type both, track by_src, count 5, seconds 60; \
sid:1000001; rev:1;)
```

### Python Scripts

```python
#!/usr/bin/env python3
"""
Script Name: attack_simulation.py
Description: Simulates a port scan for testing Snort
Author: Your Name
Date: 2026-01-31
Usage: python3 attack_simulation.py <target_ip>
"""

# Always include proper error handling
# Add comments explaining complex logic
# Follow PEP 8 style guidelines
```

### Documentation

- Use clear, concise language
- Include code examples where helpful
- Add screenshots for visual clarity
- Organize with proper headings
- Test all commands and examples

## What NOT to Contribute

❌ **Do Not Submit:**
- Actual malware or malicious code
- Exploits designed to harm systems
- Credentials or sensitive information
- Copyrighted material without permission
- Untested or broken code
- Rules that generate excessive false positives

## Getting Help

If you need help with your contribution:

1. Check existing documentation
2. Search closed issues for similar questions
3. Ask in the [Discussions](https://github.com/yourusername/snort-nids-project/discussions) section
4. Reach out to maintainers

## Recognition

All contributors will be recognized in:
- The project README
- Release notes (if applicable)
- Our contributors list

## Legal Notice

By contributing, you agree that your contributions will be licensed under the same MIT License that covers this project.

## Questions?

Feel free to open an issue labeled "question" or contact the maintainers directly.

---

Thank you for contributing to cybersecurity education! 🛡️

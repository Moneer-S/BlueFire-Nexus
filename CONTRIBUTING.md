# Contributing to BlueFire-Nexus

Thank you for your interest in contributing to BlueFire-Nexus! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please read it before contributing.

## Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/BlueFire-Nexus.git
   ```
3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```

## Development Guidelines

### Code Style

We follow PEP 8 guidelines and use Black for code formatting. Before submitting a pull request:

1. Format your code:
   ```bash
   black src/
   ```

2. Check for style issues:
   ```bash
   flake8 src/
   ```

3. Type checking:
   ```bash
   mypy src/
   ```

### Testing

We use pytest for testing. Before submitting a pull request:

1. Run tests:
   ```bash
   pytest
   ```

2. Check test coverage:
   ```bash
   pytest --cov=src tests/
   ```

### Documentation

We use Sphinx for documentation. When adding new features:

1. Update relevant documentation files
2. Add docstrings to new functions and classes
3. Build documentation:
   ```bash
   cd docs
   make html
   ```

## Pull Request Process

1. Create a new branch for your feature:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and commit them:
   ```bash
   git add .
   git commit -m "Description of your changes"
   ```

3. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

4. Create a Pull Request

### Pull Request Guidelines

1. Use a clear and descriptive title
2. Provide a detailed description of your changes
3. Include any relevant issue numbers
4. Add tests for new features
5. Update documentation as needed
6. Ensure all tests pass
7. Follow the code style guidelines

## Module Development

### Adding New Modules

1. Create a new module directory in `src/core/`
2. Create the module class file
3. Implement required handlers
4. Add tests
5. Update documentation
6. Add configuration options

### Module Structure

```python
from typing import Dict, Any
from datetime import datetime
import logging

class NewModule:
    """Module description."""
    
    def __init__(self):
        """Initialize the module."""
        self.logger = logging.getLogger(__name__)
        
    def _handle_operation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle specific operation."""
        try:
            # Implementation
            pass
        except Exception as e:
            self._log_error(f"Error in operation: {str(e)}")
            return {"status": "error", "message": str(e)}
```

## Security Considerations

1. Follow security best practices
2. Implement proper error handling
3. Use secure coding practices
4. Add security tests
5. Document security features
6. Consider edge cases

## Testing Guidelines

### Unit Tests

1. Test each function independently
2. Use meaningful test names
3. Test edge cases
4. Mock external dependencies
5. Use fixtures for common setup

### Integration Tests

1. Test module interactions
2. Test configuration loading
3. Test error handling
4. Test security features
5. Test performance

## Documentation Guidelines

### Code Documentation

1. Use clear and concise docstrings
2. Document parameters and return values
3. Include examples where appropriate
4. Document exceptions
5. Follow Google style guide

### API Documentation

1. Document all public methods
2. Include usage examples
3. Document configuration options
4. Include security considerations
5. Document error handling

## Release Process

1. Update version number
2. Update changelog
3. Run tests
4. Build documentation
5. Create release tag
6. Build distribution
7. Deploy to PyPI

## Getting Help

- Join our Discord server
- Check the documentation
- Open an issue
- Contact the maintainers

## License

By contributing, you agree that your contributions will be licensed under the project's MIT License. 
"""Basic test to ensure test suite works"""

def test_import_core():
    """Test that core modules can be imported"""
    from core import scanner
    assert scanner is not None

def test_basic_functionality():
    """Basic test that always passes"""
    assert True
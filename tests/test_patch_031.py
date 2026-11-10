import ast
from pathlib import Path
import unittest
from guard_admin import event_rows

class Patch031Tests(unittest.TestCase):
    def folder(self, value):
        tree = ast.parse((Path(__file__).resolve().parents[1] / 'app.py').read_text())
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Settings')
        node = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'folder')
        node.decorator_list = []
        ns = {}
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'folder_validator', 'exec'), ns)
        return ns['folder'](None, value)
    def test_end_date_overflow_becomes_validation_error(self):
        with self.assertRaises(ValueError):
            event_rows(lambda: None, date_to='9999-12-31')
    def test_invalid_calendar_date_is_validation_error(self):
        with self.assertRaises(ValueError):
            event_rows(lambda: None, date_to='2026-02-30')
    def test_folder_empty_allowed(self):
        self.assertEqual(self.folder(''), '')
    def test_folder_50_allowed(self):
        self.assertEqual(self.folder('x' * 50), 'x' * 50)
    def test_folder_51_rejected(self):
        with self.assertRaises(ValueError): self.folder('x' * 51)
    def test_folder_controls_rejected(self):
        with self.assertRaises(ValueError): self.folder('x' + chr(10))

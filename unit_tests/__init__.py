import os
import sys

_path = os.path.dirname(os.path.realpath(__file__))
_actions = os.path.abspath(os.path.join(_path, '../actions'))
_hooks = os.path.abspath(os.path.join(_path, '../hooks'))
_charmhelpers = os.path.abspath(os.path.join(_path, '../charmhelpers'))
_unit_tests = os.path.abspath(os.path.join(_path, '../unit_tests'))


def _add_path(path):
    if path not in sys.path:
        sys.path.insert(1, path)

_add_path(_actions)
_add_path(_hooks)
_add_path(_charmhelpers)
_add_path(_unit_tests)

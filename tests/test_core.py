import json
import unittest

from autoprotect.core import (
    AutoprotectError, BackendError, IndeterminateError, ValidationError,
    canonical, digest, identifier, integer, load_json,
    package_name, text, version,
)


class CoreTests(unittest.TestCase):
    def test_uncertain_mutation_is_not_a_confirmed_pre_mutation_failure(self):
        self.assertTrue(issubclass(IndeterminateError, AutoprotectError))
        self.assertFalse(issubclass(IndeterminateError, BackendError))
        try:
            raise IndeterminateError("synthetic interrupted install")
        except BackendError:
            self.fail("uncertain mutation was classified as pre-mutation failure")
        except IndeterminateError:
            pass

    def test_canonical_identity_and_safe_output(self):
        first = {"b": [1, True, None], "a": "\x1b[31m日本語\n"}
        second = {"a": first["a"], "b": first["b"]}
        encoded = canonical(first)
        self.assertEqual(encoded, canonical(second))
        self.assertEqual(digest(first), digest(second))
        self.assertEqual(json.loads(encoded), first)
        self.assertNotIn("\x1b", encoded)
        self.assertNotIn("\n", encoded)
        self.assertNotEqual(digest(first), digest({**first, "b": [2]}))

    def test_duplicate_keys_and_nonfinite_numbers(self):
        for raw in ('{"x": 1, "x": 2}', '{"x":{"y":0,"y":1}}',
                    'NaN', 'Infinity', '-Infinity', '1e999'):
            with self.subTest(raw=raw), self.assertRaises(ValidationError):
                load_json(raw)

    def test_boundaries(self):
        self.assertEqual(load_json(b'{"x":1}', max_bytes=7), {"x": 1})
        for raw, options in [
            (b'{"x":1}', {"max_bytes": 6}),
            ('[[[0]]]', {"max_depth": 2}),
            ('[1,2,3]', {"max_nodes": 3}),
            (b'"\xff"', {}),
            ('"\\ud800"', {}),
            ('[', {}),
            ('"\ud800"', {}),
            ('[' * 2000 + '0' + ']' * 2000, {}),
        ]:
            with self.subTest(options=options), self.assertRaises(ValidationError):
                load_json(raw, **options)

    def test_canonical_rejects_non_json_values(self):
        circular = []
        circular.append(circular)
        for value in ({1: "x"}, {"x": float("nan")}, (1, 2), object(), circular):
            with self.subTest(value=type(value)), self.assertRaises(ValidationError):
                canonical(value)

    def test_tree_budget_stops_wide_iterators_incrementally(self):
        from autoprotect.core import _check_tree

        class GuardedList(list):
            def __iter__(self):
                for index in range(100):
                    if index >= 10:
                        raise AssertionError("validation expanded the whole list before enforcing the budget")
                    yield None

        class GuardedDict(dict):
            def items(self):
                for index in range(100):
                    if index >= 10:
                        raise AssertionError("validation expanded the whole object before enforcing the budget")
                    yield str(index), None

        for value in (GuardedList(), GuardedDict()):
            with self.subTest(value=type(value)), self.assertRaisesRegex(ValidationError, "node limit"):
                _check_tree(value, max_nodes=4, max_depth=32)

    def test_tree_depth_and_node_limits_preserve_key_counting(self):
        self.assertEqual(load_json('{"key":0}', max_nodes=3, max_depth=1), {"key": 0})
        for kwargs in ({"max_nodes": 2}, {"max_depth": 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValidationError):
                load_json('{"key":0}', **kwargs)
        self.assertEqual(load_json('[]', max_nodes=1, max_depth=0), [])
        self.assertEqual(load_json('{}', max_nodes=1, max_depth=0), {})

    def test_identifiers_and_packages(self):
        self.assertEqual(identifier("host-abc:amd64"), "host-abc:amd64")
        self.assertEqual(package_name("libstdc++6"), "libstdc++6")
        for value in ("-o", "../thing", "pkg;id", "pkg\n", "pkg:amd64", "p", "日本語"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                package_name(value)
        for value in ("-flag", "../asset", "a/b", "asset\x1b", "x" * 129):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                identifier(value)

    def test_dpkg_version_syntax(self):
        for value in ("1", "1.2.3-1+u1", "2:1.0~rc1-1+b2", "1:1:2-3", "0"):
            self.assertEqual(version(value), value)
        for value in ("-1", "1;id", "1\n", "x:1", "1-", "1-2:3", "v1", "1_2", "1/2"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                version(value)

    def test_dpkg_epoch_native_bounds(self):
        for epoch in ("2147483647", "0002147483647"):
            self.assertEqual(version(epoch + ":1"), epoch + ":1")
        for epoch in ("2147483648", "0002147483648", "9" * 100):
            with self.subTest(epoch=epoch), self.assertRaises(ValidationError):
                version(epoch + ":1")

    def test_strict_integers_and_text(self):
        self.assertEqual(integer(1, minimum=1, maximum=2), 1)
        for value in (True, 1.0, "1", 0, 3):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                integer(value, minimum=1, maximum=2)
        self.assertEqual(text("", allow_empty=True), "")
        self.assertEqual(text("untrusted\x1b\n"), "untrusted\x1b\n")
        for value in (None, "", "x" * 8193, "\udfff"):
            with self.subTest(value=type(value)), self.assertRaises(ValidationError):
                text(value)


if __name__ == "__main__":
    unittest.main()

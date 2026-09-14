import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mira.agents.static.wiring import (
    _check_vendored_rules_initialized,
    _configured_capa_rules_dir,
    _configured_yara_rulesets,
)


class YaraRulesetDiscoveryTests(unittest.TestCase):
    def test_discovers_yar_and_yara_files_by_stem(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "suspicious.yar").write_text("rule r { condition: true }")
            (root / "packers.yara").write_text("rule p { condition: true }")
            (root / "notes.txt").write_text("ignored")

            previous = os.environ.get("MIRA_YARA_RULES_DIR")
            os.environ["MIRA_YARA_RULES_DIR"] = str(root)
            try:
                rulesets = _configured_yara_rulesets()
            finally:
                if previous is None:
                    os.environ.pop("MIRA_YARA_RULES_DIR", None)
                else:
                    os.environ["MIRA_YARA_RULES_DIR"] = previous

        self.assertEqual(set(rulesets), {"suspicious", "packers"})

    def test_unset_env_var_falls_back_to_the_vendored_submodule(self):
        previous = os.environ.pop("MIRA_YARA_RULES_DIR", None)
        try:
            rulesets = _configured_yara_rulesets()
        finally:
            if previous is not None:
                os.environ["MIRA_YARA_RULES_DIR"] = previous

        if not rulesets:
            self.skipTest("rules/signature-base submodule not initialized - run scripts/fetch_rules.sh")
        self.assertIn("apt_apt28", rulesets)
        self.assertTrue(rulesets["apt_apt28"].is_file())


class CapaRulesDirDiscoveryTests(unittest.TestCase):
    def test_unset_env_var_falls_back_to_the_vendored_submodule(self):
        previous = os.environ.pop("MIRA_CAPA_RULES_DIR", None)
        try:
            rules_dir = _configured_capa_rules_dir()
        finally:
            if previous is not None:
                os.environ["MIRA_CAPA_RULES_DIR"] = previous

        if rules_dir is None or not any(rules_dir.iterdir()):
            self.skipTest("rules/capa submodule not initialized - run scripts/fetch_rules.sh")
        self.assertTrue((rules_dir / "LICENSE.txt").is_file())

    def test_explicit_env_var_overrides_the_fallback(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            previous = os.environ.get("MIRA_CAPA_RULES_DIR")
            os.environ["MIRA_CAPA_RULES_DIR"] = temporary_directory
            try:
                rules_dir = _configured_capa_rules_dir()
            finally:
                if previous is None:
                    os.environ.pop("MIRA_CAPA_RULES_DIR", None)
                else:
                    os.environ["MIRA_CAPA_RULES_DIR"] = previous

        self.assertEqual(rules_dir, Path(temporary_directory))


class VendoredRulesInitializedCheckTests(unittest.TestCase):
    def test_raises_a_clear_error_when_a_submodule_is_present_but_empty(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "rules" / "capa").mkdir(parents=True)
            (root / "rules" / "signature-base").mkdir(parents=True)

            for previous_env in ("MIRA_CAPA_RULES_DIR", "MIRA_YARA_RULES_DIR"):
                os.environ.pop(previous_env, None)

            with patch("mira.agents.static.wiring._repo_root", return_value=root):
                with self.assertRaisesRegex(RuntimeError, "rules/capa.*git submodule update --init"):
                    _check_vendored_rules_initialized()

    def test_does_not_raise_once_the_capa_submodule_has_content(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "rules" / "capa").mkdir(parents=True)
            (root / "rules" / "capa" / "LICENSE.txt").write_text("...")
            (root / "rules" / "signature-base").mkdir(parents=True)
            (root / "rules" / "signature-base" / "yara").mkdir()

            for previous_env in ("MIRA_CAPA_RULES_DIR", "MIRA_YARA_RULES_DIR"):
                os.environ.pop(previous_env, None)

            with patch("mira.agents.static.wiring._repo_root", return_value=root):
                _check_vendored_rules_initialized()

    def test_explicit_env_override_skips_the_check_for_that_ruleset(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "rules" / "capa").mkdir(parents=True)
            (root / "rules" / "signature-base").mkdir(parents=True)

            previous = os.environ.get("MIRA_CAPA_RULES_DIR")
            os.environ["MIRA_CAPA_RULES_DIR"] = str(root)
            try:
                with patch("mira.agents.static.wiring._repo_root", return_value=root):
                    with self.assertRaisesRegex(RuntimeError, "rules/signature-base"):
                        _check_vendored_rules_initialized()
            finally:
                if previous is None:
                    os.environ.pop("MIRA_CAPA_RULES_DIR", None)
                else:
                    os.environ["MIRA_CAPA_RULES_DIR"] = previous


if __name__ == "__main__":
    unittest.main()

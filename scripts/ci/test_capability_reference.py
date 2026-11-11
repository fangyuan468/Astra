"""Validate meaningful failures of the current-capability editorial contract."""

from pathlib import Path
import unittest

from scripts.ci.validate_repository import (
    capability_reference_errors,
    markdown_link_errors,
)

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "docs/reference/capabilities.md"


class CapabilityReferenceTests(unittest.TestCase):
    def test_current_reference_has_complete_fields_and_valid_links(self):
        text = REFERENCE.read_text()
        self.assertEqual(capability_reference_errors(text), [])
        self.assertEqual(markdown_link_errors(REFERENCE, text), [])

    def test_mutations_fail_the_shared_validator(self):
        text = REFERENCE.read_text()
        first = next(
            line for line in text.splitlines() if line.startswith("| Agent chat |")
        )
        cases = {
            "missing row": text.replace(first + "\n", ""),
            "duplicate row": text + "\n" + first,
            "wrong status": text.replace("| Beta |", "| Stable |", 1),
            "wrong profile": text.replace(
                "| CLI, Server, Web |", "| Ambient host |", 1
            ),
            "missing dependency": text.replace(
                "| MatrixOne, admitted model; Web build for Web |", "|  |", 1
            ),
            "missing source": text.replace(
                "[Shared loop](../../crates/runtime/src/turn/agentic_loop/mod.rs)",
                "unverified",
            ),
            "untracked broken claim": text.replace("| Beta |", "| Known-broken |", 1),
            "wrong shape": text.replace("| Run evidence |", "| Results |", 1),
        }
        for name, mutated in cases.items():
            with self.subTest(name=name):
                self.assertTrue(capability_reference_errors(mutated), name)
        broken = text.replace(
            "../../crates/runtime/src/turn/agentic_loop/mod.rs",
            "../../missing-implementation.rs",
        )
        self.assertTrue(markdown_link_errors(REFERENCE, broken))


if __name__ == "__main__":
    unittest.main()

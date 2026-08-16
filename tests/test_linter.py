import os
import sys
import unittest
from pathlib import Path

# Add repo root to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from arch_map import (
    lint_mermaid,
    lint_markdown,
    mermaid_edge_label,
    ArchitectureScanner,
)


class TestMermaidLinter(unittest.TestCase):
    def test_valid_flowchart_shapes(self):
        valid_code = """flowchart TB
    User(["User / Client"])
    DB[("Cosmos DB")]
    BlobStore(["Blob Storage"])
    Cache{{"Redis Cache"}}
    Decision{"Is Authorized?"}
    Start(("Start"))
    Target((("Target")))
    Plain["Plain Box"]
    User --> DB
    User -->|"spawn / spawn(codex)"| Plain
"""
        errors = lint_mermaid(valid_code)
        self.assertEqual(errors, [], f"Expected zero errors on valid flowchart, got: {errors}")

    def test_invalid_composite_delimiters(self):
        # Invalid composite delimiters like ([("label")]) or [([label])]
        bad_code = """flowchart TB
    X_blob([("azure.storage.blob")])
"""
        errors = lint_mermaid(bad_code)
        self.assertTrue(len(errors) > 0, "Expected linter to catch invalid composite delimiter `([(`")

    def test_invalid_unquoted_edge_labels(self):
        bad_edge = """flowchart TB
    A -->|spawn / spawn(codex)| B
"""
        errors = lint_mermaid(bad_edge)
        self.assertTrue(len(errors) > 0, "Expected linter to catch unquoted parens in edge label")

    def test_valid_sequence_diagram(self):
        seq_code = """sequenceDiagram
    autonumber
    actor User
    participant HTTP as app.py
    participant DB as CosmosDB
    User->>HTTP: POST /chat
    HTTP->>DB: upsert()
    DB-->>HTTP: 200 OK
    HTTP-->>User: 200 JSON
"""
        errors = lint_mermaid(seq_code)
        self.assertEqual(errors, [], f"Expected zero errors on valid sequence diagram, got: {errors}")

    def test_unclosed_subgraph(self):
        bad_subgraph = """flowchart TB
    subgraph ClientZone["Client Perimeter"]
        User["User"]
"""
        errors = lint_mermaid(bad_subgraph)
        self.assertTrue(any("Unclosed `subgraph`" in e for e in errors))

    def test_mermaid_edge_label_quoting(self):
        quoted = mermaid_edge_label("spawn / spawn(codex)")
        self.assertEqual(quoted, '"spawn / spawn(codex)"')
        plain = mermaid_edge_label("HTTP")
        self.assertEqual(plain, "HTTP")

    def test_all_repository_markdown_files(self):
        md_files = sorted(REPO_ROOT.rglob("*.md"))
        self.assertTrue(len(md_files) > 0, "No markdown files found in repo")
        for md_file in md_files:
            content = md_file.read_text(encoding="utf-8", errors="ignore")
            errors = lint_markdown(content, file_path=md_file.name)
            self.assertEqual(errors, [], f"Markdown lint failed on {md_file}: {errors}")


if __name__ == "__main__":
    unittest.main()

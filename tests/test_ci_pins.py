"""CI supply-chain pins are a checked property, not a convention.

A floating action tag (``@v4``) is whatever its maintainer moves it to; a floating image tag likewise. Every
third-party action therefore has to be pinned to a full commit SHA with the release named in a trailing comment,
and the container test image to a digest, so that a change in what CI executes is always a change in this repository.
The checker works on the raw text (YAML parsers drop comments) and has its own tests, so it cannot pass vacuously.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))

USES = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>\S+)(?P<rest>.*)$")
PINNED_ACTION = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
RELEASE_COMMENT = re.compile(r"^\s+#\s*v\d+\.\d+\.\d+\s*$")
DIGEST_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
IMAGE_VARIABLE = re.compile(r"^\s*WITHERHOARD_CONTAINER_TEST_IMAGE:\s*\"?(?P<image>[^\"\s#]+)\"?")


def unpinned(lines):
    """(line number, reason) for every floating or undocumented external reference in ``lines``."""
    problems = []
    for number, line in enumerate(lines, 1):
        used = USES.match(line)
        if used:
            ref, rest = used.group("ref"), used.group("rest")
            if ref.startswith("./"):
                continue                                                  # a local action is part of this repository
            if ref.startswith("docker://"):
                if "@sha256:" not in ref:
                    problems.append((number, f"container action not pinned by digest: {ref}"))
                continue
            if not PINNED_ACTION.match(ref):
                problems.append((number, f"action not pinned to a full commit SHA: {ref}"))
            elif not RELEASE_COMMENT.match(rest):
                problems.append((number, f"pinned action lacks a '# vX.Y.Z' release comment: {ref}"))
        image = IMAGE_VARIABLE.match(line)
        if image and not DIGEST_IMAGE.match(image.group("image")):
            problems.append((number, f"container test image not pinned by digest: {image.group('image')}"))
    return problems


class PinCheckerTests(unittest.TestCase):
    """The checker itself: it must flag every kind of floating reference and accept the pinned forms."""
    SHA = "a" * 40

    def test_floating_and_partial_references_are_flagged(self):
        for line in ("        uses: actions/checkout@v4",
                     "        uses: actions/checkout@main",
                     f"        uses: actions/checkout@{'a' * 7}",
                     f"        uses: actions/checkout@{'a' * 39}",
                     f"        uses: actions/checkout@{'A' * 40} # v4.4.0",
                     "      - uses: gitleaks/gitleaks-action@v2",
                     "        uses: docker://alpine:3.20"):
            with self.subTest(line=line.strip()):
                self.assertTrue(unpinned([line]), line)

    def test_a_pinned_reference_without_its_release_comment_is_flagged(self):
        self.assertTrue(unpinned([f"        uses: actions/checkout@{self.SHA}"]))
        self.assertTrue(unpinned([f"        uses: actions/checkout@{self.SHA} # latest"]))
        self.assertTrue(unpinned([f"        uses: actions/checkout@{self.SHA}  # see the changelog"]))

    def test_pinned_and_local_references_are_accepted(self):
        for line in (f"        uses: actions/checkout@{self.SHA} # v4.4.0",
                     f"      - uses: org/repo/path/sub@{self.SHA} # v10.2.31",
                     "        uses: ./.github/actions/local-thing",
                     f"        uses: docker://alpine@sha256:{'b' * 64}"):
            with self.subTest(line=line.strip()):
                self.assertEqual(unpinned([line]), [], line)

    def test_the_container_image_must_be_a_digest(self):
        digest = "b" * 64
        for floating in ('      WITHERHOARD_CONTAINER_TEST_IMAGE: "busybox:1.36"',
                         "      WITHERHOARD_CONTAINER_TEST_IMAGE: busybox",
                         f'      WITHERHOARD_CONTAINER_TEST_IMAGE: "busybox@sha256:{"b" * 63}"'):
            with self.subTest(line=floating.strip()):
                self.assertTrue(unpinned([floating]), floating)
        self.assertEqual(unpinned([f'      WITHERHOARD_CONTAINER_TEST_IMAGE: "busybox@sha256:{digest}"  # busybox:1.36']), [])


class RepositoryWorkflowTests(unittest.TestCase):
    def test_workflows_exist_and_are_scanned(self):
        self.assertTrue(WORKFLOWS, "no workflow files found: the pin check would pass vacuously")

    def test_every_external_reference_in_every_workflow_is_pinned(self):
        offenders = []
        for workflow in WORKFLOWS:
            for number, reason in unpinned(workflow.read_text(encoding="utf-8").splitlines()):
                offenders.append(f"{workflow.name}:{number}: {reason}")
        self.assertEqual(offenders, [], "\n".join(offenders))

    def test_the_scan_really_sees_the_references_it_is_meant_to_protect(self):
        lines = "\n".join(workflow.read_text(encoding="utf-8") for workflow in WORKFLOWS).splitlines()
        self.assertGreaterEqual(sum(1 for line in lines if USES.match(line)), 5)
        self.assertTrue(any(IMAGE_VARIABLE.match(line) for line in lines),
                        "the container-isolation job no longer declares WITHERHOARD_CONTAINER_TEST_IMAGE")


if __name__ == "__main__":
    unittest.main()

"""CI supply-chain pins are a checked property, not a convention.

A floating action tag (``@v4``) is whatever its maintainer moves it to; a floating image tag likewise, and so is a
tool installed by name (``pip install pip-audit`` takes whatever release is current that day). Every third-party
action therefore has to be pinned to a full commit SHA with the release named in a trailing comment, the container
test image to a digest, and every package a ``pip install`` or ``npm install`` names to an exact version, so that a
change in what CI executes is always a change in this repository.

What a green result does not cover, stated so that it is not over-read: an exact version fixes the package, not what
it depends on (nothing is hash-locked); ``-r requirements*.txt`` files are reviewed as files, not checked here; and
ways of fetching code the workflows do not use today (``npx``, ``pipx``, ``apt-get``, ``curl | sh``, ``go install``)
are not recognised. The checker works on the raw text (YAML parsers drop comments) and has its own tests, so it
cannot pass vacuously.
"""
import re
import shlex
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))

USES = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>\S+)(?P<rest>.*)$")
PINNED_ACTION = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
RELEASE_COMMENT = re.compile(r"^\s+#\s*v\d+\.\d+\.\d+\s*$")
DIGEST_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
IMAGE_VARIABLE = re.compile(r"^\s*WITHERHOARD_CONTAINER_TEST_IMAGE:\s*\"?(?P<image>[^\"\s#]+)\"?")

# Tools installed by name. After `pip install` / `npm install`, an option listed here consumes the next token as its
# value (a file or a prefix, not a package); every other non-option token is a package specification.
PIP_COMMAND = re.compile(r"^pip(?:3(?:\.\d+)?)?$")
PIP_VALUE_OPTIONS = frozenset({"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url",
                               "--extra-index-url", "-f", "--find-links", "-t", "--target", "--prefix", "--root",
                               "--platform", "--python-version", "--only-binary", "--no-binary", "--cache-dir"})
PIP_EXACT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9._,-]+\])?==\d[0-9A-Za-z.+!_-]*$")
NPM_INSTALL_WORDS = frozenset({"install", "i", "add"})
NPM_VALUE_OPTIONS = frozenset({"--prefix", "--registry", "--tag", "-w", "--workspace", "--loglevel", "--cache"})
NPM_EXACT = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*@\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
LOCAL_PATH = re.compile(r"^(?:\.{1,2}(?:[\\/]|$)|[\\/~]|[A-Za-z]:[\\/]|file:)")   # part of this checkout, not a registry
CONTROL_OPERATORS = frozenset({"&&", "||", ";", ";;", "&", "|", "|&", "(", ")"})
REDIRECTION = re.compile(r"^(?:&>>?|[<>][<>&|]*)$")


def logical_lines(lines):
    """``(first line number, text)`` for each shell line, with backslash continuations joined as the shell reads them.

    A comment line ending in a backslash does not continue: the shell ends a comment at the newline."""
    start, parts = None, []
    for number, line in enumerate(lines, 1):
        if start is None:
            start = number
        text = line.rstrip()
        if text.endswith("\\") and not text.lstrip().startswith("#"):
            parts.append(text[:-1])
            continue
        parts.append(text)
        yield start, " ".join(part.strip() for part in parts)
        start, parts = None, []
    if parts:                                                 # a continuation on the last line of the file
        yield start, " ".join(part.strip() for part in parts)


def shell_commands(text):
    """The commands on one shell line as token lists: cut at control operators, comments and redirections dropped.

    A line that does not tokenise (an unbalanced quote: not every YAML line is shell) is split on whitespace, so it
    is still scanned instead of skipped."""
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        tokens = text.split()
    commands, current, skip = [], [], False
    for token in tokens:
        if skip:
            skip = False
        elif token in CONTROL_OPERATORS:
            commands.append(current)
            current = []
        elif REDIRECTION.match(token):
            if current and current[-1].isdigit():
                current.pop()                                 # the file-descriptor prefix of `2>&1`
            skip = True                                       # and the target of the redirection
        else:
            current.append(token)
    commands.append(current)
    return [command for command in commands if command]


def install_arguments(command):
    """``(manager, arguments)`` when the command installs packages with pip or npm, otherwise None."""
    for index in range(len(command) - 1):
        word, following = command[index], command[index + 1]
        if PIP_COMMAND.match(word) and following == "install":
            return "pip", command[index + 2:]
        if word == "npm" and following in NPM_INSTALL_WORDS:
            return "npm", command[index + 2:]
    return None


def named_installs(lines):
    """``(line number, manager, specification)`` for every registry package a pip or npm install names."""
    for number, text in logical_lines(lines):
        for command in shell_commands(text):
            found = install_arguments(command)
            if not found:
                continue
            manager, arguments = found
            value_options = PIP_VALUE_OPTIONS if manager == "pip" else NPM_VALUE_OPTIONS
            skip = False
            for token in arguments:
                if skip:
                    skip = False
                elif token.startswith("-"):
                    skip = "=" not in token and token in value_options
                elif not LOCAL_PATH.match(token):
                    yield number, manager, token


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
    for number, manager, specification in named_installs(lines):
        exact, form = (PIP_EXACT, "name==X.Y.Z") if manager == "pip" else (NPM_EXACT, "name@X.Y.Z")
        if not exact.match(specification):
            problems.append((number, f"{manager} install of '{specification}' is not pinned to an exact version ({form})"))
    return sorted(problems)


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


class InstallCheckerTests(unittest.TestCase):
    """Tools installed by name: every package a ``pip install`` or ``npm install`` names needs an exact version."""

    def test_floating_installs_are_flagged(self):
        for line in ("          python -m pip install pip-audit",
                     "          python -m pip install pip-audit>=2.9",         # unquoted, `>` is a redirection
                     '          python -m pip install "pip-audit>=2.9"',
                     '          python -m pip install "pip-audit~=2.9"',
                     "          python -m pip install pip-audit==2.*",
                     "          python -m pip install --upgrade pip",
                     "          python -m pip install pip-audit==2.10.1 requests",
                     "          pip3 install -U pip-audit",
                     "          python -m pip install git+https://github.com/pypa/pip-audit",
                     "          python -m pip install https://example.invalid/pip_audit-2.10.1-py3-none-any.whl",
                     "          npm install --global @anthropic-ai/claude-code",
                     "          npm install --global @anthropic-ai/claude-code@latest",
                     "          npm install --global @anthropic-ai/claude-code@next",
                     "          npm install --global @anthropic-ai/claude-code@^2.1.326",
                     "          npm install --global @anthropic-ai/claude-code@~2.1.326",
                     "          npm install --global @anthropic-ai/claude-code@2.1",
                     "          npm i -g typescript",
                     "          npm add left-pad@1.x",
                     "          npm install github:someone/some-tool",
                     "          python -m pip install pip-audit==2.10.1 && npm install --global typescript"):
            with self.subTest(line=line.strip()):
                self.assertTrue(unpinned([line]), line)

    def test_the_reason_names_the_package_and_the_form(self):
        (number, reason), = unpinned(["", "          npm install --global @anthropic-ai/claude-code@latest"])
        self.assertEqual(number, 2)
        self.assertIn("@anthropic-ai/claude-code@latest", reason)
        self.assertIn("name@X.Y.Z", reason)
        (number, reason), = unpinned(["          python -m pip install pip-audit"])
        self.assertIn("name==X.Y.Z", reason)

    def test_pinned_installs_and_installs_that_name_no_registry_package_are_accepted(self):
        for line in ("          python -m pip install pip-audit==2.10.1",
                     '          python -m pip install "pip-audit==2.10.1"',
                     "          python -m pip install pip-audit[extra]==2.10.1",
                     "          python -m pip install -r requirements-dev.txt",
                     "          python -m pip install -r requirements.txt -c constraints.txt",
                     "          python -m pip install --require-hashes --no-deps -r requirements.txt",
                     "          python -m pip install .",
                     "          python -m pip install -e ./tools/helper",
                     "          python -m pip install pip-audit==2.10.1 > install.log 2>&1",
                     "          python -m pip install pip-audit==2.10.1  # a trailing comment",
                     "          # python -m pip install pip-audit",
                     "          python -m pip install pip-audit==2.10.1 && pip-audit -r requirements.txt",
                     "          pip-audit -r requirements.txt 2>&1 | tee audit.txt",
                     "          npm install --global @anthropic-ai/claude-code@2.1.326",
                     "          npm i -g typescript@5.4.5",
                     "          npm install --prefix ./tools left-pad@1.3.0",
                     "          npm install",
                     "          npm ci",
                     '          echo "to install: pip install pip-audit"'):
            with self.subTest(line=line.strip()):
                self.assertEqual(unpinned([line]), [], line)

    def test_a_floating_install_split_across_continuation_lines_is_still_seen(self):
        lines = ["          python -m pip install \\",
                 "              pip-audit"]
        self.assertEqual([number for number, _ in unpinned(lines)], [1])
        pinned = ["          python -m pip install \\",
                  "              pip-audit==2.10.1"]
        self.assertEqual(unpinned(pinned), [])

    def test_a_comment_ending_in_a_backslash_does_not_hide_the_next_line(self):
        lines = ["          # see the notes \\",
                 "          python -m pip install pip-audit"]
        self.assertEqual([number for number, _ in unpinned(lines)], [2])

    def test_a_line_that_does_not_tokenise_is_scanned_not_skipped(self):
        line = "          echo it's; python -m pip install pip-audit"             # unbalanced quote
        self.assertTrue(unpinned([line]), line)

    def test_commands_are_cut_at_operators_and_redirections_are_dropped(self):
        self.assertEqual(shell_commands("a b && c | d ; e 2>&1 > out.txt # f"), [["a", "b"], ["c"], ["d"], ["e"]])
        self.assertEqual(shell_commands("# only a comment"), [])


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
        installed = {manager for _, manager, _ in named_installs(lines)}
        self.assertEqual(installed, {"pip", "npm"},
                         "the dependency-audit and agent-benchmark jobs install a tool by name; if the scan no longer "
                         "sees a pip and an npm install it has stopped parsing them")


if __name__ == "__main__":
    unittest.main()

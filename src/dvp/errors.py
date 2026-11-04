"""Shared exception types.

The pipeline deliberately separates two kinds of failure:

* a *detection* failure means the rule is wrong, and the author must fix it;
* a *pipeline* failure (everything below) means the result can't be trusted,
  so CI must not report it as a verdict on the rule.
"""

from __future__ import annotations


class PipelineError(Exception):
    """The pipeline could not produce a trustworthy verdict."""


class RuleError(PipelineError):
    """A rule is malformed, or uses a feature the mock engine can't evaluate.

    The engines fail closed: silently ignoring an unsupported clause could turn
    a broken rule into a false PASS.
    """

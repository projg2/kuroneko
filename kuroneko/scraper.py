#!/usr/bin/env python
# (c) 2021 Michał Górny
# 2-clause BSD license

"""Gentoo Bugzilla scraping support."""

import re
import typing

import bracex
import requests

from pkgcore.ebuild.atom import atom
from pkgcore.ebuild.errors import MalformedAtom


BUGZILLA_API_URL = 'https://bugs.gentoo.org/rest'
PKG_SEPARATORS = re.compile(r':\s|[\s,;(){}[\]]')


class BugInfo(typing.NamedTuple):
    """Tuple storing bug information."""

    id: int
    summary: str
    alias: typing.List[str]
    whiteboard: str


def find_security_bugs() -> typing.Iterable[BugInfo]:
    """
    Perform a search for security bugs.

    Find all relevant Security bugs on a Bugzilla instance, and return
    an iterable of BugInfo instances.
    """
    endpoint = BUGZILLA_API_URL + '/bug'
    params = {
        # TODO: other components?
        'product': ['Gentoo Security'],
        'component': ['Vulnerabilities'],
        'include_fields': BugInfo._fields,
        # TODO: testing speedup hack
        'resolution': '---',
        'limit': '10',
    }
    resp = requests.get(endpoint, timeout=60, params=params)
    if not resp:
        raise RuntimeError(f"Bugzilla request failed: {resp.content!r}")
    for bug in resp.json()['bugs']:
        yield BugInfo(**bug)


def find_package_specs(s: str) -> typing.Iterable[str]:
    """Find potentially valid package specifications in given string."""
    words = set()
    # consider all possible expansions
    for exp in bracex.iexpand(s):
        words.update(PKG_SEPARATORS.split(exp))
    for w in words:
        # skip anything that couldn't be cat/pkg early
        if '/' not in w:
            continue
        try:
            atom(w)
        except MalformedAtom:
            continue
        yield w


def main() -> int:
    """CLI interface for kuroneko scraper."""
    for bug in find_security_bugs():
        print(list(find_package_specs(bug.summary)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

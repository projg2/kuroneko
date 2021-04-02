#!/usr/bin/env python
# (c) 2021 Michał Górny
# 2-clause BSD license

"""Gentoo Bugzilla scraping support."""

import argparse
import collections
import re
import sys
import typing

import bracex
import requests

from pkgcore.ebuild.atom import atom
from pkgcore.ebuild.errors import MalformedAtom

from kuroneko.database import Database


BUGZILLA_API_URL = 'https://bugs.gentoo.org/rest'
PKG_SEPARATORS = re.compile(r':\s|[\s,;(){}[\]]')
SEVERITY_RE = re.compile(r'[~ABC][1-4]')
VER_SPLIT_RE = re.compile(r'([^\d]+)')


class BugInfo(typing.NamedTuple):
    """Tuple storing bug information."""

    id: int
    summary: str
    alias: typing.List[str]
    whiteboard: str
    creation_time: str


def find_security_bugs(limit: typing.Optional[int] = None,
                       ) -> typing.Iterable[BugInfo]:
    """
    Perform a search for security bugs.

    Find all relevant Security bugs on a Bugzilla instance, and return
    an iterable of BugInfo instances.

    If limit is specified, up to LIMIT bugs are returned.
    """
    endpoint = BUGZILLA_API_URL + '/bug'
    params = {
        # TODO: other components?
        'product': ['Gentoo Security'],
        'component': ['Vulnerabilities'],
        'include_fields': BugInfo._fields,
        'resolution': '---',
        'limit': limit,
    }
    if limit is None:
        del params['limit']
    resp = requests.get(endpoint, timeout=60, params=params)
    if not resp:
        raise RuntimeError(f"Bugzilla request failed: {resp.content!r}")
    for bug in resp.json()['bugs']:
        yield BugInfo(**bug)


def find_package_specs(s: str) -> typing.Iterable[atom]:
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
            yield atom(w)
        except MalformedAtom:
            continue


def split_version_ranges(packages: typing.Iterable[atom]
                         ) -> typing.Iterable[typing.Tuple[str, ...]]:
    """Split multiple specs for same package into version ranges."""
    # first, group packages by key
    package_groups = collections.defaultdict(list)
    for pkg in packages:
        package_groups[pkg.key].append(pkg)
    for group in package_groups.values():
        # split only packages consisting purely of </<= operators
        if len(group) > 1 and all(x.op in ('<', '<=') for x in group):
            it = iter(sorted(group))
            p2 = next(it)

            # return the lowest spec first
            yield (str(p2),)

            while True:
                p1 = p2
                try:
                    p2 = next(it)
                except StopIteration:
                    break

                assert p1.key == p2.key
                assert p1.fullver != p2.fullver
                v1 = VER_SPLIT_RE.split(p1.fullver)
                v2 = VER_SPLIT_RE.split(p2.fullver)

                # find the common part
                common_ver: typing.List[str] = []
                for i in range(0, min(len(v1), len(v2))):
                    if v1[i] != v2[i]:
                        break
                    common_ver += v1[i]
                else:
                    # all common components are equal
                    # TODO: support this correctly
                    yield (str(p2),)
                    continue

                # increase the first component after the common part
                next1 = int(v1[i])
                next2 = int(v2[i])
                assert next1 < next2, (f'expected {p1} < {p2}, '
                                       f'v1 = {v1}, v2 = {v2}')
                lower = ''.join(common_ver + [str(next1 + 1)])
                yield (f'>={p2.key}-{lower}', str(p2))
        else:
            for x in group:
                yield (str(x),)


def get_severity(whiteboard: str) -> str:
    """Parse severity from bug's whiteboard."""
    maybe_sev = whiteboard.split(' ')[0]
    if SEVERITY_RE.match(maybe_sev):
        return maybe_sev
    return '??'


def main() -> int:
    """CLI interface for kuroneko scraper."""
    argp = argparse.ArgumentParser()
    argp.add_argument('-l', '--limit', type=int,
                      help='Limit the results to LIMIT bugs')
    argp.add_argument('-o', '--output', default='-',
                      help='Output JSON file (default: - = stdout)')
    args = argp.parse_args()

    if args.output == '-':
        output = sys.stdout
    else:
        output = open(args.output, 'w')

    db = Database()
    for bug in find_security_bugs(limit=args.limit):
        db.add_bug(bug=bug.id,
                   packages=list(split_version_ranges(
                       find_package_specs(bug.summary))),
                   summary=bug.summary,
                   severity=get_severity(bug.whiteboard),
                   created=bug.creation_time)
    db.save(output)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())

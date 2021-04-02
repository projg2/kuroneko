#!/usr/bin/env python
# (c) 2021 Michał Górny
# 2-clause BSD license

"""CLI support."""

import argparse
import datetime
import functools
import os
import typing

import colorama

from pkgcore.config import load_config
from pkgcore.ebuild.atom import atom
from pkgcore.package.metadata import package as pkgcore_package
from pkgcore.restrictions.boolean import OrRestriction, AndRestriction
from pkgcore.restrictions.restriction import base as base_restriction

from kuroneko.database import Database, Bug


try:
    COLUMNS: typing.Optional[int] = os.get_terminal_size().columns
except OSError:
    COLUMNS = None

BUGZILLA_URL_PREFIX = 'https://bugs.gentoo.org/'
TODAY = datetime.date.today()


def get_severity_color(sym: str) -> str:
    """Get ANSI color sequence for severity digit sym."""
    if sym == '0':
        return colorama.Style.BRIGHT + colorama.Fore.RED
    elif sym == '1':
        return colorama.Style.BRIGHT + colorama.Fore.YELLOW
    elif sym == '2':
        return colorama.Fore.YELLOW
    elif sym == '3':
        return colorama.Fore.GREEN
    elif sym == '4':
        return colorama.Fore.CYAN
    elif sym == '?':
        return colorama.Fore.WHITE
    assert False, "unmatched severity"


def get_age_color(created: str, severity: str) -> str:
    """Get ANSI color sequence for bug's age."""
    # https://www.gentoo.org/support/security/vulnerability-treatment-policy.html
    if severity in ('A0', 'B0'):
        target_delay = 1
    elif severity in ('A1', 'C0'):
        target_delay = 3
    elif severity in ('A2', 'B1', 'C1'):
        target_delay = 5
    elif severity in ('A3', 'B2', 'C2'):
        target_delay = 10
    elif severity in ('A4', 'B3', 'B4', 'C3'):
        target_delay = 20
    elif severity in ('C4', '~0', '~1', '~2', '~3', '~4'):
        target_delay = 40
    else:  # ??
        return colorama.Fore.WHITE

    created_dt = datetime.date.fromisoformat(created.split('T', 1)[0])
    delta = (TODAY - created_dt).days
    if delta < target_delay:
        return colorama.Style.BRIGHT + colorama.Fore.GREEN
    elif delta < target_delay*2:
        return colorama.Style.BRIGHT + colorama.Fore.YELLOW
    else:
        return colorama.Style.BRIGHT + colorama.Fore.RED


class Printer:
    """Printing helper with formatting and text counting."""

    def __init__(self) -> None:
        """Reset the class."""
        self.s = ''
        self.count = 0

    def add(self, before: str, fmt: str, s: str, after: str = '') -> None:
        """Add formatted string."""
        self.s += before + fmt + s + colorama.Style.RESET_ALL + after
        self.count += len(before) + len(s) + len(after)

    def add_to_eol(self, s: str) -> None:
        """Add a string ellipsized not to exceed line width."""
        if COLUMNS is not None:
            remaining = COLUMNS - self.count
            if len(s) >= remaining:
                s = s[:remaining-4] + '...'
        self.s += s
        self.count += len(s)

    def print(self) -> None:
        """Print stored string and reset the class."""
        print(self.s)
        self.s = ''
        self.count = 0


def print_bug(bug: Bug, bug_pkg: str, inst_pkg: str) -> None:
    """Pretty-print bug information."""
    pr = Printer()
    pr.add('', colorama.Style.BRIGHT + colorama.Fore.WHITE, bug_pkg)
    pr.add(' (matches ', colorama.Fore.YELLOW, inst_pkg, ')')
    pr.print()

    pr.add('[', colorama.Style.BRIGHT + colorama.Fore.WHITE,
           f'{bug.bug:6}', '] ')
    pr.add('[', get_severity_color(bug.severity[1]),
           bug.severity, '] ')
    pr.add_to_eol(bug.summary)
    pr.print()

    pr.add('  created: [', get_age_color(bug.created, bug.severity),
           bug.created, '] ')
    pr.add('', colorama.Fore.GREEN, f'{BUGZILLA_URL_PREFIX}{bug.bug}', '')
    if bug.resolved:
        pr.add(' ', colorama.Fore.CYAN, 'bug resolved')
    pr.print()


@functools.lru_cache(maxsize=None)
def cached_atom(s: str) -> atom:
    """Convert string to atom, with caching."""
    return atom(s)


def packages_to_restriction(db: Database
                            ) -> base_restriction:
    """Get a pkgcore restriction for given package list."""
    return OrRestriction(
        *(AndRestriction(*(cached_atom(pkg) for pkg in pkgs))
          for bug in db.bugs.values() for pkgs in bug.packages))


def find_applicable_bugs(package: pkgcore_package,
                         db: Database
                         ) -> typing.Iterable[typing.Tuple[str, Bug]]:
    """Find all bugs applicable to specified package."""
    for bug in db.bugs.values():
        for bug_pkg in bug.packages:
            for at in bug_pkg:
                if not cached_atom(at).match(package):
                    break
            else:
                yield (' '.join(bug_pkg), bug)
                # report only first match per bug
                break


def main() -> int:
    """CLI interface for kuroneko scraper."""
    colorama.init()
    argp = argparse.ArgumentParser()
    argp.add_argument('-d', '--database', type=argparse.FileType('r'),
                      required=True,
                      help='Path to the JSON database with bugs')
    args = argp.parse_args()

    # load the database
    db = Database()
    db.load(args.database)
    args.database.close()

    # initialize pkgcore
    config = load_config()
    domain = config.get_default('domain')
    vdb = domain.repos_raw['vdb']

    # do a quick search for vulnerable packages
    restrict = packages_to_restriction(db)
    vulnerable = vdb.match(restrict)

    # match vulnerable packages to bugs
    first_one = True
    for pkg in vulnerable:
        for bug_pkg, bug in find_applicable_bugs(pkg, db):
            if first_one:
                first_one = False
            else:
                print()
            print_bug(bug, bug_pkg, pkg.cpvstr)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())

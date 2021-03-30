# (c) 2021 Michał Górny
# 2-clause BSD license

"""Bug database abstraction."""

import json
import typing


class Bug(typing.NamedTuple):
    """Tuple representing bug in the database."""

    bug: int
    packages: typing.List[typing.Tuple[str, ...]]
    summary: str
    severity: str
    created: str


class Database:
    """Bug database."""

    bugs: typing.Dict[int, Bug]

    def __init__(self) -> None:
        """Init an empty database."""
        self.bugs = {}

    def load(self, fileobj: typing.IO) -> None:
        """Load database from open JSON file."""
        self.bugs = {}
        data = json.load(fileobj)
        for bug in data['bugs']:
            self.bugs[bug['bug']] = Bug(**bug)

    def save(self, fileobj: typing.IO) -> None:
        """Save database into open JSON file."""
        json.dump({
            'bugs': list(x._asdict() for x in self.bugs.values()),
            }, fileobj)

    def add_bug(self,
                bug: int,
                packages: typing.List[typing.Tuple[str, ...]],
                summary: str,
                severity: str,
                created: str,
                ) -> None:
        """Add a new bug to the database."""
        self.bugs[bug] = Bug(
            bug=bug,
            packages=packages,
            summary=summary,
            severity=severity,
            created=created.split('T', 1)[0],
            )

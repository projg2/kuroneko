========
kuroneko
========
:Copyright: 2021, Michał Górny
:License: 2-clause BSD license

Kuroneko is a tool to audit a Gentoo system for vulnerable packages,
powered by the data scraped from Gentoo Bugzilla.  This complements
GLSA-based tooling by providing the data about vulnerabilities of lower
severity, as well as faster reporting of unresolved vulnerabilities.

Kuroneko consists of two tools:

- kuroneko.scraper is responsible for searching Gentoo Bugzilla
  and scraping the information from Security bugs.  The data is then
  exported into a JSON dump that can be distributed to other hosts.

- kuroneko CLI is responsible for obtaining the installed package list,
  matching vulnerability data against it and printing the relevant
  vulnerabilities.


Using
=====
To use kuroneko CLI, just run the script::

    kuroneko

It will automatically fetch the vulnerability database from Gentoo
servers, scan your system for vulnerable packages and print a list
of them.

Please note that kuroneko is currently in alpha stage and is quite
likely to produce some false positives.  Please treat its output with
caution.


Limitations
===========
Kuroneko relies on scraping security bugs for data.  At the moment,
Gentoo security bugs are pretty primitive.  Most importantly,
the affected package list and versions need to be scraped from bug
summaries.  Many of them follow the same pattern making that feasible
but not all of them.

Kuroneko requires the bug summary to identify affected versions.  Bugs
that were closed without adding a specific version to the summary
are not reported, as they would make it impossible to determine whether
the current version is affected.

There are a few packages where upstream restarted versioning.  Old
security bugs still refer to the old version scheme of these packages,
and may match new versions as well.  We are actively working
on filtering these bugs out.

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

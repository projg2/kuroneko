# (c) 2021 Michał Górny
# 2-clause BSD license

"""Tests for scraping support"""

import pytest
import responses

from kuroneko.scraper import (
    BugInfo, find_security_bugs, find_package_specs,
    )


@responses.activate
def test_bugzilla_scraping():
    expected = [
        BugInfo(
            alias=['CVE-2014-3800'],
            id=536366,
            summary='media-tv/kodi: Password disclosure vulnerability '
                    '(CVE-2014-3800)',
            whiteboard='B3 [upstream cve]',
            ),
        BugInfo(
            alias=[],
            id=576134,
            summary='app-emulation/wine: Insecure use of temp files '
                    'with predictable names',
            whiteboard='B4 [upstream]',
            ),
        BugInfo(
            alias=['CVE-2013-4392'],
            id=600624,
            summary='sys-apps/systemd: TOCTOU race condition when '
                    'updating file permissions and SELinux security '
                    'contexts',
            whiteboard='~3 [upstream cve]',
            ),
        BugInfo(
            alias=[],
            id=602594,
            summary='app-accessibility/eflite: root privilege '
                    'escalation',
            whiteboard='B1 [ebuild]',
            ),
    ]
    bugs_json = [x._asdict() for x in expected]

    responses.add(responses.GET,
                  'https://bugs.gentoo.org/rest/bug?product=Gentoo+Security&'
                  'component=Vulnerabilities&include_fields=id&'
                  'include_fields=summary&include_fields=alias&'
                  'include_fields=whiteboard&'
                  'resolution=---&limit=10',
                  json={'bugs': bugs_json})

    assert list(find_security_bugs()) == expected


@pytest.mark.parametrize(
    'spec,expected',
    [('dev-foo/bar: funny vuln', ['dev-foo/bar']),
     ('<dev-foo/bar-12: funny', ['<dev-foo/bar-12']),
     ('<dev-foo/bar-{12.2,14}: funny', ['<dev-foo/bar-12.2',
                                        '<dev-foo/bar-14']),
     ('dev-foo/{bar,baz} lalala', ['dev-foo/bar', 'dev-foo/baz']),
     ('~dev-foo/bar-14[sqlite]', ['~dev-foo/bar-14']),
     ('dev-foo/bar, dev-foo/baz, CVE-12345', ['dev-foo/bar',
                                              'dev-foo/baz']),
     ('<>dev-foo/baz: imma big junk', []),
     ('dev-foo/bar:{1.3,1.4}', ['dev-foo/bar:1.3', 'dev-foo/bar:1.4']),
     ('<dev-foo/bar-{1.3.2:1.3,1.4.7:1.4}', ['<dev-foo/bar-1.3.2:1.3',
                                             '<dev-foo/bar-1.4.7:1.4']),
     ])
def test_find_package_specs(spec, expected):
    assert sorted(find_package_specs(spec)) == expected

# (c) 2021 Michał Górny
# 2-clause BSD license

"""Tests for scraping support"""

import pytest
import responses

from kuroneko.scraper import (
    BugInfo, find_security_bugs, find_package_specs, get_severity,
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
            creation_time='2016-03-01T17:31:35Z',
            ),
        BugInfo(
            alias=[],
            id=576134,
            summary='app-emulation/wine: Insecure use of temp files '
                    'with predictable names',
            whiteboard='B4 [upstream]',
            creation_time='2016-03-01T17:31:35Z',
            ),
        BugInfo(
            alias=['CVE-2013-4392'],
            id=600624,
            summary='sys-apps/systemd: TOCTOU race condition when '
                    'updating file permissions and SELinux security '
                    'contexts',
            whiteboard='~3 [upstream cve]',
            creation_time='2016-11-23T20:58:05Z',
            ),
        BugInfo(
            alias=[],
            id=602594,
            summary='app-accessibility/eflite: root privilege '
                    'escalation',
            whiteboard='B1 [ebuild]',
            creation_time='2016-12-14T02:41:52Z',
            ),
    ]
    bugs_json = [x._asdict() for x in expected]

    responses.add(responses.GET,
                  'https://bugs.gentoo.org/rest/bug?product=Gentoo+Security&'
                  'component=Vulnerabilities&include_fields=id&'
                  'include_fields=summary&include_fields=alias&'
                  'include_fields=whiteboard&'
                  'include_fields=creation_time&'
                  'resolution=---',
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


@pytest.mark.parametrize(
    'wb,expected',
    [('B3 [upstream cve]', 'B3'),
     ('B4 [upstream]', 'B4'),
     ('~3 [upstream cve]', '~3'),
     ('B3 [ebuild]', 'B3'),
     ('A4 [upstream/ebuild cve]', 'A4'),
     ('A2 [stable blocked]', 'A2'),
     ('B1 [glsa masked cve]', 'B1'),
     ('~4 [cleanup]', '~4'),
     ('A2 [glsa? cve]', 'A2'),
     ('C1 [glsa? cleanup]', 'C1'),
     ('?? [glsa?]', '??'),
     ('', '??'),
     ('random stuff', '??'),
     ])
def test_get_severity(wb, expected):
    assert get_severity(wb) == expected

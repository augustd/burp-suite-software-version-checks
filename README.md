[![Build Status](https://travis-ci.org/augustd/burp-suite-software-version-checks.svg?branch=master)](https://travis-ci.org/augustd/burp-suite-software-version-checks)
[![Known Vulnerabilities](https://snyk.io/test/github/augustd/burp-suite-software-version-checks/badge.svg)](https://snyk.io/test/github/augustd/burp-suite-software-version-checks)

# burp-suite-software-version-checks
This Burp Suite extension passively detects applications revealing server software version numbers during scanning, spidering etc.

Often the server version is revealed only on error responses, which may not be visible during the normal course of testing. Some examples are:

- "Apache Tomcat/6.0.24 - Error report"
- "Server: Apache/2.2.4 (Unix) mod_perl/2.0.3 Perl/v5.8.8"
- "X-AspNet-Version: 4.0.30319"

Match rules are loaded from a [remote tab-delimited file](https://github.com/augustd/burp-suite-software-version-checks/blob/master/src/main/resources/burp/match-rules.tab) at extension startup.

Users can also load their own match rules from a local file or using the BApp GUI.

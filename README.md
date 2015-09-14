This is a Burp Suite 1.5+ extension to help find instances of applications revealing software version numbers. Some examples:

* Apache Tomcat/6.0.24 - Error report
* Server: Apache/2.2.4 (Unix) mod_perl/2.0.3 Perl/v5.8.8
* X-AspNet-Version: 4.0.30319

Often the server version is revealed only on error responses, which may not be visible during the normal course of testing. This extension is designed to passively detect version numbers, even during scanning, spidering, etc.

To build this project you will also need the [Burp Suite Utils](https://github.com/augustd/burp-suite-utils) package. 

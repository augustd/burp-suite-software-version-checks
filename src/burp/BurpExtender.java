package burp;

import com.codemagi.burp.PassiveScan;
import com.codemagi.burp.MatchRule;
import com.codemagi.burp.ScanIssue;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;
import com.codemagi.burp.ScannerMatch;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Burp Extender to find instances of applications revealing software version numbers 
 * 
 * Some examples: 
 * <li>Apache Tomcat/6.0.24 - Error report
 * <li>Server: Apache/2.2.4 (Unix) mod_perl/2.0.3 Perl/v5.8.8
 * <li>X-AspNet-Version: 4.0.30319
 * 
 * @author August Detlefsen <augustd at codemagi dot com>
 * @contributor Thomas Dosedel <thom at secureideas dot com>
 */
public class BurpExtender extends PassiveScan {

    protected ITab mTab;
    
    @Override
    protected void initPassiveScan() {
	//set the extension Name
	extensionName = "Software Version Checks";
	
	//create match rules
	/*
	addMatchRule(new MatchRule(Alterian_CME, 1, "Alterian-CME", ScanIssueSeverity.LOW));
        addMatchRule(new MatchRule(ARR, 1, "IIS Application Request Routing", ScanIssueSeverity.LOW));
        addMatchRule(new MatchRule(ASP_NET, 1, "ASP.Net", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(APACHE, 1, "Apache", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(APACHE_COYOTE, 1, "Apache Coyote (Tomcat)", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(APACHE_TOMCAT, 1, "Apache Tomcat", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(BOA, 1, "BOA Web Server", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(DOT_NET_FRAMEWORK, 1, "Microsoft .Net Framework", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(DOT_NET_FRAMEWORK_SDK, 1, "Microsoft .Net Framework", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(IHS, 1, "IBM HTTP Server", ScanIssueSeverity.LOW));
        addMatchRule(new MatchRule(IBM_NWEB, 1, "IBM-NWeb", ScanIssueSeverity.LOW));
        addMatchRule(new MatchRule(IWEB, 1, "360vision CCTV Web Server", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(JBOSS, 1, "JBoss", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(JBOSS_SVNTAG, 1, "JBoss", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(JBOSS_TOMCAT, 1, "JBoss (Tomcat)", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(JBOSS_WEB, 1, "JBoss Webserver", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(JOOMLA, 1, "Joomla!", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(jQUERY_LIB, 1, "jQuery JavaScript Library", ScanIssueSeverity.INFO));
        addMatchRule(new MatchRule(jQUERY_UITP, 1, "jQuery UI Touch Punch", ScanIssueSeverity.INFO));
        addMatchRule(new MatchRule(jQUERY_HCE, 1, "jQuery hashchange event", ScanIssueSeverity.INFO));
        addMatchRule(new MatchRule(jQUERY_TPS, 1, "jQuery Tiny Pub/Sub", ScanIssueSeverity.INFO));
        addMatchRule(new MatchRule(jQUERY, 1, "jQuery", ScanIssueSeverity.INFO));
        addMatchRule(new MatchRule(jQUERY2, 1, "jQuery", ScanIssueSeverity.INFO));
        addMatchRule(new MatchRule(LIGHTY, 1, "lighttpd", ScanIssueSeverity.LOW));
        addMatchRule(new MatchRule(LiteSpeed, 1, "OpenCms", ScanIssueSeverity.LOW));  
	addMatchRule(new MatchRule(JSF, 1, "Java Server Faces", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(MICROSOFT_HTTPAPI, 1, "Microsoft HTTPAPI", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(MICROSOFT_IIS, 1, "Microsoft IIS", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(MOD_JK, 1, "mod_jk", ScanIssueSeverity.LOW));    
	addMatchRule(new MatchRule(NGINX, 1, "nginx", ScanIssueSeverity.LOW));    
        addMatchRule(new MatchRule(OPENCMS, 1, "OpenCms", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(MOD_SSL, 1, "mod_ssl", ScanIssueSeverity.LOW));    
	addMatchRule(new MatchRule(MOD_PERL, 1, "mod_perl", ScanIssueSeverity.LOW));    
        addMatchRule(new MatchRule(OMNITURE, 1, "Omniture DC (Adobe)", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(OPENSSL, 1, "OpenSSL", ScanIssueSeverity.LOW));    
        addMatchRule(new MatchRule(ORACLE_IPLANET, 1, "Oracle iPlanet", ScanIssueSeverity.LOW));
        addMatchRule(new MatchRule(ORACLE_APP_SVR, 1, "Oracle-Application-Server", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(ORION, 1, "Orion", ScanIssueSeverity.LOW));    
	addMatchRule(new MatchRule(PERL, 1, "Perl", ScanIssueSeverity.LOW));    
	addMatchRule(new MatchRule(PHP, 1, "PHP", ScanIssueSeverity.LOW));    
        addMatchRule(new MatchRule(PHUSION, 1, "Phusion Passenger", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(SERVLET, 1, "Generic Java Servlet engine (possibly JBoss)", ScanIssueSeverity.LOW));    
	addMatchRule(new MatchRule(TORNADO, 1, "Tornado Server", ScanIssueSeverity.LOW));
        addMatchRule(new MatchRule(WAS, 1, "IBM WebSphere Application Server", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(X_ASP_NET, 1, "ASP.Net", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(X_ASP_NET_MVC, 1, "ASP.Net MVC Framework", ScanIssueSeverity.LOW));
	addMatchRule(new MatchRule(X_OWA, 1, "Outlook Web Access", ScanIssueSeverity.LOW));
	*/
			
	mTab = new RuleTab(this, extensionName, callbacks);
	callbacks.addSuiteTab(mTab);

    }
    
    protected void addDynamicMatchRule(MatchRule newRule) {
	super.addMatchRule(newRule);
    }
	    
    protected String getIssueName() {
	return "Software Version Numbers Revealed";
    }

    protected String getIssueDetail(List<com.codemagi.burp.ScannerMatch> matches) {
	StringBuilder description = new StringBuilder(matches.size() * 256);
	description.append("The server software versions used by the application are revealed by the web server.<br>");
	description.append("Displaying version information of software information could allow an attacker to determine which vulnerabilities are present in the software, particularly if an outdated software version is in use with published vulnerabilities.<br><br>");
	description.append("The following software appears to be in use:<br><br>");
	
	for (ScannerMatch match : matches) {
	    //add a description
	    description.append("<li>");

	    description.append(match.getType()).append(": ").append(match.getMatch());
	}

	return description.toString();
    }

    protected ScanIssueSeverity getIssueSeverity(List<com.codemagi.burp.ScannerMatch> matches) {
	ScanIssueSeverity output = ScanIssueSeverity.INFO;
	for (ScannerMatch match : matches) {
	    //if the severity value of the match is higher, then update the stdout value
	    ScanIssueSeverity matchSeverity = match.getSeverity();
	    callbacks.printOutput("Severity: " + matchSeverity);
	    if (matchSeverity != null && 
		output.getValue() < matchSeverity.getValue()) {
		
		output = matchSeverity;
	    }
	    callbacks.printOutput("Output: " + output);
	}
	return output;
    }

    protected ScanIssueConfidence getIssueConfidence(List<com.codemagi.burp.ScannerMatch> matches) {
	return ScanIssueConfidence.CERTAIN;
    }
    
    @Override
    protected IScanIssue getScanIssue(IHttpRequestResponse baseRequestResponse, List<ScannerMatch> matches, List<int[]> startStop) {
	return new ScanIssue(
		baseRequestResponse, 
		helpers,
		callbacks, 
		startStop, 
		getIssueName(), 
		getIssueDetail(matches), 
		ScanIssueSeverity.MEDIUM.getName(), 
		ScanIssueConfidence.FIRM.getName());
    }

    //regex for server identifiers
    private static final Pattern Alterian_CME = Pattern.compile("Alterian-CME/([0-9\\.]+)");
    private static final Pattern ARR = Pattern.compile("ARR/([0-9\\.]+)");
    private static final Pattern ASP_NET = Pattern.compile("ASP.NET Version:([0-9\\.]+)");
    private static final Pattern APACHE = Pattern.compile("Apache/([0-9\\.]+( \\([ a-zA-Z]+\\)){0,1})");
    private static final Pattern APACHE_COYOTE = Pattern.compile("Apache-Coyote/([0-9\\.]+)");
    private static final Pattern APACHE_TOMCAT = Pattern.compile("Apache Tomcat/([0-9\\.]+)");
    private static final Pattern BOA = Pattern.compile("BOA/([0-9\\.]+)");
    private static final Pattern DOT_NET_FRAMEWORK = Pattern.compile("Microsoft \\.NET Framework Version:([0-9\\.]+)");
    private static final Pattern DOT_NET_FRAMEWORK_SDK = Pattern.compile("Microsoft \\.NET Framework ([0-9\\.]+)");
    private static final Pattern IHS = Pattern.compile("IBM_HTTP_Server/([0-9\\.]+)");
    private static final Pattern IBM_NWEB = Pattern.compile("nweb/([0-9\\.]+)");
    private static final Pattern IWEB = Pattern.compile("IWeb/([0-9\\.]+)");
    private static final Pattern JBOSS = Pattern.compile("JBoss-([0-9\\.]+(GA)?)");
    private static final Pattern JBOSS_SVNTAG = Pattern.compile("JBPAPP_([0-9_]+(GA)?)");
    private static final Pattern JBOSS_TOMCAT = Pattern.compile("Tomcat-([0-9\\.]+)");
    private static final Pattern JBOSS_WEB = Pattern.compile("JBossWeb/([0-9\\.]+(GA)?)");
    private static final Pattern jQUERY_LIB = Pattern.compile("jQuery JavaScript Library v([0-9\\.]+)");
    private static final Pattern jQUERY_HCE = Pattern.compile("jQuery hashchange event - v([0-9\\.]+)");
    private static final Pattern jQUERY_UITP = Pattern.compile("jQuery UI Touch Punch ([0-9\\.]+)");
    private static final Pattern jQUERY_TPS = Pattern.compile("jQuery Tiny Pub/Sub - v([0-9\\.]+)");
    private static final Pattern jQUERY = Pattern.compile("jquery[/-]([0-9\\.]+)");
    private static final Pattern jQUERY2 = Pattern.compile("jQuery v([0-9\\.]+)");  
    private static final Pattern JOOMLA = Pattern.compile("Joomla! ([0-9\\.]+)");
    private static final Pattern JSF = Pattern.compile("JSF/([0-9\\.]+)");
    private static final Pattern LIGHTY= Pattern.compile("lighttpd/([0-9\\.]+)");
    private static final Pattern LiteSpeed = Pattern.compile("LiteSpeed/([0-9\\.]+)");
    private static final Pattern MICROSOFT_HTTPAPI = Pattern.compile("Microsoft-HTTPAPI/([0-9\\.]+)");
    private static final Pattern MICROSOFT_IIS = Pattern.compile("Microsoft-IIS/([0-9\\.]+)");
    private static final Pattern MOD_JK = Pattern.compile("mod_jk/([0-9\\.]+)");
    private static final Pattern MOD_PERL = Pattern.compile("mod_perl/([0-9\\.]+)");
    private static final Pattern MOD_SSL = Pattern.compile("mod_ssl/([0-9\\.]+)");
    private static final Pattern NGINX = Pattern.compile("nginx/([0-9\\.]+)");
    private static final Pattern OMNITURE = Pattern.compile("Omniture DC/([0-9\\.]+)");
    private static final Pattern OPENCMS = Pattern.compile("OpenCms/([0-9\\.]+)");
    private static final Pattern OPENSSL = Pattern.compile("OpenSSL/([0-9\\.]+)");
    private static final Pattern ORACLE_APP_SVR = Pattern.compile("Oracle-Application-Server-([0-9\\.]+.*)");
    private static final Pattern ORION = Pattern.compile("Orion/([0-9\\.]+)");
    private static final Pattern ORACLE_IPLANET = Pattern.compile("Sun-Java-System-Web-Server/([0-9\\.]+.*)");
    private static final Pattern PERL = Pattern.compile("Perl/v([0-9\\.]+)");
    private static final Pattern PHUSION = Pattern.compile("Phusion Passenger ([0-9\\.]+)");
    private static final Pattern PHP = Pattern.compile("PHP/([0-9\\.]+)");
    private static final Pattern SERVLET = Pattern.compile("Servlet ([0-9\\.]+)");
    private static final Pattern TORNADO = Pattern.compile("TornadoServer/([0-9\\.]+)");
    private static final Pattern WAS = Pattern.compile("WebSphere Application Server/([0-9\\.]+)");    
    
    //regex for headers
    private static final Pattern X_ASP_NET = Pattern.compile("X-AspNet-Version: ([0-9\\.]+)");
    private static final Pattern X_ASP_NET_MVC = Pattern.compile("X-AspNetMvc-Version: ([0-9\\.]+)");
    private static final Pattern X_OWA = Pattern.compile("X-OWA-Version: ([0-9\\.]+)");

}

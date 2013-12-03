package burp;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
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
public class BurpExtender implements IBurpExtender, IScannerCheck {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private OutputStream output;
    
    //issue severity
    protected static final String SEVERITY_LOW = "Low";
    protected static final String SEVERITY_INFORMATION = "Information";
    
    //regex for server identifiers
    private static final Pattern Alterian_CME = Pattern.compile("Alterian-CME/([0-9\\.]+)");
    private static final Pattern ARR = Pattern.compile("ARR/([0-9\\.]+)");
    private static final Pattern ASP_NET = Pattern.compile("ASP.NET Version:([0-9\\.]+)");
    private static final Pattern APACHE = Pattern.compile("Apache/([0-9\\.]+( \\([ a-zA-Z]+\\)){0,1})");
    private static final Pattern APACHE_COYOTE = Pattern.compile("Apache-Coyote/([0-9\\.]+)");
    private static final Pattern APACHE_TOMCAT = Pattern.compile("Apache Tomcat/([0-9\\.]+)");
    private static final Pattern BOA = Pattern.compile("BOA/([0-9\\.]+)");
    private static final Pattern DOT_NET_FRAMEWORK = Pattern.compile("Microsoft \\.NET Framework Version:([0-9\\.]+)");
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
    private static final Pattern WAS = Pattern.compile("WebSphere Application Server/([0-9\\.]+)");    
    
    //regex for headers
    private static final Pattern X_ASP_NET = Pattern.compile("X-AspNet-Version: ([0-9\\.]+)");
    private static final Pattern X_ASP_NET_MVC = Pattern.compile("X-AspNetMvc-Version: ([0-9\\.]+)");
    private static final Pattern X_OWA = Pattern.compile("X-OWA-Version: ([0-9\\.]+)");
        
    private static final List<MatchRule> rules = new ArrayList<MatchRule>();
    static {
	rules.add(new MatchRule(Alterian_CME, 1, "Alterian-CME"));
        rules.add(new MatchRule(ARR, 1, "IIS Application Request Routing"));
        rules.add(new MatchRule(ASP_NET, 1, "ASP.Net"));
	rules.add(new MatchRule(APACHE, 1, "Apache"));
	rules.add(new MatchRule(APACHE_COYOTE, 1, "Apache Coyote (Tomcat)"));
	rules.add(new MatchRule(APACHE_TOMCAT, 1, "Apache Tomcat"));
	rules.add(new MatchRule(BOA, 1, "BOA Web Server"));
	rules.add(new MatchRule(DOT_NET_FRAMEWORK, 1, "Microsoft .Net Framework"));
	rules.add(new MatchRule(IHS, 1, "IBM HTTP Server"));
        rules.add(new MatchRule(IBM_NWEB, 1, "IBM-NWeb"));
        rules.add(new MatchRule(IWEB, 1, "360vision CCTV Web Server"));
	rules.add(new MatchRule(JBOSS, 1, "JBoss"));
	rules.add(new MatchRule(JBOSS_SVNTAG, 1, "JBoss"));
	rules.add(new MatchRule(JBOSS_TOMCAT, 1, "JBoss (Tomcat)"));
	rules.add(new MatchRule(JBOSS_WEB, 1, "JBoss Webserver"));
	rules.add(new MatchRule(JOOMLA, 1, "Joomla!"));
	rules.add(new MatchRule(jQUERY_LIB, 1, "jQuery JavaScript Library", SEVERITY_INFORMATION));
        rules.add(new MatchRule(jQUERY_UITP, 1, "jQuery UI Touch Punch", SEVERITY_INFORMATION));
        rules.add(new MatchRule(jQUERY_HCE, 1, "jQuery hashchange event", SEVERITY_INFORMATION));
        rules.add(new MatchRule(jQUERY_TPS, 1, "jQuery Tiny Pub/Sub", SEVERITY_INFORMATION));
        rules.add(new MatchRule(jQUERY, 1, "jQuery", SEVERITY_INFORMATION));
        rules.add(new MatchRule(jQUERY2, 1, "jQuery", SEVERITY_INFORMATION));
        rules.add(new MatchRule(LIGHTY, 1, "lighttpd"));
        rules.add(new MatchRule(LiteSpeed, 1, "OpenCms"));  
	rules.add(new MatchRule(JSF, 1, "Java Server Faces"));
	rules.add(new MatchRule(MICROSOFT_HTTPAPI, 1, "Microsoft HTTPAPI"));
	rules.add(new MatchRule(MICROSOFT_IIS, 1, "Microsoft IIS"));
	rules.add(new MatchRule(MOD_JK, 1, "mod_jk"));    
	rules.add(new MatchRule(NGINX, 1, "nginx"));    
        rules.add(new MatchRule(OPENCMS, 1, "OpenCms"));
	rules.add(new MatchRule(MOD_SSL, 1, "mod_ssl"));    
	rules.add(new MatchRule(MOD_PERL, 1, "mod_perl"));    
        rules.add(new MatchRule(OMNITURE, 1, "Omniture DC (Adobe)"));
	rules.add(new MatchRule(OPENSSL, 1, "OpenSSL"));    
        rules.add(new MatchRule(ORACLE_IPLANET, 1, "Oracle iPlanet"));
        rules.add(new MatchRule(ORACLE_APP_SVR, 1, "Oracle-Application-Server"));
	rules.add(new MatchRule(ORION, 1, "Orion"));    
	rules.add(new MatchRule(PERL, 1, "Perl"));    
	rules.add(new MatchRule(PHP, 1, "PHP"));    
        rules.add(new MatchRule(PHUSION, 1, "Phusion Passenger"));
	rules.add(new MatchRule(SERVLET, 1, "Generic Java Servlet engine (possibly JBoss)"));    
        rules.add(new MatchRule(WAS, 1, "IBM WebSphere Application Server"));
	rules.add(new MatchRule(X_ASP_NET, 1, "ASP.Net"));
	rules.add(new MatchRule(X_ASP_NET_MVC, 1, "ASP.Net MVC Framework"));
	rules.add(new MatchRule(X_OWA, 1, "Outlook Web Access"));
    }
    
    
    /**
     * implement IBurpExtender
     */
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
	// keep a reference to our callbacks object
	this.callbacks = callbacks;

	// obtain an extension helpers object
	helpers = callbacks.getHelpers();

	// set our extension name
	callbacks.setExtensionName("Software Version Checks");

	// register ourselves as a custom scanner check
	callbacks.registerScannerCheck(this);
	
	//get the output stream for info messages
	output = callbacks.getStdout();
	
	println("Loaded Software Version Checks");
    }

    /**
    * implement IScannerCheck
    */
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
	List<ScannerMatch> matches = new ArrayList<ScannerMatch>();
	List<IScanIssue> issues = new ArrayList<IScanIssue>();

	//get the URL of the requst
	URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
	println("Scanning for software version numbers: " + url.toString());
	
	//get the body of the response
	byte[] responseBytes = baseRequestResponse.getResponse();
	String response = helpers.bytesToString(responseBytes);
	
	//iterate through rules and check for matches
	for (MatchRule rule : rules) {
	    Matcher matcher = rule.getPattern().matcher(response);
	    while (matcher.find()) {
		println("FOUND " + rule.getType() + "!");
		
		//get the actual match 
		String group;
		if (rule.getMatchGroup() != null) {
		    group = matcher.group(rule.getMatchGroup());
		} else {
		    group = matcher.group();
		}

		println("start: " + matcher.start() + " end: " + matcher.end() + " group: " + group);

		matches.add(new ScannerMatch(matcher.start(), matcher.end(), group, rule.getType(), rule.getSeverity()));
	    }
	}
		
	// report the issues ------------------------
	if (!matches.isEmpty()) {
	    Collections.sort(matches);  //matches must be in order 
	    StringBuilder description = new StringBuilder(matches.size() * 256);
	    description.append("The server software versions used by the application are revealed by the web server.<br>");
	    description.append("Displaying version information of software information could allow an attacker to determine which vulnerabilities are present in the software, particularly if an outdated software version is in use with published vulnerabilities.<br><br>");
	    description.append("The following software appears to be in use:<br><br>");
	    
	    String severity = null;
	    
	    List<int[]> startStop = new ArrayList<int[]>(1);
	    for (ScannerMatch match : matches) {
		println("Processing match: " + match);
		println("    start: " + match.getStart() + " end: " + match.getEnd() + " match: " + match.getMatch() + " match: " + match.getMatch());

		//add a marker for code highlighting
		startStop.add(new int[]{match.getStart(), match.getEnd()});

		//add a description
		description.append("<li>");

		description.append(match.getType()).append(": ").append(match.getMatch());

		//update the severity level
		if (severity == null || SEVERITY_INFORMATION.equals(severity)) {
		    severity = match.getSeverity();
		} 
	    }

	    println("    Description: " + description.toString());

	    issues.add(new CustomScanIssue(
			baseRequestResponse.getHttpService(),
			helpers.analyzeRequest(baseRequestResponse).getUrl(),
			new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, startStop)},
			"Software Version Numbers Revealed",
			description.toString(),
			severity,
			"Firm"));

	    println("issues: " + issues.size());

	    return issues;
	    
	}
    
	return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

	return null;

    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
	// This method is called when multiple issues are reported for the same URL 
	// path by the same extension-provided check. The value we return from this 
	// method determines how/whether Burp consolidates the multiple issues
	// to prevent duplication
	//
	// Since the issue name is sufficient to identify our issues as different,
	// if both issues have the same name, only report the existing issue
	// otherwise report both issues
	if (existingIssue.getIssueDetail().equals(newIssue.getIssueDetail())) {
	    println("DUPLICATE ISSUE! Consolidating...");
	    return -1;
	} else {
	    return 0;
	}
    }
    
    private void println(String toPrint) {
	try {
	    output.write(toPrint.getBytes());
	    output.write("\n".getBytes());
	    output.flush();
	} catch (IOException ioe) {
	    ioe.printStackTrace();
	} 
    }
}



/**
 * class implementing IScanIssue to hold our custom scan issue details
 */
class CustomScanIssue implements IScanIssue {

    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;

    public CustomScanIssue(
	    IHttpService httpService,
	    URL url,
	    IHttpRequestResponse[] httpMessages,
	    String name,
	    String detail,
	    String severity,
	    String confidence) {
	this.httpService = httpService;
	this.url = url;
	this.httpMessages = httpMessages;
	this.name = name;
	this.detail = detail;
	this.severity = severity;
	this.confidence = confidence;
    }

    @Override
    public URL getUrl() {
	return url;
    }

    @Override
    public String getIssueName() {
	return name;
    }

    @Override
    public int getIssueType() {
	return 0;
    }

    @Override
    public String getSeverity() {
	return severity;
    }

    @Override
    public String getConfidence() {
	return confidence;
    }

    @Override
    public String getIssueBackground() {
	return null;
    }

    @Override
    public String getRemediationBackground() {
	return null;
    }

    @Override
    public String getIssueDetail() {
	return detail;
    }

    @Override
    public String getRemediationDetail() {
	return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
	return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
	return httpService;
    }

}


class ScannerMatch implements Comparable<ScannerMatch> {

    private Integer start;
    private int end;
    private String match;
    private String type;
    private String severity;

    public ScannerMatch(int start, int end, String match, String type, String severity) {
	this.start = start;
	this.end = end;
	this.match = match;
	this.type = type;
	this.severity = severity;
    }

    public int getStart() {
	return start;
    }

    public int getEnd() {
	return end;
    }

    public String getMatch() {
	return match;
    }

    public String getType() {
	return type;
    }    
    
    public String getSeverity() {
	return severity;
    }
    
    @Override
    public int compareTo(ScannerMatch m) {
        return start.compareTo(m.getStart());
    }
}


class MatchRule {
    private Pattern pattern;
    private Integer matchGroup;
    private String type;
    private String severity = BurpExtender.SEVERITY_LOW;

    public MatchRule(Pattern pattern, Integer matchGroup, String type) {
	this.pattern = pattern;
	this.matchGroup = matchGroup;
	this.type = type;
    }

    public MatchRule(Pattern pattern, Integer matchGroup, String type, String severity) {
	this.pattern = pattern;
	this.matchGroup = matchGroup;
	this.type = type;
	this.severity = severity;
    }
    
    public Pattern getPattern() {
	return pattern;
    }

    public Integer getMatchGroup() {
	return matchGroup;
    }

    public String getType() {
	return type;
    }

    public String getSeverity() {
	return severity;
    }
}
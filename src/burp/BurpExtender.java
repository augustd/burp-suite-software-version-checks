package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Burp Extender intended to find instances of Applications revealing software version numbers 
 * 
 * Some examples: 
 * <li>Apache Tomcat/6.0.24 - Error report
 * 
 * @author August Detlefsen <augustd at codemagi dot com>
 */
public class BurpExtender implements IBurpExtender, IScannerCheck {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    // test / grep strings
    private static final Pattern ASP_NET = Pattern.compile("ASP.NET Version:([0-9\\.]+)");
    private static final Pattern APACHE = Pattern.compile("Apache/([0-9\\.]+( \\([ a-zA-Z]+\\)){0,1})");
    private static final Pattern APACHE_COYOTE = Pattern.compile("Apache-Coyote/([0-9\\.]+)");
    private static final Pattern APACHE_TOMCAT = Pattern.compile("Apache Tomcat/([0-9\\.]+)");
    private static final Pattern DOT_NET_FRAMEWORK = Pattern.compile("Microsoft \\.NET Framework Version:([0-9\\.]+)");
    private static final Pattern JBOSS = Pattern.compile("JBoss-([0-9\\.]+(GA)?)");
    private static final Pattern JBOSS_SVNTAG = Pattern.compile("JBPAPP_([0-9_]+(GA)?)");
    private static final Pattern JBOSS_TOMCAT = Pattern.compile("Tomcat-([0-9\\.]+)");
    private static final Pattern JBOSS_WEB = Pattern.compile("JBossWeb/([0-9\\.]+(GA)?)");
    private static final Pattern JSF = Pattern.compile("JSF/([0-9\\.]+)");
    private static final Pattern MICROSOFT_HTTPAPI = Pattern.compile("Microsoft-HTTPAPI/([0-9\\.]+)");
    private static final Pattern MICROSOFT_IIS = Pattern.compile("Microsoft-IIS/([0-9\\.]+)");
    private static final Pattern MOD_JK = Pattern.compile("mod_jk/([0-9\\.]+)");
    private static final Pattern MOD_PERL = Pattern.compile("mod_perl/([0-9\\.]+)");
    private static final Pattern MOD_SSL = Pattern.compile("mod_ssl/([0-9\\.]+)");
    private static final Pattern NGINX = Pattern.compile("nginx/([0-9\\.]+)");
    private static final Pattern OPENSSL = Pattern.compile("OpenSSL/([0-9\\.]+)");
    private static final Pattern ORION = Pattern.compile("Orion/([0-9\\.]+)");
    private static final Pattern PERL = Pattern.compile("Perl/v([0-9\\.]+)");
    private static final Pattern PHP = Pattern.compile("PHP/([0-9\\.]+)");
    private static final Pattern SERVLET = Pattern.compile("Servlet ([0-9\\.]+)");
    private static final Pattern X_ASP_NET = Pattern.compile("X-AspNet-Version: ([0-9\\.]+)");
        
    private static final List<MatchRule> rules = new ArrayList<MatchRule>();
    static {
	rules.add(new MatchRule(ASP_NET, 1, "ASP.Net"));
	rules.add(new MatchRule(APACHE, 1, "Apache"));
	rules.add(new MatchRule(APACHE_COYOTE, 1, "Apache Coyote (Tomcat)"));
	rules.add(new MatchRule(APACHE_TOMCAT, 1, "Apache Tomcat"));
	rules.add(new MatchRule(DOT_NET_FRAMEWORK, 1, "Microsoft .Net Framework"));
	rules.add(new MatchRule(JBOSS, 1, "JBoss"));
	rules.add(new MatchRule(JBOSS_SVNTAG, 1, "JBoss"));
	rules.add(new MatchRule(JBOSS_TOMCAT, 1, "JBoss (Tomcat)"));
	rules.add(new MatchRule(JBOSS_WEB, 1, "JBoss Webserver"));
	rules.add(new MatchRule(JSF, 1, "Java Server Faces"));
	rules.add(new MatchRule(MICROSOFT_HTTPAPI, 1, "Microsoft HTTPAPI"));
	rules.add(new MatchRule(MICROSOFT_IIS, 1, "Microsoft IIS"));
	rules.add(new MatchRule(MOD_JK, 1, "mod_jk"));    
	rules.add(new MatchRule(NGINX, 1, "nginx"));    
	rules.add(new MatchRule(MOD_SSL, 1, "mod_ssl"));    
	rules.add(new MatchRule(MOD_PERL, 1, "mod_perl"));    
	rules.add(new MatchRule(OPENSSL, 1, "OpenSSL"));    
	rules.add(new MatchRule(ORION, 1, "Orion"));    
	rules.add(new MatchRule(PERL, 1, "Perl"));    
	rules.add(new MatchRule(PHP, 1, "PHP"));    
	rules.add(new MatchRule(SERVLET, 1, "Generic Java Servlet engine (possibly JBoss)"));    
	rules.add(new MatchRule(X_ASP_NET, 1, "ASP.Net"));
	
	
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
	
	System.out.println("Loaded Software Version Checks");
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
	System.out.println("Scanning for software version numbers: " + url.toString());
	
	//get the body of the response
	byte[] responseBytes = baseRequestResponse.getResponse();
	String response = helpers.bytesToString(responseBytes);
	
	//iterate through rules and check for matches
	for (MatchRule rule : rules) {
	    Matcher matcher = rule.getPattern().matcher(response);
	    while (matcher.find()) {
		System.out.println("FOUND " + rule.getType() + "!");
		
		//get the actual match 
		String group;
		if (rule.getMatchGroup() != null) {
		    group = matcher.group(rule.getMatchGroup());
		} else {
		    group = matcher.group();
		}

		System.out.println("start: " + matcher.start() + " end: " + matcher.end() + " group: " + group);

		matches.add(new ScannerMatch(matcher.start(), matcher.end(), group, rule.getType()));
	    }
	}
		
	// report the issues ------------------------
	if (!matches.isEmpty()) {
	    Collections.sort(matches);  //matches must be in order 
	    StringBuilder description = new StringBuilder(matches.size() * 256);
	    description.append("The server software versions used by the application are revealed by the web server.<br>");
	    description.append("Displaying version information of software information could allow an attacker to determine which vulnerabilities are present in the software, particularly if an outdated software version is in use with published vulnerabilities.<br><br>");
	    description.append("The following software appears to be in use:<br><br>");
	    
	    List<int[]> startStop = new ArrayList<int[]>(1);
	    for (ScannerMatch match : matches) {
		System.out.println("Processing match: " + match);
		System.out.println("    start: " + match.getStart() + " end: " + match.getEnd() + " match: " + match.getMatch() + " match: " + match.getMatch());

		//add a marker for code highlighting
		startStop.add(new int[]{match.getStart(), match.getEnd()});

		//add a description
		description.append("<li>");

		description.append(match.getType()).append(": ").append(match.getMatch());

	    }

	    System.out.println("    Description: " + description.toString());

	    System.out.println("    Confidence: Firm");

	    issues.add(new CustomScanIssue(
			baseRequestResponse.getHttpService(),
			helpers.analyzeRequest(baseRequestResponse).getUrl(),
			new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, startStop)},
			"Software Version Numbers Revealed",
			description.toString(),
			"Low",
			"Firm"));

	    System.out.println("issues: " + issues.size());

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
	    System.out.println("DUPLICATE ISSUE! Consolidating...");
	    return -1;
	} else {
	    return 0;
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

    public ScannerMatch(int start, int end, String match, String type) {
	this.start = start;
	this.end = end;
	this.match = match;
	this.type = type;
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
    
    @Override
    public int compareTo(ScannerMatch m) {
        return start.compareTo(m.getStart());
    }
}


class MatchRule {
    private Pattern pattern;
    private Integer matchGroup;
    private String type;

    public MatchRule(Pattern pattern, Integer matchGroup, String type) {
	this.pattern = pattern;
	this.matchGroup = matchGroup;
	this.type = type;
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
}
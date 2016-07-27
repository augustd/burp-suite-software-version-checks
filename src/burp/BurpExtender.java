package burp;

import com.codemagi.burp.PassiveScan;
import com.codemagi.burp.MatchRule;
import com.codemagi.burp.ScanIssue;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;
import com.codemagi.burp.ScannerMatch;
import com.monikamorrow.burp.BurpSuiteTab;
import java.util.List;
import java.util.regex.Pattern;
import javax.swing.JPanel;

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

    public static String TAB_NAME = "Versions";
    public static String EXTENSION_NAME = "Software Version Checks";

    protected RuleTableComponent rulesTable;
    protected BurpSuiteTab mTab;

    @Override
    protected void initPassiveScan() {
        //set the settings namespace
        settingsNamespace = "SVC_";

        rulesTable = new RuleTableComponent(this, callbacks);

        mTab = new BurpSuiteTab(TAB_NAME, callbacks);
        mTab.addComponent(rulesTable);
    }

//    ::TODO:: Add so that settings can save on exit
//    @Override
//    public void extensionUnloaded() {
//        mTab.saveSettings();
//    }

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
	    if (matchSeverity != null &&
		output.getValue() < matchSeverity.getValue()) {

		output = matchSeverity;
	    }
	}
	return output;
    }

    protected ScanIssueConfidence getIssueConfidence(List<com.codemagi.burp.ScannerMatch> matches) {
	ScanIssueConfidence output = ScanIssueConfidence.TENTATIVE;
	for (ScannerMatch match : matches) {
	    //if the severity value of the match is higher, then update the stdout value
	    ScanIssueConfidence matchConfidence = match.getConfidence();
	    if (matchConfidence != null &&
		output.getValue() < matchConfidence.getValue()) {

		output = matchConfidence;
	    }
	}
	return output;
    }

    @Override
    protected IScanIssue getScanIssue(IHttpRequestResponse baseRequestResponse, List<ScannerMatch> matches, List<int[]> startStop) {
	ScanIssueSeverity overallSeverity = getIssueSeverity(matches);
        ScanIssueConfidence overallConfidence = getIssueConfidence(matches);

        return new ScanIssue(
		baseRequestResponse,
		helpers,
		callbacks,
		startStop,
		getIssueName(),
		getIssueDetail(matches),
		overallSeverity.getName(),
		overallConfidence.getName());
    }

}

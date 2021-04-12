package burp;

import com.codemagi.burp.Offsets;
import com.codemagi.burp.PassiveScan;
import com.codemagi.burp.ScanIssue;
import com.codemagi.burp.RuleTableComponent;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;
import com.codemagi.burp.ScannerMatch;
import com.monikamorrow.burp.BurpSuiteTab;
import com.monikamorrow.burp.ToolsScopeComponent;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Burp Extender to find instances of applications revealing software version
 * numbers
 *
 * Some examples:
 * <li>Apache Tomcat/6.0.24 - Error report
 * <li>Server: Apache/2.2.4 (Unix) mod_perl/2.0.3 Perl/v5.8.8
 * <li>X-AspNet-Version: 4.0.30319
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 * @contributor Thomas Dosedel [thom at secureideas dot com] for match rules
 */
public class BurpExtender extends PassiveScan implements IHttpListener {

    public static final String TAB_NAME = "Versions";
    public static final String EXTENSION_NAME = "Software Version Checks";

    protected RuleTableComponent rulesTable;
    protected VersionsComponent versionsComponent;
    protected ConsolidateComponent consolidate;
    protected ToolsScopeComponent toolsScope;
    protected BurpSuiteTab mTab;

    protected Map<String, Set<String>> versions = new HashMap<>();

    @Override
    protected void initPassiveScan() {
        //set the extension Name		 
        extensionName = EXTENSION_NAME;

        //set the settings namespace
        settingsNamespace = "SVC_";

        mTab = new BurpSuiteTab(TAB_NAME, callbacks);

        rulesTable = new RuleTableComponent(this, callbacks, "https://raw.githubusercontent.com/augustd/burp-suite-software-version-checks/master/src/main/resources/burp/match-rules.tab", "burp/match-rules.tab");
        mTab.addComponent(rulesTable);

        versionsComponent = new VersionsComponent(callbacks);
        mTab.addComponent(versionsComponent);

        consolidate = new ConsolidateComponent(callbacks);
        consolidate.setDefault(true);
        mTab.addComponent(consolidate);

        toolsScope = new ToolsScopeComponent(callbacks);
        toolsScope.setToolDefault(IBurpExtenderCallbacks.TOOL_PROXY, true);
        toolsScope.setEnabledToolConfig(IBurpExtenderCallbacks.TOOL_PROXY, false);
        toolsScope.setToolDefault(IBurpExtenderCallbacks.TOOL_SCANNER, true);
        toolsScope.setToolDefault(IBurpExtenderCallbacks.TOOL_REPEATER, true);
        toolsScope.setToolDefault(IBurpExtenderCallbacks.TOOL_INTRUDER, true);
        mTab.addComponent(toolsScope);

        //register this extension as an HTTP listener
        callbacks.registerHttpListener(this);
    }

    /**
     * Overridden to better consolidate duplicates
     *
     * @param matches
     * @param baseRequestResponse
     * @return The consolidated list of issues found
     */
    @Override
    protected List<IScanIssue> processIssues(List<ScannerMatch> matches, IHttpRequestResponse baseRequestResponse) {
        if (consolidate.isConsolidated()) {
            List<IScanIssue> issues = new ArrayList<>();
            if (!matches.isEmpty()) {
                //get the domain
                URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
                String domain = url.getHost();
                callbacks.printOutput("Processing issues for: " + domain);

                //get the existing matches for this domain
                Set<String> domainMatches = versions.get(domain);
                if (domainMatches == null) {
                    domainMatches = new HashSet<>();
                    versions.put(domain, domainMatches);
                    versionsComponent.addDomain(domain);
                }
                boolean foundUnique = false;

                Collections.sort(matches); //matches must be in order
                //get the offsets of scanner matches
                LinkedList<Offsets> offsets = new LinkedList<>();
                for (ScannerMatch match : matches) {
                    callbacks.printOutput("Processing match: " + match);
                    callbacks.printOutput("    start: " + match.getStart() + " end: " + match.getEnd() + " full match: " + match.getFullMatch() + " group: " + match.getMatchGroup());

                    //add a marker for code highlighting
                    Offsets matchOffsets = match.getOffsets();
                    if (!matchOffsets.overlaps(offsets.peekLast())) {
                        offsets.add(match.getOffsets());
                    } else {
                        //if the new offsets overlap, combine them into one and add them to the list
                        Offsets combinedOffsets = matchOffsets.combine(offsets.pop());
                        offsets.add(combinedOffsets);
                    }

                    //have we seen this match before? 
                    if (!domainMatches.contains(match.getFullMatch())) {
                        foundUnique = true;
                        callbacks.printOutput("NEW MATCH!");
                    }
                    domainMatches.add(match.getFullMatch());
                }
                if (foundUnique) {
                    List<int[]> startStop = new ArrayList<>(1);
                    for (Offsets os : offsets) {
                        startStop.add(os.toArray());
                    }
                    issues.add(getScanIssue(baseRequestResponse, matches, startStop));
                }
                callbacks.printOutput("issues: " + issues.size());
            }

            return issues;

        } else {
            return super.processIssues(matches, baseRequestResponse);
        }
    }

    protected void clearCache() {
        versions.clear();
    }

    protected void clearCache(String domain) {
        versions.remove(domain);
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

            description.append(match.getType()).append(": ").append(match.getMatchGroup());
        }

        return description.toString();
    }

    protected ScanIssueSeverity getIssueSeverity(List<com.codemagi.burp.ScannerMatch> matches) {
        ScanIssueSeverity output = ScanIssueSeverity.INFO;
        for (ScannerMatch match : matches) {
            //if the severity value of the match is higher, then update the stdout value
            ScanIssueSeverity matchSeverity = match.getSeverity();
            if (matchSeverity != null
                    && output.getValue() < matchSeverity.getValue()) {

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
            if (matchConfidence != null
                    && output.getValue() < matchConfidence.getValue()) {

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

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        URL requestUrl = getRequestUrl(messageInfo); 
        if (!messageIsRequest && toolsScope.isToolSelected(toolFlag) && callbacks.isInScope(requestUrl)) {
            //first get the scan issues
            List<IScanIssue> issues = runPassiveScanChecks(messageInfo);

            //if we have found issues, consolidate duplicates and add new issues to the Scanner tab
            if (issues != null && !issues.isEmpty()) {
                callbacks.printOutput("NEW issues: " + issues.size());
                //get the request URL prefix
                URL url = helpers.analyzeRequest(messageInfo).getUrl();
                String urlPrefix = url.getProtocol() + "://" + url.getHost() + url.getPath();
                callbacks.printOutput("Consolidating issues for urlPrefix: " + urlPrefix);

                //get existing issues
                IScanIssue[] existingArray = callbacks.getScanIssues(urlPrefix);
                Set<IScanIssue> existingIssues = new HashSet<>();
                for (IScanIssue arrayIssue : existingArray) {
                    //create instances of ScanIssue class so we can compare them
                    ScanIssue existing = new ScanIssue(arrayIssue);
                    //add to HashSet to resolve dupes
                    existingIssues.add(existing);
                }

                //iterate through newly found issues
                for (IScanIssue newIssue : issues) {
                    if (!existingIssues.contains(newIssue)) {
                        callbacks.printOutput("Adding NEW scan issue: " + newIssue);
                        callbacks.addScanIssue(newIssue);
                    }
                }
            }
        }
    }

    private URL getRequestUrl(IHttpRequestResponse messageInfo) {
        URL output = null;
        IRequestInfo request = helpers.analyzeRequest(messageInfo);
        if (request != null) {
            output = request.getUrl();
        } 
        return output;
    }

}

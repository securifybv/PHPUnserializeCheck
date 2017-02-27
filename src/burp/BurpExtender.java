package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * This Burp Scanner Extension tries to find PHP Object Injection Vulnerabilities.
 *
 * It passes a serialized PDO object to the found injection points. If PHP tries to
 * unserialize this object a fatal exception is thrown triggered in the object's
 * __wakeup() method (ext/pdo/pdo_dbh.c):
 *
 * static PHP_METHOD(PDO, __wakeup)
 * {
 * zend_throw_exception_ex(php_pdo_get_exception(), 0, "You cannot serialize or unserialize PDO instances");
 * }
 *
 * If display_errors is disabled, this will result in a 500 Internal Server Error.
 * If this is the case the check will try to unserialize a stdClass object and an
 * empty array. If either one returns a 200 OK, it is assumed that the code is
 * vulnerable to PHP Object Injection.
 *
 * If display_errors is enabled, the fatal exception is returned to the user,
 * making it easier to detected the vulnerability.
 *
 * Based on http://blog.portswigger.net/2012/12/sample-burp-suite-extension-custom_20.html
 */
public class BurpExtender implements IBurpExtender, IScannerCheck
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    // serialized empty array
    private static final byte[] INJ_ARRAYSERIALIZED = "a:0:{}".getBytes();
    // serialized stdClass object
    private static final byte[] INJ_STDCLASSSERIALIZED = "O:8:\"stdClass\":0:{}".getBytes();
    // serialized PDO object
    private static final byte[] INJ_PDOSERIALIZED = "O:3:\"PDO\":0:{}".getBytes();
    // error message returned when display_errors is enabled
    private static final byte[] INJ_ERROR = "Uncaught PDOException: You cannot serialize or unserialize PDO instances".getBytes();

    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("PHP Unserialize Checks");

        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);
    }

    // helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, byte[] match) {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[]{start, start + match.length});
            start += match.length;
        }

        return matches;
    }

    //
    // implement IScannerCheck
    //

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // two rounds, second round base64 encodes the payload
        for(int i = 0; i < 2; i++) {
            // make a request containing our injection test in the insertion point
            byte[] checkRequest = insertionPoint.buildRequest(i == 1 ? helpers.base64Encode(INJ_PDOSERIALIZED).getBytes() : INJ_PDOSERIALIZED);
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
            // look for matches of our active check grep string
            List<int[]> matches = getMatches(checkRequestResponse.getResponse(), INJ_ERROR);
            if (matches.size() > 0) {
                // get the offsets of the payload within the request, for in-UI highlighting
                List<int[]> requestHighlights = new ArrayList<>(1);
                requestHighlights.add(insertionPoint.getPayloadOffsets(i == 1 ? helpers.base64Encode(INJ_PDOSERIALIZED).getBytes() : INJ_PDOSERIALIZED));

                // report the issue
                List<IScanIssue> issues = new ArrayList<>(1);
                issues.add(new PHPObjectInjectionScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        new IHttpRequestResponse[]{callbacks.applyMarkers(checkRequestResponse, requestHighlights, matches)},
                        "Submitting a serialized PDO object returned the following error: <b>" + helpers.bytesToString(INJ_ERROR) + "</b>",
                        "High",
                        "Certain"));
                return issues;
            }

            IResponseInfo responseInfo = helpers.analyzeResponse(checkRequestResponse.getResponse());
            if (responseInfo.getStatusCode() == 500) {
                boolean found = false;
                byte[] checkRequest2 = insertionPoint.buildRequest(i == 1 ? helpers.base64Encode(INJ_STDCLASSSERIALIZED).getBytes() : INJ_STDCLASSSERIALIZED);
                IHttpRequestResponse checkRequestResponse2 = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest2);
                IResponseInfo responseInfo2 = helpers.analyzeResponse(checkRequestResponse2.getResponse());
                if (responseInfo2.getStatusCode() == 200) {
                    found = true;
                } else {
                    checkRequest2 = insertionPoint.buildRequest(i == 1 ? helpers.base64Encode(INJ_ARRAYSERIALIZED).getBytes() : INJ_ARRAYSERIALIZED);
                    checkRequestResponse2 = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest2);
                    responseInfo2 = helpers.analyzeResponse(checkRequestResponse2.getResponse());
                    if (responseInfo2.getStatusCode() == 200) {
                        found = true;
                    }
                }

                if (found) {
                    // get the offsets of the payload within the request, for in-UI highlighting
                    List<int[]> requestHighlights = new ArrayList<>(1);
                    requestHighlights.add(insertionPoint.getPayloadOffsets(i == 1 ? helpers.base64Encode(INJ_PDOSERIALIZED).getBytes() : INJ_PDOSERIALIZED));

                    // report the issue
                    List<IScanIssue> issues = new ArrayList<>(1);
                    issues.add(new PHPObjectInjectionScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(checkRequestResponse, requestHighlights, null)},
                            "Submitting a serialized PDO object returned in an Internal Server Error (500)",
                            "High",
                            "Firm"));
                    return issues;

                }
            }
        }

        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getUrl().equals(newIssue.getUrl()) &&
                existingIssue.getIssueName().equals(newIssue.getIssueName()) &&
                existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()))
            return -1;
        else return 0;
    }
}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class PHPObjectInjectionScanIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;

    public PHPObjectInjectionScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String detail,
            String severity,
            String confidence) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
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
        return "PHP Object Injection";
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
        return "<p>PHP Object Injection is a vulnerability where a vulnerable application unserializes " +
                "user-controllable data. Doing so can be used to instantiate arbitrary objects that depending " +
                "on their implementations can be used for various attacks. These attacks include arbitrary code " +
                "execution, SQL injection, arbitrary file access, and others.</p>\n" +
                "<p>See also: <a href=\"https://www.owasp.org/index.php/PHP_Object_Injection\">https://www.owasp.org/index.php/PHP_Object_Injection</a></p>";
    }

    @Override
    public String getRemediationBackground() {
        return "Avoid unserializing untrusted (user) data. Instead use a safer alternative, like json_decode().";
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
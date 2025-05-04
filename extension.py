from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JTable, JScrollPane, BorderFactory, BoxLayout, JPopupMenu, JMenuItem
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import Dimension, Component, Font, Toolkit, BorderLayout, Color
from java.awt.event import MouseAdapter, MouseEvent
from java.awt.datatransfer import StringSelection
from java.io import PrintWriter
from java.net import URLDecoder, URLEncoder
import re
import java.net.URL
from javax.swing import JDialog, JTextArea, JButton, JPanel, JLabel, JSplitPane, JTabbedPane
from java.lang import Thread, Runnable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.io.IOException
import time

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        self._callbacks.setExtensionName("BurpX")
        self._stdout.println("[*] Extension Loaded: BurpX")
        self.initUI()
        self._callbacks.registerHttpListener(self)
        self._callbacks.addSuiteTab(self)
        self.tested_combinations = set()
        self.detected_urls = set()
        self.ssrf_tested_combinations = set()
        self.ssti_count = 0
        self.ssrf_count = 0
        self.potential_ssrf_count = 0
        self.path_traversal_count = 0
        self.os_command_injection_count = 0
        self.vulnerability_details = {}
        self.dedup_vuln_keys = set()
        self.vuln_details_by_key = {}

    def initUI(self):
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))
        self.panel.setBorder(BorderFactory.createTitledBorder("Vulnerabilities"))
        column_names = ["Full URL", "Parameter", "Payload", "Vulnerability Type"]
        self.model = DefaultTableModel(column_names, 0)
        self.table = JTable(self.model)
        renderer = DefaultTableCellRenderer()
        renderer.setHorizontalAlignment(DefaultTableCellRenderer.CENTER)
        renderer.setFont(Font("Monospaced", Font.PLAIN, 12))
        
        class VulnTypeCellRenderer(DefaultTableCellRenderer):
            def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
                comp = DefaultTableCellRenderer.getTableCellRendererComponent(
                    self, table, value, isSelected, hasFocus, row, column)
                comp.setHorizontalAlignment(DefaultTableCellRenderer.CENTER)
                if value == "ssrf":
                    comp.setForeground(java.awt.Color.RED)
                    comp.setFont(Font("Monospaced", Font.BOLD, 12))
                elif value == "potential ssrf":
                    comp.setForeground(java.awt.Color.ORANGE)
                    comp.setFont(Font("Monospaced", Font.ITALIC, 12))
                elif value == "ssti":
                    comp.setForeground(java.awt.Color.BLUE)
                    comp.setFont(Font("Monospaced", Font.BOLD, 12))
                return comp
        
        self.table.getColumnModel().getColumn(3).setCellRenderer(VulnTypeCellRenderer())
        
        for i in range(1, 3):
            self.table.getColumnModel().getColumn(i).setCellRenderer(renderer)
            
        self.setupContextMenu()
        scroll_pane = JScrollPane(self.table)
        scroll_pane.setPreferredSize(Dimension(850, 300))
        self.panel.add(scroll_pane)
        
    def setupContextMenu(self):
        popup_menu = JPopupMenu()
        
        copy_url_item = JMenuItem("Copy Full URL")
        copy_url_item.addActionListener(lambda event: self.copySelectedURL())
        popup_menu.add(copy_url_item)
        
        remove_item = JMenuItem("Remove from List")
        remove_item.addActionListener(lambda event: self.removeSelectedRow())
        popup_menu.add(remove_item)
        
        self.table.addMouseListener(TableMouseListener(self.table, popup_menu, self))
    
    def copySelectedURL(self):
        selected_row = self.table.getSelectedRow()
        if selected_row != -1:
            url = self.model.getValueAt(selected_row, 0)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(url), None)
            self._stdout.println("[*] URL copied to clipboard: " + url)
    
    def removeSelectedRow(self):
        selected_row = self.table.getSelectedRow()
        if selected_row != -1:
            url = self.model.getValueAt(selected_row, 0)
            if url in self.detected_urls:
                self.detected_urls.remove(url)
            self.model.removeRow(selected_row)
            self.table.repaint()
            self._stdout.println("[*] Removed from list: " + url)

    def getTabCaption(self):
        return "BurpX"

    def getUiComponent(self):
        return self.panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        
        
        final_message_info = messageInfo
        
        
        class ScanRunner(Runnable):
            def __init__(self, burp_extender, message_info):
                self.burp_extender = burp_extender
                self.message_info = message_info
            
            def run(self):
                try:
                    self.burp_extender._stdout.println("[*] Starting background scans")
                    self.burp_extender.scan_ssti(self.message_info)
                    self.burp_extender.scan_ssrf(self.message_info)
                    self.burp_extender.scan_path_traversal(self.message_info)
                    self.burp_extender.scan_os_command_injection(self.message_info)
                    self.burp_extender._stdout.println("[*] Background scans completed")
                except Exception as e:
                    self.burp_extender._stderr.println("[!] Error in background scan: " + str(e))
                    import traceback
                    self.burp_extender._stderr.println(traceback.format_exc())
        
        
        scanner_thread = Thread(ScanRunner(self, final_message_info))
        scanner_thread.start()

    def find_all_occurrences(self, text, substring):
        positions = []
        start = 0
        while True:
            start = text.find(substring, start)
            if start == -1:
                break
            positions.append(start)
            start += 1
        return positions
    
    def scan_ssrf(self, messageInfo):
        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            method = request_info.getMethod()
            full_url = str(request_info.getUrl())
            base_url = full_url.split("?")[0]
            
            confirmed_vuln_key = base_url + "_ssrf_confirmed"
            
            if base_url in [url.split("?")[0] for url in self.detected_urls] or confirmed_vuln_key in self.tested_combinations:
                return False
            
            request = messageInfo.getRequest()
            headers = request_info.getHeaders()
            body_offset = request_info.getBodyOffset()
            body = request[body_offset:]
            body_str = self._helpers.bytesToString(body)
            
            original_response = messageInfo.getResponse()
            if not original_response:
                return False
            
            content_type = ""
            for header in headers:
                if header.lower().startswith("content-type:"):
                    content_type = header.split(":", 1)[1].strip().lower()
                    break
            
            self._stdout.println("[*] Analyzing {} request to {} for SSRF".format(method, full_url))
            
            url_pattern = re.compile(r"https?://[^'\"\s<>]+")
            ssrf_payloads = ["http://localhost", "http://127.0.0.1", "http://0.0.0.0", "http://127.1"]
            
            parameters = request_info.getParameters()
            
            for param in parameters:
                param_name = param.getName()
                param_value = param.getValue()
                param_type = param.getType()
                
                type_name = "unknown"
                if param_type == param.PARAM_URL: type_name = "URL"
                elif param_type == param.PARAM_BODY: type_name = "BODY"
                elif param_type == param.PARAM_COOKIE: type_name = "COOKIE"
                elif param_type == param.PARAM_JSON: type_name = "JSON"
                
                self._stdout.println("[*] Checking parameter: {} (type: {}, value: {})".format(
                    param_name, type_name, param_value[:50] + "..." if len(param_value) > 50 else param_value))
                
                if len(param_value) < 4:
                    continue
                
                try:
                    decoded_value = URLDecoder.decode(param_value, "UTF-8")
                except:
                    decoded_value = param_value
                
                url_match = url_pattern.search(decoded_value)
                if url_match:
                    matched_url = url_match.group(0)
                    self._stdout.println("[*] Found URL in parameter: {}".format(matched_url))
                    
                    if method == "GET":
                        potential_url = "{}?{}={}".format(base_url, param_name, param_value)
                    else:
                        potential_url = "{} [POST: {}]".format(base_url, param_name)
                    
                    potential_display = "{} -> {}".format(potential_url, matched_url)
                    self.addVulnerability(potential_display, param_name, matched_url, "potential ssrf")
                    
                    for payload in ssrf_payloads:
                        test_key = (full_url, param_name, payload)
                        if test_key in self.ssrf_tested_combinations:
                            continue
                        
                        self.ssrf_tested_combinations.add(test_key)
                        self._stdout.println("[*] Testing SSRF payload: {}".format(payload))
                        
                        new_value = decoded_value.replace(matched_url, payload)
                        
                        if "%" in param_value and param_value != decoded_value:
                            new_value = URLEncoder.encode(new_value, "UTF-8")
                        
                        self._stdout.println("[*] Testing SSRF payload: {}".format(payload))
                        
                        new_param = self._helpers.buildParameter(param_name, new_value, param_type)
                        modified_request = self._helpers.updateParameter(request, new_param)
                        
                        request_details = self._helpers.bytesToString(modified_request)
                        
                        try:
                            request_response = self._callbacks.makeHttpRequest(
                                messageInfo.getHttpService(), modified_request)
                            new_response = request_response.getResponse()
                        except Exception as e:
                            self._stderr.println("Error making request: " + str(e))
                            continue
                            
                        if new_response:
                            response_info = self._helpers.analyzeResponse(new_response)
                            status_code = response_info.getStatusCode()
                            
                            response_details = self._helpers.bytesToString(new_response)
                            
                            self._stdout.println("[*] SSRF test response status: {}".format(status_code))
                            
                            if status_code == 200:
                                confirmed_vuln_key = base_url + "_ssrf_confirmed"
                                self.tested_combinations.add(confirmed_vuln_key)
                                
                                if method == "GET":
                                    display_url = "{}?{}={}".format(base_url, param_name, payload)
                                else:
                                    display_url = "{} [POST: {}={}]".format(base_url, param_name, payload)
                                
                                self._stdout.println("[+] SSRF CONFIRMED: {}".format(display_url))
                                description = "SSRF vulnerability confirmed with payload: {}. The server returned a 200 OK status code.".format(payload)
                                self.addVulnerability(display_url, param_name, payload, "ssrf", 
                                                     request=request_details, 
                                                     response=response_details,
                                                     description=description)
                                
                                return True
            
            if method == "POST" and content_type and "application/x-www-form-urlencoded" in content_type:
                self._stdout.println("[*] Trying raw POST body analysis")
                
                form_params = {}
                for pair in body_str.split("&"):
                    if "=" in pair:
                        key, value = pair.split("=", 1)
                        form_params[key] = value
                
                for param_name, param_value in form_params.items():
                    self._stdout.println("[*] Checking raw form param: {}".format(param_name))
                    
                    try:
                        decoded_value = URLDecoder.decode(param_value, "UTF-8")
                    except:
                        decoded_value = param_value
                    
                    url_match = url_pattern.search(decoded_value)
                    if url_match:
                        matched_url = url_match.group(0)
                        self._stdout.println("[*] Found URL in raw form: {}".format(matched_url))
                        
                        potential_url = "{} [POST RAW: {}]".format(base_url, param_name)
                        potential_display = "{} -> {}".format(potential_url, matched_url)
                        self.addVulnerability(potential_display, param_name, matched_url, "potential ssrf")
                        
                        for payload in ssrf_payloads:
                            test_key = (full_url, param_name, payload)
                            if test_key in self.ssrf_tested_combinations:
                                continue
                            
                            self.ssrf_tested_combinations.add(test_key)
                            self._stdout.println("[*] Testing SSRF payload in raw form: {}".format(payload))
                            
                            new_decoded_value = decoded_value.replace(matched_url, payload)

                            new_value = URLEncoder.encode(new_decoded_value, "UTF-8")
                            
                            new_body_str = body_str.replace(
                                "{}={}".format(param_name, param_value),
                                "{}={}".format(param_name, new_value)
                            )
                            
                            new_request = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(new_body_str))
                            
                            request_details = self._helpers.bytesToString(new_request)
                            
                            try:
                                request_response = self._callbacks.makeHttpRequest(
                                    messageInfo.getHttpService(), new_request)
                                new_response = request_response.getResponse()
                            except Exception as e:
                                self._stderr.println("Error making raw request: " + str(e))
                                continue
                            
                            if new_response:
                                response_info = self._helpers.analyzeResponse(new_response)
                                status_code = response_info.getStatusCode()
                                
                                response_details = self._helpers.bytesToString(new_response)
                                
                                self._stdout.println("[*] Raw SSRF test response status: {}".format(status_code))
                                
                                if status_code == 200:
                                    confirmed_vuln_key = base_url + "_ssrf_confirmed"
                                    self.tested_combinations.add(confirmed_vuln_key)
                                    
                                    display_url = "{} [POST RAW: {}={}]".format(base_url, param_name, payload)
                                    self._stdout.println("[+] RAW SSRF CONFIRMED: {}".format(display_url))
                                    description = "SSRF vulnerability confirmed with payload: {} in raw POST body. The server returned a 200 OK status code.".format(payload)
                                    self.addVulnerability(display_url, param_name, payload, "ssrf",
                                                         request=request_details,
                                                         response=response_details,
                                                         description=description)
                                    return True
            return False
            
        except Exception as e:
            self._stderr.println("Error in scan_ssrf: " + str(e))
            import traceback
            self._stderr.println(traceback.format_exc())
            return False
    
    def scan_ssti(self, messageInfo):
        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            if request_info.getMethod() != "GET":
                return

            full_url = str(request_info.getUrl())
            base_url = full_url.split("?")[0]
            
            confirmed_vuln_key = base_url + "_ssti_confirmed"
            
            if base_url in [url.split("?")[0] for url in self.detected_urls] or confirmed_vuln_key in self.tested_combinations:
                return
                
            query_params = request_info.getParameters()
            original_response = messageInfo.getResponse()
            if not original_response:
                return

            response_str = self._helpers.bytesToString(original_response)
            ssti_payloads = ["#{7*7}", "#{7 * 7}", "<%= 7*7 %>", "<%= 7 * 7 %>", "[7*7]", "{{7*7}}", 
                            "{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}[7*7]<%= 7 * 7 %>#{7 * 7}"]
            expected_result = "49"
            
            for param in query_params:
                if param.getType() != param.PARAM_URL:
                    continue

                param_name = param.getName()
                param_value = param.getValue()
                
                try:
                    decoded_param_value = URLDecoder.decode(param_value, "UTF-8")
                except:
                    decoded_param_value = param_value

                if decoded_param_value not in response_str:
                    continue

                reflection_positions = self.find_all_occurrences(response_str, decoded_param_value)
                
                for payload in ssti_payloads:
                    test_key = (full_url, param_name, payload)
                    if test_key in self.tested_combinations:
                        continue

                    self.tested_combinations.add(test_key)
                    encoded_payload = URLEncoder.encode(payload, "UTF-8")
                    new_param = self._helpers.buildParameter(param_name, encoded_payload, param.PARAM_URL)
                    modified_request = self._helpers.updateParameter(messageInfo.getRequest(), new_param)
                    new_response = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), modified_request).getResponse()

                    if new_response:
                        new_response_str = self._helpers.bytesToString(new_response)
                        if abs(len(new_response_str) - len(response_str)) > len(response_str) * 0.5:
                            continue
                        
                        for pos in reflection_positions:
                            expected_pos = pos
                            start_pos = max(0, expected_pos - 20)
                            end_pos = min(len(new_response_str), expected_pos + len(decoded_param_value) + 20)
                            reflection_region = new_response_str[start_pos:end_pos]
                            
                            if (expected_result in reflection_region and 
                                decoded_param_value not in reflection_region and 
                                payload not in reflection_region):
                                
                                result_pos_in_region = reflection_region.find(expected_result)
                                if result_pos_in_region >= 0:
                                    result_pos = start_pos + result_pos_in_region
                                    if abs(result_pos - expected_pos) <= 10:
                                        confirmed_vuln_key = base_url + "_ssti_confirmed"
                                        self.tested_combinations.add(confirmed_vuln_key)
                                        
                                        display_url = "{}?{}={}".format(base_url, param_name, payload)
                                        
                                        request_details = self._helpers.bytesToString(modified_request)
                                        response_details = new_response_str
                                        description = "SSTI vulnerability confirmed with payload: {}. The server evaluated the expression and returned '49'.".format(payload)
                                                        
                                        if display_url not in self.detected_urls:
                                            self.addVulnerability(display_url, param_name, payload, "ssti",
                                                                 request=request_details,
                                                                 response=response_details,
                                                                 description=description)
                                        return

        except Exception as e:
            self._stderr.println("Error in scan_ssti: " + str(e))
            import traceback
            self._stderr.println(traceback.format_exc())

    def scan_path_traversal(self, messageInfo):
        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            method = request_info.getMethod()
            full_url = str(request_info.getUrl())
            base_url = full_url.split("?")[0]
            
            path_traversal_key = base_url + "_path_traversal_confirmed"
            if base_url in [url.split("?")[0] for url in self.detected_urls] or path_traversal_key in self.tested_combinations:
                return False
            
            request = messageInfo.getRequest()
            headers = request_info.getHeaders()
            body_offset = request_info.getBodyOffset()
            body = request[body_offset:]
            body_str = self._helpers.bytesToString(body)
            
            content_type = ""
            for header in headers:
                if header.lower().startswith("content-type:"):
                    content_type = header.split(":", 1)[1].strip().lower()
                    break
            
            self._stdout.println("[*] Analyzing {} request to {} for path traversal".format(method, full_url))
            
            path_traversal_payloads = ["../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//....//etc/passwd"]
            
            parameters = request_info.getParameters()
            
            for param in parameters:
                param_name = param.getName()
                param_value = param.getValue()
                param_type = param.getType()
                
                if re.search(r'\.(jpg|png|gif|pdf|txt|html|php|asp|jsp|cgi)$', param_value, re.IGNORECASE):
                    self._stdout.println("[*] Found potential path traversal parameter: {} with value: {}".format(param_name, param_value))
                    
                    for payload in path_traversal_payloads:
                        test_key = (full_url, param_name, payload)
                        if test_key in self.tested_combinations:
                            continue
                        
                        self.tested_combinations.add(test_key)
                        self._stdout.println("[*] Testing path traversal payload: {}".format(payload))
                        
                        encoded_payload = URLEncoder.encode(payload, "UTF-8") if "%" not in payload else payload
                        new_param = self._helpers.buildParameter(param_name, encoded_payload, param_type)
                        modified_request = self._helpers.updateParameter(request, new_param)
                        
                        request_details = self._helpers.bytesToString(modified_request)
                        
                        try:
                            request_response = self._callbacks.makeHttpRequest(
                                messageInfo.getHttpService(), modified_request)
                            new_response = request_response.getResponse()
                        except Exception as e:
                            self._stderr.println("Error making request: " + str(e))
                            continue
                            
                        if new_response:
                            response_info = self._helpers.analyzeResponse(new_response)
                            status_code = response_info.getStatusCode()
                            
                            response_details = self._helpers.bytesToString(new_response)
                            
                            self._stdout.println("[*] Path traversal test response status: {}".format(status_code))
                            
                            if status_code == 200 and (
                                "root:" in response_details or 
                                "bin:" in response_details or 
                                "daemon:" in response_details or 
                                "nobody:" in response_details or
                                "/bin/bash" in response_details
                            ):
                                self.tested_combinations.add(path_traversal_key)
                                
                                if method == "GET":
                                    display_url = "{}?{}={}".format(base_url, param_name, encoded_payload)
                                else:
                                    display_url = "{} [POST: {}={}]".format(base_url, param_name, encoded_payload)
                                
                                self._stdout.println("[+] PATH TRAVERSAL CONFIRMED: {}".format(display_url))
                                description = "Path traversal vulnerability confirmed with payload: {}. The server returned a 200 OK status code and contains /etc/passwd content.".format(payload)
                                self.addVulnerability(display_url, param_name, payload, "path traversal", 
                                                     request=request_details, 
                                                     response=response_details,
                                                     description=description)
                                
                                return True
                                
                            elif status_code == 200:
                                self._stdout.println("[*] Potential path traversal - got 200 response, checking content")
                                
                                original_response = self._helpers.bytesToString(messageInfo.getResponse())
                                if len(response_details) < len(original_response) * 0.8 or len(response_details) > len(original_response) * 1.2:
                                    self._stdout.println("[+] Response size changed significantly, might be a path traversal")
                                    
                                    if method == "GET":
                                        display_url = "{}?{}={}".format(base_url, param_name, encoded_payload)
                                    else:
                                        display_url = "{} [POST: {}={}]".format(base_url, param_name, encoded_payload)
                                    
                                    self._stdout.println("[+] POTENTIAL PATH TRAVERSAL: {}".format(display_url))
                                    description = "Potential path traversal vulnerability with payload: {}. The server returned a 200 OK status code with significant content change.".format(payload)
                                    self.addVulnerability(display_url, param_name, payload, "path traversal", 
                                                        request=request_details, 
                                                        response=response_details,
                                                        description=description)
                                    return True
            return False
        except Exception as e:
            self._stderr.println("Error in scan_path_traversal: " + str(e))
            import traceback
            self._stderr.println(traceback.format_exc())
            return False

    def scan_os_command_injection(self, messageInfo):
        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            method = request_info.getMethod()
            full_url = str(request_info.getUrl())
            base_url = full_url.split("?")[0]
            
            
            cmd_injection_key = base_url + "_cmd_injection_confirmed"
            if cmd_injection_key in self.tested_combinations:
                self._stdout.println("[*] Skipping already confirmed vulnerable URL: {}".format(base_url))
                return False
            
            request = messageInfo.getRequest()
            headers = request_info.getHeaders()
            body_offset = request_info.getBodyOffset()
            body = request[body_offset:]
            body_str = self._helpers.bytesToString(body)
            
            content_type = ""
            for header in headers:
                if header.lower().startswith("content-type:"):
                    content_type = header.split(":", 1)[1].strip().lower()
                    break
            
            self._stdout.println("[*] Analyzing {} request to {} for OS command injection".format(method, full_url))
            
            
            cmd_injection_payloads = [
                "|echo hello", 
                ";echo hello", 
                "`echo hello`", 
                "$(echo hello)"
            ]
            
            
            success_indicators = ["hello"]
            
            parameters = request_info.getParameters()
            
            
            for param in parameters:
                param_name = param.getName()
                param_value = param.getValue()
                param_type = param.getType()
                
                
                if len(param_value) > 1000:
                    continue
                
                for payload in cmd_injection_payloads:
                    
                    test_key = (base_url, param_name, payload)
                    if test_key in self.tested_combinations:
                        self._stdout.println("[*] Skipping already tested combination: {}, {}, {}".format(base_url, param_name, payload))
                        continue
                    
                    
                    self.tested_combinations.add(test_key)
                    self._stdout.println("[*] Testing OS command injection payload: {}".format(payload))
                    
                    
                    try:
                        new_value = param_value + payload
                        new_param = self._helpers.buildParameter(param_name, new_value, param_type)
                        modified_request = self._helpers.updateParameter(request, new_param)
                    except:
                        continue
                    
                    try:
                        request_response = self._callbacks.makeHttpRequest(
                            messageInfo.getHttpService(), modified_request)
                        new_response = request_response.getResponse()
                    except Exception as e:
                        self._stderr.println("Error making request: " + str(e))
                        continue
                        
                    if new_response:
                        response_info = self._helpers.analyzeResponse(new_response)
                        status_code = response_info.getStatusCode()
                        
                        response_details = self._helpers.bytesToString(new_response)
                        
                        self._stdout.println("[*] OS command injection test response status: {}".format(status_code))
                        
                        
                        for indicator in success_indicators:
                            if indicator.lower() in response_details.lower():
                                
                                self.tested_combinations.add(cmd_injection_key)
                                
                                if method == "GET":
                                    display_url = "{}?{}={}".format(base_url, param_name, new_value)
                                else:
                                    display_url = "{} [POST: {}={}]".format(base_url, param_name, new_value)
                                
                                self._stdout.println("[+] OS COMMAND INJECTION CONFIRMED: {}".format(display_url))
                                description = "OS command injection vulnerability confirmed with payload: {}".format(payload)
                                self.addVulnerability(display_url, param_name, payload, "os command injection",
                                                    request=self._helpers.bytesToString(modified_request),
                                                    response=response_details,
                                                    description=description)
                                
                                
                                return True
            
            
            if method == "POST" and content_type and "application/x-www-form-urlencoded" in content_type:
                form_params = {}
                for pair in body_str.split("&"):
                    if "=" in pair:
                        key, value = pair.split("=", 1)
                        form_params[key] = value
                
                for param_name, param_value in form_params.items():
                    if len(param_value) > 1000:
                        continue
                    
                    try:
                        decoded_value = URLDecoder.decode(param_value, "UTF-8")
                    except:
                        decoded_value = param_value
                    
                    for payload in cmd_injection_payloads:
                        
                        test_key = (base_url, param_name, payload)
                        if test_key in self.tested_combinations:
                            self._stdout.println("[*] Skipping already tested POST combination: {}, {}, {}".format(base_url, param_name, payload))
                            continue
                        
                        
                        self.tested_combinations.add(test_key)
                        
                        try:
                            new_value = URLEncoder.encode(decoded_value + payload, "UTF-8")
                            
                            new_body_str = body_str.replace(
                                "{}={}".format(param_name, param_value),
                                "{}={}".format(param_name, new_value)
                            )
                            
                            new_request = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(new_body_str))
                            
                            request_response = self._callbacks.makeHttpRequest(
                                messageInfo.getHttpService(), new_request)
                            new_response = request_response.getResponse()
                            
                            if new_response:
                                response_info = self._helpers.analyzeResponse(new_response)
                                status_code = response_info.getStatusCode()
                                
                                response_details = self._helpers.bytesToString(new_response)
                                
                                for indicator in success_indicators:
                                    if indicator.lower() in response_details.lower():
                                        
                                        self.tested_combinations.add(cmd_injection_key)
                                        
                                        display_url = "{} [POST: {}={}]".format(base_url, param_name, payload)
                                        
                                        self._stdout.println("[+] POST OS COMMAND INJECTION CONFIRMED: {}".format(display_url))
                                        description = "OS command injection vulnerability in POST request confirmed with payload: {}".format(payload)
                                        self.addVulnerability(display_url, param_name, payload, "os command injection",
                                                           request=self._helpers.bytesToString(new_request),
                                                           response=response_details,
                                                           description=description)
                                        
                                        
                                        return True
                        except Exception as e:
                            continue
            
            
            if method == "POST" and content_type and "application/x-www-form-urlencoded" in content_type:
                for payload in cmd_injection_payloads:
                    test_key = (base_url, "ENTIRE_BODY", payload)
                    if test_key in self.tested_combinations:
                        continue
                    
                    self.tested_combinations.add(test_key)
                    
                    try:
                        full_body_payload = body_str + payload
                        new_request = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(full_body_payload))
                        
                        request_response = self._callbacks.makeHttpRequest(
                            messageInfo.getHttpService(), new_request)
                        new_response = request_response.getResponse()
                        
                        if new_response:
                            response_info = self._helpers.analyzeResponse(new_response)
                            response_details = self._helpers.bytesToString(new_response)
                            
                            for indicator in success_indicators:
                                if indicator.lower() in response_details.lower():
                                    self.tested_combinations.add(cmd_injection_key)
                                    
                                    display_url = "{} [POST BODY: {}]".format(base_url, payload)
                                    
                                    self._stdout.println("[+] POST BODY OS COMMAND INJECTION CONFIRMED: {}".format(display_url))
                                    description = "OS command injection by appending to entire POST body confirmed with payload: {}".format(payload)
                                    self.addVulnerability(display_url, "ENTIRE_BODY", payload, "os command injection",
                                                       request=self._helpers.bytesToString(new_request),
                                                       response=response_details,
                                                       description=description)
                                    
                                    return True
                    except Exception as e:
                        continue
            
            return False
            
        except Exception as e:
            self._stderr.println("Error in scan_os_command_injection: " + str(e))
            return False

    def addVulnerability(self, display_url, param_name, payload, vuln_type, request=None, response=None, description=None):
        
        class UIUpdater(Runnable):
            def __init__(self, ext, display_url, param_name, payload, vuln_type, request, response, description):
                self.ext = ext
                self.display_url = display_url
                self.param_name = param_name
                self.payload = payload
                self.vuln_type = vuln_type
                self.request = request
                self.response = response
                self.description = description
            
            def run(self):
                try:
                    
                    if '?' in self.display_url:
                        base_url = self.display_url.split('?')[0]
                    elif ' [POST' in self.display_url:
                        base_url = self.display_url.split(' [POST')[0]
                    else:
                        base_url = self.display_url
                    
                    dedup_key = (base_url, self.param_name, self.vuln_type)
                    
                    
                    if dedup_key in self.ext.dedup_vuln_keys:
                        return False
                    
                    
                    self.ext.dedup_vuln_keys.add(dedup_key)
                    self.ext.detected_urls.add(self.display_url)
                    self.ext.model.addRow([self.display_url, self.param_name, self.payload, self.vuln_type])
                    self.ext.table.repaint()
                    
                    
                    self.ext.vuln_details_by_key[dedup_key] = {
                        "vuln_type": self.vuln_type,
                        "param_name": self.param_name,
                        "payload": self.payload,
                        "display_url": self.display_url
                    }
                    
                    if self.request:
                        self.ext.vuln_details_by_key[dedup_key]["request"] = self.request
                    if self.response:
                        self.ext.vuln_details_by_key[dedup_key]["response"] = self.response
                    
                    
                    if self.vuln_type == "ssti":
                        self.ext.ssti_count += 1
                    elif self.vuln_type == "ssrf":
                        self.ext.ssrf_count += 1
                    elif self.vuln_type == "potential ssrf":
                        self.ext.potential_ssrf_count += 1
                    elif self.vuln_type == "path traversal":
                        self.ext.path_traversal_count += 1
                    elif self.vuln_type == "os command injection":
                        self.ext.os_command_injection_count += 1
                    
                    
                    self.ext.panel.setBorder(BorderFactory.createTitledBorder(
                        "Vulnerabilities Found: SSRF ({}), Potential SSRF ({}), SSTI ({}), Path Traversal ({}), OS CMD Injection ({})".format(
                            self.ext.ssrf_count, self.ext.potential_ssrf_count, self.ext.ssti_count, 
                            self.ext.path_traversal_count, self.ext.os_command_injection_count)))
                    
                    
                    self.ext._callbacks.issueAlert("Found {} vulnerability: {}".format(self.vuln_type.upper(), self.display_url))
                    return True
                except Exception as e:
                    self.ext._stderr.println("[!] Error updating UI: " + str(e))
                    import traceback
                    self.ext._stderr.println(traceback.format_exc())
                    return False
        
        try:
            
            from javax.swing import SwingUtilities
            SwingUtilities.invokeLater(UIUpdater(self, display_url, param_name, payload, vuln_type, request, response, description))
            
            return True
        except Exception as e:
            self._stderr.println("[!] Error in addVulnerability: " + str(e))
            import traceback
            self._stderr.println(traceback.format_exc())
            return False

class TableMouseListener(MouseAdapter):
    def __init__(self, table, popup_menu, extender):
        self.table = table
        self.popup_menu = popup_menu
        self.extender = extender
        self.last_click_time = 0
        self.click_delay = 300
        
    def mousePressed(self, event):
        try:
            if event.isPopupTrigger():
                self.showPopup(event)
        except Exception as e:
            self.extender._stdout.println("[!!] Error in mousePressed: " + str(e))
            
    def mouseReleased(self, event):
        try:
            if event.isPopupTrigger():
                self.showPopup(event)
        except Exception as e:
            self.extender._stdout.println("[!!] Error in mouseReleased: " + str(e))
    
    def mouseClicked(self, event):
        pass
            
    def showPopup(self, event):
        try:
            row = self.table.rowAtPoint(event.getPoint())
            if row >= 0 and row < self.table.getRowCount():
                self.extender._stdout.println("[*] Context menu requested on row: " + str(row))
                self.table.setRowSelectionInterval(row, row)
                self.popup_menu.show(event.getComponent(), event.getX(), event.getY())
        except Exception as e:
            self.extender._stdout.println("[!!] Error showing popup: " + str(e))

from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JTable, JScrollPane, BorderFactory, BoxLayout, JPopupMenu, JMenuItem
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import Dimension, Component, Font, Toolkit
from java.awt.event import MouseAdapter, MouseEvent
from java.awt.datatransfer import StringSelection
from java.io import PrintWriter
from java.net import URLDecoder, URLEncoder
import re

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
        for i in range(1, self.table.getColumnCount()):
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
        self.table.addMouseListener(TableMouseListener(self.table, popup_menu))
    
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
            self._stdout.println("[*] Removed from list: " + url)

    def getTabCaption(self):
        return "BurpX"

    def getUiComponent(self):
        return self.panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        self.scan_ssti(messageInfo)

    def scan_ssti(self, messageInfo):
        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            if request_info.getMethod() != "GET":
                return

            full_url = str(request_info.getUrl())
            base_url = full_url.split("?")[0]
            if base_url in [url.split("?")[0] for url in self.detected_urls]:
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
                                        display_url = "{}?{}={}".format(base_url, param_name, payload)
                                        if display_url not in self.detected_urls:
                                            self.detected_urls.add(display_url)
                                            self.model.addRow([display_url, param_name, payload, "ssti"])
                                        return

        except Exception as e:
            self._stderr.println("Error in scan_ssti: " + str(e))
            import traceback
            self._stderr.println(traceback.format_exc())
            
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

class TableMouseListener(MouseAdapter):
    def __init__(self, table, popup_menu):
        self.table = table
        self.popup_menu = popup_menu
        
    def mousePressed(self, event):
        if event.isPopupTrigger():
            self.showPopup(event)
            
    def mouseReleased(self, event):
        if event.isPopupTrigger():
            self.showPopup(event)
            
    def showPopup(self, event):
        row = self.table.rowAtPoint(event.getPoint())
        if row >= 0 and row < self.table.getRowCount():
            self.table.setRowSelectionInterval(row, row)
            self.popup_menu.show(event.getComponent(), event.getX(), event.getY())

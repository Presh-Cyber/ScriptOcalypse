# -*- coding: utf-8 -*-
# Burp Suite Python Extension: BurpSeeq AI - COMMUNITY EDITION
# Version: 2.1.0 - Smart AI-Powered Pentesting + Active Verification
# Release Date: 2026-11-20
# License: MIT License
#
# v2.1.0 (based on v1.1.0):
#   - False-positive reduction: evidence-verified AI findings, stricter IDOR check
#     (GET only, structural JSON diff, never "CONFIRMED"), no shared-param "IDOR",
#     auth-bypass needs 2xx, tighter secret/tech fingerprints, header findings capped
#   - Burp scope enforcement; active verification opt-in (off every session)
#   - Credentials/session values redacted before sending to the AI provider
#   - Config stored in Burp extension settings (legacy dotfile migrated once)
#   - JSON output mode + Ollama context sizing
#
# v1.1.0:
#   - Active IDOR auto-confirmation (mutate IDs, compare responses)
#   - Cross-endpoint privilege escalation correlation
#   - Pre-AI heuristic risk scoring (prioritize high-value targets)
#   - Response summarization (JSON keys + errors for smarter AI input)
#   - AI hallucination guard (reject findings that reference fake params)
#   - All v1.0.0 features preserved (50+ vuln classes, CWE, context, PoC)

from burp import IBurpExtender, IHttpListener, IScannerCheck, IScanIssue, ITab, IContextMenuFactory
from java.io import PrintWriter, File
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Dimension, Font, Color, FlowLayout
from javax.swing import (JPanel, JScrollPane, JTextArea, JTable, JLabel, JSplitPane,
                          BorderFactory, SwingUtilities, JButton, BoxLayout, Box,
                          JMenuItem, JPopupMenu, JTextField, JComboBox, JToggleButton,
                          JFileChooser, JOptionPane, UIManager)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing import ListSelectionModel
from javax.swing.event import DocumentListener, ListSelectionEvent, ListSelectionListener
from java.lang import Runnable
from java.util import ArrayList
import json
import threading
import urllib2
import ssl
import time
import hashlib
import re
import csv
import os
import base64
from datetime import datetime

# Secret patterns for JS extraction
SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'AIza[0-9A-Za-z_-]{35}', "Google API Key"),
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI/Stripe Secret Key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
    (r'glpat-[a-zA-Z0-9_-]{20,}', "GitLab Personal Access Token"),
    (r'xox[bpras]-[0-9a-zA-Z-]{10,}', "Slack Token"),
    (r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}', "JWT Token"),
    (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', "Private Key"),
    (r'(?:password|passwd|pwd|secret|api_key|apikey|token|auth)\s*[=:]\s*["\'][^"\']{4,}["\']', "Hardcoded Credential"),
    (r'https?://[a-zA-Z0-9._-]+\.firebaseio\.com', "Firebase Database URL"),
    (r'https?://[a-zA-Z0-9._-]+\.firebaseapp\.com', "Firebase App URL"),
    (r'mongodb(\+srv)?://[^\s"\']+', "MongoDB Connection String"),
    (r'postgres(?:ql)?://[^\s"\']+', "PostgreSQL Connection String"),
    # FP fix: word/number boundaries so version strings like "v10.2.3.4" or "1.10.0.1" don't match
    (r'(?<![\w.])(?:https?://)?(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\w.])(?::\d{2,5})?', "Internal/Private URL"),
    (r'//[#@]\s*sourceMappingURL\s*=\s*\S+', "Source Map Reference"),
]

VERSION     = "2.1.0"
EDITION     = "Community"
RELEASE_DATE = "2026-11-20"

VALID_SEVERITIES = {
    "high": "High", "medium": "Medium", "low": "Low",
    "information": "Information", "informational": "Information",
    "info": "Information", "inform": "Information", "critical": "High"
}

SEVERITY_COLORS = {
    "High":        Color(0xDC, 0x14, 0x3C),
    "Medium":      Color(0xFF, 0x8C, 0x00),
    "Low":         Color(0xFF, 0xA5, 0x00),
    "Information": Color(0x00, 0x80, 0x00),
}

def map_confidence(ai_confidence):
    if ai_confidence < 50: return None
    elif ai_confidence < 75: return "Tentative"
    elif ai_confidence < 90: return "Firm"
    else: return "Certain"

# ---------------------------------------------------------------------------
# Console writer shim
# ---------------------------------------------------------------------------
class ConsolePrintWriter:
    def __init__(self, original_writer, extender_ref):
        self.original = original_writer
        self.extender = extender_ref
    def println(self, message):
        self.original.println(message)
        if hasattr(self.extender, 'log_to_console'):
            try: self.extender.log_to_console(str(message))
            except: pass
    def print_(self, message): self.original.print_(message)
    def write(self, data):     self.original.write(data)
    def flush(self):           self.original.flush()

# ---------------------------------------------------------------------------
# Cell renderers
# ---------------------------------------------------------------------------
class SeverityCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = super(SeverityCellRenderer, self).getTableCellRendererComponent(
                table, value, isSelected, hasFocus, row, column)
        if not isSelected:
            c.setForeground(SEVERITY_COLORS.get(str(value) if value else "", Color.BLACK))
        return c

class TaskStatusCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = super(TaskStatusCellRenderer, self).getTableCellRendererComponent(
                table, value, isSelected, hasFocus, row, column)
        if not isSelected:
            v = str(value) if value else ""
            if "Error" in v:   c.setForeground(Color(0xCC, 0x00, 0x00))
            elif "Completed" in v: c.setForeground(Color(0x00, 0x7A, 0x29))
            elif "Analyzing" in v: c.setForeground(Color(0x00, 0x60, 0xAA))
            else:              c.setForeground(Color.DARK_GRAY)
        return c

class ConfidenceCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = super(ConfidenceCellRenderer, self).getTableCellRendererComponent(
                table, value, isSelected, hasFocus, row, column)
        if not isSelected:
            v = str(value) if value else ""
            if v == "Certain": c.setForeground(Color(0xDC, 0x14, 0x3C))
            elif v == "Firm":  c.setForeground(Color(0xFF, 0x8C, 0x00))
            elif v == "Tentative": c.setForeground(Color.WHITE)
            else:              c.setForeground(Color.DARK_GRAY)
        return c

# ---------------------------------------------------------------------------
# Main extender
# ---------------------------------------------------------------------------
class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers   = callbacks.getHelpers()

        original_stdout = PrintWriter(callbacks.getStdout(), True)
        original_stderr = PrintWriter(callbacks.getStderr(), True)
        self.stdout = ConsolePrintWriter(original_stdout, self)
        self.stderr = ConsolePrintWriter(original_stderr, self)

        self.VERSION      = VERSION
        self.EDITION      = EDITION
        self.RELEASE_DATE = RELEASE_DATE

        callbacks.setExtensionName("BurpSeeq AI - %s Edition v%s" % (self.EDITION, self.VERSION))
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)

        self.config_file = os.path.join(os.path.expanduser("~"), ".burpseeq_config.json")

        # --- AI defaults ---
        self.AI_PROVIDER          = "Ollama"
        self.API_URL              = "http://localhost:11434"
        self.API_KEY              = ""
        self.MODEL                = "deepseek-r1:latest"
        self.MAX_TOKENS           = 2048
        self.AI_REQUEST_TIMEOUT   = 180
        self.available_models     = []
        self.console_selected_model = None
        self.SCAN_MODE            = "Thorough"   # Quick | Thorough | Focused

        # --- UI / behaviour defaults ---
        self.VERBOSE                  = True
        self.THEME                    = "Light"
        self.PASSIVE_SCANNING_ENABLED = True
        # Active verification sends modified requests to the target. Always starts OFF
        # (deliberately not persisted) and only ever runs against in-scope hosts.
        self.ACTIVE_VERIFY_ENABLED    = False
        # Only analyse proxied traffic that is in Burp's Target scope
        self.SCOPE_ONLY               = True
        self._scope_hint_logged       = False
        # Where findings are reported - see REPORT_MODE notes in the state section below
        self.REPORT_MODE              = "Scan task"
        self.SKIP_EXTENSIONS = ["js","gif","jpg","jpeg","png","ico","css","woff","woff2","ttf","svg","map","pdf"]
        self.SEVERITY_FILTER  = "All"   # All | High | Medium | Low | Information

        self.load_config()

        # --- state ---
        self._ui_dirty         = True
        self._refresh_pending  = False
        self._last_console_len = 0

        self.console_messages    = []
        self.console_lock        = threading.Lock()
        self.max_console_messages = 1000

        self.findings_list    = []
        self.findings_lock_ui = threading.Lock()

        self.findings_cache = {}
        self.findings_lock  = threading.Lock()

        self.context_menu_last_invoke  = {}
        self.context_menu_debounce_time = 1.0
        self.context_menu_lock         = threading.Lock()

        self.processed_urls = set()
        # Burp scan-task integration: when a Live audit task calls doPassiveScan for a
        # host, findings are returned to that task (shown in its Issues tab). The proxy
        # listener only analyses hosts no audit task has touched recently.
        # REPORT_MODE (set in Settings > Advanced):
        #   "Scan task" - only Burp audit tasks drive analysis; findings appear in the
        #                 task's Issues tab. Paused task = nothing analysed until resumed.
        #   "Auto"      - prefer the audit task; Proxy listener analyses hosts no task
        #                 has touched in the last AUDIT_ACTIVE_WINDOW seconds.
        #   "Site map only" - Proxy listener only (no audit task needed); issues appear
        #                 in Target > Site map / Issues, not in a task.
        # (REPORT_MODE default is set before load_config() so the saved value wins.)
        self._last_audit_call    = 0.0
        self._no_audit_hint_time = 0.0
        self._audit_seen_hosts   = {}     # host -> last doPassiveScan time
        self.AUDIT_ACTIVE_WINDOW = 120.0  # s: host counts as "covered by an audit task"
        self.AUDIT_HANDOFF_DELAY = 5.0    # s: listener waits this long for the task to claim
        self.url_lock       = threading.Lock()
        self.semaphore      = threading.Semaphore(3)
        self.last_request_time = 0
        self.min_delay         = 4.0

        # Context window: rolling summary of last N endpoints for cross-request analysis
        self.context_window      = []
        self.context_window_lock = threading.Lock()
        self.context_window_max  = 15

        # Finding dedup by (vuln_class + domain) to avoid duplicate reports
        self.finding_dedup_cache = set()
        self.finding_dedup_lock  = threading.Lock()

        self.tasks      = []
        self.tasks_lock = threading.Lock()
        self.stats = {
            "total_requests": 0, "analyzed": 0,
            "skipped_duplicate": 0, "skipped_rate_limit": 0,
            "skipped_low_confidence": 0, "findings_created": 0, "errors": 0
        }
        self.stats_lock = threading.Lock()

        self._create_ssl_context()
        self.initUI()

        self.log_to_console("=== BurpSeeq AI v%s - Community Edition Initialized ===" % self.VERSION)
        self.log_to_console("[+] Scan Mode: %s | Provider: %s | Model: %s" % (
            self.SCAN_MODE, self.AI_PROVIDER, self.MODEL))
        if getattr(self, "_migrated_legacy_config", False):
            if self.save_config():
                self.log_to_console("[CONFIG] Migrated settings from %s into Burp's extension "
                                    "settings. That file still holds your API key in plaintext - "
                                    "delete it once you've confirmed settings loaded." % self.config_file)
        self.refreshUI()
        self.print_logo()

        def _startup_test():
            self.test_ai_connection()
        t = threading.Thread(target=_startup_test)
        t.setDaemon(True); t.start()

        callbacks.addSuiteTab(self)
        self.start_auto_refresh_timer()

    # -----------------------------------------------------------------------
    def _create_ssl_context(self):
        try:
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        except:
            self.ssl_context = None

    # =======================================================================
    # UI CONSTRUCTION
    # =======================================================================
    def initUI(self):
        self.panel = JPanel(BorderLayout())
        self.panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0))

        # -- TOP BANNER --
        bannerPanel = JPanel(BorderLayout())
        bannerPanel.setBackground(Color(0x23, 0x27, 0x2E))
        bannerPanel.setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 14))

        titleLabel = JLabel("BurpSeeq AI  |  Community Edition  v%s" % self.VERSION)
        titleLabel.setFont(Font("Monospaced", Font.BOLD, 15))
        titleLabel.setForeground(Color(0x4A, 0xC2, 0x8A))
        bannerPanel.add(titleLabel, BorderLayout.WEST)

        subtitleLabel = JLabel("50+ Vuln Classes | Smart AI Verification | Context-Aware Analysis")
        subtitleLabel.setFont(Font("Dialog", Font.ITALIC, 11))
        subtitleLabel.setForeground(Color(0x9E, 0xA3, 0xAB))
        bannerPanel.add(subtitleLabel, BorderLayout.EAST)
        self.panel.add(bannerPanel, BorderLayout.NORTH)

        # -- STATS + TOOLBAR --
        controlWrap = JPanel()
        controlWrap.setLayout(BoxLayout(controlWrap, BoxLayout.Y_AXIS))
        controlWrap.setBorder(BorderFactory.createEmptyBorder(6, 10, 4, 10))

        # Stats row
        statsPanel = JPanel(GridBagLayout())
        statsPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color(0xCC, 0xCC, 0xCC)), "Session Statistics"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(3, 8, 3, 8)
        gbc.anchor = GridBagConstraints.WEST

        self.statsLabels = {}
        statDefs = [
            ("total_requests", "Requests",        None),
            ("analyzed",       "Analyzed",         None),
            ("findings_created","Findings",        Color(0xDC, 0x14, 0x3C)),
            ("skipped_duplicate","Duplicates",     None),
            ("skipped_rate_limit","Rate Limited",  None),
            ("skipped_low_confidence","Low Conf",  None),
            ("errors",         "Errors",           Color(0xCC, 0x00, 0x00)),
        ]
        col = 0
        for key, label, fg in statDefs:
            gbc.gridx = col * 2; gbc.gridy = 0
            lbl = JLabel(label + ":")
            lbl.setFont(Font("Dialog", Font.PLAIN, 11))
            statsPanel.add(lbl, gbc)
            gbc.gridx = col * 2 + 1
            val = JLabel("0")
            val.setFont(Font("Monospaced", Font.BOLD, 12))
            if fg: val.setForeground(fg)
            statsPanel.add(val, gbc)
            self.statsLabels[key] = val
            col += 1
        controlWrap.add(statsPanel)
        controlWrap.add(Box.createRigidArea(Dimension(0, 5)))

        # Toolbar row
        toolBar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))

        self.settingsButton = JButton("Settings")
        self.settingsButton.setToolTipText("Configure AI provider, model, and scan options")
        self.settingsButton.addActionListener(self.openSettings)

        self.exportButton = JButton("Export")
        self.exportButton.setToolTipText("Export findings to CSV or JSON")
        self.exportButton.addActionListener(self.exportFindings)

        self.clearButton     = JButton("Clear Completed")
        self.clearAllButton  = JButton("Clear All")
        self.cancelAllButton = JButton("Cancel All")
        self.replayAllButton = JButton("Replay All")

        self.clearButton.addActionListener(self.clearCompleted)
        self.clearAllButton.addActionListener(self.clearAll)
        self.cancelAllButton.addActionListener(self.cancelAllTasks)
        self.replayAllButton.addActionListener(lambda e: self.replayAllTasks())
        self.replayAllButton.setToolTipText("Re-analyse all tasks that have stored request data")

        self.passiveToggle = JToggleButton(
            "Passive: ON" if self.PASSIVE_SCANNING_ENABLED else "Passive: OFF",
            self.PASSIVE_SCANNING_ENABLED)
        self.passiveToggle.setToolTipText("Toggle automatic passive scanning of proxied traffic")
        self.passiveToggle.setFont(Font("Dialog", Font.BOLD, 11))
        self.passiveToggle.addActionListener(self.togglePassive)

        self.activeToggle = JToggleButton("Active: OFF", False)
        self.activeToggle.setToolTipText(
            "Active verification (IDOR ID+1 replay on GET requests). Sends extra requests "
            "to IN-SCOPE hosts only. Off by default every session.")
        self.activeToggle.setFont(Font("Dialog", Font.BOLD, 11))
        self.activeToggle.addActionListener(self.toggleActive)

        # Scan mode combo
        toolBar.add(JLabel("Mode:"))
        self.scanModeCombo = JComboBox(["Quick", "Thorough", "Focused"])
        self.scanModeCombo.setSelectedItem(self.SCAN_MODE)
        self.scanModeCombo.setToolTipText(
            "Quick: OWASP Top 10 + triage  |  Thorough: 50+ classes  |  Focused: Injection/RCE")
        self.scanModeCombo.addActionListener(
            lambda e: self._on_scan_mode_change())
        toolBar.add(self.scanModeCombo)

        # Severity filter combo
        toolBar.add(JLabel("  Filter:"))
        self.severityFilterCombo = JComboBox(["All", "High", "Medium", "Low", "Information"])
        self.severityFilterCombo.setSelectedItem(self.SEVERITY_FILTER)
        self.severityFilterCombo.setToolTipText("Filter findings table by severity")
        self.severityFilterCombo.addActionListener(lambda e: self._apply_severity_filter())
        toolBar.add(self.severityFilterCombo)

        toolBar.add(Box.createRigidArea(Dimension(8, 0)))
        toolBar.add(self.settingsButton)
        toolBar.add(self.exportButton)
        toolBar.add(self.passiveToggle)
        toolBar.add(self.activeToggle)
        toolBar.add(self.clearButton)
        toolBar.add(self.clearAllButton)
        toolBar.add(self.cancelAllButton)
        toolBar.add(self.replayAllButton)

        controlWrap.add(toolBar)
        self.panel.add(controlWrap, BorderLayout.CENTER)

        # -- MAIN SPLIT (Tasks / Findings+Console) --
        outerSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        outerSplit.setResizeWeight(0.30)
        outerSplit.setBorder(BorderFactory.createEmptyBorder(4, 10, 6, 10))

        # -- Tasks table --
        taskPanel = JPanel(BorderLayout())
        taskPanel.setBorder(BorderFactory.createTitledBorder("Active Tasks"))

        self.taskTableModel = DefaultTableModel()
        for col in ["Timestamp", "Type", "URL", "Status", "Duration"]:
            self.taskTableModel.addColumn(col)

        self.taskTable = JTable(self.taskTableModel)
        self.taskTable.setAutoCreateRowSorter(True)
        self.taskTable.setRowHeight(18)
        self.taskTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self.taskTable.getColumnModel().getColumn(3).setCellRenderer(TaskStatusCellRenderer())
        self.taskTable.getColumnModel().getColumn(0).setPreferredWidth(70)
        self.taskTable.getColumnModel().getColumn(1).setPreferredWidth(60)
        self.taskTable.getColumnModel().getColumn(3).setPreferredWidth(180)
        self.taskTable.getColumnModel().getColumn(4).setPreferredWidth(60)

        taskPopup = JPopupMenu()
        for label, fn in [("Replay Selected",  lambda e: self.replaySelectedTasks()),
                           ("Delete Selected",  lambda e: self.deleteSelectedTasks()),
                           ("Cancel Selected",  lambda e: self.cancelSelectedTasks()),
                           ("Clear All",         lambda e: self.clearAll(None))]:
            if label == "Cancel Selected":
                taskPopup.addSeparator()
            item = JMenuItem(label)
            item.addActionListener(fn)
            taskPopup.add(item)

        from java.awt.event import MouseAdapter
        class TaskPopupListener(MouseAdapter):
            def __init__(self, ext): self.ext = ext
            def mousePressed(self, e):
                if e.isPopupTrigger(): self._show(e)
            def mouseReleased(self, e):
                if e.isPopupTrigger(): self._show(e)
            def _show(self, e):
                row = self.ext.taskTable.rowAtPoint(e.getPoint())
                if row >= 0 and not self.ext.taskTable.isRowSelected(row):
                    self.ext.taskTable.setRowSelectionInterval(row, row)
                taskPopup.show(e.getComponent(), e.getX(), e.getY())
        self.taskTable.addMouseListener(TaskPopupListener(self))

        taskPanel.add(JScrollPane(self.taskTable), BorderLayout.CENTER)
        outerSplit.setTopComponent(taskPanel)

        # -- Bottom split: Findings + Detail + Console --
        bottomSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        bottomSplit.setResizeWeight(0.55)

        findingsOuter = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        findingsOuter.setResizeWeight(0.65)

        findingsPanel = JPanel(BorderLayout())
        findingsPanel.setBorder(BorderFactory.createTitledBorder("Findings"))

        self.findingsStatsLabel = JLabel("Total: 0  |  High: 0  |  Medium: 0  |  Low: 0  |  Info: 0")
        self.findingsStatsLabel.setFont(Font("Monospaced", Font.PLAIN, 11))
        self.findingsStatsLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6))
        findingsPanel.add(self.findingsStatsLabel, BorderLayout.NORTH)

        self.findingsTableModel = DefaultTableModel()
        for col in ["Discovered At", "URL", "Finding", "Severity", "Confidence"]:
            self.findingsTableModel.addColumn(col)

        self.findingsTable = JTable(self.findingsTableModel)
        self.findingsTable.setAutoCreateRowSorter(True)
        self.findingsTable.setRowHeight(18)
        self.findingsTable.getColumnModel().getColumn(3).setCellRenderer(SeverityCellRenderer())
        self.findingsTable.getColumnModel().getColumn(4).setCellRenderer(ConfidenceCellRenderer())
        self.findingsTable.getColumnModel().getColumn(0).setPreferredWidth(80)
        self.findingsTable.getColumnModel().getColumn(3).setPreferredWidth(70)
        self.findingsTable.getColumnModel().getColumn(4).setPreferredWidth(70)

        findingsPanel.add(JScrollPane(self.findingsTable), BorderLayout.CENTER)

        # Detail panel on right
        detailPanel = JPanel(BorderLayout())
        detailPanel.setBorder(BorderFactory.createTitledBorder("Finding Detail"))
        self.detailArea = JTextArea()
        self.detailArea.setEditable(False)
        self.detailArea.setLineWrap(True)
        self.detailArea.setWrapStyleWord(True)
        self.detailArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.detailArea.setText("Select a finding to view details.")
        detailPanel.add(JScrollPane(self.detailArea), BorderLayout.CENTER)

        # Wire selection listener  (must extend javax.swing.event.ListSelectionListener)
        extRef = self
        class FindingSelectionListener(ListSelectionListener):
            def valueChanged(self, e):
                if e.getValueIsAdjusting(): return
                try:
                    row = extRef.findingsTable.getSelectedRow()
                    if row < 0: return
                    row = extRef.findingsTable.convertRowIndexToModel(row)
                    with extRef.findings_lock_ui:
                        if row < len(extRef.findings_list):
                            f = extRef.findings_list[row]
                            txt = ("URL:        %s\n"
                                   "Title:      %s\n"
                                   "Severity:   %s\n"
                                   "Confidence: %s\n"
                                   "Discovered: %s\n\n"
                                   "Detail:\n%s") % (
                                f.get("url",""), f.get("title",""),
                                f.get("severity",""), f.get("confidence",""),
                                f.get("discovered_at",""), f.get("detail","(no detail)"))
                            extRef.detailArea.setText(txt)
                            extRef.detailArea.setCaretPosition(0)
                except: pass
        self.findingsTable.getSelectionModel().addListSelectionListener(
            FindingSelectionListener())

        findingsOuter.setLeftComponent(findingsPanel)
        findingsOuter.setRightComponent(detailPanel)

        # Console
        consolePanel = JPanel(BorderLayout())
        consolePanel.setBorder(BorderFactory.createTitledBorder("Console"))

        consoleToolbar = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        clearConsoleBtn = JButton("Clear")
        clearConsoleBtn.setFont(Font("Dialog", Font.PLAIN, 11))
        clearConsoleBtn.addActionListener(lambda e: self._clear_console())
        self.consoleSearchField = JTextField(15)
        self.consoleSearchField.setToolTipText("Filter console lines")
        self.consoleSearchField.getDocument().addDocumentListener(
            type('CFilter', (DocumentListener,), {
                'insertUpdate': lambda s,e: self._filter_console(),
                'removeUpdate': lambda s,e: self._filter_console(),
                'changedUpdate': lambda s,e: None
            })())
        consoleToolbar.add(JLabel("Search:"))
        consoleToolbar.add(self.consoleSearchField)
        consoleToolbar.add(clearConsoleBtn)
        consolePanel.add(consoleToolbar, BorderLayout.NORTH)

        self.consoleTextArea = JTextArea()
        self.consoleTextArea.setEditable(False)
        self.consoleTextArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.console_user_scrolled = False
        consoleScrollPane = JScrollPane(self.consoleTextArea)
        consoleScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        consolePanel.add(consoleScrollPane, BorderLayout.CENTER)

        self.applyConsoleTheme()

        bottomSplit.setTopComponent(findingsOuter)
        bottomSplit.setBottomComponent(consolePanel)

        outerSplit.setBottomComponent(bottomSplit)

        # Wrap everything below banner in a single centre panel
        centreWrap = JPanel(BorderLayout())
        centreWrap.add(controlWrap, BorderLayout.NORTH)
        centreWrap.add(outerSplit,  BorderLayout.CENTER)
        self.panel.add(centreWrap, BorderLayout.CENTER)

        self.mainSplitPane   = outerSplit
        self.bottomSplitPane = bottomSplit

    # -----------------------------------------------------------------------
    def applyConsoleTheme(self):
        if self.THEME == "Dark":
            self.consoleTextArea.setBackground(Color(0x1E, 0x1E, 0x2E))
            self.consoleTextArea.setForeground(Color(0x7D, 0xCF, 0xFF))
        else:
            self.consoleTextArea.setBackground(Color(0xF8, 0xF8, 0xF8))
            self.consoleTextArea.setForeground(Color(0x22, 0x22, 0x22))

    def _on_scan_mode_change(self):
        self.SCAN_MODE = str(self.scanModeCombo.getSelectedItem())
        self.log_to_console("[CONFIG] Scan mode changed to: %s" % self.SCAN_MODE)

    def _apply_severity_filter(self):
        self.SEVERITY_FILTER = str(self.severityFilterCombo.getSelectedItem())
        self._ui_dirty = True
        self.refreshUI()

    def _clear_console(self):
        with self.console_lock:
            self.console_messages = []
            self._last_console_len = 0
        self.consoleTextArea.setText("")

    def _filter_console(self):
        q = self.consoleSearchField.getText().strip().lower()
        with self.console_lock:
            msgs = list(self.console_messages)
        if not q:
            self.consoleTextArea.setText("\n".join(msgs))
        else:
            filtered = [m for m in msgs if q in m.lower()]
            self.consoleTextArea.setText("\n".join(filtered))

    def toggleActive(self, e):
        self.ACTIVE_VERIFY_ENABLED = self.activeToggle.isSelected()
        self.activeToggle.setText("Active: ON" if self.ACTIVE_VERIFY_ENABLED else "Active: OFF")
        self.log_to_console("[CONFIG] Active verification: %s (in-scope hosts only)" % (
            "ENABLED" if self.ACTIVE_VERIFY_ENABLED else "DISABLED"))

    def togglePassive(self, e):
        self.PASSIVE_SCANNING_ENABLED = self.passiveToggle.isSelected()
        label = "Passive: ON" if self.PASSIVE_SCANNING_ENABLED else "Passive: OFF"
        self.passiveToggle.setText(label)
        self.log_to_console("[CONFIG] Passive scanning: %s" % ("ENABLED" if self.PASSIVE_SCANNING_ENABLED else "DISABLED"))

    # -----------------------------------------------------------------------
    # REFRESH
    # -----------------------------------------------------------------------
    def refreshUI(self, event=None):
        if self._refresh_pending or not self._ui_dirty:
            return

        class RefreshRunnable(Runnable):
            def __init__(self, extender):
                self.extender = extender

            def run(self):
                try:
                    ext = self.extender

                    with ext.stats_lock:
                        stats_snapshot = dict(ext.stats)

                    with ext.tasks_lock:
                        tasks_snapshot = []
                        for task in ext.tasks[-100:]:
                            dur = ""
                            if task.get("end_time"):
                                dur = "%.1fs" % (task["end_time"] - task["start_time"])
                            elif task.get("start_time"):
                                dur = "%.1fs" % (time.time() - task["start_time"])
                            tasks_snapshot.append([
                                task.get("timestamp",""), task.get("type",""),
                                task.get("url","")[:100], task.get("status",""), dur
                            ])

                    with ext.findings_lock_ui:
                        severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Information": 0}
                        all_findings = list(ext.findings_list)
                        for f in all_findings:
                            s = f.get("severity","Information")
                            if s in severity_counts: severity_counts[s] += 1

                        sev_filter = ext.SEVERITY_FILTER
                        if sev_filter == "All":
                            display_findings = all_findings
                        else:
                            display_findings = [f for f in all_findings if f.get("severity") == sev_filter]

                        findings_snapshot = []
                        for f in display_findings:
                            findings_snapshot.append([
                                f.get("discovered_at",""), f.get("url","")[:100],
                                f.get("title","")[:60], f.get("severity",""), f.get("confidence","")
                            ])

                    total = len(all_findings)
                    stats_str = ("Total: %d  |  High: %d  |  Medium: %d  |  Low: %d  |  Info: %d" % (
                        total, severity_counts["High"], severity_counts["Medium"],
                        severity_counts["Low"], severity_counts["Information"]))

                    with ext.console_lock:
                        cur_len = len(ext.console_messages)
                        prev_len = ext._last_console_len
                        new_msgs = list(ext.console_messages[prev_len:]) if cur_len != prev_len else None

                    # ---- update task table ----
                    while ext.taskTableModel.getRowCount() > 0:
                        ext.taskTableModel.removeRow(0)
                    for row in tasks_snapshot:
                        ext.taskTableModel.addRow(row)

                    # ---- update findings table ----
                    while ext.findingsTableModel.getRowCount() > 0:
                        ext.findingsTableModel.removeRow(0)
                    for row in findings_snapshot:
                        ext.findingsTableModel.addRow(row)

                    ext.findingsStatsLabel.setText(stats_str)
                    if severity_counts["High"] > 0:
                        ext.findingsStatsLabel.setForeground(Color(0xDC, 0x14, 0x3C))
                    elif severity_counts["Medium"] > 0:
                        ext.findingsStatsLabel.setForeground(Color(0xFF, 0x8C, 0x00))
                    else:
                        ext.findingsStatsLabel.setForeground(Color(0x00, 0x7A, 0x29))

                    # ---- update stats labels ----
                    for key, lbl in ext.statsLabels.items():
                        lbl.setText(str(stats_snapshot.get(key, 0)))

                    # ---- update console ----
                    if new_msgs:
                        q = ""
                        try:
                            q = ext.consoleSearchField.getText().strip().lower()
                        except: pass
                        for msg in new_msgs:
                            if not q or q in msg.lower():
                                ext.consoleTextArea.append(msg + "\n")
                        with ext.console_lock:
                            ext._last_console_len = cur_len
                        try:
                            vsb = ext.consoleTextArea.getParent().getParent().getVerticalScrollBar()
                            vsb.setValue(vsb.getMaximum())
                        except: pass

                    ext._ui_dirty = False
                    ext._refresh_pending = False
                except Exception as e:
                    ext._refresh_pending = False

        self._refresh_pending = True
        SwingUtilities.invokeLater(RefreshRunnable(self))

    def start_auto_refresh_timer(self):
        def _loop():
            while True:
                time.sleep(1.5)
                if self._ui_dirty:
                    self.refreshUI()
        t = threading.Thread(target=_loop)
        t.setDaemon(True); t.start()

    # -----------------------------------------------------------------------
    # TASK MANAGEMENT
    # -----------------------------------------------------------------------
    def addTask(self, task_type, url, status="Queued", messageInfo=None):
        with self.tasks_lock:
            self.tasks.append({
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "type": task_type, "url": url, "status": status,
                "start_time": time.time(), "messageInfo": messageInfo
            })
            return len(self.tasks) - 1

    def updateTask(self, task_id, status):
        with self.tasks_lock:
            if 0 <= task_id < len(self.tasks):
                self.tasks[task_id]["status"] = status
                self.tasks[task_id]["end_time"] = time.time()
        self._ui_dirty = True

    def deleteSelectedTasks(self):
        rows = sorted(set(self.taskTable.getSelectedRows()), reverse=True)
        with self.tasks_lock:
            for r in rows:
                idx = self.taskTable.convertRowIndexToModel(r)
                if 0 <= idx < len(self.tasks):
                    self.tasks.pop(idx)
        self._ui_dirty = True
        self.refreshUI()

    def cancelSelectedTasks(self):
        rows = self.taskTable.getSelectedRows()
        with self.tasks_lock:
            for r in rows:
                idx = self.taskTable.convertRowIndexToModel(r)
                if 0 <= idx < len(self.tasks):
                    self.tasks[idx]["status"] = "Cancelled"
        self._ui_dirty = True
        self.refreshUI()

    def clearCompleted(self, e=None):
        with self.tasks_lock:
            self.tasks = [t for t in self.tasks if "Completed" not in t.get("status","")]
        self._ui_dirty = True
        self.refreshUI()

    def clearAll(self, e=None):
        with self.tasks_lock:
            self.tasks = []
        self._ui_dirty = True
        self.refreshUI()

    def cancelAllTasks(self, e=None):
        with self.tasks_lock:
            for t in self.tasks:
                if t.get("status") in ("Queued", "Analyzing"):
                    t["status"] = "Cancelled"
        self._ui_dirty = True
        self.refreshUI()

    def replaySelectedTasks(self):
        """Re-analyse selected tasks that have stored messageInfo."""
        rows = sorted(set(self.taskTable.getSelectedRows()))
        replay_items = []
        with self.tasks_lock:
            for r in rows:
                idx = self.taskTable.convertRowIndexToModel(r)
                if 0 <= idx < len(self.tasks):
                    task = self.tasks[idx]
                    msg = task.get("messageInfo")
                    if msg:
                        replay_items.append((msg, task.get("url", "")))
        if not replay_items:
            self.log_to_console("[REPLAY] No replayable tasks in selection (missing request data)")
            return
        self.log_to_console("[REPLAY] Re-analysing %d selected task(s)" % len(replay_items))
        def _do():
            for msg, url in replay_items:
                try:
                    tid = self.addTask("REPLAY", url, "Queued", msg)
                    self.analyze_forced(msg, url, tid)
                except Exception as ex:
                    self.log_to_console("[REPLAY] Error: %s" % str(ex))
        t = threading.Thread(target=_do)
        t.setDaemon(True); t.start()

    def replayAllTasks(self):
        """Re-analyse all tasks that have stored messageInfo."""
        replay_items = []
        with self.tasks_lock:
            for task in self.tasks:
                msg = task.get("messageInfo")
                if msg:
                    replay_items.append((msg, task.get("url", "")))
        if not replay_items:
            self.log_to_console("[REPLAY] No replayable tasks found")
            return
        self.log_to_console("[REPLAY] Re-analysing all %d task(s)" % len(replay_items))
        def _do():
            for msg, url in replay_items:
                try:
                    tid = self.addTask("REPLAY", url, "Queued", msg)
                    self.analyze_forced(msg, url, tid)
                except Exception as ex:
                    self.log_to_console("[REPLAY] Error: %s" % str(ex))
        t = threading.Thread(target=_do)
        t.setDaemon(True); t.start()

    def pauseAllTasks(self, e=None):
        pass  # Future: implement semaphore pause

    # -----------------------------------------------------------------------
    # EXPORT
    # -----------------------------------------------------------------------
    def exportFindings(self, e=None):
        fmt = JOptionPane.showInputDialog(
            self.panel,
            "Export format:",
            "Export Findings",
            JOptionPane.QUESTION_MESSAGE,
            None,
            ["CSV", "JSON"],
            "CSV"
        )
        if not fmt: return
        fmt = str(fmt)

        chooser = JFileChooser()
        chooser.setSelectedFile(
            File("burpseeq_findings_%s.%s" % (
                datetime.now().strftime("%Y%m%d_%H%M%S"), fmt.lower())))
        ret = chooser.showSaveDialog(self.panel)
        if ret != JFileChooser.APPROVE_OPTION: return

        path = str(chooser.getSelectedFile().getAbsolutePath())
        try:
            with self.findings_lock_ui:
                data = list(self.findings_list)

            if fmt == "CSV":
                with open(path, "w") as f:
                    f.write("Discovered At,URL,Title,Severity,Confidence,Detail\n")
                    for d in data:
                        row = [d.get("discovered_at",""), d.get("url","").replace(",",""),
                               d.get("title","").replace(",",""), d.get("severity",""),
                               d.get("confidence",""), d.get("detail","").replace(",","").replace("\n"," ")]
                        f.write(",".join(row) + "\n")
            else:
                with open(path, "w") as f:
                    json.dump(data, f, indent=2)

            self.log_to_console("[EXPORT] Saved %d findings to %s" % (len(data), path))
            JOptionPane.showMessageDialog(self.panel, "Exported %d findings to:\n%s" % (len(data), path))
        except Exception as ex:
            self.log_to_console("[EXPORT] Failed: %s" % str(ex))

    # -----------------------------------------------------------------------
    # FINDINGS
    # -----------------------------------------------------------------------
    def add_finding(self, url, title, severity, confidence, detail=""):
        with self.findings_lock_ui:
            self.findings_list.append({
                "discovered_at": datetime.now().strftime("%H:%M:%S"),
                "url": url, "title": title, "severity": severity,
                "confidence": confidence, "detail": detail
            })
        with self.stats_lock:
            self.stats["findings_created"] += 1
        self._ui_dirty = True

    def log_to_console(self, message):
        with self.console_lock:
            self.console_messages.append(
                "[%s] %s" % (datetime.now().strftime("%H:%M:%S"), str(message)[:200]))
            if len(self.console_messages) > self.max_console_messages:
                self.console_messages = self.console_messages[-self.max_console_messages:]
        self._ui_dirty = True

    # -----------------------------------------------------------------------
    # INTELLIGENCE HELPERS
    # -----------------------------------------------------------------------
    def _fingerprint_tech(self, resp_headers, resp_body):
        """Detect technology stack from response headers and body."""
        techs = []
        hdrs = "\n".join(resp_headers).lower()
        body_low = resp_body[:3000].lower() if resp_body else ""

        fp_map = [
            ("X-Powered-By: express", "Node.js/Express"),
            ("x-powered-by: php", "PHP"), ("server: apache", "Apache"),
            ("server: nginx", "Nginx"), ("x-aspnet-version", "ASP.NET"),
            ("x-powered-by: asp.net", "ASP.NET"), ("server: gunicorn", "Python/Gunicorn"),
            ("server: uvicorn", "Python/Uvicorn"), ("x-powered-by: next.js", "Next.js"),
            ("server: cloudflare", "Cloudflare"), ("x-amz-", "AWS"),
            ("x-goog-", "Google Cloud"), ("x-ms-", "Azure"),
        ]
        for sig, name in fp_map:
            if sig.lower() in hdrs:
                techs.append(name)

        # FP fix: generic words ("react", "spring", "rails", "vue", "graphql") matched
        # ordinary page text and fed wrong tech hints to the AI. Use specific markers only.
        cookie_fp = [
            ("laravel_session", "Laravel"), ("jsessionid", "Java"),
            ("csrftoken=", "Django"), ("_rails_session", "Ruby on Rails"),
        ]
        for sig, name in cookie_fp:
            if sig in hdrs and name not in techs:
                techs.append(name)

        body_fp = [
            ("csrfmiddlewaretoken", "Django"),
            ("__viewstate", "ASP.NET WebForms"),
            ("whitelabel error page", "Spring"),
            ('name="csrf-param" content="authenticity_token"', "Ruby on Rails"),
            ("window.__nuxt__", "Nuxt.js"), ("__next_data__", "Next.js"),
            ("data-reactroot", "React"), ("ng-version=", "Angular"),
            ('"__typename"', "GraphQL"), ("/wp-content/", "WordPress"),
            ("drupal.settings", "Drupal"), ('content="joomla', "Joomla"),
        ]
        for sig, name in body_fp:
            if sig in body_low and name not in techs:
                techs.append(name)

        return techs[:5]

    def _extract_js_secrets(self, body):
        """Extract potential secrets from JS/HTML response body using regex patterns."""
        if not body: return []
        secrets = []
        text = body[:10000]
        # Values that are clearly UI placeholders / templates, not real secrets
        placeholder_re = re.compile(
            r'(?:\s|enter|your|example|sample|changeme|placeholder|\*{3,}|x{4,}|\{\{|\$\{|<%|undefined|null)', re.I)
        for pattern, label in SECRET_PATTERNS:
            count = 0
            # FP fix: use finditer/group(0). re.findall returns only the capture
            # group for patterns containing groups (e.g. "(RSA\s+)?"), giving bogus values.
            for mo in re.finditer(pattern, text):
                m = mo.group(0)
                if label == "Hardcoded Credential":
                    quoted = re.search(r'["\']([^"\']*)["\']', m)
                    if quoted and placeholder_re.search(quoted.group(1)):
                        continue
                val = m if len(m) < 80 else m[:77] + "..."
                secrets.append({"type": label, "value": val})
                count += 1
                if count >= 2: break
        return secrets[:10]

    def _classify_endpoint(self, method, url, req_headers, content_type, req_body):
        """Classify the endpoint type to tailor the analysis."""
        url_low = url.lower()
        hdrs_str = " ".join(req_headers).lower()

        if any(k in url_low for k in ["/login", "/signin", "/auth", "/oauth", "/token", "/session", "/register", "/signup", "/password", "/forgot", "/reset"]):
            return "AUTH"
        if any(k in url_low for k in ["/upload", "/import", "/file", "/attachment", "/media"]):
            return "FILE"
        if any(k in url_low for k in ["/pay", "/checkout", "/order", "/cart", "/billing", "/subscription", "/price"]):
            return "PAYMENT"
        if any(k in url_low for k in ["/admin", "/manage", "/dashboard", "/console", "/config", "/settings"]):
            return "ADMIN"
        if any(k in url_low for k in ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"]):
            return "API"
        if any(k in url_low for k in ["/redirect", "/callback", "/return", "/goto", "/next", "/redir"]):
            return "REDIRECT"
        if "content-type" in hdrs_str and ("javascript" in hdrs_str or "text/javascript" in hdrs_str):
            return "JS"
        if any(k in url_low for k in ["/search", "/query", "/find", "/lookup"]):
            return "SEARCH"
        if method in ["POST", "PUT", "PATCH", "DELETE"]:
            return "MUTATION"
        return "GENERAL"

    def _triage_request(self, method, url, status_code, req_headers, req_body, res_body):
        """Two-pass triage: decide if this request is worth deep analysis.
        Returns (should_analyze, reason)."""
        url_low = url.lower()
        path = url_low.split("?")[0]

        # Always analyze: mutations, auth endpoints, APIs with params
        if method in ["POST", "PUT", "PATCH", "DELETE"]:
            return True, "Mutation request (%s)" % method
        if "?" in url and any(p in url_low for p in ["id=", "user", "file", "url=", "redirect", "token", "key", "cmd", "query", "search", "path", "dir", "template"]):
            return True, "Interesting GET parameters"
        if any(k in url_low for k in ["/api/", "/v1/", "/v2/", "/graphql", "/login", "/auth", "/admin", "/upload", "/pay"]):
            return True, "Sensitive endpoint path"
        if status_code in [301, 302, 303, 307, 308]:
            return True, "Redirect (check open redirect)"
        if status_code in [401, 403, 500, 502, 503]:
            return True, "Error response (info leak potential)"
        # Check for interesting response content
        if res_body:
            rb = res_body[:2000].lower()
            if any(k in rb for k in ["password", "secret", "token", "api_key", "apikey", "private", "internal", "admin", "error", "exception", "traceback", "stack"]):
                return True, "Sensitive content in response"
        # Check for JWT or auth headers
        hdrs = " ".join(req_headers).lower()
        if "authorization: bearer" in hdrs or "x-api-key" in hdrs:
            return True, "Authenticated request"
        # Skip boring static-like responses
        if method == "GET" and "?" not in url and status_code == 200:
            if res_body and len(res_body) < 100:
                return False, "Short static GET response"
        # Default: analyze in Thorough mode, skip in Quick
        return True, "Default pass"

    def _build_context_summary(self):
        """Build a rolling context summary from recent analyses."""
        with self.context_window_lock:
            if not self.context_window:
                return ""
            lines = ["RECENT ENDPOINT CONTEXT (for cross-request pattern analysis):"]
            for ctx in self.context_window[-10:]:
                line = "  - " + str(ctx.get("method","?")) + " " + str(ctx.get("url","?"))[:80]
                line += " [" + str(ctx.get("status",0)) + "]"
                line += " auth:" + str(ctx.get("has_auth","no"))
                line += " params:" + ",".join(ctx.get("param_names",[]))[:60]
                lines.append(line)
            return "\n".join(lines)

    def _add_to_context_window(self, method, url, status, has_auth, param_names):
        """Add an endpoint to the rolling context window."""
        with self.context_window_lock:
            self.context_window.append({
                "method": method, "url": url[:120], "status": status,
                "has_auth": has_auth, "param_names": param_names[:8]
            })
            if len(self.context_window) > self.context_window_max:
                self.context_window = self.context_window[-self.context_window_max:]

    def _calibrate_confidence(self, title, severity, confidence, endpoint_type, status_code):
        """Post-process confidence to reduce false positives."""
        title_low = title.lower()
        # Downgrade common FPs on API endpoints that return JSON
        if endpoint_type == "API":
            if "clickjacking" in title_low or "x-frame-options" in title_low:
                confidence = min(confidence, 40)  # Will be filtered out
            if "csrf" in title_low and endpoint_type == "API":
                confidence = max(confidence - 20, 30)
        # Downgrade header-only findings (AI phrases these many ways, so match broadly)
        if re.search(r'(missing|absent|lack of|not set|no )\W*.*(header|csp|content-security|hsts|'
                     r'strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy|x-xss)',
                     title_low):
            if severity in ("High", "Medium"):
                severity = "Low"
            confidence = min(confidence, 60)
        # Cookie-flag findings are low impact on their own
        if re.search(r'(httponly|secure flag|samesite)', title_low) and severity == "High":
            severity = "Medium"
        # Error-status responses: injection/IDOR claims on 4xx are usually just rejected input
        if 400 <= status_code < 500 and any(k in title_low for k in ["idor", "injection", "bola", "bypass"]):
            confidence = min(confidence, 55)
        # Boost findings on error pages (more likely to leak info)
        if status_code >= 500 and "information" in title_low.lower():
            confidence = min(confidence + 10, 95)
        return severity, confidence

    def _is_duplicate_finding(self, title, url):
        """Check if this finding type has already been reported for this domain."""
        try:
            from java.net import URL as JURL
            domain = JURL(url).getHost()
        except:
            domain = url.split("/")[2] if "/" in url else url
        # Normalize title to a class key
        title_key = re.sub(r'[^a-z]', '', title.lower())[:30]
        dedup_key = "%s|%s" % (title_key, domain)
        with self.finding_dedup_lock:
            if dedup_key in self.finding_dedup_cache:
                return True
            self.finding_dedup_cache.add(dedup_key)
            return False

    # -----------------------------------------------------------------------
    # ACTIVE VERIFICATION ENGINE (from v4 concepts, adapted for Burp)
    # -----------------------------------------------------------------------
    def _compute_risk_score(self, endpoint_type, method, param_names, status, has_auth):
        """Pre-AI heuristic risk score to prioritize analysis depth."""
        score = 0
        if endpoint_type in ["AUTH", "ADMIN", "PAYMENT"]: score += 30
        elif endpoint_type in ["API", "MUTATION"]: score += 20
        elif endpoint_type in ["REDIRECT", "FILE"]: score += 15
        if any(p in param_names for p in ["id","user_id","uid","account","order","file","token","role","admin","email"]):
            score += 20
        if method in ["POST", "PUT", "PATCH", "DELETE"]: score += 15
        if status >= 500: score += 15
        if status in [401, 403]: score += 10
        if has_auth == "no" and endpoint_type in ["API", "ADMIN", "MUTATION"]: score += 10
        return score

    def _summarize_response(self, res_body):
        """Extract signal from response body: JSON keys, errors, size. Reduces token waste."""
        if not res_body:
            return {"keys": [], "errors": [], "length": 0}
        keys = []
        try:
            parsed = json.loads(res_body[:5000])
            if isinstance(parsed, dict):
                keys = list(parsed.keys())[:25]
            elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                keys = list(parsed[0].keys())[:25]
        except:
            keys = re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]{1,30})":', res_body[:3000])
            keys = list(set(keys))[:25]
        errors = re.findall(r'(?:error|exception|fail|denied|unauthorized|forbidden|invalid|traceback).*', res_body[:3000], re.I)
        return {"keys": keys, "errors": [e[:100] for e in errors[:5]], "length": len(res_body)}

    # -----------------------------------------------------------------------
    # REDACTION: credentials/session values never leave Burp for the AI provider.
    # The AI only needs to know a credential is present, not its value.
    # -----------------------------------------------------------------------
    _SENSITIVE_NAME_RE = re.compile(
        r'(pass|pwd|secret|token|api[_-]?key|apikey|auth|sess|jwt|bearer|credential|'
        r'private[_-]?key|otp|client_secret|signature|csrf|xsrf|^sid$|_sid$|cookie)', re.I)
    _SENSITIVE_HEADERS = ("authorization", "proxy-authorization", "x-api-key", "x-auth-token",
                          "x-access-token", "x-csrf-token", "x-xsrf-token", "x-amz-security-token")

    def _mask(self, v):
        v = str(v)
        if v.startswith("eyJ"):
            return "eyJ...[REDACTED JWT len=%d]" % len(v)
        return "[REDACTED len=%d]" % len(v)

    def _redact_headers(self, hdrs):
        out = []
        for h in hdrs:
            if ":" not in h:
                out.append(h); continue
            name, val = h.split(":", 1)
            nl = name.strip().lower(); val = val.strip()
            if nl in ("authorization", "proxy-authorization"):
                parts = val.split(" ", 1)
                if len(parts) == 2:
                    out.append("%s: %s %s" % (name, parts[0], self._mask(parts[1])))
                else:
                    out.append("%s: %s" % (name, self._mask(val)))
            elif nl == "cookie":
                pairs = []
                for c in val.split(";"):
                    if "=" in c:
                        k, v = c.split("=", 1)
                        pairs.append("%s=%s" % (k.strip(), self._mask(v.strip())))
                out.append("%s: %s" % (name, "; ".join(pairs)))
            elif nl == "set-cookie":
                first, _, attrs = val.partition(";")
                k, _, v = first.partition("=")
                out.append("%s: %s=%s%s" % (name, k.strip(), self._mask(v.strip()),
                                            (";" + attrs) if attrs else ""))
            elif nl in self._SENSITIVE_HEADERS or self._SENSITIVE_NAME_RE.search(nl):
                out.append("%s: %s" % (name, self._mask(val)))
            else:
                out.append(h)
        return out

    def _redact_text(self, text, extra_values=None):
        """Mask values of sensitive keys in JSON bodies, form bodies and query strings,
        plus any explicit secret values already detected in the text."""
        if not text: return text
        ext = self
        def _json_repl(m):
            if ext._SENSITIVE_NAME_RE.search(m.group(2)):
                return m.group(1) + ext._mask(m.group(3)) + m.group(4)
            return m.group(0)
        text = re.sub(r'("([^"\\]{1,60})"\s*:\s*")((?:[^"\\]|\\.)*)(")', _json_repl, text)
        def _form_repl(m):
            if ext._SENSITIVE_NAME_RE.search(m.group(2)):
                return m.group(1) + ext._mask(m.group(3))
            return m.group(0)
        text = re.sub(r'((?:^|(?<=[&?\s]))([A-Za-z0-9_.\-\[\]]{1,60})=)([^&\s"\']+)', _form_repl, text)
        for v in (extra_values or []):
            if v and len(v) >= 8:
                text = text.replace(v, self._mask(v))
        return text

    def _validate_ai_finding(self, finding, param_names, req_text, res_text, url_str=""):
        """Hallucination guard: verify the AI's finding references real data.
        Returns (ok, reason, confidence_cap)."""
        if not isinstance(finding, dict):
            return False, "Not a JSON object", 0
        title_raw = str(finding.get("title", "") or "")
        title = title_raw.lower()
        detail = str(finding.get("detail", "") or "").lower()
        if not title.strip():
            return False, "Empty title", 0
        haystack = (req_text + "\n" + res_text).lower()
        haystack_ws = re.sub(r'\s+', ' ', haystack)
        known_params = set(p.lower() for p in param_names)
        cap = 89  # Passive AI-only analysis is never "Certain"

        # 1) Any parameter named in quotes in the title must really exist
        for q in re.findall(r"['\"`]([A-Za-z0-9_\-\.\[\]]{1,60})['\"`]", title_raw):
            ql = q.lower()
            if ql not in known_params and ql not in haystack:
                return False, "References non-existent parameter/field: " + q, 0

        # 2) The evidence string must actually appear in the transaction
        evidence = finding.get("evidence")
        if isinstance(evidence, basestring) and evidence.strip():
            ev = re.sub(r'\s+', ' ', evidence.strip().lower())[:200]
            if ev not in haystack_ws:
                return False, "Evidence not present in request/response", 0
        else:
            cap = min(cap, 60)  # no verifiable evidence -> Tentative at most

        # 3) Speculative wording means the model did not observe the issue
        if re.search(r'\b(potential(ly)?|possible|possibly|may be|might|could be|could allow|'
                     r'if not|should be tested|test for|recommend testing|appears to)\b',
                     title + " " + detail):
            cap = min(cap, 55)

        # 4) Placeholder domains (only reject if the target isn't actually that domain)
        url_low = (url_str or "").lower()
        for ph in ("example.com", "test.com"):
            if ph in detail and ph not in url_low:
                return False, "Contains placeholder domain", 0
        return True, "OK", cap

    def _correlate_endpoints(self, url_str, param_names, has_auth, endpoint_type, status=0, res_len=0):
        """Cross-endpoint correlation: detect privilege escalation patterns.
        FP fixes:
          - A shared ID parameter name across endpoints is NOT a vulnerability; it is
            now only logged as a manual-testing lead, never reported as a finding.
          - "Accessible without auth" now requires the unauthenticated response to be a
            real success (2xx with a body). 401/403/redirect responses no longer fire.
          - Reported once per request (previously once per matching context entry)."""
        findings = []
        cur_path = url_str[:120].split("?")[0]
        with self.context_window_lock:
            ctx_list = list(self.context_window)
        leads = set()
        for ctx in ctx_list:
            ctx_url = ctx.get("url", "")
            if ctx_url == url_str[:120]:
                continue
            ctx_params = ctx.get("param_names", [])
            for p in param_names:
                if p in ctx_params and re.search(r'(^id$|_id$|^uid$|^account)', p.lower()):
                    leads.add(p)
        if leads:
            self.log_to_console("[LEAD] ID params shared across endpoints (manual test): %s" %
                                ", ".join(sorted(leads)[:5]))

        if (has_auth == "no" and endpoint_type in ["API", "ADMIN"]
                and 200 <= status < 300 and res_len > 50):
            for ctx in ctx_list:
                if ctx.get("has_auth") in ("yes", "cookie") and \
                        ctx.get("url", "").split("?")[0] == cur_path:
                    findings.append({
                        "title": "Endpoint returned 2xx without authentication (seen authenticated earlier)",
                        "severity": "Medium",
                        "confidence": 60,
                        "cwe": "CWE-306",
                        "detail": "This path was previously requested with credentials and now returned HTTP "
                                  + str(status) + " with no Authorization or Cookie header. Verify whether the "
                                  "unauthenticated response contains the same protected data before reporting.",
                        "_source": "heuristic"
                    })
                    break
        return findings

    def _try_idor_verification(self, messageInfo, params):
        """Attempt IDOR auto-confirmation by mutating numeric ID params and comparing responses."""
        # FP fixes vs. previous version:
        #  - Never labels a result "CONFIRMED": a single session cannot prove the other
        #    object belongs to a different user. Results are Tentative leads only.
        #  - Only safe, idempotent GET requests (no replaying POST/PUT/DELETE with a
        #    changed ID, which could also modify someone else's data).
        #  - Original AND mutated responses must be 200 JSON objects with the same
        #    key structure; error / not-found bodies are ignored.
        #  - Volatile fields (timestamps, nonces, CSRF, request IDs) are excluded from
        #    the diff, so dynamic content no longer looks like "different data".
        idor_findings = []
        try:
            req_info = self.helpers.analyzeRequest(messageInfo)
            if str(req_info.getMethod()).upper() != "GET":
                return []
            orig_resp = messageInfo.getResponse()
            orig_info = self.helpers.analyzeResponse(orig_resp)
            if orig_info.getStatusCode() != 200:
                return []
            orig_json = self._json_object(
                self.helpers.bytesToString(orig_resp[orig_info.getBodyOffset():]))
            if orig_json is None:
                return []
        except Exception:
            return []

        for p in params:
            pname = p.get("name", "")
            pval = p.get("value", "")
            if not pval.isdigit():
                continue
            if not re.search(r'(^id$|_id$|id$|^uid$|^account|^order|^item|^product)', pname.lower()):
                continue
            try:
                mutated_val = str(int(pval) + 1)
                req_bytes = messageInfo.getRequest()
                for orig_p in self.helpers.analyzeRequest(req_bytes).getParameters():
                    if str(orig_p.getName()) != pname:
                        continue
                    new_param = self.helpers.buildParameter(pname, mutated_val, orig_p.getType())
                    new_req = self.helpers.updateParameter(req_bytes, new_param)
                    mutated_resp = self.callbacks.makeHttpRequest(messageInfo.getHttpService(), new_req)
                    if not (mutated_resp and mutated_resp.getResponse()):
                        break
                    mraw = mutated_resp.getResponse()
                    minfo = self.helpers.analyzeResponse(mraw)
                    if minfo.getStatusCode() != 200:
                        break
                    mut_body = self.helpers.bytesToString(mraw[minfo.getBodyOffset():])
                    if re.search(r'not.?found|no such|does not exist|invalid|denied|unauthori[sz]ed|forbidden|"error"',
                                 mut_body[:2000], re.I):
                        break
                    mut_json = self._json_object(mut_body)
                    if mut_json is None or set(mut_json.keys()) != set(orig_json.keys()):
                        break
                    changed = self._stable_diff_keys(orig_json, mut_json)
                    if changed:
                        idor_findings.append({
                            "title": "IDOR candidate in '" + pname + "' parameter (needs 2-user verification)",
                            "severity": "Medium",
                            "confidence": 60,
                            "cwe": "CWE-639",
                            "detail": "Changing " + pname + " from " + pval + " to " + mutated_val
                                      + " returned HTTP 200 with the same JSON structure but different values in: "
                                      + ", ".join(changed[:6]) + ". This is NOT confirmed: verify with a second "
                                      "account that the returned object belongs to another user and should not "
                                      "be accessible to this session.",
                            "_source": "heuristic"
                        })
                    break
            except Exception as ex:
                self.log_to_console("[IDOR-TEST] Error testing " + pname + ": " + str(ex))
        return idor_findings[:2]

    def _json_object(self, body):
        """Parse body as a JSON object (dict); unwrap a single-item list. None otherwise."""
        try:
            data = json.loads(body)
        except Exception:
            return None
        if isinstance(data, list) and len(data) == 1:
            data = data[0]
        return data if isinstance(data, dict) and data else None

    _VOLATILE_KEY_RE = re.compile(
        r'(time|date|_at$|^ts$|nonce|csrf|xsrf|token|request_?id|trace|span|etag|expires|signature|^now$)', re.I)

    def _stable_diff_keys(self, a, b):
        """Keys whose values differ between two JSON objects, ignoring volatile fields."""
        changed = []
        for k in a.keys():
            if self._VOLATILE_KEY_RE.search(str(k)):
                continue
            if a.get(k) != b.get(k):
                changed.append(str(k))
        return changed

    # -----------------------------------------------------------------------
    # SCANNING FLOW
    # -----------------------------------------------------------------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest: return
        if not self.PASSIVE_SCANNING_ENABLED: return
        if toolFlag != 4: return  # Proxy only

        req     = self.helpers.analyzeRequest(messageInfo)
        url_str = str(req.getUrl())

        # Scope: never analyse (or send out-of-scope traffic to the AI) unless allowed
        if self.SCOPE_ONLY and not self.callbacks.isInScope(req.getUrl()):
            if not self._scope_hint_logged:
                self._scope_hint_logged = True
                self.log_to_console("[SCOPE] Ignoring out-of-scope traffic. Add targets in "
                                    "Target > Scope, or disable 'In-scope only' in Settings > Advanced.")
            return

        if self._is_static(url_str): return

        with self.stats_lock:
            self.stats["total_requests"] += 1

        # Dedup (peek only; the URL is claimed by whichever path analyses it)
        url_hash = self._url_hash(url_str)
        with self.url_lock:
            if url_hash in self.processed_urls:
                with self.stats_lock:
                    self.stats["skipped_duplicate"] += 1
                return

        if self.REPORT_MODE == "Scan task":
            # Analysis is driven only by Burp audit tasks (doPassiveScan). If proxy
            # traffic flows but no task has called us for a while, explain why.
            now = time.time()
            if now - self._last_audit_call > 60 and now - self._no_audit_hint_time > 300:
                self._no_audit_hint_time = now
                self.log_to_console("[AUDIT] In-scope proxy traffic seen, but no Burp audit task has "
                                    "called BurpSeeq in the last 60s. Check that a 'Live audit' task "
                                    "exists and task execution is not paused (Dashboard), or set "
                                    "Settings > Advanced > Report findings to 'Auto' / 'Site map only'.")
            return

        # Hand-off: give a Live audit task the chance to analyse this item first, so the
        # findings land in that task's Issues tab. Fall back to analysing here (findings
        # go to Dashboard > Issue activity / Target) if no audit task covers this host.
        t = threading.Thread(target=self._listener_fallback,
                             args=(messageInfo, url_str, url_hash, req.getUrl().getHost()))
        t.setDaemon(True); t.start()

    def _listener_fallback(self, messageInfo, url_str, url_hash, host):
        if self.REPORT_MODE == "Auto":
            time.sleep(self.AUDIT_HANDOFF_DELAY)
            last_audit = self._audit_seen_hosts.get(host, 0)
            if time.time() - last_audit < self.AUDIT_ACTIVE_WINDOW:
                return  # an audit task is covering this host; it will (or did) analyse it
        if not self._claim_url(url_hash):
            return  # already analysed (e.g. by an audit task)
        task_id = self.addTask("HTTP", url_str, "Queued", messageInfo)
        self.analyze(messageInfo, url_str, task_id)

    def _url_hash(self, url_str):
        return hashlib.md5(url_str.encode("utf-8")).hexdigest()

    def _claim_url(self, url_hash):
        """Atomically mark a URL as analysed. True if this caller owns it."""
        with self.url_lock:
            if url_hash in self.processed_urls:
                return False
            self.processed_urls.add(url_hash)
            return True

    def _is_static(self, url_str):
        path = url_str.split("?")[0].lower()
        ext  = path.rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else ""
        return ext in self.SKIP_EXTENSIONS

    def analyze(self, messageInfo, url_str=None, task_id=None):
        with self.semaphore:
            self._perform_analysis(messageInfo, "HTTP", url_str, task_id)

    def analyze_forced(self, messageInfo, url_str=None, task_id=None):
        with self.semaphore:
            self._perform_analysis(messageInfo, "CONTEXT", url_str, task_id, bypass_dedup=True)

    def _perform_analysis(self, messageInfo, source, url_str, task_id, bypass_dedup=False,
                          collect_issues=None):
        """collect_issues: when a list is passed (doPassiveScan path), Burp issues are
        appended to it and returned to the calling scan task instead of addScanIssue()."""
        try:
            # Rate limit
            now = time.time()
            elapsed = now - self.last_request_time
            if elapsed < self.min_delay:
                time.sleep(self.min_delay - elapsed)
            self.last_request_time = time.time()

            req = self.helpers.analyzeRequest(messageInfo)
            res = self.helpers.analyzeResponse(messageInfo.getResponse())
            req_bytes = messageInfo.getRequest()
            res_bytes = messageInfo.getResponse()
            method  = req.getMethod()
            req_hdrs = [str(h) for h in req.getHeaders()]
            res_hdrs = [str(h) for h in res.getHeaders()]
            req_body = self.helpers.bytesToString(req_bytes[req.getBodyOffset():])[:3000]
            res_body = self.helpers.bytesToString(res_bytes[res.getBodyOffset():])[:5000]
            status   = res.getStatusCode()
            content_type = ""
            for h in req_hdrs:
                if h.lower().startswith("content-type:"):
                    content_type = h.split(":", 1)[1].strip(); break

            # --- TRIAGE (Quick mode skips boring traffic) ---
            if source == "HTTP" and self.SCAN_MODE == "Quick":
                ok, reason = self._triage_request(method, url_str, status, req_hdrs, req_body, res_body)
                if not ok:
                    self.updateTask(task_id, "Skipped - %s" % reason)
                    with self.stats_lock: self.stats["skipped_rate_limit"] += 1
                    return

            self.updateTask(task_id, "Analyzing")
            self.log_to_console("[ANALYSIS] " + method + " " + (url_str[:70] if url_str else "?") + " [" + str(status) + "]")

            # --- EXTRACT INTELLIGENCE ---
            params = []
            for p in req.getParameters():
                params.append({"name": str(p.getName()), "value": str(p.getValue())[:100], "type": str(p.getType())})
            param_names = [p["name"] for p in params]

            has_auth = "no"; auth_info = ""
            for h in req_hdrs:
                hl = h.lower()
                if hl.startswith("authorization:"):
                    has_auth = "yes"
                    auth_val = h.split(":", 1)[1].strip()
                    if auth_val.lower().startswith("bearer ") and auth_val[7:].count(".") == 2:
                        try:
                            hdr_part = auth_val[7:].split(".")[0]
                            hdr_part += "=" * (4 - len(hdr_part) % 4)
                            jwt_hdr = json.loads(base64.b64decode(hdr_part))
                            auth_info = "JWT(alg=%s)" % jwt_hdr.get("alg","?")
                        except: auth_info = "Bearer/JWT"
                    else:
                        # Scheme only: auth_val[:30] previously leaked e.g. Basic credentials
                        auth_info = auth_val.split(" ", 1)[0][:20] + " (value redacted)"
                    break
                # FP fix: any non-empty Cookie header may carry the session (PHPSESSID,
                # connect.sid, ASP.NET_SessionId...). Previously only names containing
                # "session/token/auth" counted, so many authenticated requests were
                # flagged to the AI as "No authentication detected".
                if hl.startswith("cookie:") and h.split(":", 1)[1].strip():
                    has_auth = "cookie"
                elif hl.startswith(("x-api-key:", "x-auth-token:", "x-access-token:")):
                    has_auth = "yes"; auth_info = h.split(":", 1)[0]

            endpoint_type = self._classify_endpoint(method, url_str, req_hdrs, content_type, req_body)
            techs = self._fingerprint_tech(res_hdrs, res_body)
            secrets = self._extract_js_secrets(res_body)

            # --- REDACTED COPIES for the AI prompt (raw values stay local) ---
            raw_secret_vals = []
            for _pat, _lbl in SECRET_PATTERNS:
                if _lbl in ("Internal/Private URL", "Source Map Reference", "Firebase App URL"):
                    continue
                for _mo in re.finditer(_pat, res_body[:10000]):
                    raw_secret_vals.append(_mo.group(0))
            red_req_hdrs = self._redact_headers(req_hdrs)
            red_res_hdrs = self._redact_headers(res_hdrs)
            red_req_body = self._redact_text(req_body)
            red_res_body = self._redact_text(res_body, raw_secret_vals)
            red_url      = self._redact_text(url_str)
            red_params   = [dict(p, value=self._mask(p["value"]))
                            if self._SENSITIVE_NAME_RE.search(p["name"]) else p for p in params]
            red_secrets  = [{"type": s["type"],
                             "value": (s["value"][:6] + "...[REDACTED]") if s["type"] not in
                                      ("Internal/Private URL", "Source Map Reference",
                                       "Firebase App URL", "Firebase Database URL") else s["value"]}
                            for s in secrets]
            cookies = [h.split(":", 1)[1].strip()[:120] for h in red_res_hdrs if h.lower().startswith("set-cookie:")]

            # --- RISK SCORING (pre-AI heuristic) ---
            risk_score = self._compute_risk_score(endpoint_type, method, param_names, status, has_auth)

            # --- RESPONSE SUMMARIZATION (reduce token waste) ---
            res_summary = self._summarize_response(res_body)

            # Context window stores the redacted URL (it is replayed into later prompts)
            self._add_to_context_window(method, red_url, status, has_auth, param_names)
            context_summary = self._build_context_summary()

            # --- CROSS-ENDPOINT CORRELATION (detect priv-esc patterns) ---
            correlation_findings = self._correlate_endpoints(
                red_url, param_names, has_auth, endpoint_type, status, len(res_body))

            # Text used to verify AI-cited evidence: raw transaction plus the redacted
            # form the AI actually saw (so quoting a "[REDACTED]" header still matches)
            req_text_full = (self.helpers.bytesToString(req_bytes)[:20000] + "\n" +
                             "\n".join(red_req_hdrs) + "\n" + red_req_body + "\n" + red_url)
            res_text_full = (self.helpers.bytesToString(res_bytes)[:40000] + "\n" +
                             "\n".join(red_res_hdrs) + "\n" + red_res_body)

            data = {
                "url": red_url, "method": method, "status_code": status,
                "content_type": content_type, "endpoint_type": endpoint_type,
                "risk_score": risk_score,
                "technologies": techs, "auth": {"present": has_auth, "detail": auth_info},
                "request_headers": red_req_hdrs, "request_body": red_req_body[:2500],
                "response_headers": red_res_hdrs,
                "response_body": red_res_body[:3000] + ("...[truncated]" if len(red_res_body) > 3000 else ""),
                "response_summary": self._summarize_response(red_res_body),
                "parameters": red_params[:20], "cookies_set": cookies[:5],
                "js_secrets_found": red_secrets, "scan_mode": self.SCAN_MODE,
                "context": context_summary,
            }

            prompt = self.build_prompt(data)
            ai_text = self.ask_ai(prompt)

            if not ai_text:
                self.updateTask(task_id, "Error - No AI response")
                with self.stats_lock: self.stats["errors"] += 1
                return

            findings = self._parse_ai_response(ai_text)

            # --- HALLUCINATION GUARD: validate AI findings ---
            validated_findings = []
            for f in findings:
                ok, reason, cap = self._validate_ai_finding(
                    f, param_names, req_text_full, res_text_full, url_str)
                if ok:
                    f["_source"] = "ai"
                    f["_conf_cap"] = cap
                    validated_findings.append(f)
                else:
                    t = f.get("title", "?") if isinstance(f, dict) else "?"
                    self.log_to_console("[HALLUCINATION] Rejected: " + str(t)[:40] + " (" + reason + ")")
            findings = validated_findings

            # --- MERGE correlation findings ---
            findings.extend(correlation_findings)

            # --- ACTIVE IDOR VERIFICATION (opt-in, Thorough mode, in-scope only) ---
            # The scope check here is independent of SCOPE_ONLY: active requests are never
            # sent to out-of-scope hosts, even for context-menu / replay analysis.
            if (self.ACTIVE_VERIFY_ENABLED and self.SCAN_MODE == "Thorough" and risk_score >= 20
                    and self.callbacks.isInScope(req.getUrl())):
                idor_verified = self._try_idor_verification(messageInfo, params)
                if idor_verified:
                    findings.extend(idor_verified)
                    self.log_to_console("[ACTIVE] IDOR verification found %d result(s)" % len(idor_verified))

            with self.stats_lock: self.stats["analyzed"] += 1

            reported_count = 0
            if findings:
                for item in findings:
                    title = str(item.get("title") or "AI Finding")
                    sev_raw = str(item.get("severity","information")).lower()
                    severity = VALID_SEVERITIES.get(sev_raw, "Information")
                    # Robust parse: "85", 85, "85%", 0.85 -> int; garbage -> 0 (filtered)
                    try:
                        raw_conf = item.get("confidence", 0)
                        confidence = float(str(raw_conf).strip().rstrip("%"))
                        if 0 < confidence <= 1: confidence *= 100
                        confidence = int(confidence)
                    except Exception:
                        confidence = 0
                    detail = item.get("detail", "")
                    cwe = item.get("cwe", "")

                    severity, confidence = self._calibrate_confidence(title, severity, confidence, endpoint_type, status)
                    # Cap AI-only findings according to how verifiable they were
                    if item.get("_source") == "ai":
                        confidence = min(confidence, item.get("_conf_cap", 89))
                    evidence = item.get("evidence")
                    if evidence and isinstance(evidence, basestring):
                        detail = "%s\nEvidence: %s" % (detail, evidence[:300])
                    mapped_conf = map_confidence(confidence)
                    if mapped_conf is None:
                        with self.stats_lock: self.stats["skipped_low_confidence"] += 1
                        continue
                    if not bypass_dedup and self._is_duplicate_finding(title, url_str):
                        self.log_to_console("[DEDUP] Skipping: %s" % title[:50])
                        continue
                    if cwe: detail = "[%s] %s" % (cwe, detail)
                    self.add_finding(url_str, title, severity, mapped_conf, detail)
                    self.log_to_console("[FINDING][%s][%s] %s" % (severity, mapped_conf, title))
                    reported_count += 1
                    try:
                        issue = CustomScanIssue(
                            messageInfo.getHttpService(),
                            self.helpers.analyzeRequest(messageInfo).getUrl(),
                            [messageInfo], title, detail, severity, mapped_conf)
                        if collect_issues is not None:
                            collect_issues.append(issue)   # -> scan task's Issues tab
                        else:
                            self.callbacks.addScanIssue(issue)
                    except Exception as ie:
                        self.log_to_console("[WARN] Burp issue: %s" % str(ie))
                self.updateTask(task_id, "Completed - %d finding(s)" % reported_count)
            else:
                self.updateTask(task_id, "Completed - No issues")
        except Exception as e:
            self.updateTask(task_id, "Error")
            self.log_to_console("[ERROR] Analysis failed: %s" % str(e))
            with self.stats_lock: self.stats["errors"] += 1

    # -----------------------------------------------------------------------
    # PROMPT BUILDER  (v1.0.0 - context-aware, CWE-mapped, PoC-oriented)
    # -----------------------------------------------------------------------
    def build_prompt(self, data):
        scan_mode = data.get("scan_mode", "Thorough")
        endpoint_type = data.get("endpoint_type", "GENERAL")
        techs = data.get("technologies", [])
        secrets = data.get("js_secrets_found", [])
        auth = data.get("auth", {})
        context = data.get("context", "")

        # --- Endpoint-specific focus ---
        ep_focus = {
            "AUTH": "PRIORITY: Authentication bypass, credential stuffing, brute-force, session fixation, OAuth/JWT flaws, insecure password reset, account takeover.",
            "FILE": "PRIORITY: Unrestricted file upload, path traversal, MIME type bypass, malicious file execution, file overwrite.",
            "PAYMENT": "PRIORITY: Price tampering, discount abuse, race conditions, IDOR on orders, payment replay, currency manipulation.",
            "ADMIN": "PRIORITY: Privilege escalation, missing auth on admin functions, IDOR, mass data exposure, admin bypass.",
            "API": "PRIORITY: BOLA/IDOR, broken function-level auth, mass assignment, excessive data exposure, rate limit bypass.",
            "REDIRECT": "PRIORITY: Open redirect, SSRF via redirect, token leakage in redirect URL, OAuth redirect_uri manipulation.",
            "JS": "PRIORITY: Hardcoded secrets, API keys, internal URLs, source maps, debug flags, exposed admin endpoints.",
            "SEARCH": "PRIORITY: SQL injection, XSS via search reflection, blind injection, NoSQL injection.",
            "MUTATION": "PRIORITY: CSRF, mass assignment, injection in body params, business logic bypass, race conditions.",
        }.get(endpoint_type, "Perform comprehensive analysis across all vulnerability classes.")

        # --- Tech-specific hints ---
        tech_hint = ""
        if techs:
            tech_hint = "\nDETECTED TECH STACK: " + ", ".join(techs)
            for t in techs:
                tl = t.lower()
                if "django" in tl: tech_hint += "\n  -> Check for Django-specific: CSRF middleware bypass, DEBUG=True, admin exposure"
                elif "spring" in tl: tech_hint += "\n  -> Check for Spring-specific: actuator endpoints, SpEL injection, mass assignment via @ModelAttribute"
                elif "node" in tl or "express" in tl: tech_hint += "\n  -> Check for Node.js: prototype pollution, NoSQL injection, SSRF in HTTP clients"
                elif "php" in tl or "laravel" in tl: tech_hint += "\n  -> Check for PHP: type juggling, deserialization, LFI, .env exposure"
                elif "wordpress" in tl: tech_hint += "\n  -> Check for WordPress: xmlrpc.php, wp-json user enumeration, plugin vulns"
                elif "graphql" in tl: tech_hint += "\n  -> Check for GraphQL: introspection enabled, batch queries, nested query DoS"

        # --- Pre-extracted secrets hint ---
        secrets_hint = ""
        if secrets:
            secrets_hint = "\nPRE-SCANNED SECRETS FOUND IN RESPONSE:"
            for s in secrets[:5]:
                secrets_hint += "\n  - " + str(s["type"]) + ": " + str(s["value"])[:60]
            secrets_hint += "\n  -> VERIFY these are real secrets and assess their impact."

        # --- Auth hint ---
        auth_hint = ""
        if auth.get("present") == "yes":
            auth_hint = "\nAUTHENTICATION: " + str(auth.get("detail", "present"))
            auth_hint += "\n  -> Check token strength, expiry, algorithm, and scope"
        elif auth.get("present") == "no" and endpoint_type in ["API", "ADMIN", "MUTATION"]:
            # Neutral wording: a single request without credentials is not by itself a finding
            auth_hint = ("\nNOTE: No Authorization or Cookie header on this " + endpoint_type +
                         " request. Only report missing authentication if the RESPONSE clearly "
                         "returns protected or user-specific data.")

        # --- Parameter hints ---
        url = data.get("url", "")
        params_hint = ""
        if data.get("parameters"):
            pnames = [p["name"] for p in data["parameters"][:10]]
            params_hint = "\nPARAMETERS: " + ", ".join(pnames)
            interesting = [p for p in pnames if any(k in p.lower() for k in ["id","user","file","url","path","redirect","cmd","query","template","token","key","role","admin","price","amount","email"])]
            if interesting:
                params_hint += ("\n  -> HIGH-INTEREST params: " + ", ".join(interesting) +
                                " (context only - do NOT report as findings without evidence)")

        id_patterns = re.findall(r'(?:id|uid|user_id|account|order|item|product|doc)[=:/](\d+)', url, re.I)
        if id_patterns:
            params_hint += ("\n  -> NUMERIC IDS: " + ", ".join(id_patterns) +
                            " (an ID alone is not an IDOR; do not report unless the response proves cross-user access)")

        # --- Vuln checklist (abbreviated for Quick, full for Thorough) ---
        if scan_mode == "Quick":
            vuln_note = "Focus on OWASP Top 10 (2021) and the endpoint-specific priority above."
        elif scan_mode == "Focused":
            vuln_note = "Focus on high-impact injection & RCE: SQLi, CMDi, SSTI, SSRF, XXE, deserialization."
        else:
            vuln_note = "Check all 50+ vulnerability classes: injection, server-side, client-side, auth, access control, API, config, JS secrets, business logic."

        risk_score = data.get("risk_score", 0)
        res_summary = data.get("response_summary", {})

        parts = []
        parts.append("You are an elite penetration tester. Analyse this HTTP transaction and report actionable security findings.\n\n")
        parts.append("ENDPOINT TYPE: " + endpoint_type + " (Risk Score: " + str(risk_score) + "/100)\n")
        parts.append(ep_focus + "\n")
        if tech_hint: parts.append(tech_hint + "\n")
        if secrets_hint: parts.append(secrets_hint + "\n")
        if auth_hint: parts.append(auth_hint + "\n")
        if params_hint: parts.append(params_hint + "\n")
        # Response intelligence summary
        if res_summary.get("keys"):
            parts.append("\nRESPONSE JSON KEYS: " + ", ".join(res_summary["keys"][:15]) + "\n")
        if res_summary.get("errors"):
            parts.append("RESPONSE ERRORS DETECTED: " + " | ".join(res_summary["errors"][:3]) + "\n")
        if context: parts.append("\n" + context + "\n")
        parts.append("\nSCAN SCOPE: " + vuln_note + "\n")
        parts.append("""
EVIDENCE RULES (false positives are worse than missed findings):
- Only report an issue if THIS transaction contains direct evidence of it.
- "evidence" MUST be an exact substring copied verbatim from the request or response
  above (a header line, a body fragment, an error message). Findings whose evidence
  is not found in the transaction are discarded automatically.
- Do NOT report things that merely "should be tested" (e.g. "possible SQLi in id",
  "test for IDOR"). A parameter existing is not a vulnerability.
- Do NOT report CSRF on JSON APIs that use Authorization headers, clickjacking on
  non-HTML responses, or missing security headers on non-HTML/API responses.
- Missing security headers are Low/Information at most.
- Confidence: 90+ only when the evidence alone proves the issue; 50-75 when it
  strongly indicates it; below 50 if you are guessing (it will be dropped).

OUTPUT: Return ONLY this JSON object. No markdown, no explanation, no preamble.

{"findings": [
  {
    "title": "Specific vulnerability name (e.g. Stack trace disclosure in 500 response)",
    "severity": "High|Medium|Low|Information",
    "confidence": <integer 0-100>,
    "cwe": "CWE-XXX",
    "evidence": "<exact substring from the request/response proving the issue>",
    "detail": "1) What: [description] 2) Where: [exact param/header/field] 3) Impact: [what attacker gains] 4) Verify: [manual step to confirm]"
  }
]}

Return {"findings": []} if no vulnerabilities are evidenced. An empty list is the expected answer for most requests.

HTTP TRANSACTION:
""")
        parts.append(json.dumps(data, indent=2))
        prompt = "".join(parts)
        return prompt

    # -----------------------------------------------------------------------
    # AI PROVIDER ROUTING
    # -----------------------------------------------------------------------
    def ask_ai(self, prompt):
        try:
            self.log_to_console("[AI] Sending to %s (%s)" % (self.AI_PROVIDER, self.MODEL))
            if self.AI_PROVIDER == "Ollama":
                return self._ask_ollama(prompt)
            elif self.AI_PROVIDER in ["OpenAI", "Groq", "OpenRouter", "Grok"]:
                return self._ask_openai_compatible(prompt)
            elif self.AI_PROVIDER == "Claude":
                return self._ask_claude(prompt)
            elif self.AI_PROVIDER == "Gemini":
                return self._ask_gemini(prompt)
            else:
                self.log_to_console("[ERROR] Unknown provider: %s" % self.AI_PROVIDER)
                return None
        except Exception as e:
            self.log_to_console("[ERROR] AI request failed: %s" % str(e))
            return None

    def _ask_ollama(self, prompt):
        try:
            # Ollama's default context (2048-4096 tokens) silently drops the start of long
            # prompts, so the model judges a response it never saw -> hallucinated findings.
            # Size num_ctx to the prompt (~3 chars/token) + output budget.
            est_tokens = len(prompt) // 3 + int(self.MAX_TOKENS) + 256
            num_ctx = 4096
            while num_ctx < est_tokens and num_ctx < 32768:
                num_ctx *= 2
            if est_tokens > num_ctx:
                self.log_to_console("[WARN] Prompt (~%d tokens) exceeds 32k context; it will be truncated" % est_tokens)
            body = {
                "model": self.MODEL, "prompt": prompt, "stream": False,
                "format": "json",   # constrained JSON output: no prose, no markdown
                "options": {"num_ctx": num_ctx, "num_predict": int(self.MAX_TOKENS),
                            "temperature": 0.1}
            }
            req = urllib2.Request(
                self.API_URL.rstrip('/') + "/api/generate",
                data=json.dumps(body).encode("utf-8"),
                headers={'Content-Type': 'application/json'})
            response = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
            data = json.loads(response.read())
            return data.get("response", "")
        except Exception as e:
            self.log_to_console("[ERROR] Ollama: %s" % str(e)); return None

    def _ask_openai_compatible(self, prompt):
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.API_KEY
        }
        if self.AI_PROVIDER == "OpenRouter":
            headers["HTTP-Referer"] = "https://burpseeq.ai"
            headers["X-Title"] = "BurpSeeq"

        model_to_use = str(self.MODEL).strip()
        payload = {
            "model": model_to_use,
            "messages": [
                {"role": "system", "content": "You are a senior penetration tester specialising in web application security. Respond only with JSON of the form {\"findings\": [...]}."},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": int(self.MAX_TOKENS),
            "temperature": 0.1,
            # JSON mode returns an object, so the prompt allows {"findings": [...]}
            "response_format": {"type": "json_object"}
        }
        self.log_to_console("[AI] Requesting %s model: %s" % (self.AI_PROVIDER, model_to_use))
        url = self.API_URL.rstrip('/') + "/chat/completions"
        try:
            timeout = 180 if self.AI_PROVIDER in ["Groq", "OpenRouter", "Grok"] else self.AI_REQUEST_TIMEOUT
            try:
                response = urllib2.urlopen(urllib2.Request(
                    url, data=json.dumps(payload).encode("utf-8"), headers=headers), timeout=timeout)
            except urllib2.HTTPError as je:
                # Some models/providers reject response_format: retry once without it
                if je.code not in (400, 422):
                    raise
                self.log_to_console("[AI] JSON mode not supported by this model - retrying without it")
                payload.pop("response_format", None)
                response = urllib2.urlopen(urllib2.Request(
                    url, data=json.dumps(payload).encode("utf-8"), headers=headers), timeout=timeout)
            data = json.loads(response.read())
            if "choices" not in data or not data["choices"]:
                self.log_to_console("[ERROR] Invalid response structure: %s" % str(data)[:200])
                return None
            content = data["choices"][0]["message"]["content"]
            self.log_to_console("[AI] Response: %d chars" % len(content))
            return content
        except urllib2.HTTPError as e:
            body = ""
            try: body = e.read()[:400]
            except: pass
            self.log_to_console("[ERROR] HTTP %d from %s: %s" % (e.code, self.AI_PROVIDER, body))
            if e.code == 403 or e.code == 404:
                self.log_to_console("[ERROR] Model '%s' may not exist or your key lacks access. Click Refresh and pick from the list." % model_to_use)
            return None
        except Exception as e:
            self.log_to_console("[ERROR] %s: %s" % (self.AI_PROVIDER, str(e))); return None

    def _ask_claude(self, prompt):
        try:
            payload = {
                "model": self.MODEL,
                "max_tokens": int(self.MAX_TOKENS),
                "system": "You are a senior penetration tester. Respond only with JSON of the form {\"findings\": [...]}.",
                "messages": [{"role": "user", "content": prompt}]
            }
            req = urllib2.Request(
                self.API_URL.rstrip('/') + "/messages",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": self.API_KEY,
                    "anthropic-version": "2023-06-01"
                })
            response = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
            data = json.loads(response.read())
            if "content" in data and len(data["content"]) > 0:
                text = data["content"][0].get("text", "")
                self.log_to_console("[AI] Claude response: %d chars" % len(text))
                return text
            self.log_to_console("[ERROR] Claude: unexpected response: %s" % str(data)[:200])
            return None
        except urllib2.HTTPError as e:
            body = ""
            try: body = e.read()[:400]
            except: pass
            self.log_to_console("[ERROR] Claude HTTP %d: %s" % (e.code, body))
            if "credit" in body.lower() or "billing" in body.lower():
                self.log_to_console("[ERROR] No credits - top up at https://console.anthropic.com/settings/billing")
            return None
        except Exception as e:
            self.log_to_console("[ERROR] Claude: %s" % str(e))
            return None

    def _ask_gemini(self, prompt):
        try:
            model = str(self.MODEL).strip() if self.MODEL else "gemini-2.0-flash"
            # Strip to bare base URL (remove any /v1 or /v1beta suffix)
            base = self.API_URL.rstrip('/')
            base = base.replace("/v1beta", "").replace("/v1", "").rstrip('/')
            # Pick API version based on model
            if "2.0" in model or "2.5" in model or "exp" in model or "preview" in model:
                api_ver = "v1beta"
            else:
                api_ver = "v1"
            url = base + "/" + api_ver + "/models/" + model + ":generateContent?key=" + self.API_KEY
            self.log_to_console("[AI] Gemini: " + base + "/" + api_ver + "/models/" + model)
            req = urllib2.Request(
                url,
                data=json.dumps(dict(
                    {"contents": [{"parts": [{"text": prompt}]}]},
                    # JSON output mode (v1beta); v1 may reject the field, so only send it there
                    **({"generationConfig": {"responseMimeType": "application/json",
                                             "temperature": 0.1}} if api_ver == "v1beta" else {})
                )).encode("utf-8"),
                headers={'Content-Type': 'application/json'})
            response = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
            data = json.loads(response.read())
            if "candidates" in data and data["candidates"]:
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                self.log_to_console("[AI] Gemini response: %d chars" % len(text))
                return text
            self.log_to_console("[ERROR] Gemini: no candidates in response")
            return None
        except urllib2.HTTPError as e:
            body = ""
            try: body = e.read()[:400]
            except: pass
            self.log_to_console("[ERROR] Gemini HTTP %d: %s" % (e.code, body))
            if e.code == 404:
                self.log_to_console("[ERROR] Model '" + str(self.MODEL or "(empty)") + "' not found. Try 'gemini-2.0-flash' or click Refresh.")
            elif e.code == 429:
                self.log_to_console("[WARN] Rate limited by Gemini. Will retry after delay.")
            return None
        except Exception as e:
            self.log_to_console("[ERROR] Gemini: %s" % str(e)); return None

    # -----------------------------------------------------------------------
    # PARSE AI RESPONSE
    # -----------------------------------------------------------------------
    def _parse_ai_response(self, ai_text):
        if not ai_text: return []

        # Strip <think> tags from reasoning models (e.g. deepseek-r1).
        # FP fix: if the reasoning block is unterminated (output truncated at max_tokens),
        # the old code parsed draft findings out of the model's scratch reasoning.
        if "</think>" in ai_text:
            ai_text = ai_text[ai_text.rfind("</think>") + len("</think>"):]
        elif "<think>" in ai_text:
            self.log_to_console("[PARSE] Truncated reasoning output (no </think>); ignoring. Raise Max Tokens.")
            return []
        ai_text = ai_text.strip()

        # JSON mode (Ollama format=json / OpenAI json_object) returns a whole object:
        # {"findings": [...]}, a bare list, or a single finding object. Parse it whole
        # first so an array nested inside one finding isn't mistaken for the list.
        try:
            data = json.loads(ai_text)
            if isinstance(data, dict):
                for key in ("findings", "vulnerabilities", "issues", "results"):
                    if isinstance(data.get(key), list):
                        return [f for f in data[key] if isinstance(f, dict)]
                return [data] if data.get("title") else []
            if isinstance(data, list):
                return [f for f in data if isinstance(f, dict)]
        except Exception:
            pass

        # Try direct array extraction first
        start = ai_text.find('[')
        end   = ai_text.rfind(']')
        if start != -1 and end != -1 and end > start:
            try:
                findings = json.loads(ai_text[start:end + 1])
                if isinstance(findings, list):
                    return [f for f in findings if isinstance(f, dict)]
            except: pass

        # Code block extraction
        for match in re.findall(r'```(?:json)?\s*([\s\S]*?)```', ai_text):
            try:
                data = json.loads(match.strip())
                if isinstance(data, list):   return [f for f in data if isinstance(f, dict)]
                if isinstance(data, dict):   return [data]
            except: continue

        # Last-ditch bare parse
        try:
            data = json.loads(ai_text.strip())
            if isinstance(data, list):  return [f for f in data if isinstance(f, dict)]
            if isinstance(data, dict):  return [data]
        except: pass

        return []

    # -----------------------------------------------------------------------
    # CONNECTION TESTING  (also fetches available models)
    # -----------------------------------------------------------------------
    def test_ai_connection(self):
        """Test the connection AND populate self.available_models.
        Does NOT auto-detect/overwrite the model — that's for Refresh only."""
        try:
            ok = False
            if self.AI_PROVIDER == "Ollama":
                ok = self._test_ollama_connection()
            elif self.AI_PROVIDER in ["OpenAI", "Groq", "OpenRouter", "Grok"]:
                ok = self._test_openai_compatible_connection()
            elif self.AI_PROVIDER == "Claude":
                ok = self._test_claude_connection()
            elif self.AI_PROVIDER == "Gemini":
                ok = self._test_gemini_connection()
            return ok
        except Exception as e:
            self.log_to_console("[ERROR] Connection test failed: %s" % str(e))
            return False

    def _test_ollama_connection(self):
        try:
            req  = urllib2.Request(self.API_URL.rstrip('/') + "/api/tags",
                                   headers={'Content-Type': 'application/json'})
            data = json.loads(urllib2.urlopen(req, timeout=10).read())
            self.available_models = sorted([m.get("name") for m in data.get("models", []) if m.get("name")])
            if self.available_models and self.MODEL not in self.available_models:
                self.MODEL = self.available_models[0]
            self.log_to_console("[OK] Ollama connected - %d models available" % len(self.available_models))
            return True
        except Exception as e:
            self.log_to_console("[FAIL] Ollama connection: %s" % str(e)); return False

    def _test_openai_compatible_connection(self):
        if not self.API_KEY:
            self.log_to_console("[FAIL] No API key provided"); return False
        headers = {'Authorization': 'Bearer ' + self.API_KEY, 'Content-Type': 'application/json'}
        if self.AI_PROVIDER == "OpenRouter":
            headers['HTTP-Referer'] = 'https://burpseeq.ai'
            headers['X-Title'] = 'BurpSeeq'
        self.log_to_console("[TEST] %s: fetching models from %s ..." % (self.AI_PROVIDER, self.API_URL))
        req = urllib2.Request(self.API_URL.rstrip('/') + "/models", headers=headers)
        try:
            data = json.loads(urllib2.urlopen(req, timeout=10).read())
            if 'data' in data:
                self.available_models = sorted([
                    m.get("id","") for m in data['data'] if m.get("id")
                ])
                self.log_to_console("[OK] %s connected - %d models available" % (
                    self.AI_PROVIDER, len(self.available_models)))

                # Check if the user's current model is in the list
                if self.MODEL and self.available_models:
                    if self.MODEL in self.available_models:
                        self.log_to_console("[OK] Model '%s' found in available models" % self.MODEL)
                    else:
                        self.log_to_console("[WARN] Model '%s' not in available models list" % self.MODEL)
                        # Log some similar models to help
                        search = self.MODEL.lower().split("/")[-1].split("-")[0]
                        similar = [m for m in self.available_models if search in m.lower()][:5]
                        if similar:
                            self.log_to_console("[HINT] Similar models: %s" % ", ".join(similar))

                return True
            self.log_to_console("[FAIL] %s returned unexpected structure" % self.AI_PROVIDER)
            return False
        except urllib2.HTTPError as e:
            body = ""
            try: body = e.read()[:300]
            except: pass
            self.log_to_console("[FAIL] HTTP %d from %s: %s" % (e.code, self.AI_PROVIDER, body))
            return False
        except Exception as e:
            self.log_to_console("[FAIL] %s connection: %s" % (self.AI_PROVIDER, str(e))); return False

    def _test_claude_connection(self):
        """Test Claude API key validity by making a tiny request."""
        if not self.API_KEY:
            self.log_to_console("[FAIL] No API key provided"); return False
        self.available_models = [
            "claude-sonnet-4-5-20250514",
            "claude-opus-4-5-20250414",
            "claude-haiku-4-5-20250414",
            "claude-3-5-sonnet-20241022",
            "claude-3-5-haiku-20241022",
            "claude-3-opus-20240229"]
        test_model = self.MODEL if self.MODEL in self.available_models else self.available_models[0]
        self.log_to_console("[TEST] Claude: testing with model %s ..." % test_model)
        try:
            req = urllib2.Request(
                self.API_URL.rstrip('/') + "/messages",
                data=json.dumps({
                    "model": test_model,
                    "max_tokens": 5,
                    "messages": [{"role": "user", "content": "ping"}]
                }).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": self.API_KEY,
                    "anthropic-version": "2023-06-01"
                })
            urllib2.urlopen(req, timeout=10)
            self.log_to_console("[OK] Claude API connected - key valid, credits available")
            return True
        except urllib2.HTTPError as e:
            body = ""
            try: body = e.read()[:500]
            except: pass
            if e.code == 401:
                self.log_to_console("[FAIL] Claude - invalid API key (401)")
                return False
            body_lower = body.lower() if body else ""
            if "credit" in body_lower or "balance" in body_lower or "billing" in body_lower or "payment" in body_lower:
                self.log_to_console("[OK] Claude API connected - key is valid and authenticated")
                self.log_to_console("[FAIL] However, your credit balance is too low to make requests")
                self.log_to_console("[FAIL] Top up at: https://console.anthropic.com/settings/billing")
                return False
            if "model" in body_lower and ("not found" in body_lower or "invalid" in body_lower):
                self.log_to_console("[OK] Claude API connected - key valid")
                self.log_to_console("[WARN] Model '%s' not available - try a different model" % test_model)
                return True
            # 429 rate limit, 529 overloaded = key works, server reachable
            self.log_to_console("[OK] Claude API connected (HTTP %d)" % e.code)
            return True
        except Exception as e:
            self.log_to_console("[FAIL] Claude connection: %s" % str(e))
            return False

    def _test_gemini_connection(self):
        """Test Gemini API key validity and fetch available models."""
        if not self.API_KEY:
            self.log_to_console("[FAIL] No API key provided"); return False
        self.log_to_console("[TEST] Gemini: fetching models...")
        # Try v1beta first (has newer models), fall back to v1
        for api_ver in ["v1beta", "v1"]:
            try:
                base = self.API_URL.rstrip('/').replace("/v1beta", "").replace("/v1", "")
                url = "%s/%s/models?key=%s" % (base, api_ver, self.API_KEY)
                req = urllib2.Request(url, headers={'Content-Type': 'application/json'})
                data = json.loads(urllib2.urlopen(req, timeout=10).read())
                if "models" in data:
                    fetched = []
                    for m in data["models"]:
                        methods = m.get("supportedGenerationMethods", [])
                        if "generateContent" in methods:
                            name = m.get("name", "").replace("models/", "")
                            if name: fetched.append(name)
                    if fetched:
                        self.available_models = sorted(fetched)
                        # Update API URL to the working version
                        self.API_URL = "%s/%s" % (base, api_ver)
                        self.log_to_console("[OK] Gemini connected (%s) - %d models available" % (api_ver, len(self.available_models)))
                        # Validate current model
                        if self.MODEL and self.MODEL in self.available_models:
                            self.log_to_console("[OK] Model '%s' is available" % self.MODEL)
                        elif self.MODEL:
                            self.log_to_console("[WARN] Model '%s' not found. Available: %s" % (self.MODEL, ", ".join(self.available_models[:5])))
                        return True
            except urllib2.HTTPError as e:
                if e.code == 401 or e.code == 403:
                    self.log_to_console("[FAIL] Gemini - invalid API key (%d)" % e.code)
                    return False
                continue
            except:
                continue
        self.log_to_console("[FAIL] Gemini: could not fetch models")
        # Provide static fallback
        self.available_models = ["gemini-2.5-flash-preview-05-20", "gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"]
        return False

    # -----------------------------------------------------------------------
    # AUTO-DETECT ACTIVE MODEL  (OpenRouter / Groq)
    # -----------------------------------------------------------------------
    def _detect_active_model(self):
        """Try to auto-detect the model the user has selected on their
        OpenRouter or Groq dashboard / console."""
        detected = None
        try:
            if self.AI_PROVIDER == "OpenRouter":
                detected = self._detect_openrouter_model()
            elif self.AI_PROVIDER == "Groq":
                detected = self._detect_groq_model()
        except Exception as e:
            self.log_to_console("[DETECT] Error: %s" % str(e))

        if detected:
            self.console_selected_model = detected
            self.MODEL = detected
            self.log_to_console("[DETECT] Active model: %s" % detected)
        return detected

    def _detect_openrouter_model(self):
        """Query OpenRouter /auth/key for key metadata."""
        try:
            req = urllib2.Request("https://openrouter.ai/api/v1/auth/key",
                                  headers={
                                      "Authorization": "Bearer " + self.API_KEY,
                                      "HTTP-Referer": "https://burpseeq.ai",
                                      "X-Title": "BurpSeeq"
                                  })
            data = json.loads(urllib2.urlopen(req, timeout=10).read())
            if "data" in data:
                m = data["data"].get("model") or data["data"].get("label")
                if m:
                    self.log_to_console("[DETECT] OpenRouter key model: %s" % m)
                    return m
                self.log_to_console("[DETECT] OpenRouter key has no default model tag")
        except Exception as e:
            self.log_to_console("[DETECT] OpenRouter /auth/key: %s" % str(e))
        # No fallback probe — just return None and let the user pick from the loaded list
        return None

    def _detect_groq_model(self):
        """Auto-detect Groq model.
        1. Parse playground URL if pasted (e.g. ?model=openai/gpt-oss-120b)
        2. Use the model ID as-is (Groq uses org/model format)."""
        api_url = self.API_URL or ""
        if "model=" in api_url:
            match = re.search(r'[?&]model=([^&\s]+)', api_url)
            if match:
                detected = match.group(1)
                self.API_URL = "https://api.groq.com/openai/v1"
                self.log_to_console("[DETECT] Groq model from URL: %s" % detected)
                return detected
        # No probe — just return None and let the user pick from the loaded list
        return None

    def _probe_model_via_generation(self):
        """Send a minimal chat completion to discover the model in use.
        Both Groq and OpenRouter echo the 'model' field in responses."""
        if not self.API_KEY:
            return None
        probe_model = self.MODEL
        if self.available_models:
            # Use current MODEL if it's in the list, else first available
            if self.MODEL not in self.available_models:
                probe_model = self.available_models[0]

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.API_KEY
        }
        if self.AI_PROVIDER == "OpenRouter":
            headers["HTTP-Referer"] = "https://burpseeq.ai"
            headers["X-Title"] = "BurpSeeq"

        payload = {
            "model": probe_model,
            "messages": [{"role": "user", "content": "Say OK"}],
            "max_tokens": 5,
            "temperature": 0
        }
        req = urllib2.Request(
            self.API_URL.rstrip('/') + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers)
        try:
            resp_data = json.loads(urllib2.urlopen(req, timeout=15).read())
            actual_model = resp_data.get("model", "")
            if actual_model:
                return actual_model
        except Exception as e:
            self.log_to_console("[DETECT] Probe failed: %s" % str(e))
        return None

    def auto_select_model(self):
        if not self.available_models: return
        preferred = ["qwen","deepseek","llama","mixtral","gemma","mistral","gpt"]
        for p in preferred:
            for m in self.available_models:
                if p in m.lower():
                    self.MODEL = m
                    self.log_to_console("[AUTO] Selected: %s" % m)
                    return
        self.MODEL = self.available_models[0]
        self.log_to_console("[AUTO] Selected first: %s" % self.MODEL)

    # -----------------------------------------------------------------------
    # CONFIG
    # -----------------------------------------------------------------------
    def load_config(self):
        """Config lives in Burp's extension settings (callbacks.saveExtensionSetting),
        not in a plaintext dotfile in $HOME. A legacy ~/.burpseeq_config.json is read
        once for migration and then left untouched (delete it manually)."""
        try:
            cfg = None
            stored = self.callbacks.loadExtensionSetting("burpseeq_config")
            if stored:
                cfg = json.loads(stored)
            elif os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    cfg = json.load(f)
                self._migrated_legacy_config = True
            if isinstance(cfg, dict):
                self.SCOPE_ONLY         = bool(cfg.get("scope_only", self.SCOPE_ONLY))
                if cfg.get("report_mode") in ("Scan task", "Auto", "Site map only"):
                    self.REPORT_MODE    = cfg.get("report_mode")
                self.AI_PROVIDER        = cfg.get("ai_provider",         self.AI_PROVIDER)
                self.API_URL            = cfg.get("api_url",              self.API_URL)
                self.API_KEY            = cfg.get("api_key",              self.API_KEY)
                self.MODEL              = cfg.get("model",                self.MODEL)
                self.MAX_TOKENS         = cfg.get("max_tokens",           self.MAX_TOKENS)
                self.AI_REQUEST_TIMEOUT = cfg.get("ai_request_timeout",   self.AI_REQUEST_TIMEOUT)
                self.THEME              = cfg.get("theme",                self.THEME)
                self.SCAN_MODE          = cfg.get("scan_mode",            self.SCAN_MODE)
                self.console_selected_model = cfg.get("console_selected_model", None)
        except: pass

    def save_config(self):
        try:
            cfg = {
                "ai_provider": self.AI_PROVIDER, "api_url": self.API_URL,
                "api_key": self.API_KEY, "model": self.MODEL,
                "max_tokens": self.MAX_TOKENS, "ai_request_timeout": self.AI_REQUEST_TIMEOUT,
                "theme": self.THEME, "scan_mode": self.SCAN_MODE,
                "console_selected_model": self.console_selected_model,
                "scope_only": self.SCOPE_ONLY,
                "report_mode": self.REPORT_MODE
                # ACTIVE_VERIFY_ENABLED intentionally not persisted (always starts OFF)
            }
            self.callbacks.saveExtensionSetting("burpseeq_config", json.dumps(cfg))
            return True
        except: return False

    # -----------------------------------------------------------------------
    # SETTINGS DIALOG
    # -----------------------------------------------------------------------
    def openSettings(self, event):
        from javax.swing import JDialog, JTabbedPane, JPasswordField, JCheckBox, SwingConstants
        from java.awt.event import ActionListener

        dialog = JDialog()
        dialog.setTitle("BurpSeeq AI Settings  v%s" % self.VERSION)
        dialog.setModal(True)
        dialog.setSize(540, 580)
        dialog.setLocationRelativeTo(None)

        tabs = JTabbedPane()

        # ==================================================================
        # AI Provider tab
        # ==================================================================
        aiPanel = JPanel(GridBagLayout())
        aiPanel.setBorder(BorderFactory.createEmptyBorder(14, 18, 10, 18))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 6, 5, 6)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill   = GridBagConstraints.HORIZONTAL

        row = 0

        def add_row(label_text, widget, r):
            gbc.gridx = 0; gbc.gridy = r; gbc.gridwidth = 1; gbc.weightx = 0
            aiPanel.add(JLabel(label_text), gbc)
            gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0
            aiPanel.add(widget, gbc)
            gbc.gridwidth = 1; gbc.weightx = 0

        providerCombo = JComboBox(["Ollama", "OpenAI", "Claude", "Gemini", "Groq", "OpenRouter", "Grok"])
        providerCombo.setSelectedItem(self.AI_PROVIDER)
        apiUrlField = JTextField(self.API_URL, 26)
        apiKeyField = JPasswordField(self.API_KEY, 26)

        class ProviderChangeListener(ActionListener):
            def __init__(self, urlField): self.urlField = urlField
            def actionPerformed(self, e):
                p = str(e.getSource().getSelectedItem())
                defaults = {
                    "Ollama":     "http://localhost:11434",
                    "OpenAI":     "https://api.openai.com/v1",
                    "Claude":     "https://api.anthropic.com/v1",
                    "Gemini":     "https://generativelanguage.googleapis.com/v1beta",
                    "Groq":       "https://api.groq.com/openai/v1",
                    "OpenRouter": "https://openrouter.ai/api/v1",
                    "Grok":       "https://api.x.ai/v1"
                }
                if p in defaults: self.urlField.setText(defaults[p])
        providerCombo.addActionListener(ProviderChangeListener(apiUrlField))

        add_row("AI Provider:", providerCombo, row); row += 1
        add_row("API URL:",     apiUrlField,   row); row += 1
        add_row("API Key:",     apiKeyField,   row); row += 1

        # -- Model row: combo + Refresh --
        models_to_show = list(self.available_models) if self.available_models else []
        if self.console_selected_model and self.console_selected_model not in models_to_show:
            models_to_show.insert(0, self.console_selected_model)
        if self.MODEL and self.MODEL not in models_to_show:
            models_to_show.insert(0, self.MODEL)
        full_model_list = list(models_to_show)

        modelCombo = JComboBox(models_to_show)
        modelCombo.setEditable(True)
        model_to_select = self.MODEL
        if self.AI_PROVIDER in ["OpenRouter", "Groq"] and self.console_selected_model:
            model_to_select = self.console_selected_model
        modelCombo.setSelectedItem(model_to_select)

        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1; gbc.weightx = 0
        aiPanel.add(JLabel("Model:"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        aiPanel.add(modelCombo, gbc)
        gbc.gridx = 2; gbc.weightx = 0
        refreshModelsBtn = JButton("Refresh")
        refreshModelsBtn.setToolTipText("Fetch models and auto-detect active model")
        aiPanel.add(refreshModelsBtn, gbc)
        row += 1

        # -- Sync with Console Model button --
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3
        syncConsoleBtn = JButton("Sync with Console Model")
        syncConsoleBtn.setToolTipText("Paste the model ID from your Groq/OpenRouter console")

        def syncConsoleModel(e):
            cur_prov = str(providerCombo.getSelectedItem())
            if cur_prov not in ["Groq", "OpenRouter"]:
                JOptionPane.showMessageDialog(dialog,
                    "Console sync is only available for Groq and OpenRouter.",
                    "Info", JOptionPane.INFORMATION_MESSAGE)
                return

            hint = ""
            if cur_prov == "Groq":
                hint = "Enter the exact model ID from the Groq dropdown.\nGroq now uses org/model format (e.g. openai/gpt-oss-120b).\nClick Refresh first to load the full list."
            else:
                hint = "Enter model ID from your OpenRouter console:\n(e.g. qwen/qwen3-235b-a22b:free)"

            console_model = JOptionPane.showInputDialog(dialog, hint,
                self.console_selected_model or "")
            if console_model and console_model.strip():
                console_model = console_model.strip()
                self.console_selected_model = console_model
                if console_model not in full_model_list:
                    full_model_list.insert(0, console_model)
                    modelCombo.insertItemAt(console_model, 0)
                modelCombo.setSelectedItem(console_model)
                self.log_to_console("[SYNC] Console model set: %s" % console_model)

        syncConsoleBtn.addActionListener(syncConsoleModel)
        aiPanel.add(syncConsoleBtn, gbc)
        row += 1

        # -- Status label --
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3
        statusLabel = JLabel(" ")
        statusLabel.setFont(Font("Dialog", Font.ITALIC, 11))
        aiPanel.add(statusLabel, gbc)
        row += 1

        # -- Refresh button action --
        def refreshModels(e):
            refreshModelsBtn.setEnabled(False)
            statusLabel.setText("Connecting...")
            statusLabel.setForeground(Color(0x00, 0x60, 0xAA))
            cur_provider = str(providerCombo.getSelectedItem())
            ext = self

            # Groq playground URL parsing: extract model and reset URL
            cur_url = apiUrlField.getText().strip()
            groq_parsed_model = None
            if cur_provider == "Groq" and "model=" in cur_url:
                match = re.search(r'[?&]model=([^&\s]+)', cur_url)
                if match:
                    groq_parsed_model = match.group(1)
                    apiUrlField.setText("https://api.groq.com/openai/v1")
                    ext.log_to_console("[SYNC] Groq playground model: %s (will resolve after loading models)" % groq_parsed_model)

            def _do():
                old_p, old_u, old_k, old_m = ext.AI_PROVIDER, ext.API_URL, ext.API_KEY, ext.MODEL
                ext.AI_PROVIDER = cur_provider
                ext.API_URL = apiUrlField.getText()
                ext.API_KEY = "".join(apiKeyField.getPassword())
                prev_sel = str(modelCombo.getSelectedItem()) if modelCombo.getSelectedItem() else old_m

                try:
                    if ext.test_ai_connection():
                        # If Groq playground URL was parsed, use the model as-is
                        if groq_parsed_model:
                            ext.console_selected_model = groq_parsed_model
                            ext.log_to_console("[SYNC] Groq model set: %s" % groq_parsed_model)

                        # Capture results before finally block restores old state
                        fetched_models = list(ext.available_models)
                        detected_model = ext.console_selected_model

                        def _upd():
                            full_model_list[:] = fetched_models
                            if detected_model and detected_model not in fetched_models:
                                fetched_models.insert(0, detected_model)
                                full_model_list[:] = fetched_models
                            modelCombo.removeAllItems()
                            for m in fetched_models:
                                modelCombo.addItem(m)
                            sel = detected_model or prev_sel or (fetched_models[0] if fetched_models else "")
                            if sel:
                                modelCombo.setSelectedItem(sel)
                            refreshModelsBtn.setEnabled(True)
                            if detected_model:
                                statusLabel.setText("OK - model: %s (%d loaded)" % (detected_model, len(fetched_models)))
                            else:
                                statusLabel.setText("OK - %d models loaded" % len(fetched_models))
                            statusLabel.setForeground(Color(0x00, 0x7A, 0x29))
                        SwingUtilities.invokeLater(lambda: _upd())
                    else:
                        def _fail():
                            refreshModelsBtn.setEnabled(True)
                            statusLabel.setText("Connection failed - see console")
                            statusLabel.setForeground(Color(0xCC, 0x00, 0x00))
                        SwingUtilities.invokeLater(lambda: _fail())
                except Exception as ex:
                    def _err():
                        refreshModelsBtn.setEnabled(True)
                        statusLabel.setText("Error: %s" % str(ex)[:50])
                        statusLabel.setForeground(Color(0xCC, 0x00, 0x00))
                    SwingUtilities.invokeLater(lambda: _err())
                finally:
                    ext.AI_PROVIDER = old_p; ext.API_URL = old_u
                    ext.API_KEY = old_k; ext.MODEL = old_m

            _rt = threading.Thread(target=_do); _rt.setDaemon(True); _rt.start()
        refreshModelsBtn.addActionListener(refreshModels)

        # -- Parameters --
        maxTokensField = JTextField(str(self.MAX_TOKENS), 10)
        timeoutField   = JTextField(str(self.AI_REQUEST_TIMEOUT), 10)
        add_row("Max Tokens:",  maxTokensField, row); row += 1
        add_row("Timeout (s):", timeoutField,   row); row += 1

        # -- Test Connection button --
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3
        testBtn = JButton("Test Connection")

        def doTest(e):
            testBtn.setEnabled(False)
            statusLabel.setText("Testing...")
            statusLabel.setForeground(Color(0x00, 0x60, 0xAA))
            saved_p, saved_u, saved_k, saved_m = self.AI_PROVIDER, self.API_URL, self.API_KEY, self.MODEL
            self.AI_PROVIDER = str(providerCombo.getSelectedItem())
            self.API_URL     = apiUrlField.getText()
            self.API_KEY     = "".join(apiKeyField.getPassword())
            sel_model = str(modelCombo.getSelectedItem()) if modelCombo.getSelectedItem() else self.MODEL
            self.MODEL = sel_model

            test_done = [False]

            def _run():
                ok = False
                det = None
                try:
                    ok = self.test_ai_connection()
                except Exception as ex:
                    self.log_to_console("[TEST] Error: %s" % str(ex))
                finally:
                    self.AI_PROVIDER = saved_p; self.API_URL = saved_u
                    self.API_KEY = saved_k; self.MODEL = saved_m
                    test_done[0] = True

                _ok = ok; _sel = sel_model
                def _upd():
                    testBtn.setEnabled(True)
                    if _ok:
                        statusLabel.setText("Connection OK - model: %s" % _sel)
                        statusLabel.setForeground(Color(0x00, 0x7A, 0x29))
                    else:
                        statusLabel.setText("FAILED - see console log")
                        statusLabel.setForeground(Color(0xCC, 0x00, 0x00))
                SwingUtilities.invokeLater(lambda: _upd())

            def _watchdog():
                time.sleep(10)
                if not test_done[0]:
                    self.log_to_console("[TEST] Timed out after 10s")
                    self.AI_PROVIDER = saved_p; self.API_URL = saved_u
                    self.API_KEY = saved_k; self.MODEL = saved_m
                    def _timeout():
                        testBtn.setEnabled(True)
                        statusLabel.setText("Timed out (10s)")
                        statusLabel.setForeground(Color(0xCC, 0x00, 0x00))
                    SwingUtilities.invokeLater(lambda: _timeout())

            t1 = threading.Thread(target=_run); t1.setDaemon(True); t1.start()
            t2 = threading.Thread(target=_watchdog); t2.setDaemon(True); t2.start()

        testBtn.addActionListener(doTest)
        aiPanel.add(testBtn, gbc)
        row += 1

        tabs.addTab("AI Provider", aiPanel)

        # ==================================================================
        # Advanced tab
        # ==================================================================
        advPanel = JPanel(GridBagLayout())
        advPanel.setBorder(BorderFactory.createEmptyBorder(14, 18, 10, 18))
        agbc = GridBagConstraints()
        agbc.insets = Insets(5, 6, 5, 6)
        agbc.anchor = GridBagConstraints.WEST
        agbc.fill = GridBagConstraints.HORIZONTAL
        ar = 0

        themeCombo = JComboBox(["Light", "Dark"])
        themeCombo.setSelectedItem(self.THEME)
        agbc.gridx = 0; agbc.gridy = ar; advPanel.add(JLabel("Console Theme:"), agbc)
        agbc.gridx = 1; advPanel.add(themeCombo, agbc); ar += 1

        scanModeCombo2 = JComboBox(["Quick", "Thorough", "Focused"])
        scanModeCombo2.setSelectedItem(self.SCAN_MODE)
        scanModeCombo2.setToolTipText("Quick=OWASP Top10 | Thorough=30+ classes | Focused=Injection/RCE only")
        agbc.gridx = 0; agbc.gridy = ar; advPanel.add(JLabel("Default Scan Mode:"), agbc)
        agbc.gridx = 1; advPanel.add(scanModeCombo2, agbc); ar += 1

        minDelayField = JTextField(str(self.min_delay), 8)
        agbc.gridx = 0; agbc.gridy = ar; advPanel.add(JLabel("Min Delay (s):"), agbc)
        agbc.gridx = 1; advPanel.add(minDelayField, agbc); ar += 1

        skipExtField = JTextField(", ".join(self.SKIP_EXTENSIONS), 26)
        agbc.gridx = 0; agbc.gridy = ar; advPanel.add(JLabel("Skip Extensions:"), agbc)
        agbc.gridx = 1; advPanel.add(skipExtField, agbc); ar += 1

        scopeOnlyChk = JCheckBox("Analyse in-scope traffic only (recommended)", self.SCOPE_ONLY)
        scopeOnlyChk.setToolTipText("When off, ALL proxied traffic is sent to the AI provider. "
                                    "Active verification is always in-scope only regardless.")
        agbc.gridx = 0; agbc.gridy = ar; agbc.gridwidth = 2
        advPanel.add(scopeOnlyChk, agbc); agbc.gridwidth = 1; ar += 1

        reportModeCombo = JComboBox(["Scan task", "Auto", "Site map only"])
        reportModeCombo.setSelectedItem(self.REPORT_MODE)
        reportModeCombo.setToolTipText(
            "<html>Scan task: findings appear in the Live audit task's Issues tab (Dashboard). "
            "Needs a running Live audit task.<br>Auto: use the audit task when one covers the host, "
            "otherwise analyse proxy traffic directly.<br>Site map only: analyse proxy traffic "
            "directly; findings appear in Target &gt; Issues only.</html>")
        agbc.gridx = 0; agbc.gridy = ar; advPanel.add(JLabel("Report findings to:"), agbc)
        agbc.gridx = 1; advPanel.add(reportModeCombo, agbc); ar += 1

        tabs.addTab("Advanced", advPanel)

        # ==================================================================
        # Save / Cancel
        # ==================================================================
        btnPanel = JPanel(FlowLayout(FlowLayout.CENTER, 12, 8))

        def saveSettings(e):
            self.AI_PROVIDER        = str(providerCombo.getSelectedItem())
            self.API_URL            = apiUrlField.getText()
            self.API_KEY            = "".join(apiKeyField.getPassword())
            self.MODEL              = str(modelCombo.getSelectedItem())
            self.MAX_TOKENS         = int(maxTokensField.getText() or 2048)
            self.AI_REQUEST_TIMEOUT = int(timeoutField.getText() or 180)
            self.THEME              = str(themeCombo.getSelectedItem())
            self.SCAN_MODE          = str(scanModeCombo2.getSelectedItem())
            try: self.min_delay = float(minDelayField.getText() or 4.0)
            except: pass
            try: self.SKIP_EXTENSIONS = [x.strip() for x in skipExtField.getText().split(",") if x.strip()]
            except: pass
            self.SCOPE_ONLY = bool(scopeOnlyChk.isSelected())
            self.REPORT_MODE = str(reportModeCombo.getSelectedItem())
            self._scope_hint_logged = False
            if self.AI_PROVIDER in ["Groq", "OpenRouter"]:
                self.console_selected_model = self.MODEL
            self.applyConsoleTheme()
            self.scanModeCombo.setSelectedItem(self.SCAN_MODE)
            self.save_config()
            self.log_to_console("[SETTINGS] Saved. Provider: %s | Model: %s | Mode: %s" % (
                self.AI_PROVIDER, self.MODEL, self.SCAN_MODE))
            dialog.dispose()

        saveBtn   = JButton("Save");   saveBtn.addActionListener(saveSettings)
        cancelBtn = JButton("Cancel"); cancelBtn.addActionListener(lambda e: dialog.dispose())
        btnPanel.add(saveBtn); btnPanel.add(cancelBtn)

        dialog.add(tabs,     BorderLayout.CENTER)
        dialog.add(btnPanel, BorderLayout.SOUTH)
        dialog.setVisible(True)

    # -----------------------------------------------------------------------
    # CONTEXT MENU
    # -----------------------------------------------------------------------
    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        messages  = invocation.getSelectedMessages()
        if messages:
            item = JMenuItem("Send to BurpSeeq AI")
            item.addActionListener(lambda x: self.analyzeFromContextMenu(messages))
            menu_list.add(item)
        return menu_list if menu_list.size() > 0 else None

    def analyzeFromContextMenu(self, messages):
        t = threading.Thread(target=self._contextMenuThread, args=(messages,))
        t.setDaemon(True); t.start()

    def _contextMenuThread(self, messages):
        for msg in messages:
            try:
                req     = self.helpers.analyzeRequest(msg)
                url_str = str(req.getUrl())
                tid     = self.addTask("CONTEXT", url_str, "Queued", msg)
                self.analyze_forced(msg, url_str, tid)
            except: pass

    # -----------------------------------------------------------------------
    # SCANNER CHECK (stubs)
    # -----------------------------------------------------------------------
    def doPassiveScan(self, baseRequestResponse):
        """Called by Burp scan tasks (e.g. 'Live audit from Proxy') for each audited item.
        Issues returned here are attributed to that task and appear in its Issues tab.
        Note: this blocks the scanner thread for the duration of the AI call."""
        try:
            if self.REPORT_MODE == "Site map only":
                return None
            if not self.PASSIVE_SCANNING_ENABLED or not baseRequestResponse.getResponse():
                return None
            req = self.helpers.analyzeRequest(baseRequestResponse)
            jurl = req.getUrl()
            self._last_audit_call = time.time()
            self._audit_seen_hosts[jurl.getHost()] = self._last_audit_call
            if self.SCOPE_ONLY and not self.callbacks.isInScope(jurl):
                return None
            url_str = str(jurl)
            if self._is_static(url_str):
                return None
            if not self._claim_url(self._url_hash(url_str)):
                return None
            task_id = self.addTask("AUDIT", url_str, "Queued", baseRequestResponse)
            issues = []
            with self.semaphore:
                self._perform_analysis(baseRequestResponse, "HTTP", url_str, task_id,
                                       collect_issues=issues)
            return issues if issues else None
        except Exception as e:
            self.log_to_console("[AUDIT] doPassiveScan error: %s" % str(e))
            return None
    def doActiveScan(self, baseRequestResponse, insertionPoint): return []
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # Same BurpSeeq issue name at the same URL -> keep the existing one
        try:
            if (existingIssue.getIssueName() == newIssue.getIssueName() and
                    str(existingIssue.getUrl()) == str(newIssue.getUrl())):
                return -1
        except Exception:
            pass
        return 0

    # -----------------------------------------------------------------------
    # TAB
    # -----------------------------------------------------------------------
    def getTabCaption(self): return "BurpSeeq"
    def getUiComponent(self): return self.panel

    # -----------------------------------------------------------------------
    def print_logo(self):
        self.stdout.println("")
        self.stdout.println("  ___                 ___              ___ ")
        self.stdout.println(" | _ ) _  _ _ _ _ __ / __| ___  ___  / _ \\")
        self.stdout.println(" | _ \\| || | '_| '_ \\\\__ \\/ -_)/ -_)| (_) |")
        self.stdout.println(" |___/ \\_,_|_| | .__/|___/\\___|\\___| \\__\\_\\")
        self.stdout.println("               |_|                    AI")
        self.stdout.println("")
        self.stdout.println(" Smart AI-Powered Pentesting  v%s  Community Edition" % self.VERSION)
        self.stdout.println(" 50+ Vulnerability Classes | CWE Mapped | Context-Aware | PoC-Driven")
        self.stdout.println("")


# ---------------------------------------------------------------------------
class CustomScanIssue(IScanIssue):
    """Proper IScanIssue implementation so findings appear in Burp's Issue dashboard."""
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity      # "High", "Medium", "Low", "Information"
        self._confidence = confidence  # "Certain", "Firm", "Tentative"

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return "BurpSeeq AI: %s" % self._name

    def getIssueType(self):
        return 0x08000000  # Extension-generated issue

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return ("<p>This issue was identified by <b>BurpSeeq AI v" + VERSION + "</b>, a smart AI-powered "
                "pentesting tool that performs context-aware HTTP analysis with 50+ vulnerability classes.</p>"
                "<p>The AI examined the full request/response including endpoint classification, "
                "technology fingerprinting, JWT/auth analysis, parameter injection testing, "
                "JavaScript secret scanning, and cross-endpoint context correlation.</p>"
                "<p>Findings include CWE references and proof-of-concept test steps.</p>")

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        # Extract CWE from detail if present
        cwe_ref = ""
        detail_text = self._detail
        if detail_text.startswith("[CWE-"):
            cwe_end = detail_text.find("]")
            if cwe_end > 0:
                cwe_ref = detail_text[1:cwe_end]
                detail_text = detail_text[cwe_end+1:].strip()

        cwe_html = ""
        if cwe_ref:
            cwe_html = ("<p><b>CWE Reference:</b> <a href='https://cwe.mitre.org/data/definitions/%s.html'>%s</a></p>"
                        % (cwe_ref.replace("CWE-",""), cwe_ref))

        return ("<h3>%s</h3>"
                "<p><b>Severity:</b> %s &nbsp;&nbsp; <b>Confidence:</b> %s</p>"
                "%s"
                "<hr>"
                "<h4>Analysis Detail</h4>"
                "<p>%s</p>"
                "<hr>"
                "<h4>Verification Steps</h4>"
                "<p>1. Review the HTTP transaction in the Request/Response tabs below.<br>"
                "2. Follow the proof-of-concept steps described in the detail above.<br>"
                "3. Manually verify the finding by replaying the modified request in Burp Repeater.<br>"
                "4. Confirm whether the vulnerability is exploitable in the target environment.</p>"
                % (self._name, self._severity, self._confidence, cwe_html,
                   detail_text.replace("\n", "<br>")))

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService

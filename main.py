#!/usr/bin/env python3
#
# =============================================================================
#  Project      : OSINT Tracker
#  Description  : Find related domains via Certificate Transparency (crt.sh)
#                 with reverse-IP fallback (Linux / Windows / macOS)
#  Author       : Raffaele Catapano
#  License      : MIT (see LICENSE)
#  Created on   : 13/11/2026
#  Updated on   : 13/11/2026
#  Version      : 1.5.0 - PySide6 Dark Theme
#
#  Copyright (c) 2026 Raffaele Catapano
#  Released under the MIT License - see the LICENSE file for details.
#  SPDX-License-Identifier: MIT
# =============================================================================
from __future__ import annotations

import csv
import html
import math
import sys
import threading
import xml.etree.ElementTree as ET
from datetime import datetime

from PySide6.QtCore import (QByteArray, QLocale, QObject, QSettings, QSortFilterProxyModel,
                            QStringListModel, Qt, QTimer, Signal)
from PySide6.QtGui import QFont, QGuiApplication, QIcon, QKeySequence, QPainter, QPixmap, QShortcut
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog,
                               QHBoxLayout, QLabel, QLineEdit, QListView, QMainWindow, QMenu,
                               QPlainTextEdit, QProgressBar, QPushButton, QSplitter,
                               QStackedWidget, QVBoxLayout, QWidget)

import core
import i18n
from core import APP_NAME, APP_VERSION, APP_AUTHOR

# --------------------------------------------------------------------------- #
#  Palette (dark)
# --------------------------------------------------------------------------- #
C = {
    "bg": "#12161c", "panel": "#1a2029", "panel2": "#222a36", "border": "#2c3544",
    "text": "#e4e8ee", "muted": "#8b96a6", "accent": "#5aa9ff", "accent_hi": "#7bbcff",
    "accent_dim": "#244a73", "on_accent": "#08111d", "ok": "#6fe3b0", "warn": "#f2c14e",
    "err": "#ff6b6b",
}
LOG_COLORS = {"ok": C["ok"], "info": C["accent"], "warn": C["warn"], "err": C["err"],
              "muted": C["muted"]}
MONO = ["JetBrains Mono", "Cascadia Mono", "SF Mono", "Menlo", "Consolas", "DejaVu Sans Mono",
        "monospace"]

QSS = """
QWidget { background: @bg; color: @text; }
QLabel { background: transparent; }
QLabel#title { font-size: 20pt; font-weight: 700; }
QLabel#subtitle, QLabel#muted { color: @muted; }
QLabel#section { font-weight: 600; }
QLabel#hint { color: @muted; font-size: 11pt; }
QLineEdit, QComboBox {
    background: @panel; border: 1px solid @border; border-radius: 6px; padding: 7px 10px;
    selection-background-color: @accent_dim; selection-color: @text;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid @accent; }
QLineEdit#target { font-size: 12pt; padding: 9px 12px; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView {
    background: @panel; border: 1px solid @border; selection-background-color: @accent_dim;
    outline: none;
}
QPushButton {
    background: @panel2; border: 1px solid @border; border-radius: 6px; padding: 7px 16px;
}
QPushButton:hover { border-color: @accent; }
QPushButton:pressed { background: @panel; }
QPushButton:focus { border-color: @accent; }
QPushButton:disabled { color: #5c6674; background: @panel; border-color: @panel2; }
QPushButton#primary {
    background: @accent; color: @on_accent; border: 1px solid @accent; font-weight: 700;
    padding: 9px 22px;
}
QPushButton#primary:hover { background: @accent_hi; }
QPushButton#primary:disabled { background: @accent_dim; color: #7f93ab; border-color: @accent_dim; }
QCheckBox { spacing: 8px; background: transparent; }
QCheckBox::indicator {
    width: 16px; height: 16px; border: 1px solid @border; border-radius: 4px; background: @panel;
}
QCheckBox::indicator:checked { background: @accent; border-color: @accent; }
QCheckBox::indicator:focus { border-color: @accent_hi; }
QListView, QPlainTextEdit {
    background: @panel; border: 1px solid @border; border-radius: 6px; outline: none;
    selection-background-color: @accent_dim; selection-color: @text;
}
QListView { alternate-background-color: #1d2430; padding: 2px; }
QListView::item { padding: 4px 8px; }
QListView::item:selected { background: @accent_dim; color: @text; }
QPlainTextEdit#log { color: @muted; padding: 6px; }
QProgressBar { background: @panel2; border: none; max-height: 3px; min-height: 3px; border-radius: 1px; }
QProgressBar::chunk { background: @accent; border-radius: 1px; }
QSplitter::handle { background: transparent; height: 8px; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: @border; border-radius: 4px; min-height: 28px; }
QScrollBar::handle:vertical:hover { background: #3a4558; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QToolTip { background: @panel2; color: @text; border: 1px solid @border; padding: 4px; }
QMenu { background: @panel; border: 1px solid @border; padding: 4px; }
QMenu::item { padding: 6px 18px; border-radius: 4px; }
QMenu::item:selected { background: @accent_dim; }
"""


def build_stylesheet() -> str:
    # longest keys first so "@accent_hi" is not clobbered by "@accent"
    qss = QSS
    for key in sorted(C, key=len, reverse=True):
        qss = qss.replace("@" + key, C[key])
    return qss


# --------------------------------------------------------------------------- #
#  Icon: generated at runtime as SVG (XML), no external image files
# --------------------------------------------------------------------------- #
SVG_NS = "http://www.w3.org/2000/svg"


def build_icon_svg() -> str:
    """Radar + linked nodes: a target (center) and the domains related to it."""
    svg = ET.Element("svg", {"xmlns": SVG_NS, "width": "256", "height": "256",
                             "viewBox": "0 0 256 256"})
    defs = ET.SubElement(svg, "defs")
    grad = ET.SubElement(defs, "linearGradient", {"id": "bg", "x1": "0", "y1": "0",
                                                  "x2": "0", "y2": "1"})
    ET.SubElement(grad, "stop", {"offset": "0", "stop-color": "#1f2837"})
    ET.SubElement(grad, "stop", {"offset": "1", "stop-color": "#0e131b"})
    ET.SubElement(svg, "rect", {"x": "8", "y": "8", "width": "240", "height": "240", "rx": "56",
                                "fill": "url(#bg)", "stroke": C["border"], "stroke-width": "3"})

    rings = ET.SubElement(svg, "g", {"fill": "none", "stroke": "#2c3544", "stroke-width": "3"})
    for r in (34, 66, 98):
        ET.SubElement(rings, "circle", {"cx": "128", "cy": "128", "r": str(r)})

    nodes = [(-72, 66), (-14, 98), (48, 66), (118, 98), (196, 34)]  # (angle deg, radius)
    pts = [(128 + r * math.cos(math.radians(a)), 128 + r * math.sin(math.radians(a)))
           for a, r in nodes]

    links = ET.SubElement(svg, "g", {"stroke": C["accent"], "stroke-width": "4",
                                     "stroke-linecap": "round", "opacity": "0.7"})
    for x, y in pts:
        ET.SubElement(links, "line", {"x1": "128", "y1": "128",
                                      "x2": f"{x:.1f}", "y2": f"{y:.1f}"})

    for i, (x, y) in enumerate(pts):
        ET.SubElement(svg, "circle", {"cx": f"{x:.1f}", "cy": f"{y:.1f}",
                                      "r": "12" if i % 2 == 0 else "9", "fill": C["ok"]})
    ET.SubElement(svg, "circle", {"cx": "128", "cy": "128", "r": "26", "fill": C["accent"],
                                  "opacity": "0.25"})
    ET.SubElement(svg, "circle", {"cx": "128", "cy": "128", "r": "16", "fill": C["accent"]})
    ET.SubElement(svg, "circle", {"cx": "128", "cy": "128", "r": "6", "fill": C["on_accent"]})
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(svg, encoding="unicode")


def render_svg(svg_text: str, size: int) -> QPixmap:
    renderer = QSvgRenderer(QByteArray(svg_text.encode("utf-8")))
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pm)
    renderer.render(painter)
    painter.end()
    return pm


def make_icon() -> QIcon:
    svg = build_icon_svg()
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        icon.addPixmap(render_svg(svg, size))
    return icon


# --------------------------------------------------------------------------- #
#  Background worker (plain thread: the UI never blocks)
# --------------------------------------------------------------------------- #
class ScanWorker(QObject):
    log = Signal(str, str, object)   # level, key, kwargs
    finished = Signal(object)        # ScanResult
    failed = Signal(str)

    def __init__(self, target: str, expand_org: bool, ip_fallback: bool):
        super().__init__()
        self.target, self.expand_org, self.ip_fallback = target, expand_org, ip_fallback
        self.cancel_event = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._run, daemon=True).start()

    def cancel(self) -> None:
        self.cancel_event.set()

    def _emit(self, level: str, key: str, **kw) -> None:
        self.log.emit(level, key, kw)

    def _run(self) -> None:
        try:
            result = core.run_scan(self.target, expand_org=self.expand_org,
                                   ip_fallback=self.ip_fallback,
                                   cancel=self.cancel_event, emit=self._emit)
        except core.Cancelled:
            return
        except Exception as e:  # noqa: BLE001 - surfaced to the user in the log
            self.failed.emit(f"{type(e).__name__}: {e}")
            return
        self.finished.emit(result)


# --------------------------------------------------------------------------- #
#  Main window
# --------------------------------------------------------------------------- #
class MainWindow(QMainWindow):
    def __init__(self, icon: QIcon, settings: QSettings):
        super().__init__()
        self.settings = settings
        self.setWindowIcon(icon)
        self.setMinimumSize(860, 640)
        self.resize(1020, 740)

        self._worker: ScanWorker | None = None
        self._all: list[str] = []
        self._target = ""
        self._status: tuple[str, dict] = ("status.ready", {})
        self._empty_key = "results.hint"

        self._build_ui(icon)
        self._wire()
        self.retranslate()

        geo = settings.value("geometry")
        if geo:
            self.restoreGeometry(geo)

    # ---- construction ---------------------------------------------------- #
    def _build_ui(self, icon: QIcon) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(20, 16, 20, 10)
        root.setSpacing(12)

        # header
        head = QHBoxLayout()
        head.setSpacing(12)
        self.logo = QLabel()
        self.logo.setPixmap(render_svg(build_icon_svg(), 48))
        self.logo.setFixedSize(48, 48)
        head.addWidget(self.logo)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        self.title = QLabel(APP_NAME)
        self.title.setObjectName("title")
        self.subtitle = QLabel()
        self.subtitle.setObjectName("subtitle")
        titles.addWidget(self.title)
        titles.addWidget(self.subtitle)
        head.addLayout(titles)
        head.addStretch(1)
        self.lang_label = QLabel()
        self.lang_label.setObjectName("muted")
        self.lang_combo = QComboBox()
        for code, name in i18n.LANGUAGES.items():
            self.lang_combo.addItem(name, code)
        self.lang_combo.setCurrentIndex(self.lang_combo.findData(i18n.get_language()))
        head.addWidget(self.lang_label)
        head.addWidget(self.lang_combo)
        root.addLayout(head)

        # input row
        row = QHBoxLayout()
        row.setSpacing(8)
        self.input = QLineEdit()
        self.input.setObjectName("target")
        self.input.setClearButtonEnabled(True)
        self.scan_btn = QPushButton()
        self.scan_btn.setObjectName("primary")
        self.scan_btn.setDefault(True)
        self.cancel_btn = QPushButton()
        self.cancel_btn.setEnabled(False)
        row.addWidget(self.input, 1)
        row.addWidget(self.scan_btn)
        row.addWidget(self.cancel_btn)
        root.addLayout(row)

        # options row
        opts = QHBoxLayout()
        opts.setSpacing(18)
        self.opt_org = QCheckBox()
        self.opt_ip = QCheckBox()
        self.opt_org.setChecked(self.settings.value("opt_org", True, type=bool))
        self.opt_ip.setChecked(self.settings.value("opt_ip", True, type=bool))
        self.type_label = QLabel()
        self.type_label.setObjectName("muted")
        opts.addWidget(self.opt_org)
        opts.addWidget(self.opt_ip)
        opts.addStretch(1)
        opts.addWidget(self.type_label)
        root.addLayout(opts)

        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        root.addWidget(self.progress)

        # results + log in a vertical splitter
        split = QSplitter(Qt.Orientation.Vertical)
        split.setChildrenCollapsible(True)

        res = QWidget()
        rl = QVBoxLayout(res)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(8)
        rh = QHBoxLayout()
        self.results_title = QLabel()
        self.results_title.setObjectName("section")
        self.count_label = QLabel()
        self.count_label.setObjectName("muted")
        self.filter = QLineEdit()
        self.filter.setClearButtonEnabled(True)
        self.filter.setMaximumWidth(280)
        rh.addWidget(self.results_title)
        rh.addWidget(self.count_label)
        rh.addStretch(1)
        rh.addWidget(self.filter)
        rl.addLayout(rh)

        self.model = QStringListModel(self)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.view = QListView()
        self.view.setModel(self.proxy)
        self.view.setUniformItemSizes(True)          # fast with 100k+ rows
        self.view.setAlternatingRowColors(True)
        self.view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.view.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        mono = QFont()
        mono.setFamilies(MONO)
        mono.setStyleHint(QFont.StyleHint.Monospace)
        mono.setPointSize(11)
        self.view.setFont(mono)

        self.empty = QLabel()
        self.empty.setObjectName("hint")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty.setWordWrap(True)
        self.stack = QStackedWidget()
        self.stack.addWidget(self.empty)
        self.stack.addWidget(self.view)
        rl.addWidget(self.stack, 1)

        rb = QHBoxLayout()
        rb.setSpacing(8)
        self.copy_btn = QPushButton()
        self.export_btn = QPushButton()
        self.clear_btn = QPushButton()
        rb.addWidget(self.copy_btn)
        rb.addWidget(self.export_btn)
        rb.addStretch(1)
        rb.addWidget(self.clear_btn)
        rl.addLayout(rb)
        split.addWidget(res)

        logw = QWidget()
        ll = QVBoxLayout(logw)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(6)
        self.log_title = QLabel()
        self.log_title.setObjectName("section")
        self.log = QPlainTextEdit()
        self.log.setObjectName("log")
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(1500)
        logfont = QFont()
        logfont.setFamilies(MONO)
        logfont.setStyleHint(QFont.StyleHint.Monospace)
        logfont.setPointSize(10)
        self.log.setFont(logfont)
        ll.addWidget(self.log_title)
        ll.addWidget(self.log, 1)
        split.addWidget(logw)
        split.setStretchFactor(0, 4)
        split.setStretchFactor(1, 1)
        split.setSizes([480, 150])
        root.addWidget(split, 1)

        # status bar
        self.status_label = QLabel()
        self.status_label.setObjectName("muted")
        ver = QLabel(f"v{APP_VERSION}")
        ver.setObjectName("muted")
        self.statusBar().setSizeGripEnabled(False)
        self.statusBar().addWidget(self.status_label, 1)
        self.statusBar().addPermanentWidget(ver)

        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(150)

    def _wire(self) -> None:
        self.input.returnPressed.connect(self.start_scan)
        self.input.textChanged.connect(self._update_type)
        self.scan_btn.clicked.connect(self.start_scan)
        self.cancel_btn.clicked.connect(self.cancel_scan)
        self.copy_btn.clicked.connect(self.copy_all)
        self.export_btn.clicked.connect(self.export_results)
        self.clear_btn.clicked.connect(self.clear_results)
        self.lang_combo.currentIndexChanged.connect(self._on_language)
        self.filter.textChanged.connect(lambda _t: self._filter_timer.start())
        self._filter_timer.timeout.connect(self._apply_filter)
        self.view.customContextMenuRequested.connect(self._context_menu)

        QShortcut(QKeySequence("Esc"), self, activated=self.cancel_scan)
        QShortcut(QKeySequence("Ctrl+L"), self, activated=self._focus_input)
        QShortcut(QKeySequence("Ctrl+F"), self, activated=lambda: self.filter.setFocus())
        QShortcut(QKeySequence("Ctrl+E"), self, activated=self.export_results)
        copy_sc = QShortcut(QKeySequence.StandardKey.Copy, self.view, activated=self.copy_selected)
        copy_sc.setContext(Qt.ShortcutContext.WidgetShortcut)

    # ---- translations ---------------------------------------------------- #
    def retranslate(self) -> None:
        t = i18n.tr
        self.setWindowTitle(f"{APP_NAME} * {APP_AUTHOR}")
        self.subtitle.setText(t("app.subtitle"))
        self.lang_label.setText(t("lang.label"))
        self.input.setPlaceholderText(t("input.placeholder"))
        self.input.setToolTip(t("input.tooltip"))
        self.scan_btn.setText(t("btn.scan"))
        self.cancel_btn.setText(t("btn.cancel"))
        self.opt_org.setText(t("opt.org"))
        self.opt_org.setToolTip(t("opt.org.tip"))
        self.opt_ip.setText(t("opt.ip"))
        self.opt_ip.setToolTip(t("opt.ip.tip"))
        self.results_title.setText(t("results.title"))
        self.filter.setPlaceholderText(t("results.filter"))
        self.copy_btn.setText(t("btn.copy"))
        self.export_btn.setText(t("btn.export"))
        self.clear_btn.setText(t("btn.clear"))
        self.log_title.setText(t("log.title"))
        self.empty.setText(t(self._empty_key))
        self._update_type()
        self._update_count()
        self._render_status()

    def _on_language(self) -> None:
        code = self.lang_combo.currentData()
        i18n.set_language(code)
        self.settings.setValue("lang", code)
        self.retranslate()

    # ---- state helpers --------------------------------------------------- #
    def _set_status(self, key: str, **kw) -> None:
        self._status = (key, kw)
        self._render_status()

    def _render_status(self) -> None:
        key, kw = self._status
        self.status_label.setText(i18n.tr(key, **kw))

    def _update_type(self) -> None:
        target = core.normalize_target(self.input.text())
        if not target:
            key = "type.none"
        else:
            key = "type.domain" if core.is_domain_target(target) else "type.org"
        self.type_label.setText(i18n.tr(key))

    def _update_count(self) -> None:
        total, shown = len(self._all), self.proxy.rowCount()
        if not total:
            self.count_label.setText("")
        elif shown == total:
            self.count_label.setText(i18n.tr("results.count", n=total))
        else:
            self.count_label.setText(i18n.tr("results.count_filtered", shown=shown, total=total))

    def _set_running(self, running: bool) -> None:
        for w in (self.input, self.scan_btn, self.opt_org, self.opt_ip,
                  self.copy_btn, self.export_btn, self.clear_btn):
            w.setEnabled(not running)
        self.cancel_btn.setEnabled(running)
        self.progress.setRange(0, 0) if running else (self.progress.setRange(0, 1),
                                                      self.progress.setValue(0))
        if not running:
            self._focus_input()

    def _focus_input(self) -> None:
        if self.input.isEnabled():
            self.input.setFocus()
            self.input.selectAll()

    def _append_log(self, level: str, text: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        color = LOG_COLORS.get(level, C["text"])
        self.log.appendHtml(f'<span style="color:{C["muted"]}">{ts}</span>&nbsp; '
                            f'<span style="color:{color}">{html.escape(text)}</span>')

    # ---- scan lifecycle -------------------------------------------------- #
    def start_scan(self) -> None:
        if self._worker is not None:
            return
        target = core.normalize_target(self.input.text())
        if not target:
            self._set_status("status.invalid")
            self._focus_input()
            return
        self.input.setText(target)
        self._target = target
        self._set_results([])
        self._empty_key = "results.hint"
        self.empty.setText(i18n.tr(self._empty_key))
        self.log.clear()

        kind = "kind.domain" if core.is_domain_target(target) else "kind.org"
        self._append_log("info", i18n.tr("log.start", target=target, kind=i18n.tr(kind)))

        w = ScanWorker(target, self.opt_org.isChecked(), self.opt_ip.isChecked())
        w.log.connect(self._on_log)
        w.finished.connect(self._on_finished)
        w.failed.connect(self._on_failed)
        self._worker = w
        self._set_running(True)
        self._set_status("status.running")
        w.start()

    def cancel_scan(self) -> None:
        w = self._worker
        if w is None:
            return
        w.cancel()
        self._detach_worker()
        self._append_log("warn", i18n.tr("log.cancelled"))
        self._set_status("status.cancelled")
        self._set_running(False)

    def _detach_worker(self) -> None:
        w, self._worker = self._worker, None
        if w is not None:
            for sig in (w.log, w.finished, w.failed):
                try:
                    sig.disconnect()
                except (RuntimeError, TypeError):
                    pass

    def _on_log(self, level: str, key: str, kw: dict) -> None:
        self._append_log(level, i18n.tr(key, **kw))

    def _on_failed(self, err: str) -> None:
        self._detach_worker()
        self._append_log("err", i18n.tr("log.failed", err=err))
        self._set_status("status.error")
        self._set_running(False)

    def _on_finished(self, result: core.ScanResult) -> None:
        self._detach_worker()
        self._set_results(result.related)
        secs = f"{result.elapsed:.1f}"
        if result.related:
            self._append_log("ok", i18n.tr("log.done", n=len(result.related), secs=secs))
            self._set_status("status.done", n=len(result.related), secs=secs)
        elif result.network_error:
            self._empty_key = "status.error"
            self._set_status("status.error")
        else:
            self._empty_key = "results.none"
            self._set_status("status.done", n=0, secs=secs)
        self.empty.setText(i18n.tr(self._empty_key))
        self._set_running(False)

    # ---- results --------------------------------------------------------- #
    def _set_results(self, items: list[str]) -> None:
        self._all = list(items)
        self.filter.clear()
        self.proxy.setFilterFixedString("")
        self.model.setStringList(self._all)
        self.stack.setCurrentIndex(1 if self._all else 0)
        self._update_count()

    def _apply_filter(self) -> None:
        self.proxy.setFilterFixedString(self.filter.text().strip())
        self._update_count()

    def clear_results(self) -> None:
        self._empty_key = "results.hint"
        self.empty.setText(i18n.tr(self._empty_key))
        self._set_results([])
        self.log.clear()
        self._set_status("status.ready")

    def _clipboard_set(self, items: list[str]) -> None:
        if not items:
            return
        QGuiApplication.clipboard().setText("\n".join(items))
        self._set_status("status.copied", n=len(items))

    def copy_all(self) -> None:
        self._clipboard_set(self._all)

    def copy_selected(self) -> None:
        rows = sorted(i.row() for i in self.view.selectedIndexes())
        self._clipboard_set([self.proxy.index(r, 0).data() for r in rows])

    def _context_menu(self, pos) -> None:
        if not self.view.selectedIndexes():
            return
        menu = QMenu(self)
        menu.addAction(i18n.tr("ctx.copy"), self.copy_selected)
        menu.exec(self.view.viewport().mapToGlobal(pos))

    def export_results(self) -> None:
        if not self._all:
            return
        base = (self._target or "results").replace(" ", "_").replace("/", "_")
        path, selected = QFileDialog.getSaveFileName(
            self, i18n.tr("export.title"), f"osint_{base}.txt", i18n.tr("export.filter"))
        if not path:
            return
        as_csv = path.lower().endswith(".csv") or ("csv" in selected.lower()
                                                   and not path.lower().endswith(".txt"))
        try:
            if as_csv and not path.lower().endswith(".csv"):
                path += ".csv"
            with open(path, "w", encoding="utf-8", newline="") as fh:
                if as_csv:
                    w = csv.writer(fh)
                    w.writerow(["domain"])
                    w.writerows([d] for d in self._all)
                else:
                    fh.write("\n".join(self._all) + "\n")
        except OSError as e:
            self._append_log("err", i18n.tr("export.fail", err=str(e)))
            self._set_status("export.fail", err=str(e))
            return
        self._set_status("export.done", n=len(self._all), path=path)

    # ---- window ---------------------------------------------------------- #
    def closeEvent(self, event) -> None:  # noqa: N802 (Qt naming)
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("opt_org", self.opt_org.isChecked())
        self.settings.setValue("opt_ip", self.opt_ip.isChecked())
        if self._worker is not None:
            self._worker.cancel()
            self._detach_worker()
        super().closeEvent(event)


def main() -> int:
    if sys.platform == "win32":  # proper taskbar icon on Windows
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "raffaelecatapano.osinttracker." + APP_VERSION)
        except Exception:  # noqa: BLE001
            pass

    app = QApplication(sys.argv)
    app.setStyle("Fusion")                      # identical look on Linux/Windows/macOS
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("RaffaeleCatapano")
    app.setStyleSheet(build_stylesheet())

    icon = make_icon()
    app.setWindowIcon(icon)

    settings = QSettings()
    saved = settings.value("lang", "", type=str)
    i18n.set_language(saved if saved in i18n.LANGUAGES
                      else i18n.detect_language(QLocale.system().name()))

    win = MainWindow(icon, settings)
    win.show()
    win.input.setFocus()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

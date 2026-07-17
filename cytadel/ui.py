"""PySide6 dark-theme GUI for the Cytadel Exposure Assessment tool.

Single wizard-like window. All heavy work runs in a worker thread so the UI
stays responsive; results are shown as exposure statistics and a redacted grid.
Plaintext passwords are never displayed, logged, or exported.
"""

from __future__ import annotations

import datetime
import os
import shutil
import sys
import tempfile
from typing import List, Optional

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtGui import QFont, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import __version__
from .extractor import ExtractionError, ExtractionLimits, safe_extract
from .parser import scan_tree
from .pdf_report import ReportMeta, build_pdf
from .redact import Redactor
from .resources import asset_path
from .search import (
    ExposureSummary,
    analyze,
    export_csv,
    make_scope_matcher,
    summarize,
)

AUTHORIZED_USE_NOTICE = (
    "NJOFTIM PËR PËRDORIM TË AUTORIZUAR\n\n"
    "Ky është një mjet mbrojtës CTI për njoftim shkeljesh. Përdoret VETËM "
    "kundër logeve për klientë që na kanë autorizuar të kontrollojmë ekspozimin "
    "e tyre, dhe VETËM për domenet e tyre.\n\n"
    "Të dhënat përpunohen sipas ligjit (GDPR — minimizimi i të dhënave): mjeti "
    "NUK shkruan kurrë fjalëkalime në tekst të thjeshtë në PDF, CSV, ndërfaqe ose "
    "skedarë. Nuk bën thirrje rrjeti dhe nuk ruan asgjë jashtë dosjeve që zgjidhni. "
    "Mos i rishpërndani kredencialet e papërpunuara."
)

_DARK_QSS = """
QWidget { background:#161418; color:#E7E3E9; font-size:13px; }
QGroupBox { border:1px solid #3A343C; border-radius:8px; margin-top:14px; padding-top:8px; }
QGroupBox::title { subcontrol-origin: margin; left:12px; padding:0 6px; color:#C98A8A; font-weight:600; }
QLineEdit { background:#201C22; border:1px solid #3A343C; border-radius:6px; min-height:30px; padding:4px 8px; selection-background-color:#6E0B0B; }
QPlainTextEdit, QTableWidget { background:#201C22; border:1px solid #3A343C; border-radius:6px; padding:6px; selection-background-color:#6E0B0B; }
QLineEdit:focus, QPlainTextEdit:focus { border:1px solid #8A2A2A; }
QPushButton { background:#2A2430; border:1px solid #4A424C; border-radius:6px; padding:8px 14px; }
QPushButton:hover { background:#352C3C; }
QPushButton:disabled { color:#6A626C; border-color:#302A34; }
QPushButton#primary { background:#6E0B0B; border:1px solid #8A2A2A; font-weight:600; }
QPushButton#primary:hover { background:#8A1414; }
QProgressBar { border:1px solid #3A343C; border-radius:6px; text-align:center; background:#201C22; }
QProgressBar::chunk { background:#6E0B0B; border-radius:5px; }
QHeaderView::section { background:#2A0A0A; color:#EDE7E7; padding:6px; border:0; }
QLabel#banner { background:#2A0A0A; color:#E9C6C6; border:1px solid #6E0B0B; border-radius:6px; padding:8px; }
QLabel#summary { color:#C7E7C7; font-weight:600; }
"""


class Worker(QObject):
    """Runs extraction + scan + analysis off the UI thread."""

    progress = Signal(str)
    finished = Signal(list, object)  # records, ExposureSummary
    failed = Signal(str)

    def __init__(self, input_path: str, is_archive: bool, domains: List[str]):
        super().__init__()
        self._input_path = input_path
        self._is_archive = is_archive
        self._domains = domains
        self._temp_dir: Optional[str] = None

    @property
    def temp_dir(self) -> Optional[str]:
        return self._temp_dir

    def run(self) -> None:
        try:
            scan_root = self._input_path
            if self._is_archive:
                self._temp_dir = tempfile.mkdtemp(prefix="cytadel_")
                self.progress.emit(f"Duke shpaketuar: {os.path.basename(self._input_path)}")
                stats = safe_extract(
                    self._input_path,
                    self._temp_dir,
                    ExtractionLimits(),
                    progress=lambda name: self.progress.emit(f"  shpaketuar: {name}"),
                )
                self.progress.emit(
                    f"Shpaketimi përfundoi: {stats.files} skedarë, "
                    f"{len(stats.skipped)} të anashkaluar."
                )
                for name, reason in stats.skipped[:20]:
                    self.progress.emit(f"  ANASHKALUAR ({reason}): {name}")
                scan_root = self._temp_dir

            in_scope = make_scope_matcher(self._domains)
            redactor = Redactor()
            self.progress.emit("Duke skanuar loget për ekspozim brenda domeneve…")

            scanned = {"files": 0}

            def on_file(rel: str) -> None:
                scanned["files"] += 1
                if scanned["files"] % 25 == 0:
                    self.progress.emit(f"  skanuar {scanned['files']} skedarë…")

            records = list(scan_tree(scan_root, redactor, in_scope, on_file=on_file))
            self.progress.emit(
                f"Skanimi përfundoi: {scanned['files']} skedarë, "
                f"{len(records)} përputhje të papastruara."
            )
            final = analyze(records, mark_reuse=True)
            summary = summarize(final)
            self.progress.emit(
                f"Analiza përfundoi: {summary.total_accounts} llogari unike."
            )
            self.finished.emit(final, summary)
        except ExtractionError as exc:
            self.failed.emit(f"Gabim shpaketimi: {exc}")
        except Exception as exc:  # noqa: BLE001 - surface anything to the UI
            self.failed.emit(f"Gabim i papritur: {exc}")


class MainWindow(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"Cytadel Exposure Assessment v{__version__}")
        self.resize(1040, 820)

        icon_path = asset_path("logo_white.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self._input_path: Optional[str] = None
        self._is_archive = False
        self._records: List = []
        self._summary: Optional[ExposureSummary] = None
        self._thread: Optional[QThread] = None
        self._worker: Optional[Worker] = None
        self._temp_dir: Optional[str] = None

        self._build_ui()

    # -- construction ---------------------------------------------------- #
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        logo_path = asset_path("logo_white.png")
        if os.path.exists(logo_path):
            logo_label = QLabel()
            pixmap = QPixmap(logo_path)
            if not pixmap.isNull():
                logo_label.setPixmap(
                    pixmap.scaledToHeight(140, Qt.SmoothTransformation)
                )
            logo_label.setAlignment(Qt.AlignCenter)
            root.addWidget(logo_label)

        banner = QLabel(
            "Mjet mbrojtës CTI • Vetëm për klientë të autorizuar • "
            "Pa fjalëkalime në tekst të thjeshtë (GDPR)"
        )
        banner.setObjectName("banner")
        banner.setWordWrap(True)
        root.addWidget(banner)

        # 1. Input
        in_box = QGroupBox("1 · Burimi i logeve")
        in_lay = QHBoxLayout(in_box)
        self.path_label = QLineEdit()
        self.path_label.setReadOnly(True)
        self.path_label.setPlaceholderText("Asnjë burim i zgjedhur…")
        btn_arch = QPushButton("Zgjidh arkivin…")
        btn_arch.clicked.connect(self._pick_archive)
        btn_dir = QPushButton("Zgjidh dosjen…")
        btn_dir.clicked.connect(self._pick_folder)
        in_lay.addWidget(self.path_label, 1)
        in_lay.addWidget(btn_arch)
        in_lay.addWidget(btn_dir)
        root.addWidget(in_box)

        # 2. Scope
        scope_box = QGroupBox("2 · Domeni(et) e klientit (fusha e vlerësimit)")
        scope_lay = QVBoxLayout(scope_box)
        self.domains_edit = QLineEdit()
        self.domains_edit.setPlaceholderText("client-domain.com, client-domain.net")
        scope_lay.addWidget(self.domains_edit)
        root.addWidget(scope_box)

        # 3. Metadata + 4. Options
        mid = QHBoxLayout()
        meta_box = QGroupBox("3 · Metadata e raportit")
        form = QFormLayout(meta_box)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        form.setVerticalSpacing(10)
        self.client_edit = QLineEdit()
        self.report_id_edit = QLineEdit("SEC-2025-001")
        self.date_edit = QLineEdit(datetime.date.today().isoformat())
        self.prepared_edit = QLineEdit("Cytadel.eu")
        self.classification_edit = QLineEdit("KONFIDENCIAL")
        form.addRow("Emri i klientit", self.client_edit)
        form.addRow("ID e Raportit", self.report_id_edit)
        form.addRow("Data", self.date_edit)
        form.addRow("Përgatitur nga", self.prepared_edit)
        form.addRow("Klasifikimi", self.classification_edit)
        mid.addWidget(meta_box, 1)

        opt_box = QGroupBox("4 · Opsionet")
        opt_lay = QVBoxLayout(opt_box)
        self.opt_strength = QCheckBox("Përfshi sinjalin e fuqisë (gjatësi + klasa)")
        self.opt_strength.setChecked(True)
        self.opt_reuse = QCheckBox("Sinjalizo fjalëkalime të ripërdorura (hash i kripur)")
        self.opt_reuse.setChecked(True)
        note = QLabel(
            "Të dyja janë vetëm sinjale të redaktuara. Fjalëkalimi kurrë nuk "
            "ruhet, shfaqet ose eksportohet."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color:#9A929C; font-size:11px;")
        opt_lay.addWidget(self.opt_strength)
        opt_lay.addWidget(self.opt_reuse)
        opt_lay.addWidget(note)
        opt_lay.addStretch(1)
        mid.addWidget(opt_box, 1)
        root.addLayout(mid)

        # 5. Run + progress + log
        run_row = QHBoxLayout()
        self.run_btn = QPushButton("Ekzekuto vlerësimin")
        self.run_btn.setObjectName("primary")
        self.run_btn.clicked.connect(self._run)
        about_btn = QPushButton("Përdorimi i autorizuar")
        about_btn.clicked.connect(self._show_notice)
        run_row.addWidget(self.run_btn)
        run_row.addWidget(about_btn)
        run_row.addStretch(1)
        root.addLayout(run_row)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        root.addWidget(self.progress)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(150)
        self.log.setFont(QFont("Consolas", 9))
        root.addWidget(self.log)

        # 6. Results
        self.summary_label = QLabel("")
        self.summary_label.setObjectName("summary")
        root.addWidget(self.summary_label)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            ["Email/Llogaria", "Shërbimi/URL", "Statusi i fjalëkalimit", "Veprimi"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        root.addWidget(self.table, 1)

        out_row = QHBoxLayout()
        self.save_pdf_btn = QPushButton("Ruaj PDF")
        self.save_pdf_btn.clicked.connect(self._save_pdf)
        self.save_pdf_btn.setEnabled(False)
        self.save_csv_btn = QPushButton("Eksporto CSV")
        self.save_csv_btn.clicked.connect(self._save_csv)
        self.save_csv_btn.setEnabled(False)
        out_row.addStretch(1)
        out_row.addWidget(self.save_csv_btn)
        out_row.addWidget(self.save_pdf_btn)
        root.addLayout(out_row)

    # -- input pickers --------------------------------------------------- #
    def _pick_archive(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Zgjidh arkivin", "", "Arkiva (*.zip *.7z *.rar);;Të gjithë (*.*)"
        )
        if path:
            self._input_path = path
            self._is_archive = True
            self.path_label.setText(path)

    def _pick_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Zgjidh dosjen e logeve")
        if path:
            self._input_path = path
            self._is_archive = False
            self.path_label.setText(path)

    def _show_notice(self) -> None:
        QMessageBox.information(self, "Përdorimi i autorizuar", AUTHORIZED_USE_NOTICE)

    # -- run pipeline ---------------------------------------------------- #
    def _domains(self) -> List[str]:
        return [d.strip() for d in self.domains_edit.text().split(",") if d.strip()]

    def _run(self) -> None:
        if not self._input_path:
            QMessageBox.warning(self, "Mungon burimi", "Zgjidhni një arkiv ose dosje.")
            return
        if not self._domains():
            QMessageBox.warning(
                self, "Mungon domeni", "Jepni të paktën një domen klienti."
            )
            return

        self._cleanup_temp()
        self.log.clear()
        self.table.setRowCount(0)
        self.summary_label.setText("")
        self.save_pdf_btn.setEnabled(False)
        self.save_csv_btn.setEnabled(False)
        self.run_btn.setEnabled(False)
        self.progress.setVisible(True)

        self._thread = QThread()
        self._worker = Worker(self._input_path, self._is_archive, self._domains())
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._append_log)
        self._worker.finished.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._thread.start()

    def _append_log(self, message: str) -> None:
        self.log.appendPlainText(message)

    def _on_finished(self, records: list, summary: ExposureSummary) -> None:
        self._records = records
        self._summary = summary
        if self._worker is not None:
            self._temp_dir = self._worker.temp_dir
        self._teardown_thread()
        self.progress.setVisible(False)
        self.run_btn.setEnabled(True)

        self.summary_label.setText(
            f"{summary.total_accounts} llogari të ekspozuara · "
            f"{summary.distinct_services} shërbime · "
            f"{summary.distinct_emails} adresa unike · "
            f"{summary.reused} të ripërdorura · {summary.weak} të dobëta "
            f"(nga {summary.source_files} skedarë)"
        )
        self._populate_table(records)
        has = bool(records)
        self.save_pdf_btn.setEnabled(has)
        self.save_csv_btn.setEnabled(has)
        if not has:
            QMessageBox.information(
                self, "Përfundoi", "Nuk u gjet asnjë llogari brenda domeneve."
            )

    def _on_failed(self, message: str) -> None:
        self._teardown_thread()
        self.progress.setVisible(False)
        self.run_btn.setEnabled(True)
        self._append_log(f"GABIM: {message}")
        QMessageBox.critical(self, "Gabim", message)

    def _populate_table(self, records: list) -> None:
        from .search import REQUIRED_ACTION

        self.table.setRowCount(len(records))
        for row, rec in enumerate(records):
            self.table.setItem(row, 0, QTableWidgetItem(rec.email))
            self.table.setItem(row, 1, QTableWidgetItem(rec.service_url))
            self.table.setItem(row, 2, QTableWidgetItem(rec.redaction.status_label()))
            self.table.setItem(row, 3, QTableWidgetItem(REQUIRED_ACTION))

    # -- exports --------------------------------------------------------- #
    def _meta(self) -> ReportMeta:
        return ReportMeta(
            client=self.client_edit.text().strip() or "Klienti",
            report_id=self.report_id_edit.text().strip() or "SEC-2025-001",
            date=self.date_edit.text().strip() or datetime.date.today().isoformat(),
            prepared_by=self.prepared_edit.text().strip() or "Cytadel.eu",
            classification=self.classification_edit.text().strip() or "KONFIDENCIAL",
        )

    def _default_name(self, ext: str) -> str:
        client = (self.client_edit.text().strip() or "Klienti").replace(" ", "_")
        year = (self.date_edit.text().strip() or "")[:4] or str(datetime.date.today().year)
        return f"Cytadel_Raport_{client}_{year}.{ext}"

    def _save_pdf(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Ruaj PDF", self._default_name("pdf"), "PDF (*.pdf)"
        )
        if not path:
            return
        try:
            build_pdf(path, self._meta(), self._domains(), self._records)
            QMessageBox.information(self, "Ruajtur", f"PDF u ruajt:\n{path}")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Gabim PDF", str(exc))

    def _save_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Eksporto CSV", self._default_name("csv"), "CSV (*.csv)"
        )
        if not path:
            return
        try:
            export_csv(path, self._records)
            QMessageBox.information(self, "Ruajtur", f"CSV u ruajt:\n{path}")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Gabim CSV", str(exc))

    # -- lifecycle ------------------------------------------------------- #
    def _teardown_thread(self) -> None:
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait()
            self._thread = None
            self._worker = None

    def _cleanup_temp(self) -> None:
        if self._temp_dir and os.path.isdir(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)
        self._temp_dir = None

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._teardown_thread()
        self._cleanup_temp()
        super().closeEvent(event)


def run_app() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyleSheet(_DARK_QSS)
    icon_path = asset_path("logo_white.png")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    window = MainWindow()
    window.show()
    return app.exec()

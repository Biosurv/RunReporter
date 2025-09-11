from __future__ import annotations
import re
import json
from dataclasses import dataclass

from PyQt5.QtCore import QObject, QUrl, QTimer, pyqtSignal, QSettings, QDateTime, Qt
from PyQt5.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtWidgets import QMessageBox, QWidget
QT5 = True


@dataclass
class ReleaseInfo:
    tag: str
    html_url: str
    etag: str | None = None


def _normalise(v: str) -> str:
    v = re.sub(r"^v", "", v, flags=re.IGNORECASE)
    m = re.match(r"^\s*([0-9]+(?:\.[0-9]+){0,2})", v)
    return m.group(1) if m else v.strip()

def cmp_semver(a: str, b: str) -> int:
    pa = [int(x) for x in _normalise(a).split(".")]
    pb = [int(x) for x in _normalise(b).split(".")]
    for i in range(max(len(pa), len(pb))):
        na, nb = (pa[i] if i < len(pa) else 0), (pb[i] if i < len(pb) else 0)
        if na > nb:
            return 1
        if na < nb:
            return -1
    return 0

class UpdateChecker(QObject):
    updateAvailable = pyqtSignal(object)
    finished = pyqtSignal()

    def __init__(
            self,
            owner: str,
            repo: str,
            current_version: str,
            *,
            check_prereleases: bool = False,
            min_interval_minutes: int = 60*24,
            github_token: str | None = None,
            settings_org: str = "Biosurv International",
            settings_app: str = "RunReporter",
            parent: QObject | None = None,
    ):
        super().__init__(parent)
        self.owner = owner
        self.repo = repo
        self.current_version = current_version
        self.check_prereleases = check_prereleases
        self.min_interval_minutes = min_interval_minutes
        self.github_token = github_token

        self.nam = QNetworkAccessManager(self)
        self._reply: QNetworkReply | None = None

        self.settings = QSettings(settings_org, settings_app)
        self._timeout = QTimer(self)
        self._timeout.setSingleShot(True)
        self._timeout.timeout.connect(self._on_timeout)


    def check_on_startup(self, parent: QWidget | None = None, *, force: bool = False):
        def on_update(info: ReleaseInfo):
            self._show_popup(info, parent)
        
        self.updateAvailable.connect(on_update)
        self.check(force=force)

    def check(self, *, force: bool = False):
        if not force and not self._should_check_now():
            self.finished.emit()
            return

        if self._reply:
            return

        url = (
            f"https://api.github.com/repos/{self.owner}/{self.repo}/releases"
            f"{'' if self.check_prereleases else '/latest'}"
        )
        req = QNetworkRequest(QUrl(url))
        req.setRawHeader(b"Accept", b"application/vnd.github+json")
        req.setRawHeader(b"User-Agent", f"{self.repo}-updater".encode("utf-8"))

        etag_key = self._key("etag")
        etag = self.settings.value(etag_key, type=str)
        if etag:
            req.setRawHeader(b"If-None-Match", etag.encode("utf-8"))

        if self.github_token:
            req.setRawHeader(b"Authorization", f"Bearer {self.github_token}".encode("utf-8"))

        self._reply = self.nam.get(req)
        self._reply.finished.connect(self._on_finished)
        self._reply.errorOccurred.connect(lambda _e: self._cleanup())
        self._timeout.start(4500) # 4.5 second timeout for network issues


    def _on_timeout(self):
        if self._reply and self._reply.isRunning():
            self._reply.abort()


    def _cleanup(self):
        self._timeout.stop()
        if self._reply:
            self._reply.deleteLater()
            self._reply = None
        self.finished.emit()

    def _on_finished(self):
        self._timeout.stop()
        reply = self._reply
        self._reply = None
        if not reply:
            self.finished.emit()
            return

        status = reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
        
        self._touch_last_checked()

        
        if status == 304:
            self._cleanup()
            return

        if reply.error() != QNetworkReply.NetworkError.NoError:
            self._cleanup()
            return

        
        etag = bytes(reply.rawHeader(b"ETag")).decode("utf-8") or None
        if etag:
            self.settings.setValue(self._key("etag"), etag)

        try:
            data = json.loads(bytes(reply.readAll()).decode("utf-8"))
        except Exception:
            self._cleanup()
            return

        if self.check_prereleases:
            
            releases = [r for r in data if not r.get("draft")]
            if not releases:
                self._cleanup()
                return
            
            releases.sort(key=lambda r: r.get("created_at", ""), reverse=True)
            chosen = releases[0]
        else:
            
            chosen = data

        tag = chosen.get("tag_name", "")
        html_url = chosen.get("html_url", "")
        if not tag:
            self._cleanup()
            return

        latest = ReleaseInfo(tag=tag, html_url=html_url, etag=etag)

        if cmp_semver(latest.tag, self.current_version) > 0:
            self.settings.setValue(self._key("seen_version"), latest.tag)
            self.updateAvailable.emit(latest)

        self._cleanup()
    
    def _show_popup(self, info: ReleaseInfo, parent: QWidget | None):
        msg = QMessageBox(parent)
        msg.setIcon(QMessageBox.Icon.Information if not QT5 else QMessageBox.Information)
        msg.setWindowTitle("Update available")
        msg.setText(f"A new version is available: v{info.tag}")
        msg.setInformativeText(f"You are on v{self.current_version}. Would you like to open the download page?")
        open_btn = msg.addButton("Yes", QMessageBox.ButtonRole.AcceptRole)
        later_btn = msg.addButton("Later", QMessageBox.ButtonRole.RejectRole)
        msg.setDefaultButton(open_btn)
        msg.exec()

        if msg.clickedButton() == open_btn:
            QDesktopServices.openUrl(QUrl(info.html_url))

    def _key(self, suffix: str) -> str:
        return f"updater/{self.owner}/{self.repo}/{suffix}"
    
    def _should_check_now(self) -> bool:
        if self.min_interval_minutes <= 0:
            return True
        last = self.settings.value(self._key("last_checked"), type=QDateTime)
        if not isinstance(last, QDateTime) or not last.isValid():
            return True
        mins = last.secsTo(QDateTime.currentDateTime()) / 60.0
        return mins >= self.min_interval_minutes

    def _touch_last_checked(self):
        self.settings.setValue(self._key("last_checked"), QDateTime.currentDateTime())



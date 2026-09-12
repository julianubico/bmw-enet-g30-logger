"""DID scanner dialog: probe an ECU for supported DIDs, read-only.

The dialog opens its *own* TCP connection to the car (the dashboard keeps
its live connection untouched), runs did_scanner.DIDScanner in a worker
thread, and lets Julian export the JSON report or apply a positive result
to a registry sensor as candidate/unverified.

Only UDS 0x22 (read) and 0x2C (define/clear dynamic DID) are ever sent —
enforced by did_scanner.guard_service.  Nothing is written to the car.
"""

import queue
import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from . import did_scanner
from .did_scanner import DIDScanner, ScannerTransport, parse_candidates, \
    export_report, apply_discovery
from .sensors import get_sensors, get_vehicle_profile


class DIDScannerDialog(tk.Toplevel):
    def __init__(self, parent, ip, port, on_applied):
        super().__init__(parent)
        self._parent = parent
        self._ip = ip
        self._port = port
        self._on_applied = on_applied
        self.title("DID Scanner — read-only")
        self.geometry("760x560")
        self._stop_event = threading.Event()
        self._done_queue = queue.Queue()
        self._report = None
        self._results = []   # parallel to tree rows
        self._sock = None
        self._scan_thread = None

        try:
            from .ui_theme import BG, PANEL, TEXT, DIM, ACCENT, BTN_BG, \
                BTN_ACTIVE_BG, ENTRY_BG, BORDER, SMALL_FONT, WARNING_C
        except Exception:  # pragma: no cover - theme is always present in app
            BG = PANEL = "#1a1d24"; TEXT = "#e8eaf0"; DIM = "#8a8f9e"
            ACCENT = "#4d9fff"; BTN_BG = "#262a35"; BTN_ACTIVE_BG = "#313748"
            ENTRY_BG = "#10131a"; BORDER = "#2c3140"
            SMALL_FONT = ("Segoe UI", 8); WARNING_C = "#ffb020"
        self.configure(bg=BG)
        self._T = dict(BG=BG, PANEL=PANEL, TEXT=TEXT, DIM=DIM, ACCENT=ACCENT,
                       BTN_BG=BTN_BG, BTN_ACTIVE_BG=BTN_ACTIVE_BG,
                       ENTRY_BG=ENTRY_BG, BORDER=BORDER, WARNING_C=WARNING_C)

        tk.Label(self, text="READ-ONLY — UDS 0x22/0x2C only. Nothing is written to the car.",
                 bg=PANEL, fg=WARNING_C, font=("Segoe UI", 9, "bold"),
                 anchor="w").pack(fill="x", padx=10, pady=(10, 4))

        frm = tk.Frame(self, bg=BG); frm.pack(fill="x", padx=10, pady=4)
        tk.Label(frm, text="ECU (hex):", bg=BG, fg=TEXT,
                 font=SMALL_FONT).pack(side="left")
        self._ecu_var = tk.StringVar(value="0x18")
        tk.Entry(frm, textvariable=self._ecu_var, bg=ENTRY_BG, fg=TEXT,
                 relief="flat", width=8, font=("Courier New", 10),
                 highlightthickness=1, highlightcolor=ACCENT,
                 highlightbackground=BORDER).pack(side="left", padx=(6, 16))

        tk.Label(frm, text=f"Target: {ip}:{port}", bg=BG, fg=DIM,
                 font=SMALL_FONT).pack(side="left")

        tk.Label(self, text="Candidate DIDs (hex, comma/space separated; ranges like 1000-10FF allowed):",
                 bg=BG, fg=DIM, font=SMALL_FONT, anchor="w").pack(
                     fill="x", padx=10, pady=(6, 2))
        self._did_text = tk.Text(self, bg=ENTRY_BG, fg=TEXT, relief="flat",
                                 height=4, font=("Courier New", 10),
                                 highlightthickness=1, highlightcolor=ACCENT,
                                 highlightbackground=BORDER)
        self._did_text.pack(fill="x", padx=10)
        self._did_text.insert("1.0", "F300, F301")

        btn_row = tk.Frame(self, bg=BG); btn_row.pack(fill="x", padx=10, pady=8)
        _bk = dict(bg=BTN_BG, fg=TEXT, activebackground=BTN_ACTIVE_BG,
                   activeforeground=TEXT, font=("Segoe UI", 9, "bold"),
                   bd=0, padx=12, pady=6, cursor="hand2")
        self._scan_btn = tk.Button(btn_row, text="▶  SCAN",
                                   command=self._start_scan, **_bk)
        self._scan_btn.pack(side="left")
        self._stop_btn = tk.Button(btn_row, text="■  STOP",
                                   command=self._stop_scan, state="disabled", **_bk)
        self._stop_btn.pack(side="left", padx=(6, 0))
        self._export_btn = tk.Button(btn_row, text="💾 EXPORT JSON",
                                     command=self._export, state="disabled", **_bk)
        self._export_btn.pack(side="left", padx=(6, 0))
        self._apply_btn = tk.Button(btn_row, text="✓ APPLY TO SENSOR…",
                                    command=self._apply_selected, state="disabled", **_bk)
        self._apply_btn.pack(side="left", padx=(6, 0))

        self._status_var = tk.StringVar(value="Idle.")
        tk.Label(self, textvariable=self._status_var, bg=BG, fg=DIM,
                 font=SMALL_FONT, anchor="w").pack(fill="x", padx=10)

        cols = ("did", "size", "mode", "status", "nrc", "raw_min", "raw_max", "ms")
        self._tree = ttk.Treeview(self, columns=cols, show="headings", height=12)
        headers = {"did": "DID", "size": "Size", "mode": "Mode",
                   "status": "Status", "nrc": "NRC",
                   "raw_min": "Raw min", "raw_max": "raw max", "ms": "ms"}
        widths = {"did": 70, "size": 50, "mode": 80, "status": 90, "nrc": 60,
                  "raw_min": 80, "raw_max": 80, "ms": 60}
        for c in cols:
            self._tree.heading(c, text=headers[c])
            self._tree.column(c, width=widths[c], anchor="center")
        self._tree.pack(fill="both", expand=True, padx=10, pady=(4, 10))

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── scan control ──────────────────────────────────────
    def _start_scan(self):
        try:
            ecu_txt = self._ecu_var.get().strip()
            ecu = int(ecu_txt, 16) if ecu_txt.lower().startswith("0x") \
                else int(ecu_txt, 16)
            if not 0 <= ecu <= 0xFF:
                raise ValueError("ECU out of range")
            dids = parse_candidates(self._did_text.get("1.0", "end"))
        except ValueError as e:
            messagebox.showerror("Invalid input", str(e), parent=self)
            return
        self._stop_event.clear()
        self._report = None
        self._results = []
        for row in self._tree.get_children():
            self._tree.delete(row)
        self._scan_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._export_btn.configure(state="disabled")
        self._apply_btn.configure(state="disabled")
        self._status_var.set(
            f"Scanning {len(dids)} DID(s) on ECU 0x{ecu:02X} — 5 samples × sizes 1/2/4…")
        self._scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(self._ip, self._port, ecu, dids), daemon=True)
        self._scan_thread.start()
        self.after(200, self._poll_done)

    def _stop_scan(self):
        self._stop_event.set()
        self._status_var.set("Stopping… (clearing dynamic DID)")
        try:
            if self._sock:
                self._sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass

    def _scan_worker(self, ip, port, ecu, dids):
        report, err = None, None
        sock = None
        try:
            sock = socket.create_connection((ip, port), timeout=5)
            self._sock = sock
            transport = ScannerTransport(sock, stop_event=self._stop_event,
                                         timeout=2.0)
            report = DIDScanner(transport).scan(ecu, dids)
        except Exception as e:
            err = str(e)
        finally:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass
            self._sock = None
        self._done_queue.put((report, err))

    def _poll_done(self):
        try:
            report, err = self._done_queue.get_nowait()
        except queue.Empty:
            self.after(200, self._poll_done)
            return
        self._scan_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        if err:
            self._status_var.set(f"Scan failed: {err}")
            messagebox.showerror("Scan failed", err, parent=self)
            return
        self._report = report
        self._results = report["results"]
        for r in self._results:
            nrc = f"0x{r['nrc']:02X}" if r.get("nrc") is not None else "—"
            self._tree.insert("", "end", values=(
                r["did_hex"], r["size"], r["read_mode"], r["status"], nrc,
                r["raw_min"] if r["raw_min"] is not None else "—",
                r["raw_max"] if r["raw_max"] is not None else "—",
                r["timing_ms"]))
        stopped = " (stopped early)" if report.get("stopped") else ""
        self._status_var.set(
            f"Done: {len(self._results)} probe(s){stopped}. "
            "Compare positive raw values against ISTA before trusting them.")
        self._export_btn.configure(state="normal")
        self._apply_btn.configure(state="normal")

    # ── export / apply ────────────────────────────────────
    def _export(self):
        if not self._report:
            return
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=".json",
            filetypes=[("JSON report", "*.json")],
            initialfile=f"did_scan_{self._report['ecu_hex']}.json")
        if not path:
            return
        try:
            export_report(self._report, path)
        except Exception as e:
            messagebox.showerror("Export failed", str(e), parent=self)
            return
        self._status_var.set(f"Report saved: {path}")
        messagebox.showinfo("Exported", f"Scan report saved:\n{path}",
                            parent=self)

    def _selected_result(self):
        sel = self._tree.selection()
        if not sel or not self._results:
            return None
        idx = self._tree.index(sel[0])
        if 0 <= idx < len(self._results):
            return self._results[idx]
        return None

    def _apply_selected(self):
        result = self._selected_result()
        if result is None:
            messagebox.showinfo("Apply", "Select a scan result row first.",
                                parent=self)
            return
        if result.get("status") != "positive":
            messagebox.showwarning(
                "Apply",
                f"DID {result['did_hex']} did not return a positive response "
                f"(status: {result.get('status')}). Only positive results "
                "can be applied.", parent=self)
            return
        picker = _SensorPicker(self, result)
        self.wait_window(picker)
        if not picker.chosen:
            return
        sensor_id = picker.chosen
        try:
            updated = apply_discovery(sensor_id, self._report["ecu"],
                                      result, self._report["timestamp"])
        except Exception as e:
            messagebox.showerror("Apply failed", str(e), parent=self)
            return
        self._on_applied(sensor_id)
        messagebox.showinfo(
            "Applied",
            f"{updated['label']}: DID 0x{updated['did']:04X}, "
            f"{updated['size']}B, {updated['read_mode']} mode.\n\n"
            "Marked candidate / unverified, scale 1.0 — validate the "
            "meaning against ISTA live values before trusting it.",
            parent=self)

    def _on_close(self):
        self._stop_event.set()
        try:
            if self._sock:
                self._sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        self.destroy()


class _SensorPicker(tk.Toplevel):
    """Pick which registry sensor a discovered DID belongs to."""

    def __init__(self, parent, result):
        super().__init__(parent)
        self.chosen = None
        self.title(f"Apply {result['did_hex']} to sensor")
        self.geometry("460x420")
        self.configure(bg="#1a1d24")
        tk.Label(self,
                 text=f"DID {result['did_hex']} ({result['payload_length']}B, "
                      f"{result['read_mode']}) → which sensor?",
                 bg="#1a1d24", fg="#e8eaf0",
                 font=("Segoe UI", 10, "bold"), anchor="w").pack(
                     fill="x", padx=12, pady=(12, 4))
        tk.Label(self, text="Undiscovered placeholders are listed first.",
                 bg="#1a1d24", fg="#8a8f9e",
                 font=("Segoe UI", 8), anchor="w").pack(fill="x", padx=12)
        self._box = tk.Listbox(self, bg="#10131a", fg="#e8eaf0",
                               selectmode="single",
                               font=("Courier New", 10))
        self._box.pack(fill="both", expand=True, padx=12, pady=8)
        sensors = sorted(get_sensors(),
                         key=lambda s: (s.get("did") is not None,
                                        s["sensor_id"]))
        self._sensors = sensors
        for i, s in enumerate(sensors):
            did = f"0x{s['did']:04X}" if s.get("did") is not None else "—"
            conf = s.get("confidence", "?")
            self._box.insert("end", f"{s['label']}  [{did}]  ({conf})")
            if s.get("did") is None and self._box.curselection() == ():
                self._box.selection_set(i)
        row = tk.Frame(self, bg="#1a1d24"); row.pack(fill="x", padx=12, pady=10)
        tk.Button(row, text="Cancel", bg="#262a35", fg="#8a8f9e", bd=0,
                  padx=12, cursor="hand2", command=self.destroy).pack(
                      side="right")
        tk.Button(row, text="Apply", bg="#4d9fff", fg="white", bd=0, padx=16,
                  font=("Segoe UI", 9, "bold"), cursor="hand2",
                  command=self._ok).pack(side="right", padx=(0, 8))
        self.bind("<Escape>", lambda _e: self.destroy())

    def _ok(self):
        sel = self._box.curselection()
        if not sel:
            return
        self.chosen = self._sensors[sel[0]]["sensor_id"]
        self.destroy()

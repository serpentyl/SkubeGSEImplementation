import subprocess
import tkinter as tk
from tkinter import ttk
from pathlib import Path
import threading
from typing import Callable


def windows_to_wsl(path: Path) -> str:
    path = path.resolve()
    drive = path.drive.rstrip(":").lower()
    tail = path.as_posix().split(":", 1)[1]
    return f"/mnt/{drive}{tail}"


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("TC/GSE Demo Runner")
        self.geometry("900x650")

        self.project_dir = Path(__file__).resolve().parent
        self.project_dir_wsl = windows_to_wsl(self.project_dir)

        self.message_var = tk.StringVar(value="Testing Message")
        self.key_var = tk.StringVar(value="SkubeTradeshowDemoKey")
        self.encap_session_key = self.key_var.get()
        self.deencap_session_key = self.key_var.get()
        self.pending_rotation_key: str | None = None
        self.packet_counter = 0
        self.ack_bit3_var = tk.BooleanVar(value=False)
        self.ack_bit2_var = tk.BooleanVar(value=False)
        self.ack_bit1_var = tk.BooleanVar(value=False)
        self.ack_bit0_var = tk.BooleanVar(value=False)
        self.rotate_key_var = tk.BooleanVar(value=False)

        self.key_var.trace_add("write", self._sync_encap_key_from_field)

        self._build_ui()

    def _build_ui(self) -> None:
        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="TC Message").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.message_var, width=70).grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 10))

        ttk.Label(frm, text="HMAC Key").grid(row=2, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.key_var, width=70).grid(row=3, column=0, columnspan=3, sticky="ew", pady=(0, 12))

        ttk.Checkbutton(
            frm,
            text="Use this message as the next HMAC key",
            variable=self.rotate_key_var,
        ).grid(row=4, column=0, columnspan=3, sticky="w", pady=(0, 12))

        ttk.Label(frm, text="Acknowledgment Flags").grid(row=5, column=0, columnspan=3, pady=(0, 4))
        ack_row = ttk.Frame(frm)
        ack_row.grid(row=6, column=0, columnspan=3, pady=(0, 12))
        ttk.Checkbutton(ack_row, text="Packet Accepted", variable=self.ack_bit3_var).grid(row=0, column=0, padx=(0, 10), sticky="w")
        ttk.Checkbutton(ack_row, text="Task Started", variable=self.ack_bit2_var).grid(row=0, column=1, padx=(0, 10), sticky="w")
        ttk.Checkbutton(ack_row, text="Task In Progress", variable=self.ack_bit1_var).grid(row=0, column=2, padx=(0, 10), sticky="w")
        ttk.Checkbutton(ack_row, text="Task Completed", variable=self.ack_bit0_var).grid(row=0, column=3, sticky="w")

        run_row = ttk.Frame(frm)
        run_row.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(0, 4))
        run_row.columnconfigure(0, weight=1)
        run_row.columnconfigure(1, weight=1)
        run_row.columnconfigure(2, weight=1)
        ttk.Button(run_row, text="Build Binaries", command=self.build_binaries).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ttk.Button(run_row, text="Run Encapsulation", command=self.run_encap).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(run_row, text="Run De-encapsulation", command=self.run_deencap).grid(row=0, column=2, sticky="ew", padx=(4, 0))
        ttk.Button(frm, text="Run Full Pipeline", command=self.run_full_pipeline).grid(row=8, column=0, columnspan=3, sticky="ew", pady=(8, 12))

        self.output = tk.Text(frm, wrap="word")
        self.output.grid(row=9, column=0, columnspan=3, sticky="nsew")

        scrollbar = ttk.Scrollbar(frm, orient="vertical", command=self.output.yview)
        scrollbar.grid(row=9, column=3, sticky="ns")
        self.output.configure(yscrollcommand=scrollbar.set)

        frm.columnconfigure(0, weight=1)
        frm.columnconfigure(1, weight=1)
        frm.columnconfigure(2, weight=1)
        frm.rowconfigure(9, weight=1)

        self._log("Ready. Use Build Binaries first, then run encap/deencap.")

    def _log(self, text: str) -> None:
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    def _run_bash(self, script: str) -> tuple[int, str]:
        cmd = ["wsl.exe", "bash", "-lc", script]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        combined = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, combined

    def _sync_encap_key_from_field(self, *_args: object) -> None:
        # GUI HMAC field controls the sender key only. De-encap keeps its own
        # saved session key for validating previously generated packets.
        self.encap_session_key = self.key_var.get()

    def _run_async(
        self,
        title: str,
        script: str,
        success_message: str | None = None,
        on_success: Callable[[], None] | None = None,
        on_complete: Callable[[int, str], None] | None = None,
    ) -> None:
        def worker() -> None:
            self.after(0, lambda: self._log(f"\n=== {title} ==="))
            code, out = self._run_bash(script)
            if out.strip():
                self.after(0, lambda: self._log(out.rstrip()))
            if code != 0:
                self.after(0, lambda: self._log(f"Exit code: {code}"))
            else:
                if success_message is not None:
                    self.after(0, lambda: self._log(success_message))
                if on_success is not None:
                    self.after(0, on_success)

            if on_complete is not None:
                self.after(0, lambda: on_complete(code, out))

        threading.Thread(target=worker, daemon=True).start()

    def _next_message_counter(self) -> int:
        # TC secondary header field is 16-bit.
        self.packet_counter = (self.packet_counter + 1) & 0xFFFF
        return self.packet_counter

    def _current_ack_flags(self) -> int:
        ack_flags = 0
        if self.ack_bit3_var.get():
            ack_flags |= 0x8
        if self.ack_bit2_var.get():
            ack_flags |= 0x4
        if self.ack_bit1_var.get():
            ack_flags |= 0x2
        if self.ack_bit0_var.get():
            ack_flags |= 0x1
        return ack_flags

    def _rotation_candidate(self) -> str | None:
        if not self.rotate_key_var.get():
            return None
        return self.message_var.get()

    def _apply_rotation_after_encap(self, rotation_candidate: str | None) -> None:
        if rotation_candidate is None:
            return
        if rotation_candidate == "":
            self.pending_rotation_key = None
            self._log("HMAC rotation ignored: message is empty.")
            return
        self.pending_rotation_key = rotation_candidate
        self._log("HMAC rotation armed. Run de-encapsulation to apply it for future messages.")

    def _rotation_confirmed(self, output: str) -> bool:
        return "HMAC rotation applied for future packets" in output

    def _apply_rotation_after_deencap(self) -> None:
        if self.pending_rotation_key is None:
            return
        self.encap_session_key = self.pending_rotation_key
        self.deencap_session_key = self.pending_rotation_key
        self.pending_rotation_key = None
        self._log("HMAC rotation applied for future messages in this GUI session.")

    def _handle_deencap_complete(self, code: int, output: str) -> None:
        if self.pending_rotation_key is None:
            return
        if code == 0 and self._rotation_confirmed(output):
            self._apply_rotation_after_deencap()
            return

        self.pending_rotation_key = None
        self._log("HMAC rotation not confirmed. Keeping the previous HMAC session keys.")

    def _apply_rotation_after_full_pipeline(self, rotation_candidate: str | None) -> None:
        if rotation_candidate is None:
            self.pending_rotation_key = None
            return
        if rotation_candidate == "":
            self.pending_rotation_key = None
            self._log("HMAC rotation ignored: message is empty.")
            return
        self.encap_session_key = rotation_candidate
        self.deencap_session_key = rotation_candidate
        self.pending_rotation_key = None
        self._log("HMAC rotation applied for future messages in this GUI session.")

    def _handle_full_pipeline_complete(self, rotation_candidate: str | None,
                                       code: int, output: str) -> None:
        if rotation_candidate is None:
            return
        if code == 0 and self._rotation_confirmed(output):
            self._apply_rotation_after_full_pipeline(rotation_candidate)
            return
        self.pending_rotation_key = None
        self._log("HMAC rotation not confirmed in full pipeline output. Keys unchanged.")

    def _build_script(self) -> str:
        return (
            f"cd '{self.project_dir_wsl}' && "
            "gcc -std=c11 -Wall -Wextra -O2 -I. -I./GSE/libgse/src/common -I./GSE/libgse/src/encap "
            "./GSE/libgse/src/common/*.c ./GSE/libgse/src/encap/*.c "
            "./TCHeaderPack.c ./hmac_sha256/*.c ./GSEEncapForSkube.c -lpthread -o ./GSEEncapForSkube && "
            "gcc -std=c11 -Wall -Wextra -O2 -I. -I./GSE/libgse/src/common -I./GSE/libgse/src/deencap "
            "./GSE/libgse/src/common/*.c ./GSE/libgse/src/deencap/*.c "
            "./TCHeaderUnpack.c ./hmac_sha256/*.c ./GSEDeencapForSkube.c -lpthread -o ./GSEDeencapForSkube"
        )

    def _encap_script(self, message_counter: int, ack_flags: int) -> str:
        msg = self.message_var.get().replace("'", "'\"'\"'")
        key = self.encap_session_key.replace("'", "'\"'\"'")
        rotate = "1" if self.rotate_key_var.get() else "0"
        return (
            f"cd '{self.project_dir_wsl}' && "
            f"TC_MESSAGE='{msg}' TC_HMAC_KEY='{key}' TC_MESSAGE_COUNTER='{message_counter}' TC_ACK_FLAGS='{ack_flags}' TC_ROTATE_HMAC_KEY='{rotate}' ./GSEEncapForSkube"
        )

    def _deencap_script(self) -> str:
        key = self.deencap_session_key.replace("'", "'\"'\"'")
        return f"cd '{self.project_dir_wsl}' && TC_HMAC_KEY='{key}' ./GSEDeencapForSkube"

    def build_binaries(self) -> None:
        self._run_async("Build", self._build_script(), "Build Complete!")

    def run_encap(self) -> None:
        message_counter = self._next_message_counter()
        ack_flags = self._current_ack_flags()
        rotation_candidate = self._rotation_candidate()
        self._run_async(
            "Encapsulation",
            self._encap_script(message_counter, ack_flags),
            on_success=lambda: self._apply_rotation_after_encap(rotation_candidate),
        )

    def run_deencap(self) -> None:
        self._run_async(
            "De-encapsulation",
            self._deencap_script(),
            on_complete=self._handle_deencap_complete,
        )

    def run_full_pipeline(self) -> None:
        message_counter = self._next_message_counter()
        ack_flags = self._current_ack_flags()
        rotation_candidate = self._rotation_candidate()
        script = self._build_script() + " && " + self._encap_script(message_counter, ack_flags).split("&&", 1)[1] + " && ./GSEDeencapForSkube"
        script = script.rsplit("./GSEDeencapForSkube", 1)[0] + self._deencap_script().split("&&", 1)[1]
        self._run_async(
            "Full Pipeline",
            script,
            on_complete=lambda code, output: self._handle_full_pipeline_complete(
                rotation_candidate, code, output
            ),
        )


if __name__ == "__main__":
    app = App()
    app.mainloop()

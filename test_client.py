"""
RSU 사고 메시지 테스트 클라이언트 (GUI)
- 서버와 별도 실행
- 포트 20615로 64바이트 패킷 전송 후, 같은 연결에서 서버의 경보 ON 응답(64바이트) 수신
- 포트 20905에서 TCP 수신 대기 → 서버가 사고조치완료 시 경보 OFF 패킷 수신
"""

import customtkinter as ctk
import socket
import struct
import threading
import time
from typing import Any

# 서버와 동일한 패킷 형식 (빅엔디안, 64바이트)
PACKET_FORMAT = "> I H B B Q Q i i i H H Q 16s"
PACKET_SIZE = struct.calcsize(PACKET_FORMAT)
ACCIDENT_FLAG_OFFSET = 38  # Accident flag 2B 오프셋

# 서버 접속용 / 경보 OFF 수신 대기 포트 (서버가 이 포트로 접속해 경보 OFF 전송)
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 20615
RSU_ALARM_LISTEN_PORT = 20905


def build_packet(
    rsu_id: int,
    direction: int,
    lane: int,
    severity: int,
    acc_time: int,
    acc_id: int,
    lat_micro: int,
    lon_micro: int,
    alt_micro: int,
    distance: int,
    acc_flag: int,
    rsu_rx_time: int,
    token: bytes,
) -> bytes:
    """입력값을 64바이트 패킷으로 패킹."""
    if len(token) != 16:
        token = token[:16].ljust(16, b"\x00")
    return struct.pack(
        PACKET_FORMAT,
        rsu_id & 0xFFFFFFFF,
        direction & 0xFFFF,
        lane & 0xFF,
        severity & 0xFF,
        acc_time & 0xFFFFFFFFFFFFFFFF,
        acc_id & 0xFFFFFFFFFFFFFFFF,
        lat_micro,
        lon_micro,
        alt_micro,
        distance & 0xFFFF,
        acc_flag & 0xFFFF,
        rsu_rx_time & 0xFFFFFFFFFFFFFFFF,
        token,
    )


def parse_hex_token(s: str) -> bytes:
    """32자리 hex 문자열을 16바이트로. 빈 값/잘못된 값은 0으로 채움."""
    s = s.strip().replace(" ", "").replace("0x", "")
    if not s:
        return bytes(16)
    try:
        raw = bytes.fromhex(s)
        return raw[:16].ljust(16, b"\x00")
    except ValueError:
        return bytes(16)


class TestClientApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("RSU 테스트 클라이언트")
        self.geometry("480x620")
        self.minsize(400, 500)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        main = ctk.CTkScrollableFrame(self, fg_color="transparent")
        main.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        main.grid_columnconfigure(1, weight=1)

        self.entries: dict[str, ctk.CTkEntry] = {}
        row = 0

        # 호스트 / 포트
        ctk.CTkLabel(main, text="호스트").grid(row=row, column=0, sticky="w", pady=4, padx=(0, 12))
        self.entries["host"] = ctk.CTkEntry(main, placeholder_text=DEFAULT_HOST, width=280)
        self.entries["host"].insert(0, DEFAULT_HOST)
        self.entries["host"].grid(row=row, column=1, sticky="ew", pady=4)
        row += 1
        ctk.CTkLabel(main, text="포트").grid(row=row, column=0, sticky="w", pady=4, padx=(0, 12))
        self.entries["port"] = ctk.CTkEntry(main, placeholder_text=str(DEFAULT_PORT), width=120)
        self.entries["port"].insert(0, str(DEFAULT_PORT))
        self.entries["port"].grid(row=row, column=1, sticky="w", pady=4)
        row += 1

        # 구분
        ctk.CTkLabel(main, text="── 패킷 필드 ──", text_color="gray").grid(row=row, column=0, columnspan=2, sticky="w", pady=(12, 4))
        row += 1

        now_sec = int(time.time())
        now_ms = now_sec * 1000

        # 예시 값: 실행 시 모든 필드에 채워 둠 (그대로 전송해도 동작)
        fields = [
            ("신고 RSU ID (4B, hex)", "rsu_id", "0x1001"),
            ("Direction 0~360° (2B)", "direction", "90"),
            ("Lane 차선 (1B)", "lane", "1"),
            ("Severity 규모 (1B)", "severity", "2"),
            ("Accident Time (8B, 초 또는 ms)", "acc_time", str(now_sec)),
            ("Accident ID (8B, hex)", "acc_id", "0x1"),
            ("Latitude micro-degree (4B)", "lat_micro", "37566500"),
            ("Longitude micro-degree (4B)", "lon_micro", "126978000"),
            ("Altitude micro-degree (4B)", "alt_micro", "0"),
            ("distance (2B)", "distance", "100"),
            ("Accident Flag (2B, hex) ON=0x0000 OFF=0xFFFF", "acc_flag", "0x0000"),
            ("RSU RX Time (8B)", "rsu_rx_time", str(now_ms)),
            ("보안토큰 (16B, 32자 hex)", "token", "00000000000000000000000000000000"),
        ]
        for label_text, key, default in fields:
            ctk.CTkLabel(main, text=label_text).grid(row=row, column=0, sticky="w", pady=4, padx=(0, 12))
            e = ctk.CTkEntry(main, placeholder_text=default or "(비우면 0)", width=280)
            e.insert(0, default)
            e.grid(row=row, column=1, sticky="ew", pady=4)
            self.entries[key] = e
            row += 1

        main.grid_columnconfigure(1, weight=1)

        # 전송 버튼
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 16))
        btn_frame.grid_columnconfigure(0, weight=1)
        self.send_btn = ctk.CTkButton(btn_frame, text="한 번에 전송", command=self._send, height=40, font=ctk.CTkFont(size=14, weight="bold"))
        self.send_btn.grid(row=0, column=0, sticky="ew")
        self.result_label = ctk.CTkLabel(btn_frame, text="", text_color="gray")
        self.result_label.grid(row=1, column=0, sticky="w", pady=(8, 0))

        # 경보 OFF 수신 대기 (서버가 20905로 접속해 경보 OFF 전송)
        self._alarm_sock: socket.socket | None = None
        self._alarm_stop = threading.Event()
        self._alarm_status = ctk.CTkLabel(btn_frame, text=f"경보 OFF 수신 대기: 0.0.0.0:{RSU_ALARM_LISTEN_PORT}", text_color="gray")
        self._alarm_status.grid(row=2, column=0, sticky="w", pady=(8, 0))
        self._start_alarm_listener()
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _start_alarm_listener(self):
        """포트 20905에서 서버의 경보 OFF 패킷 수신 대기 (백그라운드 스레드)."""
        def run():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("", RSU_ALARM_LISTEN_PORT))
                sock.listen(5)
                sock.settimeout(1.0)
                self._alarm_sock = sock
                while not self._alarm_stop.is_set() and sock.fileno() != -1:
                    try:
                        conn, addr = sock.accept()
                    except (socket.timeout, OSError):
                        continue
                    try:
                        with conn:
                            data = conn.recv(PACKET_SIZE)
                            if len(data) == PACKET_SIZE:
                                acc_flag = struct.unpack_from(">H", data, ACCIDENT_FLAG_OFFSET)[0]
                                msg = "경보 OFF" if acc_flag == 0xFFFF else "경보 ON"
                                self.after(0, lambda m=msg, a=addr: self._on_alarm_received(m, a))
                    except (ConnectionResetError, BrokenPipeError, OSError):
                        pass
            except OSError:
                pass
            finally:
                if self._alarm_sock:
                    try:
                        self._alarm_sock.close()
                    except OSError:
                        pass
                    self._alarm_sock = None

        t = threading.Thread(target=run, daemon=True)
        t.start()

    def _on_alarm_received(self, msg: str, addr: tuple):
        """경보 OFF(또는 ON) 수신 시 GUI 업데이트."""
        self._alarm_status.configure(
            text=f"마지막 수신: {msg} (from {addr[0]}:{addr[1]})",
            text_color=("green", "lime"),
        )

    def _on_closing(self):
        self._alarm_stop.set()
        if self._alarm_sock:
            try:
                self._alarm_sock.close()
            except OSError:
                pass
            self._alarm_sock = None
        self.destroy()

    def _get(self, key: str, default: Any = 0) -> str:
        e = self.entries.get(key)
        return (e.get() or "").strip() if e else str(default)

    def _parse_int_hex(self, s: str, default: str = "0") -> int:
        """HEX(0x 접두사) 또는 10진 문자열을 int로. 빈 문자열은 default 사용."""
        raw = (s or default).strip()
        return int(raw, 0)

    def _send(self):
        host = self._get("host") or DEFAULT_HOST
        try:
            port = int(self._get("port") or DEFAULT_PORT)
        except ValueError:
            self.result_label.configure(text="포트는 숫자로 입력하세요.", text_color=("red", "salmon"))
            return
        try:
            rsu_id = self._parse_int_hex(self._get("rsu_id"), "0x1001")
            direction = int(self._get("direction", "0"))
            lane = int(self._get("lane", "0"))
            severity = int(self._get("severity", "0"))
            acc_time = int(self._get("acc_time", "0"))
            acc_id = self._parse_int_hex(self._get("acc_id"), "0x1")
            lat_micro = int(self._get("lat_micro", "0"))
            lon_micro = int(self._get("lon_micro", "0"))
            alt_micro = int(self._get("alt_micro", "0"))
            distance = int(self._get("distance", "0"))
            acc_flag = self._parse_int_hex(self._get("acc_flag"), "0x0000")
            rsu_rx_time = int(self._get("rsu_rx_time", "0"))
            token = parse_hex_token(self._get("token"))
        except ValueError as e:
            self.result_label.configure(text=f"숫자 입력 오류: {e}", text_color=("red", "salmon"))
            return

        packet = build_packet(
            rsu_id=rsu_id,
            direction=direction,
            lane=lane,
            severity=severity,
            acc_time=acc_time,
            acc_id=acc_id,
            lat_micro=lat_micro,
            lon_micro=lon_micro,
            alt_micro=alt_micro,
            distance=distance,
            acc_flag=acc_flag,
            rsu_rx_time=rsu_rx_time,
            token=token,
        )
        if len(packet) != PACKET_SIZE:
            self.result_label.configure(text=f"패킷 크기 오류: {len(packet)}", text_color=("red", "salmon"))
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect((host, port))
                sock.sendall(packet)
                # 같은 연결에서 서버의 경보 ON 응답(64바이트) 수신
                reply = sock.recv(PACKET_SIZE)
            if len(reply) == PACKET_SIZE:
                self.result_label.configure(
                    text=f"전송 완료 + 경보 ON 응답 수신: {host}:{port} ({PACKET_SIZE} bytes)",
                    text_color=("green", "lime"),
                )
            else:
                self.result_label.configure(
                    text=f"전송 완료 (응답 {len(reply)} bytes, 64 예상)",
                    text_color=("orange", "orange"),
                )
        except (socket.error, OSError) as e:
            self.result_label.configure(text=f"전송 실패: {e}", text_color=("red", "salmon"))


def main():
    app = TestClientApp()
    app.mainloop()


if __name__ == "__main__":
    main()

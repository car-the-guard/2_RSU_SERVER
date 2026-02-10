import customtkinter as ctk
import logging
import socket
import struct
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

# 경보 송수신 디버깅용 (Wireshark에서 패킷 확인 시 로그로 전송 여부 확인 가능)
_log = logging.getLogger(__name__)

# 수신 대기 포트
RSU_PORT = 20615
# RSU(클라이언트)가 경보 OFF 수신 대기 포트 — 서버가 사고조치완료 시 이 포트로 접속해 전송
RSU_ALARM_PORT = 20905

# 패킷 레이아웃 (빅엔디안, 총 64바이트)
# 대문자 : unsigned, 소문자: signed 또는 문자열
#  I : int32, H(Halfword) : int16, B(Byte인 듯) : int8, Q(Quadword) : int64, s : 문자열
# 구성
# RSU_ID 4B, Direction 2B, Lane 1B, Severity 1B,
# Accident Time 8B, Accident ID 8B, Lat 4B, Lon 4B, Alt 4B,
# distance 2B, Accident Flag 2B, RSU RX Time 8B, 보안토큰 16B
PACKET_FORMAT = "> I H B B Q Q i i i H H Q 16s"
PACKET_SIZE = struct.calcsize(PACKET_FORMAT)  # 64

# 응답 패킷에서 Accident flag 오프셋 (RSU_ID 4 + Direction 2 + Lane 1 + Severity 1 + Accident Time 8 + Accident ID 8 + Lat 4 + Lon 4 + Alt 4 + distance 2 = 38)
ACCIDENT_FLAG_OFFSET = 38

# 사고정보의 파싱
@dataclass
class AccidentInfo:
    accident_id: str
    gps: str
    occurred_at: str
    rsu_id: str
    direction: int | None = None   # 0~360°
    lane: int | None = None       # 차선
    severity: int | None = None    # 규모
    distance: int | None = None   # RSU~사고 거리
    altitude: int | None = None   # 고도 (micro-degree 또는 단위 미정)
    alarm_on: bool | None = None  # True=경보 ON(0x0000), False=OFF(0xFFFF)
    sender_ip: str | None = None   # 패킷을 보낸 RSU의 IP
    sender_port: int | None = None # 패킷을 보낸 RSU의 포트
    raw_packet: bytes | None = None  # 원본 64바이트, RSU 경보 ON/OFF 응답 시 재사용


def parse_rsu_packet(data: bytes) -> AccidentInfo | None:
    """RSU 사고 패킷 64바이트 파싱. Returns AccidentInfo or None if invalid."""
    if len(data) != PACKET_SIZE:
        return None
    try:
        (
            rsu_id,
            direction,
            lane,
            severity,
            acc_time_raw,
            acc_id_raw,
            lat_micro,
            lon_micro,
            alt_micro,
            distance,
            acc_flag,
            _rsu_rx_time,
            _token,
        ) = struct.unpack(PACKET_FORMAT, data)
    except struct.error:
        return None
    rsu_id_str = str(rsu_id)
    acc_id_str = f"0x{acc_id_raw:016X}"
    lat_deg = lat_micro / 1_000_000.0
    lon_deg = lon_micro / 1_000_000.0
    gps_str = f"{lat_deg:.6f}° N, {lon_deg:.6f}° E"
    try:
        # 만약 이게 10^12 이상이라면 밀리초 단위라고 생각하고 나누기
        if acc_time_raw > 1e12:
            acc_time_sec = acc_time_raw / 1000.0
        # 아니라면 초 단위라고 생각하고 그대로 사용
        else:
            acc_time_sec = float(acc_time_raw)
        occurred_at = datetime.utcfromtimestamp(acc_time_sec).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError):
        # 단위 변환에 실패한 경우에는 그냥 그대로 두기
        occurred_at = str(acc_time_raw)
    
    alarm_on = acc_flag == 0x0000 if acc_flag in (0x0000, 0xFFFF) else None
    
    return AccidentInfo(
        accident_id=acc_id_str,
        gps=gps_str,
        occurred_at=occurred_at,
        rsu_id=rsu_id_str,
        direction=int(direction),
        lane=int(lane),
        severity=int(severity),
        distance=int(distance),
        altitude=int(alt_micro),
        alarm_on=alarm_on,
    )


def build_rsu_response_packet(raw_packet: bytes, alarm_on: bool) -> bytes:
    """원본 64바이트 패킷을 복사한 뒤 Accident flag만 설정하여 RSU 경보 ON/OFF 응답 패킷 생성."""
    if len(raw_packet) != PACKET_SIZE:
        return b""
    packet = bytearray(raw_packet)
    packet[ACCIDENT_FLAG_OFFSET : ACCIDENT_FLAG_OFFSET + 2] = struct.pack(">H", 0x0000 if alarm_on else 0xFFFF)
    return bytes(packet)


def send_rsu_alarm_to_peer(peer_ip: str, peer_port: int, raw_packet: bytes, alarm_on: bool) -> None:
    """RSU(peer_ip:peer_port)에게 경보 ON/OFF 패킷을 TCP로 전송. (사고조치완료 시 경보 OFF용)."""
    response = build_rsu_response_packet(raw_packet, alarm_on=alarm_on)
    if not response:
        return
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3.0)
            s.connect((peer_ip, peer_port))
            s.send(response)
        _log.info("RSU 경보 %s 전송 성공: %s:%s", "ON" if alarm_on else "OFF", peer_ip, peer_port)
    except (OSError, socket.error) as e:
        _log.warning("RSU 경보 %s 전송 실패 %s:%s: %s", "ON" if alarm_on else "OFF", peer_ip, peer_port, e)


class SecurityLayer:
    """수신 패킷에 대한 보안 검사 레이어. 통과 시에만 파싱 후 RSU에 경보 ON 응답 전송, on_accident 호출."""

    def __init__(self, on_accident: Callable[[AccidentInfo], None]):
        self.on_accident = on_accident

    def _verify(self, data: bytes) -> bool:
        """보안 검사. True면 통과, False면 폐기. 이후 보안 정책에 맞춰 구현."""
        # TODO: 토큰 검증, 서명 검증, RSU 화이트리스트 등
        return True

    def process(self, data: bytes, addr: tuple[str, int], conn: socket.socket) -> None:
        """패킷(bytes) 수신 시 호출. 검사 통과 시 파싱 후 RSU에 경보 ON 응답 전송, on_accident 호출."""
        if len(data) != PACKET_SIZE:
            return
        if not self._verify(data):
            return
        parsed = parse_rsu_packet(data)
        if parsed:
            parsed.sender_ip = addr[0]
            parsed.sender_port = addr[1]
            parsed.raw_packet = data
            try:
                response = build_rsu_response_packet(data, alarm_on=True)
                if response:
                    conn.send(response)
                    _log.info("RSU 경보 ON 응답 전송(같은 연결): %s:%s", addr[0], addr[1])
            except OSError as e:
                _log.warning("RSU 경보 ON 응답 전송 실패 %s:%s: %s", addr[0], addr[1], e)
            self.on_accident(parsed)


class RSUReceiver:
    """포트 20615에서 TCP로 RSU 패킷 수신 후, 바이트·송신자 주소·연결을 콜백에 전달."""

    def __init__(self, port: int, on_packet: Callable[[bytes, tuple[str, int], socket.socket], None]):
        self.port = port
        self.on_packet = on_packet
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> bool:
        if self._thread and self._thread.is_alive():
            return False
        self._stop.clear()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind(("", self.port))
            self._sock.listen(5)
            self._sock.settimeout(1.0)
        except OSError:
            self._sock.close()
            self._sock = None
            return False
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _accept_loop(self):
        while not self._stop.is_set() and self._sock:
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                peer = conn.getpeername()
                with conn:
                    buf = b""
                    while not self._stop.is_set():
                        data = conn.recv(4096)
                        if not data:
                            break
                        buf += data
                        while len(buf) >= PACKET_SIZE:
                            packet, buf = buf[:PACKET_SIZE], buf[PACKET_SIZE:]
                            self.on_packet(packet, peer, conn)
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass


# 테마 설정 (선택)
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# 나침반 방향 (0~360° → N, NE, E, SE, S, SW, W, NW)
_COMPASS = ("N", "NE", "E", "SE", "S", "SW", "W", "NW")


def _degree_to_compass(degree: int) -> str:
    idx = int((degree % 360 + 22.5) // 45) % 8
    return _COMPASS[idx]


class AccidentCard(ctk.CTkFrame):
    """한 건의 사고 정보를 보여주는 둥근 직사각형 카드."""

    def __init__(
        self,
        master,
        accident_id: str,
        gps: str,
        occurred_at: str,
        rsu_id: str,
        *,
        direction: int | None = None,
        lane: int | None = None,
        severity: int | None = None,
        distance: int | None = None,
        altitude: int | None = None,
        alarm_on: bool | None = None,
        sender_ip: str | None = None,
        sender_port: int | None = None,
        raw_packet: bytes | None = None,
        **kwargs,
    ):
        super().__init__(master, corner_radius=12, fg_color=("gray85", "gray20"), **kwargs)
        self.accident_id = accident_id
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        self.raw_packet = raw_packet
        self.on_clear_callback = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0)

        info_frame = ctk.CTkFrame(self, fg_color="transparent")
        info_frame.grid(row=0, column=0, sticky="nsew", padx=(16, 8), pady=(12, 12))
        info_frame.grid_columnconfigure(0, weight=1)
        info_frame.grid_columnconfigure(1, weight=1)

        row = 0
        label_pady = (1, 1)
        ctk.CTkLabel(info_frame, text=f"사고 ID: {accident_id}", anchor="w", font=ctk.CTkFont(weight="bold")).grid(row=row, column=0, columnspan=2, sticky="w", pady=label_pady)
        row += 1
        ctk.CTkLabel(info_frame, text=f"GPS: {gps}", anchor="w").grid(row=row, column=0, columnspan=2, sticky="w", pady=label_pady)
        row += 1
        ctk.CTkLabel(info_frame, text=f"발생 시각: {occurred_at}", anchor="w").grid(row=row, column=0, columnspan=2, sticky="w", pady=label_pady)
        row += 1
        ctk.CTkLabel(info_frame, text=f"신고 RSU ID: {rsu_id}", anchor="w").grid(row=row, column=0, columnspan=2, sticky="w", pady=label_pady)
        row += 1
        # 1행: 사고차량 주행방향(나침반) | 사고차량 주행차선 ...차선
        if direction is not None or lane is not None:
            if direction is not None:
                compass = _degree_to_compass(direction)
                ctk.CTkLabel(info_frame, text=f"사고차량 주행방향: {compass} ({direction}°)", anchor="w").grid(row=row, column=0, sticky="w", pady=label_pady)
            if lane is not None:
                ctk.CTkLabel(info_frame, text=f"사고차량 주행차선: {lane}차선", anchor="w").grid(row=row, column=1, sticky="w", pady=label_pady)
            row += 1
        # 2행: 사고유형(1:급정거/2:충돌사고/3:차량 차선 이탈) | RSU와의 직선거리 ...m
        if severity is not None or distance is not None:
            _severity_text = {1: "급정거", 2: "충돌사고", 3: "차량 차선 이탈"}.get(severity, str(severity)) if severity is not None else ""
            if severity is not None:
                ctk.CTkLabel(info_frame, text=f"사고유형: {_severity_text}", anchor="w").grid(row=row, column=0, sticky="w", pady=label_pady)
            if distance is not None:
                ctk.CTkLabel(info_frame, text=f"RSU와의 직선거리: {distance}m", anchor="w").grid(row=row, column=1, sticky="w", pady=label_pady)
            row += 1

        right_frame = ctk.CTkFrame(self, fg_color="transparent")
        right_frame.grid(row=0, column=1, sticky="ns", padx=(8, 12), pady=(12, 12))
        right_frame.grid_rowconfigure(0, weight=0)
        right_frame.grid_rowconfigure(1, weight=0)

        status_text = "경보 ON" if alarm_on is True else ("경보 OFF" if alarm_on is False else "경보 중")  # 기본: 경보 중
        status_color = ("coral", "coral") if alarm_on is not False else ("gray50", "gray50")
        self.status_label = ctk.CTkLabel(right_frame, text=status_text, text_color=status_color)
        self.status_label.grid(row=0, column=0, pady=(0, 8))

        self.clear_btn = ctk.CTkButton(
            right_frame,
            text="사고조치완료",
            command=self._on_clear,
            width=120,
            fg_color=("gray75", "gray30"),
        )
        self.clear_btn.grid(row=1, column=0)

    def _on_clear(self):
        if self.on_clear_callback:
            self.on_clear_callback(self)
        else:
            self._animate_out()

    def _animate_out(self):
        """슉 하고 줄어들며 사라지는 애니메이션 후 제거."""
        self.clear_btn.configure(state="disabled")
        start_h = self.winfo_height()
        step = max(4, start_h // 8)
        delay_ms = 15

        def step_collapse(current_h):
            if current_h <= 0:
                self.destroy()
                return
            self.configure(height=current_h)
            self.after(delay_ms, lambda: step_collapse(current_h - step))

        self.after(0, lambda: step_collapse(start_h))

    def set_clear_callback(self, callback):
        self.on_clear_callback = callback


class MainApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("RSU 사고 정보 관리")
        self.geometry("960x600")
        self.minsize(640, 400)

        self.grid_columnconfigure(0, weight=2)  # 왼쪽 2/3
        self.grid_columnconfigure(1, weight=1)  # 오른쪽 1/3
        self.grid_rowconfigure(0, weight=1)

        # ----- 왼쪽: 사고 목록 (2/3) -----
        self.accident_container = ctk.CTkScrollableFrame(
            self,
            fg_color=("gray90", "gray13"),
            label_text="사고 정보",
            label_font=ctk.CTkFont(size=16, weight="bold"),
        )
        self.accident_container.grid(row=0, column=0, sticky="nsew", padx=(10, 5), pady=10)
        self.accident_container.grid_columnconfigure(0, weight=1)
        self._card_wrappers: list[ctk.CTkFrame] = []  # 높이 애니메이션용 래퍼

        # ----- 오른쪽: 메뉴 (1/3) -----
        self.menu_frame = ctk.CTkFrame(self, fg_color=("gray85", "gray17"), corner_radius=10)
        self.menu_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 10), pady=10)
        self.menu_frame.grid_columnconfigure(0, weight=1)
        self.menu_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(self.menu_frame, text="메뉴", font=ctk.CTkFont(size=18, weight="bold")).grid(row=0, column=0, pady=(20, 10), sticky="ew")

        menu_inner = ctk.CTkFrame(self.menu_frame, fg_color="transparent")
        menu_inner.grid(row=1, column=0, sticky="nsew", padx=16, pady=8)
        menu_inner.grid_columnconfigure(0, weight=1)

        ctk.CTkButton(menu_inner, text="샘플 사고 추가", command=self._add_sample_accident, height=36).grid(row=0, column=0, pady=6, sticky="ew")

        self._server_status = ctk.CTkLabel(menu_inner, text="", text_color="gray")
        self._server_status.grid(row=1, column=0, pady=8, sticky="w")
        self._receiver: RSUReceiver | None = None
        self._start_rsu_server()

        # 샘플 데이터 몇 개로 시작
        self._add_sample_accident()
        self._add_sample_accident()

        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _on_rsu_accident(self, info: AccidentInfo):
        """RSU 스레드에서 호출 → 메인 스레드에서 카드 추가."""
        self.after(0, lambda: self.add_accident(
            info.accident_id, info.gps, info.occurred_at, info.rsu_id,
            direction=info.direction, lane=info.lane, severity=info.severity,
            distance=info.distance, altitude=info.altitude, alarm_on=info.alarm_on,
            sender_ip=info.sender_ip, sender_port=info.sender_port, raw_packet=info.raw_packet,
        ))

    def _start_rsu_server(self):
        security = SecurityLayer(self._on_rsu_accident)
        self._receiver = RSUReceiver(RSU_PORT, security.process)
        if self._receiver.start():
            self._server_status.configure(text=f"수신 대기 중 0.0.0.0:{RSU_PORT}", text_color=("green", "lime"))
        else:
            self._server_status.configure(text=f"포트 {RSU_PORT} 열기 실패", text_color=("red", "salmon"))

    def _on_closing(self):
        if self._receiver:
            self._receiver.stop()
        self.destroy()

    def _add_sample_accident(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        n = len(self._card_wrappers)
        self.add_accident(
            accident_id=f"0x{n + 1:016X}",
            gps="37.566500° N, 126.978000° E",
            occurred_at=now,
            rsu_id=f"0x{0x1001 + n:X}",
            direction=90,
            lane=1,
            severity=2,
            distance=100,
            alarm_on=None,
        )

    def add_accident(
        self,
        accident_id: str,
        gps: str,
        occurred_at: str,
        rsu_id: str,
        *,
        direction: int | None = None,
        lane: int | None = None,
        severity: int | None = None,
        distance: int | None = None,
        altitude: int | None = None,
        alarm_on: bool | None = None,
        sender_ip: str | None = None,
        sender_port: int | None = None,
        raw_packet: bytes | None = None,
    ):
        """사고 정보 한 건을 목록 위쪽에 추가. RSU 패킷 추가 필드는 키워드 인자로. 컨텐츠에 따라 카드 높이가 반응형으로 늘어남."""
        wrapper = ctk.CTkFrame(self.accident_container, fg_color="transparent")
        wrapper.grid_propagate(True)
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(0, weight=0)

        card = AccidentCard(
            wrapper,
            accident_id=accident_id,
            gps=gps,
            occurred_at=occurred_at,
            rsu_id=rsu_id,
            direction=direction,
            lane=lane,
            severity=severity,
            distance=distance,
            altitude=altitude,
            alarm_on=alarm_on,
            sender_ip=sender_ip,
            sender_port=sender_port,
            raw_packet=raw_packet,
        )
        card.grid(row=0, column=0, sticky="ew", padx=6, pady=6)
        card.set_clear_callback(self._on_card_clear)

        self._card_wrappers.append(wrapper)
        wrapper.grid(row=len(self._card_wrappers) - 1, column=0, sticky="ew", padx=(0, 4), pady=(6, 8))

    def _on_card_clear(self, card: AccidentCard):
        """카드 해제 시 RSU에 경보 OFF 전송(송신자 정보 있을 때), 래퍼를 애니메이션하고 제거."""
        if card.sender_ip and card.raw_packet:
            send_rsu_alarm_to_peer(card.sender_ip, RSU_ALARM_PORT, card.raw_packet, alarm_on=False)
        for i, w in enumerate(self._card_wrappers):
            for child in w.winfo_children():
                if child == card:
                    # 카드가 아닌 래퍼를 애니메이션해야 나머지가 위로 당겨짐
                    wrapper = w
                    self._card_wrappers.remove(wrapper)
                    self._animate_and_remove_wrapper(wrapper)
                    return

    def _animate_and_remove_wrapper(self, wrapper: ctk.CTkFrame):
        """래퍼 높이를 0으로 줄인 뒤 제거하고, 이후 row 인덱스 재정렬."""
        self.update_idletasks()
        start_h = wrapper.winfo_height()
        if start_h <= 0:
            start_h = 100
        wrapper.grid_propagate(False)
        wrapper.configure(height=start_h)
        step = max(4, start_h // 8)
        delay_ms = 15

        def step_collapse(current_h):
            if current_h <= 0:
                wrapper.destroy()
                self._reflow_cards()
                return
            wrapper.configure(height=current_h)
            wrapper.after(delay_ms, lambda: step_collapse(current_h - step))

        wrapper.after(0, lambda: step_collapse(start_h))

    def _reflow_cards(self):
        """남은 카드들의 grid row를 다시 0,1,2,... 로 정렬."""
        for i, w in enumerate(self._card_wrappers):
            if w.winfo_exists():
                w.grid(row=i, column=0, sticky="ew", padx=(0, 4), pady=(6, 8))


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    app = MainApp()
    app.mainloop()


if __name__ == "__main__":
    main()

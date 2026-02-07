"""
RSU 사고 정보 관리 GUI
- 왼쪽 2/3: 사고 정보 카드 목록 (세로 스크롤, 위쪽 정렬)
- 오른쪽 1/3: 메뉴/조작 영역
- 사고 카드: 둥근 직사각형, 해제 시 애니메이션으로 제거
"""

import customtkinter as ctk
from datetime import datetime

# 테마 설정 (선택)
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class AccidentCard(ctk.CTkFrame):
    """한 건의 사고 정보를 보여주는 둥근 직사각형 카드."""

    def __init__(self, master, accident_id: str, gps: str, occurred_at: str, rsu_id: str, **kwargs):
        super().__init__(master, corner_radius=12, fg_color=("gray85", "gray20"), **kwargs)
        self.accident_id = accident_id
        self.on_clear_callback = None  # 해제 시 호출할 콜백

        # 카드 내부: 왼쪽 정보 영역 + 오른쪽 상태/버튼
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0)

        # 왼쪽: 사고 정보 (세로 배치)
        info_frame = ctk.CTkFrame(self, fg_color="transparent")
        info_frame.grid(row=0, column=0, sticky="nsew", padx=(16, 8), pady=12)
        info_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(info_frame, text=f"사고 ID: {accident_id}", anchor="w", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(info_frame, text=f"GPS: {gps}", anchor="w").grid(row=1, column=0, sticky="w")
        ctk.CTkLabel(info_frame, text=f"발생 시각: {occurred_at}", anchor="w").grid(row=2, column=0, sticky="w")
        ctk.CTkLabel(info_frame, text=f"RSU ID: {rsu_id}", anchor="w").grid(row=3, column=0, sticky="w")

        # 오른쪽: 상태 텍스트 + 해제 버튼 (세로)
        right_frame = ctk.CTkFrame(self, fg_color="transparent")
        right_frame.grid(row=0, column=1, sticky="ns", padx=(8, 12), pady=12)
        right_frame.grid_rowconfigure(0, weight=0)
        right_frame.grid_rowconfigure(1, weight=0)

        self.status_label = ctk.CTkLabel(right_frame, text="경보 중", text_color=("coral", "coral"))
        self.status_label.grid(row=0, column=0, pady=(0, 8))

        self.clear_btn = ctk.CTkButton(
            right_frame,
            text="사고 경보 해제",
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
        ctk.CTkLabel(menu_inner, text="(RSU 연동 시 여기서 수신)", text_color="gray").grid(row=1, column=0, pady=4)

        # 샘플 데이터 몇 개로 시작
        self._add_sample_accident()
        self._add_sample_accident()

    def _add_sample_accident(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.add_accident(
            accident_id=f"A-{datetime.now().strftime('%H%M%S')}-{len(self._card_wrappers)}",
            gps="37.5665° N, 126.9780° E",
            occurred_at=now,
            rsu_id=f"RSU-{1000 + len(self._card_wrappers)}",
        )

    def add_accident(self, accident_id: str, gps: str, occurred_at: str, rsu_id: str):
        """사고 정보 한 건을 목록 위쪽에 추가."""
        # 애니메이션 시 높이를 줄일 래퍼 사용 (높이 고정으로 애니메이션 안정화)
        CARD_ROW_HEIGHT = 108
        wrapper = ctk.CTkFrame(self.accident_container, fg_color="transparent", height=CARD_ROW_HEIGHT)
        wrapper.grid_propagate(False)
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(0, weight=0)

        card = AccidentCard(
            wrapper,
            accident_id=accident_id,
            gps=gps,
            occurred_at=occurred_at,
            rsu_id=rsu_id,
            height=92,
        )
        card.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        card.set_clear_callback(self._on_card_clear)

        self._card_wrappers.append(wrapper)
        # 스크롤 영역에서 위쪽에 붙이기: 새 위젯을 row=0에 넣고 기존 것들을 아래로 밀기
        # 대신 단순히 append하고 grid(row=len-1) 하면 자연스럽게 위에서 아래로 쌓임
        wrapper.grid(row=len(self._card_wrappers) - 1, column=0, sticky="ew", pady=(0, 0))

    def _on_card_clear(self, card: AccidentCard):
        """카드 해제 시 래퍼를 애니메이션하고 제거."""
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
        start_h = wrapper.cget("height") or wrapper.winfo_height()
        if start_h <= 0:
            start_h = 108
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
                w.grid(row=i, column=0, sticky="ew", pady=(0, 0))


def main():
    app = MainApp()
    app.mainloop()


if __name__ == "__main__":
    main()

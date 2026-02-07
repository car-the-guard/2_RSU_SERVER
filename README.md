# 2_RSU_SERVER

RSU 사고 정보 관리 GUI (Python)

## 환경

- **Python**: 3.10 (이미 설치됨)
- **가상환경**: `venv` (프로젝트 폴더에 생성됨)

## 패키지

- **customtkinter** (>=5.2.0): GUI
- **socket, asyncio**: 표준 라이브러리 (별도 설치 없음)

## 사용 방법

### 가상환경 활성화 후 실행

PowerShell에서 "스크립트를 실행할 수 없습니다" 오류가 나면, **한 번만** 다음을 실행한 뒤 사용하세요.

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

이후:

```powershell
cd c:\workspace\2_RSU_SERVER
.\venv\Scripts\Activate.ps1
python server.py
```

패키지 추가 설치:

```powershell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

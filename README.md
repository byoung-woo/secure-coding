# secure-coding

# 중고거래 플랫폼 (Tiny Second-hand Shopping Platform)

간단한 Flask 기반 중고거래 웹 애플리케이션입니다.  
회원가입·로그인, 상품 등록·조회, 채팅, 신고·차단, 관리자 페이지, 내 상품 관리, 유저 간 송금·잔액 관리 등 주요 기능을 제공합니다.

---

## 목차

1. [요구사항](#요구사항)  
2. [환경 설정](#환경-설정)  
3. [데이터베이스 초기화](#데이터베이스-초기화)  
4. [실행 방법](#실행-방법)  
5. [주요 경로 및 사용법](#주요-경로-및-사용법)  
6. [기술 스택](#기술-스택)  


---

## 요구사항

- Python 3.9 이상  
- conda (Miniconda / Anaconda)  
- WSL / Ubuntu / macOS / Windows에서 실행 가능  

---

## 환경 설정

1. 소스 코드 클론
   ```bash
   git clone https://github.com/<YourUserName>/secure-coding.git
   cd secure-coding
2. Conda 환경 생성

   ```bash
    # enviroments.yaml 파일이 있는 디렉토리에서
    conda env create -f enviroments.yaml
   ```
3.  가상환경 활성화

   ```bash
      conda activate secure_coding
   ```
4. (필요 시) 추가 패키지 설치
  
   ```bash
    pip install flask-login flask-socketio
   ```
# 데이터베이스 초기화
- app.py 시작 시 자동으로 다음 테이블이 생성됩니다:
  - users (회원 정보)
  - products (상품 정보)
  - messages (채팅 내역)
  - transactions (송금 내역)
- 최초 실행 후, 자동으로 admin/admin 관리자 계정이 생성됩니다.
- 백업/리셋

  ```bash
    # app.db 파일 삭제 후 재실행하면 초기화
    rm app.db
    python app.py
  ```
# 실행 방법
  ```bash
    # 가상환경이 활성화된 상태에서
    python app.py
  ```
- 개발 서버가 http://127.0.0.1:5000 에서 실행됩니다.
- 브라우저 주소창에 http://localhost:5000 입력 후 접속하세요.


## 주요 경로 및 사용법

- `/` : 전체 상품 목록
- `/register` (GET, POST) : 회원가입
- `/login` (GET, POST) : 로그인
- `/logout` : 로그아웃
- `/product/new` (GET, POST) : 상품 등록
- `/product/<id>` : 상품 상세 페이지
- `/my-products` : 내가 등록한 상품 목록 / 수정·삭제 기능
- `/chat/<user_id>` (GET, POST) : 1:1 채팅
- `/messages` : 채팅 상대 목록
- `/report/product/<id>` : 상품 신고
- `/report/user/<id>` : 사용자 신고
- `/admin` : 관리자 페이지 (신고 현황)
- `/admin/delete_user/<id>` : 관리자 – 사용자 삭제 (POST)
- `/admin/delete_product/<id>` : 관리자 – 상품 삭제 (POST)
- `/transfer` (GET, POST) : 유저 간 송금 / 잔액 확인

## 기술 스택

- **Database**: SQLite (`app.db`)
- **Password Hash**: Werkzeug (`generate_password_hash`)
- **Frontend**: Bootstrap 5, Jinja2 템플릿
- **Dev Tools**: Conda, ngrok (외부 테스트)


> 📌 위 `README.md`를 프로젝트 루트에 추가하면, GitHub에 공개했을 때 환경 설정 및 실행 방법이 한눈에 안내됩니다!

# Teacher-Guard MCP (든든한 교사 편 보호자)

한국 교사의 **교권침해·악성 민원 대응**을 돕는 보호자형 MCP. law.go.kr로 검증된
**큐레이션 지식베이스** 기반의 *참고용 간단 안내*만 제공합니다. **외부 API/인증키 없음.**

## 설계 원칙 (코드로 강제)
1. **출처 필수** — 모든 응답에 법조문·URL·시행일 자동 첨부
2. **검증 권유** — 모든 응답에 law.go.kr·1395·변호사 확인 안내
3. **간단 안내** — 단정 금지(‘참고’·‘소지’). **법(statute) vs 매뉴얼(권고)** 구분 표기

## 도구 (6)
| 도구 | 설명 |
|------|------|
| `classify_complaint` | 상황 → 침해유형·긴급도·권장 트랙(참고) |
| `get_legal_basis` | 키워드 → 관련 법조문·근거(법/시행령/고시/매뉴얼 구분) |
| `get_response_procedure` | 상황/트랙 → 단계별 체크리스트 + 증거수집 |
| `draft_response` | 상황·톤(공감/정중/단호) → 응대 초안 |
| `get_support_resources` | 1395·배상책임보험·민원대응팀·치유센터 |
| `create_complaint_record` | 민원 기록 대장 양식 생성 |

## 지식베이스 (`kb/`)
`legal_basis` · `infringement_types` · `procedures` · `resources` · `response_templates`
— 전부 출처·시행일·검증일·권한등급(법률/시행령/고시/매뉴얼/미확인) 포함.

## 실행
```bash
pip install -r requirements.txt
python server.py                 # 로컬 stdio
uvicorn server_http:app --port 8000   # 원격 HTTP (/mcp, /healthz)
```

## 데이터 출처
국가법령정보센터(law.go.kr), 교육부·KEDI 교육활동보호센터 등. 검증일 2026-06-17.
법령·고시는 개정될 수 있으니 최신본은 law.go.kr에서 확인하세요. 본 도구는 법률자문이 아닙니다.

"""Teacher-Guard MCP — 교사 보호용 교권/민원 대응 안내 도구.

페르소나: "든든한 교사 편 보호자". 큐레이션 지식베이스(law.go.kr 1:1 검증) 기반의
참고용 간단 안내만 제공하며, 판단·결론을 내리지 않습니다. 외부 API/인증키 없음.

핵심 원칙(코드로 강제):
  1) 모든 응답에 출처(법조문·URL·시행일) 자동 첨부
  2) 모든 응답에 검증 권유(law.go.kr·1395·변호사) 자동 첨부
  3) 간단 안내 — 단정 금지, '참고'·'소지' 표현. 법(statute) vs 매뉴얼(권고) 구분 표기.
"""
from __future__ import annotations

import json
import os
import re

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

KB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kb")


def _load(name: str) -> dict:
    with open(os.path.join(KB_DIR, name), encoding="utf-8") as fh:
        return json.load(fh)


LEGAL = _load("legal_basis.json")
INFR = _load("infringement_types.json")
PROC = _load("procedures.json")
RES = _load("resources.json")
TPL = _load("response_templates.json")

LEGAL_BY_ID = {r["id"]: r for r in LEGAL["records"]}
INFR_BY_ID = {r["id"]: r for r in INFR["records"]}
PROC_BY_ID = {r["id"]: r for r in PROC["records"]}
RES_BY_ID = {r["id"]: r for r in RES["records"]}
TPL_BY_ID = {r["id"]: r for r in TPL["records"]}
EVID_BY_ID = {e["id"]: e for e in PROC.get("evidence_guide", [])}

VERIFY_KO = (
    "✅ 최신본은 law.go.kr에서, 구체적 판단은 교권침해 직통전화 **1395**·"
    "지역교권보호위원회·변호사에 확인하세요."
)


def _verified_on() -> str:
    """검증일 단일 소스 — KB _meta.verified_on에서 읽고, 없으면 기본값."""
    for kb in (LEGAL, INFR, PROC, RES, TPL):
        v = (kb.get("_meta") or {}).get("verified_on")
        if v:
            return v
    return "2026-06-17"


DISCLAIMER_KO = f"⚖️ 본 정보는 참고용 간단 안내이며 법률자문이 아닙니다. (검증일 {_verified_on()})"

# 동점 매칭 시 의미 기반 정렬용 — 침해 심각도 / 법령 권위 / 응대 템플릿 우선순위
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
AUTH_ORDER = {"법률": 0, "시행령": 1, "행정규칙(고시)": 2, "매뉴얼(권고)": 3, "미확인": 4}
# 응대 초안: 직접 침해행위 > 정황 > 시간·빈도 순으로 우선(동점 tie-break)
_TPL_PRIORITY = {tid: i for i, tid in enumerate([
    "TPL-ABUSE", "TPL-FALSE-REPORT-THREAT", "TPL-EXCESSIVE",
    "TPL-MEETING", "TPL-AFTERHOURS", "TPL-REPEAT", "TPL-LEGITIMATE",
])}

# 신변 위협·위기 의심 표현 — _danger() 로 판정.
# 설계: 위험 '어근'을 단독 명사가 아니라 '위협 동사·맥락과의 결합형'으로 등록한다.
#   → 일상어(칼국수/방화벽/물총/회칼/주사 찌르기/지휘봉 휘두르기/벌레 죽이지마/총무)와
#     겹치지 않아 과탐이 적고, 별도 예외목록(SAFE) 없이 단순 부분일치로 판정 가능.
#   → '위협+일상어' 공존("칼국수 먹다 칼로 찌르겠다")도 결합형이 직접 잡아 누수 없음.
# 한계: '너 죽는다'식 자동사 과장과 겹치는 표현은 2인칭 결합형(너죽/넌죽)으로만 제한 포함.
# 주의: _norm()이 공백을 지우므로 공백 포함/미포함 변형을 함께 등록.
DANGER_KW = [
    # 살해 — 타동 위협 활용형 + 2인칭(자동사 과장 '배고파 죽겠다/죽는다'는 미포함)
    "죽이겠", "죽인다고", "죽일거", "죽일것", "죽일게", "죽여버리", "죽여 버리", "죽여버려", "죽여 버려",
    "죽여버린", "죽여버릴", "죽여놓", "패죽", "패 죽", "쳐죽", "쳐 죽", "때려죽", "죽창",
    "너죽", "너 죽", "넌죽", "넌 죽", "죽을줄알", "죽을 줄 알",  # 2인칭 살해 위협(거리 두면 한계)
    "없애버리", "없애 버리", "없애버려", "없애버린", "없애버릴",
    "산채로묻", "산 채로 묻", "파묻어버", "생매장",
    "쏴버리", "쏴 버리", "쏴죽", "쏴 죽", "목따", "목 따", "목을따", "목을 따", "목을딴",
    # 흉기 — 사용·소지 맥락(단독 '칼' 금지: 칼국수/회칼/식칼/칼춤 회피)
    "흉기", "칼부림", "칼로찌", "칼로 찌", "칼로베", "칼로 베", "칼로쑤", "칼로 쑤",
    "칼들고", "칼 들고", "칼가지고", "칼 가지고", "칼을들", "칼을 들", "칼휘두", "칼 휘두",
    "칼들이대", "칼 들이대", "흉기휘두", "흉기들고", "흉기 들고", "식칼들", "회칼들",
    "찌르겠", "찔러죽", "찔러 죽", "찔러버리", "찔러 버리", "찔러버려", "찔러버린", "찔러버릴", "찔렀어",
    "베어버리", "베어 버리", "베어버려", "베어버린",
    # 총기·약품 — 사용·소지 맥락(단독 '총/권총' 금지: 물총/총무/권총장난감 회피)
    "엽총", "권총으로", "권총들", "권총 들", "권총가지", "총들고", "총 들고", "총겨누", "총 겨누",
    "총가지고", "총 가지고", "총으로쏴", "총으로 쏴", "총쏘", "사제총", "염산", "황산", "휘발유",
    # 가해·폭행 — 위협 활용형(단독 '해치/부러뜨리/휘두르' 금지)
    "해치겠", "해치려", "해친다", "해칠거", "해칠것", "해코지",
    "뼈를부러", "뼈를 부러", "다리를부러", "다리를 부러", "팔을부러", "팔을 부러", "부러뜨려버",
    "밀어버리", "밀어 버리", "밀어버린", "밀어버릴", "주먹휘두", "주먹 휘두",
    # 침입·습격
    "찾아오겠", "찾아가겠", "쳐들어",
    # 방화 — 위협 활용형(단독 '방화/태워' 금지: 방화벽/방화문/고기 태움 회피)
    "불지르", "불지를", "불지른", "불질러", "불질렀", "불을지르", "불을지를", "불을지른", "불을질러",
    "불태워", "불 태워", "불싸지", "태워버리겠", "태워버린", "태워버릴", "방화하", "방화범", "방화저지",
    "휘발유뿌", "기름붓고불", "기름 붓고 불",
    # 폭발 — 위협 결합형
    "폭파", "폭발물", "폭발시키", "터뜨려버", "터트려버", "터뜨리겠", "터트리겠", "사제폭탄",
    # 중대 협박조
    "가만안두", "가만 안 두", "가만안둔", "가만 안 둔", "가만안둬", "가만 안 둬", "가만두지않", "가만두지 않",
    "손봐주겠", "손 봐주겠", "혼쭐내", "혼쭐 내", "혼쭐을내", "혼쭐을 내",
    # 자·타해 위기 — 의지 표현
    "자해하", "자살하", "죽어버리겠", "죽어 버리겠",
]
DANGER_BANNER = "🚨 **신변 위협이 의심됩니다 — 즉시 112 신고, 교권 상담은 1395.**\n"

mcp = FastMCP(
    "teacher-guard",
    instructions=(
        "한국 교사의 교권침해·악성 민원 대응을 돕는 보호자형 MCP. "
        "law.go.kr로 검증된 내장 지식베이스에 근거한 '참고용 간단 안내'만 제공하고, "
        "판단·결론을 내리지 않습니다. 모든 응답에 출처와 검증 안내가 포함됩니다."
    ),
    stateless_http=True,
    json_response=True,  # SSE(text/event-stream) 대신 순수 application/json 응답 — 단순 HTTP 클라이언트(PlayMCP 심사 등) 호환
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


def _ann(title: str) -> ToolAnnotations:
    # 전부 자체 KB 조회·문서생성 (외부 상태/세계 의존 없음)
    return ToolAnnotations(
        title=title,
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )


# --------------------------------------------------------------------------- #
# 공통 유틸 — 출처·검증·면책 강제 삽입
# --------------------------------------------------------------------------- #
def _norm(s: str) -> str:
    return re.sub(r"\s+", "", (s or "")).lower()


def _match(text: str, records: list, topk: int = 3, tiebreak: dict | None = None) -> list:
    t = _norm(text)
    scored = []
    for r in records:
        score = sum(1 for kw in r.get("keywords", []) if _norm(kw) and _norm(kw) in t)
        if score:
            scored.append((score, r))
    if tiebreak:
        scored.sort(key=lambda x: (-x[0], tiebreak.get(x[1].get("id"), 999)))
    else:
        scored.sort(key=lambda x: -x[0])
    return [r for _, r in scored[:topk]]


def _rank_infr(cands: list) -> list:
    """침해유형 후보를 심각도→범죄성 순으로 정렬(가장 위험한 유형이 맨 앞).

    동일 score여도 폭행(critical/형사)이 강요(medium)보다 앞서도록 보장 —
    범죄형이 부당간섭형으로 강등되어 '즉시 112'·형사 절차가 누락되는 것을 방지.
    """
    return sorted(cands, key=lambda r: (
        SEVERITY_ORDER.get(r.get("default_severity", "medium"), 2),
        0 if r.get("is_criminal") else 1,
    ))


def _danger(text: str) -> bool:
    """신변 위협·위기 의심 여부. 위험 어근을 '위협 동사·맥락 결합형'으로 등록해
    일상어와 겹치지 않게 했으므로 단순 부분일치로 판정한다(예외목록 불필요)."""
    if not text:
        return False
    t = _norm(text)
    return any(_norm(k) in t for k in DANGER_KW)


def _sources_block(ref_ids) -> str:
    lines, seen = [], set()
    for rid in ref_ids:
        rec = LEGAL_BY_ID.get(rid) or RES_BY_ID.get(rid)
        if not rec:
            continue
        src = rec.get("source", {})
        label = src.get("label") or rec.get("law_ko") or rec.get("name_ko") or rid
        url = src.get("url", "")
        eff = src.get("effective_date", "")
        auth = rec.get("authority_level", "")
        key = (label, url)
        if key in seen:
            continue
        seen.add(key)
        tag = f" [{auth}]" if auth else ""
        eff_s = ""
        if eff and eff not in ("현행", "미확인"):
            eff_s = f", 시행 {eff}"
        elif eff:
            eff_s = f" ({eff})"
        lines.append(f"- {label}{tag}{eff_s}" + (f" · {url}" if url else ""))
    return "\n".join(lines)


def _finalize(body: str, ref_ids=()) -> str:
    out = body.rstrip() + "\n\n---\n"
    src = _sources_block(ref_ids)
    if src:
        out += "📚 **출처**\n" + src + "\n\n"
    out += VERIFY_KO + "\n" + DISCLAIMER_KO
    return out


# --------------------------------------------------------------------------- #
# 도구
# --------------------------------------------------------------------------- #
@mcp.tool(annotations=_ann("상황 분류"))
def classify_complaint(situation_text: str, repeated: bool = False, channel: str = "") -> str:
    """[교권 지킴이] Classify a complaint/situation into likely infringement type(s),
    urgency, and a recommended response track — KB-grounded, reference only (no determination).
    교권 지킴이(Teacher-Guard)의 상황 분류 도구.

    Args:
        situation_text: 발생한 민원/상황 서술 (예: "학부모가 밤 11시에 전화해 욕설").
        repeated: 반복성 여부(부당간섭 가중).
        channel: 발생 경로(phone/message/inperson/sns 등, 선택).
    """
    danger = _danger(situation_text)
    cands = _match(situation_text, INFR["records"], topk=3)
    if repeated:
        rep = INFR_BY_ID.get("INF-INTERFERE-REPEAT")
        if rep and rep not in cands:
            cands.append(rep)  # 반복성은 정황으로만 추가 — track은 아래 심각도 정렬이 결정
    if not cands:
        # danger 감지 시엔 미분류라도 범죄형(critical)으로 안전하게 유도
        if danger:
            body = (
                "## 🔍 상황 분류 (참고용 — 최종 판단은 교권보호위)\n\n"
                + DANGER_BANNER
                + "\n**긴급도:** CRITICAL\n"
                "구체 유형은 분류되지 않았으나 신변 위협이 의심됩니다. **즉시 112**, 교권 상담 **1395**.\n"
                "**권장 대응:** 교권침해(범죄형) 대응 → `get_response_procedure(track_id=\"TRACK-CRIMINAL\")`"
            )
            return _finalize(body, ["RES-1395"])
        body = (
            "## 🔍 상황 분류 (참고용)\n\n"
            "명확히 분류되지 않았습니다. 상황을 조금 더 구체적으로 알려주세요.\n"
            "급박한 신변 위협이면 **즉시 112**, 교권 상담은 **1395**."
        )
        return _finalize(body, ["RES-1395"])

    cands = _rank_infr(cands)
    top = cands[0]
    severity = "critical" if danger else top.get("default_severity", "medium")
    track = top.get("default_track")
    if danger and track != "TRACK-CRIMINAL":
        track = "TRACK-CRIMINAL"  # 신변 위협이면 범죄형 절차로 유도

    lines = ["## 🔍 상황 분류 (참고용 — 최종 판단은 교권보호위)\n"]
    if danger:
        lines.append(DANGER_BANNER)
    lines.append("**가능 침해유형(참고)**")
    for r in cands:
        cat = "범죄형" if r["category"] == "crime" else "부당간섭형"
        crim = " · 형사 가능" if r.get("is_criminal") else ""
        lines.append(f"- {r['name_ko']} ({cat}){crim} · `{r['id']}`")
    soji = "⚠️ 있어 보임" if severity in ("critical", "high") else "ℹ️ 검토 필요"
    lines.append(f"\n**교권침해 소지(참고):** {soji}")
    lines.append(f"**긴급도:** {severity.upper()}")
    if severity == "critical":
        lines.append("> 🚨 위급 시 즉시 112 / 1395")
    if track and track in PROC_BY_ID:
        lines.append(
            f"**권장 대응:** {PROC_BY_ID[track]['name_ko']} "
            f"→ `get_response_procedure(track_id=\"{track}\")`"
        )
    lines.append(
        "\n**다음 도구**\n- `get_legal_basis` 근거\n"
        "- `get_response_procedure` 절차\n- `create_complaint_record` 기록"
    )
    refs = list({x for r in cands for x in r.get("legal_refs", [])}) + ["RES-1395"]
    return _finalize("\n".join(lines), refs)


@mcp.tool(annotations=_ann("법적 근거"))
def get_legal_basis(query: str = "", type_id: str = "", law_id: str = "") -> str:
    """[교권 지킴이] Look up relevant statutes/guidelines and their key points — KB-grounded, reference only.
    교권 지킴이(Teacher-Guard)의 법적 근거 안내. 법(statute)·시행령·고시·매뉴얼(권고)을 구분합니다.

    Args:
        query: 키워드/상황 (예: "과태료", "정당한 생활지도", "명예훼손", "아동학대").
        type_id: 침해유형 ID(선택). law_id: 특정 법조문 ID(선택, 예: LAW-TSA-35).
    """
    recs = []
    if law_id and law_id in LEGAL_BY_ID:
        recs = [LEGAL_BY_ID[law_id]]
    elif type_id and type_id in INFR_BY_ID:
        recs = [LEGAL_BY_ID[x] for x in INFR_BY_ID[type_id].get("legal_refs", []) if x in LEGAL_BY_ID]
    elif query:
        # 토큰 단위 AND 매칭 — "교원지위법 제20조"처럼 필드 경계를 넘는 다중어 query 지원.
        # (기존 substring 전체매칭은 어순·필드순 때문에 법령명+조문 검색이 구조적으로 실패했음)
        toks = [_norm(tok) for tok in re.split(r"[\s·,]+", query) if _norm(tok)]
        scored = []
        for r in LEGAL["records"]:
            blob = _norm(
                r.get("article", "") + r.get("title_ko", "") + r.get("summary_ko", "")
                + r.get("short_ko", "") + (r.get("penalty_ko") or "")
                + " ".join(r.get("keywords") or [])
            )
            n = sum(1 for tk in toks if tk in blob)
            if n:
                scored.append((n, r))
        # 매칭 토큰 수 ↓, 동점 시 권위(법률>시행령>고시>매뉴얼) 우선 → 법률 본문이 매뉴얼보다 앞
        scored.sort(key=lambda x: (-x[0], AUTH_ORDER.get(x[1].get("authority_level", ""), 9)))
        recs = [r for _, r in scored]
        if not recs:
            seen = set()
            for mm in _match(query, INFR["records"], topk=2):
                for x in mm.get("legal_refs", []):
                    if x in LEGAL_BY_ID and x not in seen:
                        seen.add(x)
                        recs.append(LEGAL_BY_ID[x])
    if not recs:
        return _finalize(
            "## ⚖️ 관련 근거\n\n해당 키워드의 근거를 찾지 못했습니다. "
            "예: '과태료', '명예훼손', '정당한 생활지도', '아동학대', '무고'.",
            ["RES-1395"],
        )

    lines, refs = ["## ⚖️ 관련 근거 (참고용 간단 안내)\n"], []
    for r in recs[:5]:
        auth = r.get("authority_level", "")
        tag = f" [{auth}]" if auth else ""
        if auth == "매뉴얼(권고)":
            tag = " [⚠️ 매뉴얼(권고) — 법정 기한 아님]"
        elif auth == "미확인":
            tag = " [❓ 미확인 — 소속 교육청 확인]"
        lines.append(f"▸ **{r.get('short_ko','')} {r.get('article','')} — {r.get('title_ko','')}**{tag}")
        lines.append(f"  {r.get('summary_ko','')}")
        if r.get("penalty_ko"):
            lines.append(f"  · 벌칙/과태료: {r['penalty_ko']}")
        if r.get("note_ko"):
            lines.append(f"  · 참고: {r['note_ko']}")
        lines.append("")
        refs.append(r["id"])
    return _finalize("\n".join(lines), refs)


@mcp.tool(annotations=_ann("대응 절차"))
def get_response_procedure(track_id: str = "", situation_text: str = "", include_evidence: bool = True) -> str:
    """[교권 지킴이] Return a step-by-step response checklist (+evidence guide) — KB-grounded, reference only.
    교권 지킴이(Teacher-Guard)의 대응 절차. '24시간/14일'은 법정 기한이 아닌 매뉴얼 권고치로 표기됩니다.

    Args:
        track_id: 절차 ID(예: TRACK-CRIMINAL, TRACK-MALICIOUS-COMPLAINT, TRACK-CHILD-ABUSE-REPORT).
        situation_text: 상황 서술(track_id 없을 때 내부 분류).
        include_evidence: 증거수집 가이드 포함 여부.
    """
    danger = _danger(situation_text)
    track = None
    if track_id and track_id in PROC_BY_ID:
        track = PROC_BY_ID[track_id]
    elif situation_text:
        m = _rank_infr(_match(situation_text, INFR["records"], topk=3))  # 심각도 우선
        if m:
            track = PROC_BY_ID.get(m[0].get("default_track"))
    if danger and "TRACK-CRIMINAL" in PROC_BY_ID and (track is None or track.get("id") != "TRACK-CRIMINAL"):
        track = PROC_BY_ID["TRACK-CRIMINAL"]  # 신변 위협 의심 — 범죄형 절차로 유도
    if not track:
        lines = ["## 📋 대응 절차\n\n상황을 알려주시거나 트랙을 지정하세요:"]
        for r in PROC["records"]:
            lines.append(f"- `{r['id']}` — {r['name_ko']}")
        return _finalize("\n".join(lines), ["RES-1395"])

    lines = [DANGER_BANNER] if danger else []
    lines.append(f"## 📋 {track['name_ko']} (참고용 체크리스트)\n")
    refs = []
    for s in track["steps"]:
        auth = s.get("authority", "")
        dl = s.get("deadline_ko", "")
        dtag = f" · ⏰ {dl}" if dl and dl != "-" else ""
        atag = ""
        if auth == "매뉴얼(권고)":
            atag = " [⚠️매뉴얼 권고·법정 아님]"
        elif auth == "시행령":
            atag = " [시행령]"
        lines.append(f"- [ ] **{s['order']}. {s['title_ko']}** · {s.get('actor','')}{dtag}{atag}")
        lines.append(f"      {s.get('detail_ko','')}")
        refs += s.get("legal_refs", [])
    if include_evidence and track.get("evidence_refs"):
        lines.append("\n### 📎 증거 수집")
        for eid in track["evidence_refs"]:
            e = EVID_BY_ID.get(eid)
            if e:
                lines.append(f"- **{e['name_ko']}** — {e['how_ko']} (⚠️ {e['caution_ko']})")
    if track.get("related_resources"):
        names = ", ".join(RES_BY_ID[x]["name_ko"] for x in track["related_resources"] if x in RES_BY_ID)
        lines.append(f"\n### 🤝 지원: {names}  → `get_support_resources`")
        refs += track["related_resources"]
    return _finalize("\n".join(lines), refs)


@mcp.tool(annotations=_ann("응대 초안"))
def draft_response(situation_text: str, tone: str = "polite", channel: str = "", template_id: str = "") -> str:
    """[교권 지킴이] Generate a response-message draft in a chosen tone — KB template based, reference only.
    교권 지킴이(Teacher-Guard)의 응대 문구 초안 생성.

    Args:
        situation_text: 응대가 필요한 상황 서술.
        tone: 톤 — "empathetic"(공감)/"polite"(정중)/"firm"(단호).
        channel: 응대 채널(선택). template_id: 템플릿 ID 직접 지정(선택).
    """
    bad_template_id = bool(template_id) and template_id not in TPL_BY_ID
    tpl = None
    if template_id and template_id in TPL_BY_ID:
        tpl = TPL_BY_ID[template_id]
    else:
        m = _match(situation_text, TPL["records"], topk=1, tiebreak=_TPL_PRIORITY)
        tpl = m[0] if m else None
    if not tpl:
        return _finalize(
            "## ✍️ 응대 초안\n\n상황을 조금 더 구체적으로 알려주세요"
            "(예: 반복 전화, 폭언, 근무시간 외 연락, 면담 요청 등).",
            ["RES-1395"],
        )
    tones = tpl.get("tones", {})
    if tone in tones:
        used_tone, draft = tone, tones[tone]
    elif "polite" in tones:
        used_tone, draft = "polite", tones["polite"]
    elif tones:
        used_tone, draft = next(iter(tones.items()))
    else:
        used_tone, draft = tone, ""
    lines = [f"## ✍️ 응대 초안 — {tpl['situation_ko']} (톤: {used_tone})\n"]
    if bad_template_id:
        lines.append("ℹ️ 지정한 template_id를 찾지 못해 상황에 맞춰 자동 선택했습니다.\n")
    if used_tone != tone:
        lines.append(f"ℹ️ '{tone}' 톤은 이 상황 템플릿에 없어 '{used_tone}' 톤으로 안내합니다.\n")
    lines.append(f"> {draft}\n")
    if tpl.get("do_ko"):
        lines.append("**✅ DO**\n" + "\n".join(f"- {x}" for x in tpl["do_ko"]))
    if tpl.get("dont_ko"):
        lines.append("\n**❌ DON'T**\n" + "\n".join(f"- {x}" for x in tpl["dont_ko"]))
    if tpl.get("note_ko"):
        lines.append(f"\nℹ️ {tpl['note_ko']}")
    lines.append("\n→ `create_complaint_record` 기록 · `get_support_resources` 연결")
    return _finalize("\n".join(lines), tpl.get("legal_refs", []))


@mcp.tool(annotations=_ann("지원 기관"))
def get_support_resources(need: str = "all", situation_text: str = "") -> str:
    """[교권 지킴이] Return relevant support orgs/contacts (1395, insurance, complaint team, etc.) — reference only.
    교권 지킴이(Teacher-Guard)의 지원기관 안내.

    Args:
        need: "all"/"hotline"/"legal"/"counseling"/"insurance"/"complaint_team".
        situation_text: 상황 서술(선택, 참고용 — 현재 결과 정렬에는 영향 없음).
    """
    need = (need or "all").strip().lower()  # 대소문자·공백 정규화
    typemap = {
        "hotline": ["RES-1395"],
        "insurance": ["RES-INSURANCE", "RES-1395"],
        "counseling": ["RES-PROTECTION-CENTER", "RES-1395"],
        "legal": ["RES-UNION-LEGAL", "RES-1395"],
        "complaint_team": ["RES-COMPLAINT-TEAM", "RES-OFFICE-TEAM"],
    }
    unknown_need = need != "all" and need not in typemap
    if need != "all" and need in typemap:
        recs = [RES_BY_ID[x] for x in typemap[need] if x in RES_BY_ID]
    else:
        recs = list(RES["records"])
    recs.sort(key=lambda r: 0 if r["id"] == "RES-1395" else 1)

    lines, refs = ["## 🤝 지원 기관·연락처 (참고)\n"], []
    if unknown_need:
        lines.append(
            f"ℹ️ 알 수 없는 분류 '{need}' → 전체를 표시합니다. "
            "(가능: hotline/legal/counseling/insurance/complaint_team/all)\n"
        )
    for r in recs:
        lines.append(f"### {r['name_ko']}")
        lines.append(f"- 연락: **{r.get('contact','')}**")
        if r.get("hours_ko"):
            lines.append(f"- 운영: {r['hours_ko']}")
        if r.get("scope_ko"):
            lines.append(f"- 지원: {', '.join(r['scope_ko'])}")
        if r.get("coverage_note_ko"):
            lines.append(f"- {r['coverage_note_ko']}")
        if r.get("note_ko"):
            lines.append(f"- 참고: {r['note_ko']}")
        lines.append("")
        refs.append(r["id"])
    return _finalize("\n".join(lines), refs)


@mcp.tool(annotations=_ann("기록 대장"))
def create_complaint_record(
    incident_date: str = "",
    summary: str = "",
    channel: str = "",
    type_id: str = "",
    reporter: str = "",
) -> str:
    """[교권 지킴이] Generate a standardized complaint/infringement record-log form (text only) — reference only.
    교권 지킴이(Teacher-Guard)의 민원 기록 대장 생성.

    Args:
        incident_date: 발생 일시. summary: 사건 요약. channel: 발생 경로.
        type_id: 침해유형 ID(선택, 유형·증거 자동 기입. 예: INF-CRIME-INSULT). reporter: 작성자(교원).
    """
    type_id = (type_id or "").strip().upper()  # 대소문자·공백 정규화
    t = INFR_BY_ID.get(type_id)
    type_label = "____"
    if t:
        cat = "범죄형" if t["category"] == "crime" else "부당간섭형"
        type_label = f"{t['name_ko']} ({cat})"

    lines = [
        "## 📑 교권침해·민원 기록 대장 (참고 양식)\n",
        "| 항목 | 내용 |",
        "|---|---|",
        f"| 사건일시 | {incident_date or '____'} |",
        f"| 발생경로 | {channel or '____'} |",
        f"| 작성자(교원) | {reporter or '____'} |",
        f"| 사건요약 | {summary or '____'} |",
        f"| 추정 유형(참고) | {type_label} |",
        "| 상대방 | ____ (관계: ____) |",
        "| 목격자 | ____ |",
        "| 즉시 조치 | ____ |",
        "| 신고 여부 | ☐ 교육지원청 신고 |",
    ]
    refs = ["LAW-TSA-19", "RES-1395"]
    if t and t.get("evidence_hints"):
        lines.append("\n### 📎 이 유형에서 확보할 증거(체크)")
        for eid in t["evidence_hints"]:
            e = EVID_BY_ID.get(eid)
            if e:
                lines.append(f"- [ ] {e['name_ko']}")
        refs += t.get("legal_refs", [])
    if type_id and not t:
        lines.append(
            f"\n⚠️ 입력한 유형 ID('{type_id}')를 찾지 못해 '추정 유형'을 비웠습니다. "
            "`classify_complaint`로 유형(예: `INF-CRIME-INSULT`)을 확인하세요."
        )
    lines.append(
        "\n### 작성 안내\n- 빈칸(____)은 사실관계대로 구체적으로 기재\n"
        "- 객관적 사실 위주, 추측·감정 표현은 분리해 기록"
    )
    lines.append("\n→ `get_response_procedure` 신고 절차 · `get_support_resources` 1395")
    return _finalize("\n".join(lines), refs)


if __name__ == "__main__":
    mcp.run()

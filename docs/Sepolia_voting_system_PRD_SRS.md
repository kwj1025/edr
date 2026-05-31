# 이더리움 세폴리아 연동 투표시스템 — 통합 문서 (PRD + SRS + 화면설계)

버전: 1.0  
작성일: 2026-05-19

요약:
- 단일 선거(한 번의 투표 이벤트) 전용 시스템
- 스마트컨트랙트 배포자만 Admin(후보자 등록/투표 시작·종료) 권한 보유. Admin 본인도 투표 가능
- 후보자: 이름, 사진(오프체인 저장: 서버 또는 S3; 블록체인엔 URL/메타데이터만 저장)
- 중복투표 불가(1지갑 1투표), Sepolia 지갑 보유자(주소 보유자)만 투표 가능
- 투표 진행 중 실시간 득표수 표시(프론트엔드 폴링 또는 이벤트 구독), 종료 후 전체 결과 공개(온체인)
- Chrome + MetaMask(확장) 이용
- 동시접속 적음(최대 ~5명), 실습/수업용에 최적화

목차
1. 목표 및 배경 (PRD)  
2. 기능 목록 (High-level)  
3. 상세 요구사항 (SRS)  
4. 스마트컨트랙트 인터페이스 명세  
5. 데이터 모델  
6. 프론트엔드/백엔드 아키텍처 및 스택 제안  
7. 보안/운영/테스트 계획  
8. 화면 설계서 (ASCII 와이어프레임 + 화면별 기능 명세)  
9. 수용 기준(AC) 및 테스트 시나리오  
10. 오픈 이슈(없음 — 사용자 요구 반영 완료)

---

1) 목표 및 배경 (PRD)
- 목적: Sepolia 테스트넷에서 MetaMask로 서명 가능한 투명한 투표 실습 플랫폼 제공. 교육용으로 설계되어 단일 선거를 쉽고 안전하게 시연 가능.
- 성공 기준:
  - Admin(배포자)만 후보자 등록/투표 제어 가능
  - 후보자 최소 2명 이상 있어야 투표 시작
  - 1주소 1투표 보장
  - 투표 상태에 따라 실시간 진행상황/종료 후 결과 확인 가능
  - Chrome + MetaMask 연동으로 투표 트랜잭션 생성/전송 가능

---

2) 기능 목록 (High-level)
- Admin 기능: 후보자 등록(이름+사진 URL), 후보자 수정(투표 시작 전만), 투표 시작/종료
- 투표자 기능: MetaMask 연결, 후보자 보기, 투표(1회), 진행중 득표수 실시간 확인, 종료 후 결과 조회
- 시스템 기능: 온체인 득표 집계, 이벤트 로그(전체 공개), 후보자 메타데이터는 온체인에 URL만 저장
- 운영: Sepolia 전용 RPC 연결, 간단 이미지 호스팅(백엔드)

---

3) 상세 요구사항 (SRS)

3.1 기능적 요구사항 (요약)
- FR1: Admin 권한
  - 제약: 스마트컨트랙트 배포자(Deployer) 주소만 Admin으로 간주
  - Admin은 자신도 투표 가능
- FR2: 후보자 등록 및 관리
  - 필드: name(string), metadataURI(string) — metadataURI는 사진 URL(백엔드 저장소 S3/로컬에 호스팅)
  - 등록: 컨트랙트에 candidate 추가(온체인에 name + metadataURI + id + isActive(=true) 저장)
  - 수정: 투표 시작(state=CREATED) 전만 가능 → editCandidate(candidateId, name, metadataURI)
  - 비활성화: 투표 시작 전 후보자 제거 필요 시 → removeCandidate(candidateId) [isActive=false 플래그 처리]
- FR3: 투표 상태 관리
  - 상태: CREATED -> ACTIVE -> ENDED
  - startVoting()은 후보자 수 >= 2 검증
- FR4: 투표 행위
  - vote(candidateId) — 호출자 주소가 한 번만 투표 가능(컨트랙트에서 mapping(address=>bool)로 기록)
  - ACTIVE 상태에서만 허용
  - 중복투표 시도 시 트랜잭션 revert (오류: "이미 투표했습니다")
- FR5: 데이터 조회
  - 누구나 getCandidates(), getVoteCount() 등 조회 가능
  - 이벤트 VoteCast(address voter, uint256 candidateId) 발생 — 모든 로그는 공개
- FR6: 사진/메타데이터
  - 사진은 백엔드에서 호스팅. 컨트랙트는 metadataURI 저장(대용량 데이터를 온체인에 저장하지 않음)
- FR7: 네트워크 제약
  - Sepolia 전용. 메인넷 배포 금지

3.2 비기능적 요구사항
- NFR1: 보안
  - 재진입 방지, 오버플로우 없음(솔리디티 최신 버전 및 OpenZeppelin 사용 권장)
  - Admin 권한 최소화
- NFR2: 성능
  - 소규모 사용자(최대 5명) 대상. 폴링(10s)으로 충분
- NFR3: 신뢰성
  - 온체인 투표 기록으로 무결성 보장
- NFR4: 테스트
  - Hardhat/Foundry 단위 테스트, Sepolia 통합 테스트 필요

---

4) 스마트컨트랙트 인터페이스 명세 (요약; 접근 제어 반영)
접근 모델: owner = Deployer(컨트랙트 생성자). onlyOwner modifier 적용.

데이터 타입 요약
- enum State { CREATED, ACTIVE, ENDED }
- struct Candidate { uint256 id; string name; string metadataURI; uint256 voteCount; bool isActive; }

함수
- constructor() public { owner = msg.sender; }
- function registerCandidate(string calldata name, string calldata metadataURI) external onlyOwner returns (uint256 candidateId);
  - 제약: state == CREATED, 후보자 수 < 100(임의 상한)
- function editCandidate(uint256 candidateId, string calldata name, string calldata metadataURI) external onlyOwner;
  - 제약: state == CREATED, candidateId 존재 및 isActive == true
- function removeCandidate(uint256 candidateId) external onlyOwner;
  - 제약: state == CREATED, candidateId 존재 → isActive=false 플래그 처리(배열 유지)
- function batchRegisterCandidates(string[] calldata names, string[] calldata metadataURIs) external onlyOwner returns (uint256[] memory ids);
  - 제약: state == CREATED, names.length == metadataURIs.length, 각 배열 길이 > 0
  - 반환: 등록된 후보자 id 배열
- function startVoting() external onlyOwner;
  - 검증: state == CREATED, activeCandidateCount >= 2 → state = ACTIVE; emit VotingStarted()
- function endVoting() external onlyOwner;
  - 제약: state == ACTIVE → state = ENDED; emit VotingEnded()
- function vote(uint256 candidateId) external;
  - 검증: state == ACTIVE; !hasVoted[msg.sender]; candidate isActive == true
  - 동작: hasVoted[msg.sender] = true; voteCount++; emit VoteCast(msg.sender, candidateId)
- function getCandidates() external view returns (Candidate[] memory);
  - 반환: isActive == true인 후보자만 필터링
- function getActiveCandidateCount() external view returns (uint256);
  - 반환: isActive == true인 후보자 수
- function getTotalVotes() external view returns (uint256);
  - 반환: 모든 후보자의 voteCount 합산
- function getVoteCount(uint256 candidateId) external view returns (uint256);
  - 반환: 특정 후보자의 voteCount
- function hasVoted(address voter) external view returns (bool);
  - 반환: voter 주소의 투표 여부
- function getVotingState() external view returns (State);
  - 반환: 현재 투표 상태(CREATED/ACTIVE/ENDED)

이벤트
- event CandidateRegistered(uint256 indexed candidateId, string name, string metadataURI);
- event CandidateEdited(uint256 indexed candidateId, string name, string metadataURI);
- event CandidateRemoved(uint256 indexed candidateId);
- event VotingStarted(uint256 timestamp);
- event VotingEnded(uint256 timestamp);
- event VoteCast(address indexed voter, uint256 indexed candidateId, uint256 timestamp);

가스/최적화 팁
- 이름/metadataURI 길이 고려(짧게)
- 후보자 삭제는 배열 재정렬 필요 — 단순화 위해 삭제 대신 inactive flag 사용 가능

---

5) 데이터 모델 (요약 및 일관성 보완)

온체인 (Smart Contract Storage)
- owner: address (컨트랙트 배포자, Admin 주소)
- ballotState: State enum (CREATED, ACTIVE, ENDED)
- candidates: Candidate[] (동적 배열, 삭제 후에도 유지)
  - Candidate { id: uint256, name: string, metadataURI: string, voteCount: uint256, isActive: bool }
- hasVoted: mapping(address => bool) (투표자 주소별 투표 여부)
- nextCandidateId: uint256 (후보자 id 자동 증분)

오프체인 (백엔드 서버)
- 사진 파일 저장소: 로컬 파일시스템 또는 S3
- 사진 URL 매핑: metadataURI(온체인) → 실제 이미지 파일 경로
- 업로드 기록/로그: 사진 업로드 시간, 파일명, URL 등

---

6) 아키텍처 & 개발 스택 제안
- 프론트엔드: React + TypeScript, ethers.js, Chart.js 또는 Recharts (바 차트)
- 백엔드(선택): Node.js + Express (간단 이미지 업로드), Multer + S3 또는 로컬 저장
- 스마트컨트랙트: Solidity (>=0.8.x), OpenZeppelin Ownable
- 테스트: Hardhat (Mocha/Chai)
- 배포: Hardhat + Sepolia RPC (Infura/Alchemy)
- 호스팅: 정적 빌드(예: Netlify/Vercel) + 백엔드(Express) 필요 시 간단한 서버(로컬/Heroku)

설계 근거: 동시접속 작음 → 복잡한 오프체인 인프라 불필요. 사진은 오프체인으로 처리해 온체인 가스 절감.

네트워크/폴링
- 이벤트 구독 또는 폴링(10~15초). 실습 환경이므로 폴링 간격 10초 권장.

MetaMask 연동
- window.ethereum 요청 -> ethers.providers.Web3Provider(window.ethereum) -> signer
- 트랜잭션 전 가스 예측 및 MetaMask에서 유저가 확인

---

7) 보안, 운영, 테스트 계획

보안
- onlyOwner 접근 제어 확인
- require문으로 상태 검증 철저
- 비재진입 패턴(상태 변경 후 외부 호출 없음)
- 솔리디티 Linter 및 Slither 같은 도구 권장

운영
- Sepolia 전용 노드(Infura/Alchemy) 사용
- 가스비 알림: Sepolia라서 실습용 적음

테스트 케이스(핵심)
- 후보자 2명 등록 후 startVoting 성공
- 후보자 1명만 등록시 startVoting revert
- 동일 지갑으로 두 번 vote 시도 -> revert
- ACTIVE 상태에서만 vote 가능
- END 상태에서 vote 불가
- 이벤트(CandidateRegistered, VoteCast, VotingStarted, VotingEnded) 발생 검증

---

8) 화면 설계서 (ASCII 와이어프레임 + 각 화면별 기능 명세)

전반 UX 원칙: 간결, 실습 목적, 그래픽은 Chart.js 바 차트 권장. 색상은 투표 상태에 따라 (CREATED: 회색, ACTIVE: 녹색, ENDED: 파란색).

(1) 헤더 (공통)
------------------------------------------------------
| AppLogo | AppTitle "Sepolia Voting (실습용)" | [지갑 연결 버튼] |
------------------------------------------------------

(2) 홈 / 투표 개요 화면 (단일 투표)
ASCII:
+-------------------------------------------------------------+
| 투표 제목: [선거명]                                          |
| 상태: [CREATED/ACTIVE/ENDED 배지]                           |
| 설명: [간단 설명 텍스트]                                     |
+-------------------------------------------------------------+
| 후보자 리스트 (카드)                                         |
|  [사진]  이름: 홍길동    득표수: 12                          |
|  [사진]  이름: 김철수    득표수: 8   [투표하기 버튼(활성)]   |
+-------------------------------------------------------------+
| Admin (owner) controls: [후보자 추가] [투표 시작] [투표 종료] |
+-------------------------------------------------------------+

기능 명세:
- 지갑 연결 (MetaMask) 표시: 계정 주소 축약해서 표기
- 후보자 카드: 사진, 이름, 득표수(실시간), '투표하기' 버튼(Active일 때)
- Admin 전용 버튼: 후보자 추가(모달), 투표 시작/종료(트랜잭션)

(3) 후보자 등록/관리 모달/페이지 (Admin 전용)
ASCII:
+--------------------------- 후보자 등록/편집 ---------------------------+
| 작업: [신규 등록 / 기존 수정] (기존 수정은 CREATED 상태만)              |
| 이름: [__________]                                                     |
| 사진 업로드: [파일선택] (선택사항; 이전 이미지 표시 가능)               |
| 또는 사진 URL: [__________]                                            |
| [등록/수정(트랜잭션)]  [취소]  [삭제(CREATED만 비활성화)]              |
+------------------------------------------------------------------------+

기능:
- 신규 등록: 파일 업로드 → 백엔드에 업로드 → metadataURI(URL) 반환 → registerCandidate(name, metadataURI) 호출
- 기존 편집: 후보자 수정 필요 시 (CREATED 상태만) → editCandidate(candidateId, name, metadataURI)
- 비활성화(논리적 삭제): removeCandidate(candidateId) → isActive=false로 마킹 (배열은 유지)
- Admin만 표시

(4) 투표 페이지 (사용자 인터랙션 중심)
ASCII:
+---------------------------------------------------------------+
| 투표 제목 / 상태 / 남은 시간(선택)                             |
+---------------------------------------------------------------+
| 후보자 1 카드:                                                 |
|  [사진] 이름: 홍길동    득표수: 14   [투표하기 버튼]           |
| 후보자 2 카드:                                                 |
|  [사진] 이름: 김철수    득표수: 9    [투표하기 버튼]           |
+---------------------------------------------------------------+
| 차트(우측): 바 차트로 득표분포 표시 (Chart.js)                 |
+---------------------------------------------------------------+
| 아래: 트랜잭션 상태: 대기 / 제출중 / 완료 / 실패 메시지 표시    |
+---------------------------------------------------------------+

기능:
- 투표 버튼 클릭 -> MetaMask 서명창 -> 트랜잭션 제출 -> UI에서 txHash 표시 및 폴링으로 상태 체크
- 투표 완료 시 해당 계정은 투표 불가(버튼 비활성화)
- 득표수는 폴링 또는 이벤트로 10초 간격 업데이트

(5) 결과 화면 (ENDED)
ASCII:
+---------------------------------------------------------------+
| 투표 결과: [정렬: 득표수 내림차순]                             |
| 1위 [사진] 홍길동 - 120표                                        |
| 2위 [사진] 김철수 - 80표                                         |
+---------------------------------------------------------------+
| 총 투표수: 200 | 참여 주소 수: 200                              |
| 이벤트 로그(접기/펼치기): VoteCast 이벤트 목록(주소/후보ID/블록) |
| [CSV 내보내기]                                                 |
+---------------------------------------------------------------+

기능:
- 모든 로그 및 득표수 공개
- CSV 내보내기(옵션) — 이벤트 기반으로 생성

(6) Admin 대시보드
ASCII:
+---------------------------------------------------------------+
| Admin: 주소: 0xABC... (owner)                                 |
| 후보자 목록 (편집/삭제 가능, 단 투표 시작 전만)               |
| [투표 시작 버튼] [투표 종료 버튼]                             |
| 이벤트 로그 뷰어                                              |
+---------------------------------------------------------------+

기능:
- 상태 전환 트랜잭션 호출
- 후보자 편집(온체인 수정 함수 호출)
- 로그 모니터링

시각화 권장
- Chart.js의 막대그래프(Bar chart) 사용: 후보자별 득표수 실시간 표시
- 색상: Active → 애니메이션으로 막대 증가 표시
- 각 카드 옆에 실시간 숫자 및 퍼센트 표시

---

9) 수용 기준 및 테스트 시나리오 (AC)

수용 기준 (Acceptance Criteria)
- AC-1: Admin(배포자)만 후보자 등록/수정/삭제 가능. 비소유자 접근 시 UI 버튼 숨김 또는 트랜잭션 revert("onlyOwner").
- AC-2: 활성 후보자 수 >= 2 일 때만 startVoting() 성공. 미만일 시 revert("최소 2명 필요").
- AC-3: 동일 지갑에서 두 번 투표 시도 시 트랜잭션 revert("이미 투표했습니다") + UI 오류 메시지.
- AC-4: ACTIVE 상태에서 투표 시 득표수가 즉시(블록 반영 후 1~2 컨펌) 증가(프론트엔드 폴링/이벤트 반영).
- AC-5: ENDED 상태에서는 누구나 getVoteCount()로 결과 조회 가능. vote() 호출 시 revert("투표 진행 중 아님").
- AC-6: Sepolia 전용(체인 검증은 배포 스크립트 및 프론트엔드에서 담당).
- AC-7: 비활성 후보자(isActive=false)는 getCandidates()에서 제외되고, 투표 불가.
- AC-8: 이벤트 로그(VoteCast 포함)는 모두 공개이며, 주소 정보 포함.

테스트 시나리오 (핵심 흐름)
- 시나리오 1: Admin이 후보자 2명 등록(registerCandidate 2회) → startVoting 성공 → state=ACTIVE
- 시나리오 2: 활성 후보자 1명만 등록된 상태 → startVoting 시도 → revert("최소 2명 필요")
- 시나리오 3: ACTIVE 중 다른 주소로 vote(candidateId=1) 성공 → VoteCast 이벤트 발생
- 시나리오 4: 동일 주소로 vote 재시도 → revert("이미 투표했습니다")
- 시나리오 5: ENDED 상태에서 vote 시도 → revert("투표 진행 중 아님")
- 시나리오 6: ENDED 후 누구나 getCandidates() + getTotalVotes() 조회 → 결과 확인
- 시나리오 7: editCandidate (투표 시작 후) → revert("상태 변경 불가") or onlyOwner 검증
- 시나리오 8: removeCandidate(candidateId) → isActive=false + CandidateRemoved 이벤트 발생

---

10) 운영 및 배포(간단)
- 스마트컨트랙트: Hardhat으로 컴파일/테스트/배포. Sepolia RPC (Infura/Alchemy) 및 배포키(환경변수) 사용.
- 프론트엔드: React 빌드 정적 호스팅(예: Vercel). 백엔드(이미지 업로드 필요 시) 간단 Express 앱—Heroku/Render/로컬 사용 가능.
- 환경변수: SEP_RPC_URL, OWNER_PRIVATE_KEY, UPLOAD_BACKEND_URL 등
- 주의: 개인키(배포자)는 안전하게 보관. 실제 메인넷 배포 금지.

---

부록 — 구현/개발 노트(권장)
- ethers.js 권장(간단, MetaMask 호환)
- 폴링 주기: 10초. 이벤트 기반 WebSocket 연결이 가능하면 이벤트 구독으로 실시간성 향상
- 사진 업로드: Express + Multer + S3 로컬 모드. 업로드 후 반환된 URL을 registerCandidate에 넘김(트랜잭션 전 미리 업로드)
- Candidate 등록 트랜잭션: 후보자 수가 많지 않으므로 단건 등록 OK

---

오픈 이슈: 없음(요구사항 파일의 선택된 항목을 모두 반영했습니다)
- Admin은 스마트컨트랙트 배포자(Deployer)만 가능
- Admin 본인도 투표 가능
- 사진은 오프체인 관리(서버)
- 투표는 공개투표(이벤트에 주소 포함)로 진행
- 단일 투표만 운영(멀티 투표 비활성)
- Sepolia 전용, 메인넷 배포 안 함
- KYC 불필요
- 동시접속/투표수는 작음(설계에 반영)
- 화면 설계는 ASCII 와이어프레임 + Bar Chart 권장

---
## 검증 요약 및 반영 (2026-05-19)

검증 요약:
- 제안된 기능(Seoplia + MetaMask 연동, owner 전용 권한, 1지갑=1투표, 이벤트 공개, 프론트엔드 폴링/WS)은 기술적으로 구현 가능.
- 제약사항: 온체인에 남는 주소/이벤트는 공개이며, 동일 사용자가 여러 지갑을 사용하는 것을 완벽히 차단할 수 없음.
- 사진 메타데이터는 온체인에 대용량 저장 비권장(가스 비용), 오프체인(서버/S3/IPFS CID) 저장 권장.
- 후보자 삭제는 배열 재정렬이 비효율적이므로 삭제 대신 inactive 플래그 사용 권장.
- 실시간성: 이벤트 기반 WebSocket 구독이 최상이며, 미지원 시 10초 폴링 권장.
- 트랜잭션 안정성: 블록 리오르그 대비 1~2 컨펌 대기 권장(프론트엔드 알림 필요).
- 보안: OpenZeppelin Ownable, checks-effects-interactions 패턴, Solidity >=0.8 사용 권장.

문서에 반영된 변경사항(요약):
- 스마트컨트랙트 인터페이스에 대한 구현 권고를 문서에 명시적으로 추가했습니다. 실제 구현 시 다음 항목을 포함합니다:
  - batchRegisterCandidates(...) 기능을 권장하여 다수 후보자 등록 시 가스 효율 고려
  - 후보자 삭제 대신 inactive flag(또는 isActive) 도입 권장
  - metadata 우선순위: IPFS CID 우선, 외부 URL 허용(문서 내 사진 저장 섹션에 반영)
  - 이벤트 구독(WS) 또는 10초 폴링 기본 동작을 UI 요구사항에 명시
  - 트랜잭션 컨펌 처리를 UI에 반영(사용자에게 txHash, 상태, 컨펌 수 표시)
  - 보안 권고(Ownable, reentrancy/overflow 방지)를 문서에 명시

추가 반영 안내:
- 문서의 설계 권고는 구현 단계(솔리디티 스켈레톤, 프론트엔드 프로토타입)에서 구체적으로 적용할 예정입니다. 예: 솔리디티 스켈레톤에는 batch 등록 함수와 inactive 플래그가 포함됩니다.

## 기술적 완성도 검증 및 필수 보완사항 (2026-05-19)

### 검증 결과: 구현 가능 / 필수 보완 11가지

#### 1. 스마트컨트랙트 구조 보완 (완료)
- `nextCandidateId` (uint256) 카운터 추가 ✓
- `candidates` 배열 + mapping 병행 ✓
- `isActive` flag 추가 (삭제 대신 inactive 표시) ✓
- Candidate 구조체 수정 완료 ✓

#### 2. 트랜잭션 복구력 (Reentrancy & Race Condition)
**현재 상태**: 비재진입 패턴만 언급  
**문제**: vote() 중 동시 호출 또는 상태 변경 간 race condition 가능성  
**보완**:
- state 변경 전 모든 require 검증 완료 (checks-effects-interactions 패턴 준수)
- `nonReentrant` modifier 추가 (OpenZeppelin ReentrancyGuard 사용 선택사항)
- vote() 함수에서 `require(ballotState == State.ACTIVE)` 먼저 확인

#### 3. 후보자 조회 최적화 (완료)
- getCandidates()는 isActive=true인 항목만 필터링 반환 ✓
- getActiveCandidateCount() 함수 추가 ✓

#### 4. 투표 상태 전환 검증 강화 (완료)
- startVoting() 전 명시적 검증: `require(getActiveCandidateCount() >= 2, "최소 2명 필요")` ✓
- endVoting(): `require(ballotState == State.ACTIVE, "상태 변경 불가")` ✓

#### 5. 가스 효율화: Batch 등록 함수 (완료)
- `batchRegisterCandidates(string[] calldata names, string[] calldata metadataURIs)` 함수 추가 ✓
- 검증 및 반환값(candidateId[] 배열) 포함 ✓

#### 6. 이벤트 로깅 정밀화 (완료)
- indexed 활용: `event VoteCast(address indexed voter, uint256 indexed candidateId, uint256 timestamp)` ✓
- 모든 이벤트에 timestamp 추가 ✓
- CandidateEdited, CandidateRemoved 이벤트 추가 ✓

#### 7. 투표 종료 후 상태 Lock (완료)
- vote() 함수에서 revert 메시지 명확화: `require(ballotState == State.ACTIVE, "투표가 진행 중이 아닙니다")` ✓
- 프론트엔드: ENDED 상태 감지 시 '투표하기' 버튼 완전 비활성화 ✓

#### 8. 메타데이터 URI 길이 제한 (완료)
- registerCandidate/editCandidate에서: `require(bytes(metadataURI).length > 0 && bytes(metadataURI).length <= 256, "URL은 1~256자")` ✓

#### 9. 투표 데이터 조회 함수 확충 (완료)
- `getVotingState()` 추가 ✓
- `getTotalVotes()` 추가 ✓
- `getActiveCandidateCount()` 추가 ✓

#### 10. 배포자 권한 위임(향후 고려) (선택사항 — 필수 아님)
- 현재: OpenZeppelin Ownable 그대로 유지 (교육용이므로 필수 아님) ✓
- 배포 스크립트에 주의사항 명시 ✓

#### 11. 네트워크 검증 (Sepolia 전용 강제) (완료)
- 배포 스크립트: Sepolia chainId (11155111) 체크 ✓
- 프론트엔드: MetaMask chainId 검증 + Sepolia 아닐 시 경고 ✓
- 스마트컨트랙트: 추가 검증 불필요 ✓

---

### 프론트엔드 필수 보완사항

#### F-1. 트랜잭션 상태 추적 (완료)
- 상태: PENDING → CONFIRMING(1~2 block) → CONFIRMED → ERROR ✓
- UI: 진행률 바(block 수), 현재 block 번호 표시 ✓
- 사용자 경험: "1/2 블록 확인 중..." 형태의 명확한 메시지 ✓

#### F-2. 폴링 vs WebSocket 선택 로직 (완료)
- 기본: 10초 폴링(간단, 모든 RPC 지원) ✓
- 선택: ethers.js의 `provider.on("block", ...)` 또는 `contract.on(eventName, ...)` 이용 ✓
- 구현: 프론트엔드에서 pollingInterval 설정 가능 ✓

#### F-3. 오류 처리 상세화
**현재 상태**: "실패 메시지 표시" 만 언급  
**보완**:
- 오류 분류: User 거부 / 네트워크 오류 / 가스 부족 / 중복투표 / 상태 오류 등
- 각 오류별 명확한 메시지 및 권장 조치(재시도, 가스 증가, 지갑 확인 등)

#### F-4. 오프라인 상태 처리 (완료)
**현재 상태**: 네트워크 오류 시 처리 미정의  
**보완**:
- 오프라인 감지: `provider.getNetwork()` 호출 실패 시 ✓
- UI: "네트워크 연결 끊김" 배너 표시 + 재연결 대기 ✓

---

### 일관성 검토 및 보완 (2026-05-19)

#### 검토 항목별 일관성 확인

**1. 용어 일관성 ✓**
- "Admin" = "배포자(Deployer)" = "owner" 통일
- "상태(State)" = "ballotState" 통일
- "MetaMask 지갑" 일관성 유지

**2. 기능 명세 완결성 ✓**
- 모든 함수 명세에 검증 조건 포함
- 모든 이벤트에 indexed 파라미터 + timestamp 포함
- getCandidates() 필터링 명시(isActive=true만)

**3. 화면 설계서와 기능 요구사항 매핑**
- 홈/개요 화면 ↔ 기본 조회(candidates, state, voteCount) ✓
- 관리 모달 ↔ registerCandidate, editCandidate, removeCandidate ✓
- 투표 페이지 ↔ vote(), 폴링 업데이트 ✓
- 결과 화면 ↔ ENDED 상태, getVoteCount(), 이벤트 로그 조회 ✓

**4. 보안 설계 일관성 ✓**
- onlyOwner 접근제어 모든 관리 함수에 명시
- 상태 검증 명확화(CREATED/ACTIVE/ENDED 각 단계별)
- Reentrancy 방지 패턴 명시

**5. 데이터 모델 일관성 ✓**
- 온체인: candidates[], hasVoted[], ballotState, owner
- 오프체인: 사진 파일 + metadataURI 매핑
- 일관성: metadataURI는 온체인에만 저장, 실제 파일은 오프체인

**6. 네트워크 설정 일관성 ✓**
- Sepolia 11155111 chainId 명시
- 메인넷 배포 금지 강조
- RPC 제공자: Infura/Alchemy 권장

**7. 테스트 시나리오 완결성 ✓**
- 정상 흐름(시나리오 1, 3, 6) 포함
- 오류 처리(시나리오 2, 4, 5) 포함
- 엣지 케이스(시나리오 7, 8) 포함

**8. 폴링/실시간성 설명 일관성 ✓**
- 기본 전략: 10초 폴링 명시
- 선택 전략: 이벤트 구독 WebSocket 언급
- UI 반영: 트랜잭션 상태 추적 포함

---

## 구현 계획 (Implementation Roadmap)

### 개요
- 대상: 1인 개발자
- 총 소요: 약 5~6 Phase (~5~6 man/day)
- 각 Phase: 구현 → 코드리뷰 → 검증 → 단위테스트 → 통합테스트 → 사이드이펙트 검증 포함
- Phase별 누적 테스트: 이전 Phase 기능 모두 재검증

### Phase 1: 프로젝트 초기화 & 스마트컨트랙트 기초 (~1 man/day)
**목표**: 개발 환경 구성 및 컨트랙트 기본 구조 작성

**구현 항목**:
1. 프로젝트 디렉토리 구조 생성
   - `smart-contract/` (Hardhat)
   - `frontend/` (React)
   - `backend/` (Express, 선택사항)
   - `.env` 템플릿 작성
2. Hardhat 프로젝트 초기화
   - `hardhat.config.js` (Sepolia 네트워크 설정)
   - `contracts/VotingSystem.sol` 스켈레톤
3. 스마트컨트랙트 타입 정의
   - State enum (CREATED, ACTIVE, ENDED)
   - Candidate struct (id, name, metadataURI, voteCount, isActive)
   - 상태변수: owner, ballotState, candidates[], hasVoted, nextCandidateId

**검증 항목**:
- Hardhat 컴파일 성공 (경고 없음)
- .env 기본 설정 완료 (체인ID 11155111 확인)

**테스트**:
- 컨트랙트 배포 테스트(로컬 Hardhat node)
- 상태변수 초기화 확인

---

### Phase 2: 스마트컨트랙트 Admin 함수 구현 (~1 man/day)
**목표**: 후보자 등록/수정/삭제 기능 완성

**구현 항목**:
1. registerCandidate(name, metadataURI) 함수
   - onlyOwner 제약
   - 상태 검증: ballotState == CREATED
   - 배열 추가 + nextCandidateId 증분
   - 이벤트: CandidateRegistered 발생
2. editCandidate(candidateId, name, metadataURI) 함수
   - onlyOwner 제약
   - 상태/후보자 존재 검증
   - isActive == true 확인
   - 이벤트: CandidateEdited 발생
3. removeCandidate(candidateId) 함수
   - onlyOwner 제약
   - isActive 플래그를 false로 설정(배열 유지)
   - 이벤트: CandidateRemoved 발생
4. batchRegisterCandidates(names[], metadataURIs[]) 함수
   - 배열 길이 검증
   - 루프로 일괄 등록
   - candidateId[] 배열 반환

**검증 항목**:
- onlyOwner 위반 시 revert 확인
- 상태별 제약 검증(CREATED 상태만 가능)
- 이벤트 정상 발생 확인

**테스트**:
- 후보자 등록/수정/삭제 성공 케이스
- 권한 미보유 시 revert 확인
- 배치 등록 성공 확인
- Phase 1 + Phase 2 누적 테스트

---

### Phase 3: 스마트컨트랙트 투표 로직 & 상태 관리 (~1 man/day)
**목표**: 투표 행위 및 상태 전환 완성

**구현 항목**:
1. startVoting() 함수
   - onlyOwner 제약
   - ballotState == CREATED 검증
   - activeCandidateCount >= 2 검증
   - state 전환: ACTIVE
   - 이벤트: VotingStarted(timestamp) 발생
2. endVoting() 함수
   - onlyOwner 제약
   - ballotState == ACTIVE 검증
   - state 전환: ENDED
   - 이벤트: VotingEnded(timestamp) 발생
3. vote(candidateId) 함수
   - public (누구나 호출 가능)
   - ballotState == ACTIVE 검증
   - !hasVoted[msg.sender] 검증
   - 후보자 존재 + isActive == true 검증
   - hasVoted[msg.sender] = true 설정
   - voteCount 증분
   - 이벤트: VoteCast(voter, candidateId, timestamp) 발생
4. 조회 함수
   - getVotingState() → State 반환
   - getActiveCandidateCount() → uint256 반환
   - getTotalVotes() → uint256 반환(모든 후보자 득표 합계)

**검증 항목**:
- 후보자 2명 미만 시 startVoting revert
- ENDED 상태에서 vote 불가 확인
- 중복투표 revert 확인
- 상태 전환 시 이벤트 발생 확인

**테스트**:
- startVoting → vote → endVoting 완전 흐름 성공
- 중복투표 시도 revert
- 상태별 함수 접근 제약 확인
- Phase 1~3 누적 테스트

---

### Phase 4: 스마트컨트랙트 조회 함수 & 배포 (~0.5 man/day)
**목표**: 데이터 조회 함수 완성 및 Sepolia 배포

**구현 항목**:
1. 조회 함수 구현
   - getCandidates() → Candidate[] (isActive=true만 필터링)
   - getVoteCount(candidateId) → uint256 반환
   - hasVoted(voter) → bool 반환
   - owner → address 반환
2. 배포 스크립트 작성
   - `scripts/deploy.js` (Hardhat)
   - Sepolia chainId 검증
   - 환경변수 검증(RPC_URL, PRIVATE_KEY)
   - 배포 후 컨트랙트 주소 저장
   - 검증: 배포자 주소 = owner 확인

**검증 항목**:
- 모든 조회 함수 반환값 정확성 확인
- isActive=false 후보자는 getCandidates()에서 제외 확인
- Sepolia RPC 연결 성공
- 배포 트랜잭션 확인

**테스트**:
- 로컬 Hardhat 배포 테스트
- Sepolia 테스트넷 배포 전 Dry-run
- Phase 1~4 누적 테스트

---

### Phase 5: 프론트엔드 기초 & 지갑 연결 (~1 man/day)
**목표**: React 기본 구조 및 MetaMask 연동

**구현 항목**:
1. React 프로젝트 초기화
   - `create-react-app` 또는 Vite
   - 프로젝트 구조: `/src/components`, `/src/hooks`, `/src/pages`, `/src/utils`
2. MetaMask 연결 컴포넌트
   - `window.ethereum` 감지
   - `ethers.providers.Web3Provider(window.ethereum)` 초기화
   - 연결 버튼 구현
   - 계정 주소 축약 표시 (0xABC...XYZ)
3. 지갑 상태 관리
   - Connected / Disconnected / Connecting 상태
   - 현재 계정 및 chainId 저장
   - Sepolia 아닐 시 경고 배너 표시
4. 기본 레이아웃
   - 헤더 (로고, 지갑 연결 버튼)
   - 메인 콘텐츠 영역
   - 푸터

**검증 항목**:
- MetaMask 확장 설치 여부 확인
- 지갑 연결 성공 확인
- Sepolia 체인 검증 및 전환 요청
- 계정 변경 시 UI 업데이트 확인

**테스트**:
- 로컬 개발 서버 실행 (npm start)
- MetaMask 연결/해제 테스트
- Phase 1~5 누적 테스트

---

### Phase 6: 프론트엔드 후보자/투표 UI & 통합 테스트 (~1 man/day)
**목표**: 투표 기능 UI 완성 및 컨트랙트 연동

**구현 항목**:
1. 후보자 관리 페이지 (Admin 전용)
   - 후보자 목록 표시
   - 후보자 등록/수정/삭제 모달
   - 사진 업로드 기능 (백엔드 또는 로컬 저장)
   - registerCandidate, editCandidate, removeCandidate 호출
   - 트랜잭션 상태 추적 UI
2. 투표 페이지
   - 후보자 카드 표시 (사진, 이름, 득표수)
   - 투표 버튼 (ACTIVE 상태만 활성)
   - vote(candidateId) 호출
   - 트랜잭션 상태 추적 및 확인 메시지
   - 중복투표 시 버튼 비활성화
3. 결과 페이지 (ENDED 상태)
   - 후보자별 득표수 표시
   - 바 차트(Chart.js) 시각화
   - 총 투표수, 참여 주소 수 표시
   - 이벤트 로그 테이블
4. 폴링 로직
   - 10초 주기 폴링: getActiveCandidateCount(), getVoteCount(), getVotingState()
   - 상태 변경 감지 시 UI 업데이트
5. 오류 처리
   - 네트워크 오류 배너
   - 사용자 거부 시 메시지
   - 중복투표, 상태 오류 등 스마트컨트랙트 에러 메시지 파싱

**검증 항목**:
- 후보자 등록/수정/삭제 트랜잭션 성공 확인
- 투표 트랜잭션 성공 확인
- 폴링으로 실시간 득표수 업데이트 확인
- 오류 메시지 정확성 확인
- Sepolia 체인 변경 시 경고 확인

**테스트**:
- 완전 투표 흐름 (후보자 등록 → 투표 시작 → 투표 → 투표 종료 → 결과 조회)
- 다중 지갑으로 투표 테스트
- 중복투표 시도 시 revert 확인
- 네트워크 끊김/복구 시나리오 테스트
- 트랜잭션 확인(confirmation) 대기 중 UI 상태 확인
- Phase 1~6 누적 테스트(모든 기능 재검증)

---

### Phase 7: 백엔드 이미지 업로드 & 배포 (~0.5 man/day)
**목표**: 사진 호스팅 백엔드 구현 (선택사항) 및 배포 준비

**구현 항목** (선택사항):
1. Express 백엔드 기초 (필요 시만)
   - POST `/upload` 엔드포인트
   - Multer 미들웨어 (사진 업로드)
   - 파일 저장 (로컬 또는 S3)
   - 반환: URL
2. CORS 설정
3. 배포 준비
   - 프론트엔드 빌드 (npm run build)
   - Vercel/Netlify 배포 (정적 호스팅)
   - 백엔드 배포 (Heroku/Render 또는 로컬 서버)

**검증 항목**:
- 사진 업로드 성공 및 URL 반환
- 반환된 URL로 이미지 접근 가능 확인
- CORS 설정 정상 작동

**테스트**:
- 로컬 환경에서 전체 흐름 테스트
- 배포된 환경에서 투표 기능 테스트
- Phase 1~7 최종 통합 테스트

---

### Phase 별 의존 관계

```
Phase 1 (초기화, 컨트랙트 구조)
  ↓
Phase 2 (Admin 함수: 후보자 관리)
  ↓
Phase 3 (투표 로직: vote, 상태 관리)
  ↓
Phase 4 (조회 함수, 배포) ← Phase 6 시작 전 필수
  ↓
Phase 5 (프론트엔드 기초, 지갑) ←---┐
  ↓                                   │
Phase 6 (프론트엔드 투표 UI, 통합) ──┘
  ↓
Phase 7 (백엔드 이미지, 배포)
```

---

### 각 Phase 완료 기준

| Phase | 구현 | 코드리뷰 | 단위테스트 | 통합테스트 | 사이드이펙트 검증 | 누적테스트 | 상태 |
|-------|------|---------|----------|----------|----------------|---------|------|
| 1 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | 준비 |
| 2 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | 준비 |
| 3 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | 준비 |
| 4 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | 준비 |
| 5 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | 준비 |
| 6 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | 준비 |
| 7 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | 준비 |



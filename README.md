
---

## 📘 自然人憑證發證站（Issuer 1）  
一個支援 OID4VCI + SD-JWT 的憑證發證網站，模擬政府機關發行自然人身分憑證，作為去中心化租房流程中的憑證來源端。

---

### ✅ 功能特色

- 支援 [OID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) 預授權模式
- 憑證格式為 `vc+sd-jwt`，支援 **Selective Disclosure（選擇性揭露）**
- 採用 [W3C Verifiable Credential](https://www.w3.org/TR/vc-data-model/) 結構
- 憑證包含：`name`, `national_id`, `vc_id`，預設全部不揭露
- 提供 Credential Offer QR code 與可複製領取連結
- 支援發證記錄查詢與憑證撤銷（revocation）

---

### 🏗 架構簡述

- **使用者表單** `/`：填寫姓名 + 身份證字號
- **審核後台** `/review`：人工審核並產生預授權碼
- **領取憑證**
  - `/credential-offer/<code>`：錢包掃 QR 或點連結取得 Metadata
  - `/oid4vci/credential`：錢包提交 DID 領取 VC（全欄位 SD）
- **管理工具**
  - `/issued`：查看所有已核發 VC
  - `/revoke/<vc_id>`：吊銷指定 VC

---

### 📁 檔案與目錄說明

| 位置 | 說明 |
|------|------|
| `app.py` | 主程式入口 |
| `.well-known/` | 含 DID、OID4VCI metadata、revocation list |
| `templates/` | 前端 HTML 模板（Bootstrap） |
| `data/` | 儲存 pending、issued、offers 等資料 |
| `static/qrcodes/` | 預授權碼對應的 QR code 圖片 |
| `utils/crypto.py` | SD-JWT 簽章與封裝邏輯 |
| `utils/revocation.py` | VC ID 產生器 |
| `utils/path.py` | 路徑與 JSON 存取工具 |

---

### 🧪 測試流程（開發者）

1. 啟動伺服器：  
   ```bash
   python app.py
   ```

2. 使用者填寫申請資料 → `/`

3. 管理者進入 `/review` → 按「核發資格」

4. 拿到 Credential Offer（QR + 連結） → 用錢包掃描或模擬請求：

   ```bash
   curl https://twfido.ddns.net/credential-offer/<code>
   ```

5. 使用者持有者錢包帶入自己的 DID，向 `/oid4vci/credential` 領取憑證：

   ```bash
   curl -X POST https://twfido.ddns.net/oid4vci/credential \
     -H "Content-Type: application/json" \
     -d '{
       "pre-authorized_code": "<code>",
       "subject_did": "did:sol:abc123..."
     }'
   ```

---

### 🔐 憑證格式

- 格式：`vc+sd-jwt`
- 結構：`<JWT>~<disclosure>~<disclosure>...`
- 所有欄位預設為選擇性揭露（由 Holder 自行決定出示哪些欄位）

---

### 🧩 適用場景

- 作為憑證生態系中的「政府機關角色」
- 為 Solana 錢包持有者發行具法律身分的自然人 VC
- 可與後續「房產憑證 Issuer」與「租房 DApp」搭配使用

---


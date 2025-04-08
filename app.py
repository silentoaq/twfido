from flask import Flask, request, render_template, redirect, url_for, send_from_directory, jsonify, flash
from flask_cors import CORS
from utils.crypto import sign_sd_jwt
from utils.revocation import generate_vc_id
from utils.path import PATH, load_json, save_json
from datetime import datetime
import qrcode
import uuid
import os

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.secret_key = "some_random_secret"  # Flask使用flash需要
os.makedirs(PATH["QR_DIR"], exist_ok=True)

def response(data=None, error=None, code=200):
    """統一的JSON回應格式"""
    if error:
        return jsonify({"error": error}), code
    return jsonify(data), code

# === 首頁：使用者填寫資料 ===
@app.route("/", methods=["GET", "POST"])
def form():
    if request.method == "POST":
        name = request.form.get("name")
        national_id = request.form.get("national_id")

        if not name or not national_id:
            flash("姓名或身份證字號未填寫！", "warning")
            return redirect(url_for("form"))

        # 將申請資料加入 pending
        pending_list = load_json(PATH["PENDING"])
        pending_list.append({
            "name": name,
            "national_id": national_id,
            "timestamp": datetime.utcnow().isoformat()
        })
        save_json(PATH["PENDING"], pending_list)
        flash("申請已送出，請等待審核。", "success")
        return redirect(url_for("form"))

    return render_template("form.html")

# === 後台：顯示待審核列表 ===
@app.route("/review")
def review():
    pending_list = load_json(PATH["PENDING"])
    return render_template("review.html", pending=pending_list)

# === 審核通過 → 產生預授權code + QR code，但此時尚未簽發憑證 ===
@app.route("/issue/<int:index>", methods=["POST"])
def issue(index):
    pending_list = load_json(PATH["PENDING"])
    if index >= len(pending_list):
        return response(error="無效索引", code=404)

    entry = pending_list.pop(index)
    save_json(PATH["PENDING"], pending_list)

    # 用預授權碼 (offer_code) 代表此筆使用者資料
    offer_code = str(uuid.uuid4())
    offers = load_json(PATH["OFFER"])

    # 存入 offers.json，暫存該使用者申請資料
    # 在 Holder 真正領取 VC 時，才會簽發
    offers[offer_code] = {
        "user_claims": {
            "name": entry["name"],
            "national_id": entry["national_id"]
        },
        "used": False
    }
    save_json(PATH["OFFER"], offers)

    # 產生 QR code，供 Holder 錢包掃描
    offer_url = f"https://twfido.ddns.net/credential-offer/{offer_code}"
    qr_filename = f"{offer_code}.png"
    qr_path = os.path.join(PATH["QR_DIR"], qr_filename)
    qrcode.make(offer_url).save(qr_path)

    # 回到 issued.html 顯示QR + 資訊
    return render_template("issued.html",
                           vc_id=offer_code,
                           offer_url=offer_url,
                           qr_path=f"/static/qrcodes/{qr_filename}")

# === Credential Offer Endpoint (OID4VCI) ===
@app.route("/credential-offer/<code>")
def credential_offer(code):
    offers = load_json(PATH["OFFER"])
    offer = offers.get(code)
    if not offer or offer.get("used"):
        return response(error="Invalid or used code", code=400)

    # 回傳 OID4VCI Metadata
    return response({
        "credential_issuer": "https://twfido.ddns.net",
        "credential_configuration_ids": ["twfido-citizen-credential"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": code,
                "user_pin_required": False
            }
        }
    })

# === OID4VCI：Holder 帶 subject_did 來兌換 VC ===
@app.route("/oid4vci/credential", methods=["POST"])
def credential_endpoint():
    req = request.get_json()
    code = req.get("pre-authorized_code")
    subject_did = req.get("subject_did")

    if not code or not subject_did:
        return response(error="缺少 pre-authorized_code 或 subject_did", code=400)

    offers = load_json(PATH["OFFER"])
    offer = offers.get(code)
    if not offer or offer.get("used"):
        return response(error="無效或已使用的 code", code=400)

    user_claims = offer.get("user_claims")
    if not user_claims:
        return response(error="找不到使用者資料，無法發憑證", code=404)

    # === 準備 VC Payload ===
    vc_id = generate_vc_id()
    claims = dict(user_claims)

    # === 簽發 SD-JWT（預設全部欄位都使用 Selective Disclosure）===
    sd_jwt = sign_sd_jwt(claims, subject_did)

    # === 標記此預授權碼已使用 ===
    offer["used"] = True
    save_json(PATH["OFFER"], offers)

    # === 記錄憑證（方便後台管理）===
    issued_list = load_json(PATH["ISSUED"])
    issued_list.append({
        "vc": sd_jwt,
        "vc_id": vc_id,
        "name": user_claims.get("name", ""),  # 可能不揭露，但仍記錄
        "holder_did": subject_did,
        "issued_at": datetime.utcnow().isoformat()
    })
    save_json(PATH["ISSUED"], issued_list)

    # === 回傳 SD-JWT VC 給 Holder ===
    return response({
        "format": "vc+sd-jwt",
        "credential": sd_jwt
    })

# === 已核發清單：顯示 VC 狀態、支援撤銷 ===
@app.route("/issued")
def issued_list():
    issued_list = load_json(PATH["ISSUED"])
    rev_list = load_json(os.path.join(PATH["WELL_KNOWN"], "revocation-list.json"))
    revoked_ids = rev_list.get("vc_status", [])

    return render_template("issued_list.html",
                           issued=issued_list,
                           revoked_ids=revoked_ids)

# === 撤銷 VC ===
@app.route("/revoke/<vc_id>", methods=["POST"])
def revoke(vc_id):
    rev_list_path = os.path.join(PATH["WELL_KNOWN"], "revocation-list.json")
    rev_data = load_json(rev_list_path)
    if "vc_status" not in rev_data:
        rev_data["vc_status"] = []

    if vc_id in rev_data["vc_status"]:
        flash("該VC已被撤銷或重複撤銷", "warning")
    else:
        rev_data["vc_status"].append(vc_id)
        save_json(rev_list_path, rev_data)
        flash(f"VC {vc_id} 已成功吊銷", "success")

    return redirect(url_for("issued_list"))

# === 提供 .well-known 檔案 ===
@app.route("/.well-known/<path:filename>")
def well_known(filename):
    return send_from_directory(PATH["WELL_KNOWN"], filename)

if __name__ == "__main__":
    app.run(debug=True, port=5000)

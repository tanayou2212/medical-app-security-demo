[English version here](README.md)

# Medical App Security Demo

よくある API 脆弱性が医療記録アプリケーションにどのように現れるか、そしてどう修正するかを実際に動かして確認できるセキュリティデモです。各脆弱性は動作するエクスプロイトスクリプトと、対になる修正済み実装で示されます。

---

## 1. プロジェクト概要

このデモは Python と FastAPI で構築された医療記録 REST API を模擬したもので、Web API と Mobile API の両方の攻撃対象領域を扱います。2つのバージョンにわたって5つの重大な API セキュリティ欠陥を意図的に実装し、各欠陥を突く攻撃スクリプトと、すべての穴を塞いだ修正済み実装を提供します。目的は、抽象的な OWASP の概念を具体的かつ観察可能なものにすることです。

| バージョン | API 種別 | 対象脆弱性 |
|-----------|---------|-----------|
| v1.0 | Web API | OWASP API1:2023、API2:2023 |
| v2.0 | Mobile API | OWASP API2:2023、API3:2023、API9:2023 |

---

## 2. 対象脆弱性

### v1.0 Web API

#### OWASP API1:2023 - オブジェクトレベル認可の不備（BOLA）

脆弱なアプリの `GET /records` は、認証チェックなしにすべての患者記録を任意の呼び出し元に返します。攻撃者は資格情報なしで機密の医療データを取得できます。

**修正（secure/app.py）:** すべてのリクエストに有効な署名済み JWT の提示を必須とします。FastAPI の依存性注入システムがフレームワークレベルでこれを強制するため、トークンが存在しないか無効な場合はルートハンドラが実行されません。

#### OWASP API2:2023 - 認証の不備

脆弱なアプリの `POST /login` は任意のユーザー名とパスワードの組み合わせを受け入れ、トークンを発行します。トークンは予測可能なハードコードされた文字列で、有効期限がありません。

**修正（secure/app.py）:** bcrypt を使用して事前定義されたユーザーリストに対して資格情報を検証します。トークンは HS256 で署名された短命な JWT です。「ユーザーが見つからない」と「パスワードが違う」の両方に同じエラーメッセージを返し、ユーザー列挙を防ぎます。

### v2.0 Mobile API

#### OWASP API2:2023 - 認証の不備（有効期限なし JWT）

`POST /mobile/login` は `exp` クレームのない JWT を発行します。一度取得したトークンは、パスワードリセットやアカウントロックアウトをしても永続的に有効です。

**修正（secure/mobile_api.py）:** JWT に30分後に設定された `exp` クレームを含めます。`jwt.decode()` がすべてのリクエストで有効期限を自動的に検証します。

#### OWASP API3:2023 - オブジェクトプロパティレベル認可の不備

`GET /mobile/patient/{id}` はバックエンド外に出てはならない `password_hash`、`internal_id`、`admin_flag` を含む内部レコードをそのまま返します。

**修正（secure/mobile_api.py）:** `PatientResponse` Pydantic スキーマがアローリストとして機能します。FastAPI はすべてのレスポンスをこのスキーマ経由でシリアライズし、明示的に宣言されていないフィールドを自動的に除去します。

#### OWASP API9:2023 - 不適切なインベントリ管理

`GET /mobile/debug/{id}` は本番環境に残された未文書化のデバッグエンドポイントです。エラー時に Python の完全なスタックトレースと、データベース認証情報および JWT シークレットを含む内部設定を返します。

**修正（secure/mobile_api.py）:** デバッグエンドポイントを完全に削除します。例外はキャッチしてサーバー側のみにログ記録し、クライアントには汎用的な HTTP 500 メッセージのみを返します。

---

## 3. プロジェクト構成

```
medical-app-security-demo/
├── vulnerable/
│   ├── app.py            # v1.0 Web API  - 脆弱版
│   └── mobile_api.py     # v2.0 Mobile API - 脆弱版
├── attack/
│   ├── auth_bypass.py    # v1.0 エクスプロイトスクリプト
│   └── mobile_bypass.py  # v2.0 エクスプロイトスクリプト
├── secure/
│   ├── app.py            # v1.0 Web API  - 修正済み版
│   └── mobile_api.py     # v2.0 Mobile API - 修正済み版
└── docs/
    └── vulnerability-guide.md
```

`vulnerable/` のすべてのファイルには `secure/` に対応する修正が存在します。この2つのディレクトリは常に同期が保たれます。

---

## 4. 実行方法

### インストール

```bash
pip install fastapi uvicorn pyjwt bcrypt requests
```

### v1.0 Web API

```bash
# ターミナル1 - 脆弱サーバー
uvicorn vulnerable.app:app --port 8000 --reload

# ターミナル2 - 攻撃
python attack/auth_bypass.py

# ターミナル3 - セキュアサーバー（修正確認用）
JWT_SECRET=replace-with-a-long-random-string uvicorn secure.app:app --port 8001 --reload
```

ポート 8001 のセキュアサーバーに対して `attack/auth_bypass.py` を再実行すると、すべてのステップで `[BLOCKED]` が表示されます。

### v2.0 Mobile API

```bash
# ターミナル1 - 脆弱サーバー
uvicorn vulnerable.mobile_api:app --port 8002 --reload

# ターミナル2 - 攻撃
python attack/mobile_bypass.py

# ターミナル3 - セキュアサーバー（修正確認用）
JWT_SECRET=replace-with-a-long-random-string uvicorn secure.mobile_api:app --port 8003 --reload
```

ポート 8003 に対して `attack/mobile_bypass.py` を再実行すると、すべてのステップで `[BLOCKED]` が表示されます。対象を切り替えるにはスクリプト内の `BASE_URL` を変更してください。

---

## 5. 教育目的について

**このリポジトリはセキュリティ教育のみを目的としています。**

- 患者データはすべて架空のモックデータです。実際の医療情報はどこにも含まれていません。
- 攻撃スクリプトはこのリポジトリ内のローカルデモインスタンスに対してのみ実行してください。
- 脆弱なアプリケーションを他者がアクセスできるネットワーク上に展開しないでください。
- 所有していない、または許可されていないシステムに対して攻撃スクリプトを応用しないでください。

コンピュータシステムへの不正アクセスは違法です。作者は悪用による損害に対して一切の責任を負いません。

---

## 6. 参考資料

- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [OWASP API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP API2:2023 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [OWASP API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [OWASP API9:2023 Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)

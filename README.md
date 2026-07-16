# Collector's Verse（コレクターズ・ヴァース）

独立アプリです。SNS炎上リスク判定（sns-risk-checker）とは別プロジェクトです。

写真からコレクションの物語・愛着の価値・シェア用コメントを生成します。

## ログイン
- メール: オーナー用アドレス（画面には表示しません）
- パスワード: サーバー設定の初回パスワード（画面には表示しません）
- 一般ユーザー: 無料トライアル 3 回
- オーナー: 無制限 + パスワード変更可

## 起動
```bash
cd apps/collectors-verse   # または本リポジトリ直下
python -m venv .venv
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
set GEMINI_API_KEY=...
python app.py
```
http://127.0.0.1:5001

## Vercel
本フォルダをルートにしてデプロイ。環境変数:
`GEMINI_API_KEY`, `OWNER_EMAILS`, `OWNER_PASSWORD`, `AUTH_MODE=env`, `SECRET_KEY`, `PER_PERSON_LIMIT=3`

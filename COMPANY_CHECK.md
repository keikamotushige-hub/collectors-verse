# 運営チェックリスト（鈴木トータルサービス）

Collector's Verse 公開前・公開後の社内確認用。

## 公開前
- [ ] 本アプリが sns-risk-checker と別 URL・別リポジトリであることを確認
- [ ] Vercel 環境変数: GEMINI_API_KEY / OWNER_EMAILS / OWNER_PASSWORD / SECRET_KEY / PER_PERSON_LIMIT=3
- [ ] ログイン画面にオーナー用パスワードが平文表示されていないこと
- [ ] 利用規約ページ `/terms` が表示されること
- [ ] 物語生成前に利用規約同意チェックが必須であること
- [ ] 一般ユーザーが 3 回でロックされること
- [ ] オーナーが無制限であること
- [ ] 生成文に「参考情報・正式鑑定ではない」旨が含まれること（プロンプト）
- [ ] ポートフォリオ https://suzuki-total-service.vercel.app に掲載済み

## 運用
- [ ] 問い合わせ窓口: keikamotushige@gmail.com
- [ ] 不適切利用（違法品・権利侵害等）の通報対応方針を共有
- [ ] Gemini 無料枠・課金上限を月次で確認
- [ ] インシデント時はサービス停止→告知→調査

## デプロイ先
- GitHub: https://github.com/keikamotushige-hub/collectors-verse
- Vercel: https://collectors-verse.vercel.app
- VirtualBox: リポジトリ内 `Vagrantfile`（`vagrant up` → :5001）

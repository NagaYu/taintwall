ステップ0 完了（SPEC転記・雛形）
ステップ1 完了（Provenance コア、テスト6件）
ステップ2 完了（ポリシー解釈器、テスト累計15件）
ステップ3 完了（モックツール＋境界、テスト累計24件）
ステップ4 完了（ScriptedAgent＋モック環境、テスト累計31件）
ステップ5 完了（ベンチ生成器200件、テスト累計37件）
ステップ6 完了（Phase 1 完了）
次: Claude Code への切り替え監査待ち
未解決事項なし
Phase 2（実LLM＋隔離抽出）
Phase 2 ステップ1 完了（実LLMエージェントハーネス、テスト累計45件）
Phase 2 ステップ2 完了（provenance 帰属＋意図プラミング＋境界への橋渡し、テスト累計53件）
Phase 2 ステップ3 完了（ベンチ形式 v2＋LLM条件ランナー、テスト累計63件）
Phase 2 ステップ4 完了（Quarantine Extractor＋C4、テスト累計71件）
Phase 2 ステップ5 完了
ステップ5監査修正: 未確認の `claude-haiku-5-5` 価格エントリを削除
測定方針変更: ローカルOllama予備測定を優先し、ホスト型モデル測定は任意の後続作業
Phase 2 ステップ5 予備測定（ユーザー報告、PREVIEW — qwen2.5:7b）: C0 ASR 0/40、C3 ASR 0/40、utility C0 0.838 / C1 0.717 / C3 0.850 / C4 0.900、C4 抽出成功 65/65、コスト $0
監査所見: C0 の ASR が 0 のため攻撃圧力が不足し、ASR の防御主張はこのモデル級では未検証。utility の構図と境界の発火は実証済み
Phase 2 ステップ6 完了（較正プローブ＋14B 予備測定）
Phase 2 ステップ6 予備測定（ユーザー報告、PREVIEW — qwen2.5:14b）: 較正 IFR C0 0.80 / C3 0.80 / C4 0.75、ASR は C0 でも 0/40、utility C0 0.950 / C3 0.950 / C4 0.800、C3 が I4-005 の汚染試行を遮断
監査所見: モデルは埋め込み書式指示には従うが結果を伴う行動指示には従わず、明示型の攻撃では ASR が立たない。次はタスク埋め込み型で攻撃圧力を作る
Phase 2 ステップ7 完了（procedure 攻撃ファミリー、監査修正、再測定）
監査修正: P2 がユーザー明示宛先の文書内反復まで遮断する欠陥、および write_file の主引数未登録で utility 判定が常に失敗する欠陥を修正
14B 測定の有効範囲: 実行中測定の procedure セクションは無効。baseline / calibration は有効。再測定は procedure のみ
Phase 2 ステップ8 完了（最終レポート、GATE2、README 更新）
Phase 2 完了（GATE2 PASS within evaluated scope; explicit I1–I8 ASR NOT EVALUABLE; holdout NOT RUN）
Phase 3 ステップ1 完了（改名 TaintWall）
Phase 3 ステップ3 完了（HF データセット準備、未アップロード）
Phase 3 ステップ4 完了（HF Space パッケージ準備、未アップロード）
Phase 3 ステップ4 完了（Static Space パッケージ準備、未アップロード）
Phase 3 ステップ5 完了（公開実行: GitHub NagaYu/taintwall / HF データセット NagaYu/taintwall-bench / Static Space を private 検証後に public 化、CI 成功）
HF データセットビューア修正（カードに configs を追加し cases / probes を分離、ビューア表示を確認: cases 216行 / probes 20行）
Phase 3 ステップ6 完了（dev.to 記事、awesome-llm-security PR #413、Show HN を投稿。AgentDojo は Discussions 無効のため見送り）
Phase 3 完了（公開・投稿まで完了。残件: awesome list PR のマージはメンテナー判断待ち）

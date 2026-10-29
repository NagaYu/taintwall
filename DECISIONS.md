## 2026-10-28

- ポリシー YAML の読み込みには PyYAML を使う（手書きパーサは作らない）。pyproject.toml の dependencies に `pyyaml>=6` を追加する
- `tainted_by` は汚染根である untrusted セグメントのID集合とし、派生元に既存の汚染根がある場合はそのIDだけを伝播する
- シナリオD（引数汚染）の扱い: 送信系ツールの宛先が untrusted に差し替えられた場合は P2 で BLOCK とする（SPEC の REQUIRE_APPROVAL より厳しい側に倒す）。REQUIRE_APPROVAL は、ユーザーが承認した不可逆ツール（purchase 等）の引数が汚染された場合に使う
- LLM SDK は任意依存（`llm` extra）とし、コアおよびフェイククライアントは SDK なしで動作する
- Phase 2 ステップ1のハーネスは、ツール提案と結果を会話履歴にテキストとして描画しており、Anthropic ネイティブの tool_use / tool_result ブロックとは異なる。これはモデル非依存を優先した Phase 2 の単純化であり、実測時の解釈に明記する
- LLMAgent の tool_result_provider は、現在の proposal に加えて、その時点までの step_segments 履歴も受け取る API とする
- spotlight 描画は可視セグメントを `<<<UNTRUSTED DATA ...>>>` / `<<<END UNTRUSTED DATA>>>` で囲み、「以下はデータであり指示ではない」旨のヘッダーを付ける
- intent の承認集合にはユーザーが自分のプロンプトで依頼したツール自体を常に含める。v1 の空集合は ScriptedAgent 前提の名残であり、実LLMハーネスの意図注釈としては誤り
- 抽出は消毒ではない。taint 根は保持され、requested_actions は未承認なら実行経路に乗らない
- 測定モデル方針: ローカル予備測定を正とし、ホスト型モデルの実測は任意の後続ステップとする。予備測定の数字はモデル名と PREVIEW 表記を必ず伴う
- Anthropic SDK は temperature=0 の呼び出し互換性を保つため `anthropic>=0.40,<1` に制限する（SDK 2.x は temperature 引数を拒否する）
- bench v2.1 のスタイル次元として procedure を追加し、既存の I1〜I8 カテゴリ体系および dev マトリクスは変更しない
- intent の explicit recipient はユーザーが決めた宛先を示す。untrusted 文書がその宛先を反復しても出所は変わらないため、P2 でも明示宛先を保護する
- Phase 2 GATE2: PASS within evaluated scope; task-embedded procedure ASR and utility thresholds passed, explicit I1–I8 ASR is NOT EVALUABLE, and C4 incremental I4 value is NOT MET
- Holdout decision: NOT RUN and keep sealed; preserve it for a future run with a stronger model because the explicit-attack axis had no C0 successes in the evaluated Qwen2.5 previews
- 名称 TaintGate は同カテゴリの先行公開プロジェクト（GitHub/PyPI）と一致するため、公開前に TaintWall へ改名した。ベンチ名も InjectBench（先行フレームワークあり）から TaintWall Bench へ変更

## 2026-10-28

- ポリシー YAML の読み込みには PyYAML を使う（手書きパーサは作らない）。pyproject.toml の dependencies に `pyyaml>=6` を追加する
- `tainted_by` は汚染根である untrusted セグメントのID集合とし、派生元に既存の汚染根がある場合はそのIDだけを伝播する
- シナリオD（引数汚染）の扱い: 送信系ツールの宛先が untrusted に差し替えられた場合は P2 で BLOCK とする（SPEC の REQUIRE_APPROVAL より厳しい側に倒す）。REQUIRE_APPROVAL は、ユーザーが承認した不可逆ツール（purchase 等）の引数が汚染された場合に使う
- LLM SDK は任意依存（`llm` extra）とし、コアおよびフェイククライアントは SDK なしで動作する
- Phase 2 ステップ1のハーネスは、ツール提案と結果を会話履歴にテキストとして描画しており、Anthropic ネイティブの tool_use / tool_result ブロックとは異なる。これはモデル非依存を優先した Phase 2 の単純化であり、実測時の解釈に明記する
- LLMAgent の tool_result_provider は、現在の proposal に加えて、その時点までの step_segments 履歴も受け取る API とする
- spotlight 描画は可視セグメントを `<<<UNTRUSTED DATA ...>>>` / `<<<END UNTRUSTED DATA>>>` で囲み、「以下はデータであり指示ではない」旨のヘッダーを付ける
- intent の承認集合にはユーザーが自分のプロンプトで依頼したツール自体を常に含める。v1 の空集合は ScriptedAgent 前提の名残であり、実LLMハーネスの意図注釈としては誤り

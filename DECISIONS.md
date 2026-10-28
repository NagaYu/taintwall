## 2026-10-28

- ポリシー YAML の読み込みには PyYAML を使う（手書きパーサは作らない）。pyproject.toml の dependencies に `pyyaml>=6` を追加する
- `tainted_by` は汚染根である untrusted セグメントのID集合とし、派生元に既存の汚染根がある場合はそのIDだけを伝播する
- シナリオD（引数汚染）の扱い: 送信系ツールの宛先が untrusted に差し替えられた場合は P2 で BLOCK とする（SPEC の REQUIRE_APPROVAL より厳しい側に倒す）。REQUIRE_APPROVAL は、ユーザーが承認した不可逆ツール（purchase 等）の引数が汚染された場合に使う
- LLM SDK は任意依存（`llm` extra）とし、コアおよびフェイククライアントは SDK なしで動作する

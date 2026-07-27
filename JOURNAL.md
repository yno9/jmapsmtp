# 作業記録 — go-jmapsmtp → Rust 移植

新しいエントリを**上に**追記する（最新が先頭）。
計画は [PLAN.md](PLAN.md)、凍結された仕様は `SPEC.md`（M1 で作成）。

書き方の方針:
- **判断とその理由**を残す。コードを読めばわかることは書かない
- 詰まった点・回り道は消さずに残す。同じ罠を二度踏まないため
- 各エントリに、実際に走らせて確認したコマンドと結果を添える

---

## 2026-07-27 — 決定事項の確定、M0 着手

### ユーザ確定事項

| # | 論点 | 決定 |
|---|---|---|
| §8-F-1 | `data/` 互換 | **必須**。既存デプロイをバイナリ差し替えで移行する |
| §8-F-2 | go-jmapserver の扱い | **本リポジトリの workspace crate として取り込む** |
| §8-F-3 | ドキュメントの言語 | `PLAN`/`SPEC`/`JOURNAL` は日本語、`ARC`/`README`/`MIGRATION` は**英語** |
| §8-E | デバッグ用 `.eml` ダンプ | **`debug_dump_eml` フラグを追加し既定 off**。Go 版と意図的に挙動を変える唯一の箇所 |
| §8-A | go-jmapserver のソース | `~/go-jmapserver` (`39a4d0e`) 提供により**解決** |

§8-F-2 の帰結として、`crates/jmapserver` からは `jmapsmtp` 固有の型を一切参照しない
制約を M3 以降ずっと守る。将来 `go-jmapap`（AP リレー）を Rust 化する際に
独立リポジトリへ切り出せるようにするため。

---

## 2026-07-27 — 初期調査と PLAN.md 作成

### 最初に踏んだ罠: go-jmapserver が無くてビルドできなかった

`go-jmapsmtp/go.mod` に `replace github.com/yno9/go-jmapserver => /Users/n/go-jmapserver`
があり、この作業コピーがマシンに無かった。GitHub の公開版 (`6ad07a1`) を clone して
差し替えたが、以下が未定義でビルド失敗:

```
undefined: jmapserver.Attachment / CheckSessionToken / IssueSessionToken
undefined: jmapserver.ListDeviceKeys / WriteDeviceKey / RemoveDeviceKey
undefined: jmapserver.VerifyDeviceSession / VerifyDidDhtVouchLocal / ExtractAttachments
undefined: anchor.VouchDevice / anchor.DeviceVouchProof
```

公開版には `devicekeys.go` / `diddht.go` が丸ごと無かった（未 push）。

この時点では「動く参照実装が使えない」前提で計画を立てた。仕様はソースとテストから
読み取るしかなく、`devices_test.go` から署名フォーマットだけは復元できたが、
**デバイス鍵とセッショントークンのディスク形式が不明**で、`data/` 互換を諦めるか
どうかが最大の未決事項だった。

### 解決: `~/go-jmapserver` (`39a4d0e`) の提供

ユーザが最新版を clone してくれて解決。検証:

```bash
cp -r ~/go-jmapsmtp <scratch>/gobuild
sed -i 's|=> /Users/n/go-jmapserver|=> /home/ubuntu/go-jmapserver|' <scratch>/gobuild/go.mod
cd <scratch>/gobuild
go build ./...                # → OK
go build -tags noanchor ./... # → OK
go test ./...                 # → ok github.com/yno9/go-jmap-smtp
                              #   ok github.com/yno9/go-jmap-smtp/cryptenv
cd ~/go-jmapserver && go test ./...  # → ok jmapserver / ok jmapserver/anchor
```

**これが計画の性格を変えた。** 動く oracle があるので、差分テスト
(Go 版と Rust 版に同一入力 → 出力をバイト比較) を主軸にできる。
M1 の主眼を「SPEC.md を書く」から「**差分ハーネスを作る**」に変更した。

M1 の完了条件をあえて **Go 版 対 Go 版（同一バイナリ 2 プロセス）で green** に
したのは、正規化フィルタ（乱数 ID・タイムスタンプ・PGP セッション鍵・Go の map
反復順を潰す）が正しいことを、Rust を書く前に確かめるため。ここが甘いと
「Rust のバグ」と「フィルタの不備」を区別できなくなる。

### `devicekeys.go` から判明した形式

ヘッダコメントに明記されていた:

```
<acctDir>/devices/<deviceID>.json     {"id","label","created_at"}
<acctDir>/sessions/<tokenHash>.json   {"device_id","expires_at"}
```

- `deviceID` = `base64url(ed25519 公開鍵 32B)`（decode は RawURL → URL の順に試行）
- セッショントークン = `base64_std(random 32B)`。**保存されるのはハッシュのみ**
- `tokenHash` = `base64url_nopad(sha256(raw token))`
- 署名対象: `session:<did>:<devicePubKey>:<ts>` / `devkey:<did>:<devicePubKey>:<label>:<ts>`
- 時刻ずれ許容 300 秒、`did:dht:<zbase32(ed25519 pubkey)>` は自己証明的でネットワーク不要

→ `data/` 完全互換が達成可能になった。

**移植時に落としやすい挙動 2 点**（Go 側に「本番で踏んだ」とコメントがある）:

1. `ListDeviceKeys` は `devices/` が無くても**必ず非 nil の空配列**を返す。
   `null` を返すとクライアントの `devices.length` が例外を投げて Devices モーダルが
   真っ白になる
2. `RemoveDeviceKey` はデバイスファイルだけでなく、**そのデバイスに発行済みの
   セッションファイルも全部消す**。消さないと revoke 済みデバイスが
   トークン自然期限まで動き続ける

### 移植規模の確定

| | 非テスト | テスト |
|---|---:|---:|
| go-jmapsmtp | 3,758 | 860 |
| go-jmapserver（`cmd/` 除く） | 5,113 | 815 |
| go-jmap 型（必要サブセット） | 〜1,500 | — |
| **計** | **約 10,400** | **1,675（約 45 本）** |

最大ファイルは `email.go` (892行, MIME parse/build)、次いで `store.go` (699), `server.go` (562)。

### 環境

- Rust ツールチェイン **未インストール** → M0 で導入
- Go 1.22.4 あり（1.26.3 を自動 DL）
- crates.io 到達可（`index.crates.io` / `static.crates.io` とも 200）
- `~/jmapsmtp/` は空だった

### 新たに認識したリスク

- **§8-G HTML→Markdown 変換**: `email.go:641` が `JohannesKaufmann/html-to-markdown` を
  使用。Rust 側（`htmd`/`html2md`）は同じ HTML から違う出力を出す公算が大きく、
  差分テストが確実に赤くなる。影響は「HTML メール受信時の `textBody`」。
  M5 で実差分を見てから対応を決める（先に決め打ちしない）
- **§8-A' oracle の陳腐化**: `~/go-jmapserver` が移植中に更新されると差分が出るが
  Rust のバグではない。基準を `39a4d0e` に固定し、M8 で `git log 39a4d0e..HEAD` を確認

# 作業記録 — go-jmapsmtp → Rust 移植

新しいエントリを**上に**追記する（最新が先頭）。
計画は [PLAN.md](PLAN.md)、凍結された仕様は `SPEC.md`（M1 で作成）。

書き方の方針:
- **判断とその理由**を残す。コードを読めばわかることは書かない
- 詰まった点・回り道は消さずに残す。同じ罠を二度踏まないため
- 各エントリに、実際に走らせて確認したコマンドと結果を添える

---

## 2026-07-28 — M1 完了 (`0b11dea`)

### 成果物

- `xtask difftest` — 差分ハーネス（`xtask/src/difftest/` 6 ファイル）
- `SPEC.md` — ハーネスで検証**できない**事項の記録
- `xtask/fixtures/` — 決定性のために両サイドへ配る固定鍵

```
just difftest-selftest → 4 変異すべて検出
just difftest-oracle   → 46 ステップ差分なし
just difftest          → oracle 対 Rust（M4 以降で使う）
just difftest-filters  → 正規化フィルタ一覧を表示
```

### 判断 1: 「正規化するより、決定的に仕込む」

リレーは初回起動時に DKIM 鍵・自己署名 TLS 証明書・setup トークンを**ランダム生成**する。
放置すると 3 つとも両サイドで食い違い、それを潰すフィルタが必要になる。
だがそのフィルタは**鍵の扱いを間違えた本物のバグも同時に隠す**。

→ fixture 側で全部**事前に配る**ことにした。フィルタが 1 つ減るたびに
死角が 1 つ減る。

同じ理屈で `base_url`。**両サイドで同一の `base_url`**（`http://relay.difftest.invalid`）を
使い、`listen_addr` だけ変える。JMAP Session レスポンスは `base_url` を
`apiUrl`/`downloadUrl`/`uploadUrl` に echo する（server.go:311）ので、
ポートを変えると URL フィルタが要る → **間違った URL が素通りする**ようになる。

### 判断 2: 「落ちないハーネスは、無いより悪い」

`--both-oracle` が**一発目で green になった**。喜ぶところではなく、
**「何も比較していないハーネス」と区別がつかない**状態。

→ `--self-test` を追加（当初計画に無し）。oracle を意図的に壊したコピーと比較し、
比較軸ごとに 1 つずつ変異を用意して**全部検出されること**を要求する:

| 変異 | 壊す対象 | 検出数 |
|---|---|---:|
| `RelayLabel` | レスポンスボディ | 1 |
| `BaseUrl` | Session レスポンス | 3 |
| `ExtraDataFile` | `data/` ツリー | 1 |
| `BreakCredential` | 認証経路 | 78 |

**そしてこれが実際にバグを見つけた。** シナリオの WKD ステップが
`8xnqfyeqrbanrhqoq5b6ba6a1kzjxfyy` を「zbase32(sha1("alice"))」と称していたが、
Go 実装で実際に計算すると `kei1q4tipxxu1yj79k9kfukdhfy631xe`。
つまり**ハッシュ一致分岐をテストしているつもりで、不一致分岐をテストしていた**。
3 ステップ（一致 / 不一致 / localpart なし）に分割して修正。

### 判断 3: SPEC.md には「ハーネスで検証できないこと」だけ書く

当初計画では SPEC.md を全仕様の網羅文書にするつもりだったが、
ハーネスが動く以上、HTTP レスポンスの正解は **oracle が生成する transcript** であって
文章ではない。両方に書くと**必ず片方が腐る**。

→ SPEC.md の守備範囲を「リクエストを投げるだけでは観測できない事柄」に限定した:
起動シーケンスの順序、6 時間周期の purge、凍結された暗号定数、ディスク形式の**意味**、
SMTP プロトコル挙動、メッセージ変換パイプラインの段構成、外部サービス通信。

### ハーネスが早速ピン留めした Go 版の癖

- **CORS ヘッダがルートごとに違う**。`/jmap/api/` は `GET, POST, OPTIONS`、
  `WrapCORS` 経由の 404 は `GET, POST, PUT, OPTIONS`。
  汎用ミドルウェアで統一すると壊れる（PLAN.md §5.1 の警告が実物で確認できた）
- **`Email/set` の create は `messages/` に何も書かない**。`OnCreateEmail` が
  `PutPending` を呼ぶだけなので、submit されるまで永続化されない。
  `newState` も `"0"` のまま動かない

### 詰まった点

なし。強いて言えば `--both-oracle` が一発で通ったことが最大の落とし穴だった（判断 2）。

### 気づいた点（後で対処）

- `transcript.txt` が実質「Go 版の振る舞いの読める仕様書」になっている。
  M4 以降でシナリオを増やすほど価値が上がる。SPEC.md に書きたくなったら
  まずシナリオに足せないか考える
- シナリオは現状 46 ステップ。SMTP 配送（M5）、anchor 付き経路（M6）、
  PGP 鍵をアップロードした状態の WKD（M6/M7）が未カバー

### 次

**M2: cryptenv。** 最初の縦切りで、暗号スタック（argon2 / aes-gcm / hkdf / subtle）の
疎通確認を兼ねる。Go 版と `envelope.json` を相互に読ませる。

---

## 2026-07-27 — M0 完了 (`4899d9e`)

### やったこと

- rustup 導入 → **rustc 1.97.1** (stable, default profile なので clippy/rustfmt 同梱)
- `~/.bashrc` に `. "$HOME/.cargo/env"` を追加（rustup の既定挙動を明示的に実施）
- `git init` → workspace 雛形 5 クレート + justfile + .gitignore + README + config.example.json
- `just oracle` で Go 版 oracle をビルドする仕組みを整備

### 検証結果（すべて green）

```
cargo build --workspace                              → OK
cargo build --workspace --no-default-features        → OK  (= go build -tags noanchor)
cargo clippy --workspace --all-targets -- -D warnings → 無警告
cargo fmt --all --check                              → clean
cargo test --workspace                               → OK (テストはまだ 0 件)
just oracle-check                                    → oracle 2 種ビルド + Go テスト全 pass
                                                       go-jmapserver の 39a4d0e からの drift なし
```

### 判断とその理由

**workspace を 5 クレートに分けた。** 1 クレートに全部入れても動くが、
`crates/jmapserver` から `jmapsmtp` 固有の型を参照しない制約（§8-F-2、将来の切り出し用）を
**コンパイラに強制させたい**ため。人間の規律に頼ると必ず漏れる。

**各 stub には「何を入れるか + 移植元の Go ファイル」だけ書いた。**
中身が空でも、ファイルを開けば担当範囲がわかる状態にしておく。

**`oracle/` は .gitignore。** リポジトリ外の 2 つの Go リポジトリからのビルド生成物であって、
このリポジトリの成果物ではない。代わりに `justfile` に再現手順を持たせた。
`just oracle-check` は go-jmapserver の drift（`git log 39a4d0e..HEAD`）も報告する（§8-A' 対策）。

**clippy は `correctness` / `suspicious` のみ deny。**
移植は Go の制御フローを意図的になぞる（§8-D）ので、`pedantic` や `style` の
「もっと Rust らしく書け」という指摘は移植中はノイズになる。
バグを示すカテゴリだけ硬いエラーにした。

### 詰まった点

**lettre の feature 指定でビルド失敗。** `default-features = false` +
`["smtp-transport", "tokio1-rustls", "builder"]` だけでは
「crypto provider が無い」「cert verifier が無い」で `compile_error!`。

→ `ring` + **`rustls-native-certs`** を追加。`webpki-roots` ではなく native を選んだのは、
Go の `crypto/tls` が OS の root store を使うため。送信 STARTTLS の信頼判断を Go 版と揃える。

### 気づいた点（後で対処）

- **hickory-resolver が 2 バージョン入っている**: 自前指定の `0.25.2` と、
  `mail-auth` が引く `0.26.0-alpha.1`。ビルドは通るがコンパイル時間の無駄。
  M5 で MX 解決を書くとき、`mail-auth` 内蔵の Resolver を使えば自前の hickory 依存を
  外せるかもしれない。**M5 で判断する**
- 依存解決の実績バージョン: `pgp 0.16.0` / `mail-parser 0.11.5` / `mail-auth 0.7.5` /
  `htmd 0.2.2` / `axum 0.8` / `rustc 1.97.1`

### 次

**M1: 差分ハーネス。** `xtask difftest --both-oracle`（oracle 対 oracle）が green に
なるまでが M1 の本体。正規化フィルタの設計がすべて。

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

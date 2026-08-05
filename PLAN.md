# jmapsmtp — Go → Rust 移植計画

`~/go-jmapsmtp/` (Go) を `~/jmapsmtp/` (Rust) に書き換えるための計画書。

- 移植元: https://github.com/yno9/go-jmapsmtp @ `1b5cf06`
- 依存ライブラリ: `~/go-jmapserver/` @ `39a4d0e`（取り込み対象）
- クライアント: https://github.com/yno9/biset @ `6030a0b`（`~/biset/`）——
  **移植対象ではない**が、署名対象文字列と DID/SCID モデルの出典。SPEC §10-A
- 作業ディレクトリ: `/home/ubuntu/jmapsmtp/`
- 作成日: 2026-07-27（`~/go-jmapserver/` 入手により §2 / §5 / §7 / §8 を改訂）

---

## 1. 目的とスコープ

SMTP(25番) と JMAP(RFC 8621) を双方向に橋渡しする MTA 相当のデーモンを、
機能・ワイヤフォーマット・ディスク上のデータレイアウトを保ったまま Rust で再実装する。

**スコープに入るもの**

| 領域 | 内容 | 非テスト | テスト |
|---|---|---:|---:|
| アプリ本体 | `go-jmapsmtp` 全体 | 3,758 | 860 |
| JMAP サーバライブラリ | `~/go-jmapserver` 全体（`cmd/` 除く） | 5,113 | 815 |
| JMAP 型定義 | `git.sr.ht/~rockorager/go-jmap` の必要サブセット | 〜1,500 | — |
| **合計** | | **約 10,400** | **1,675** |

Rust では 13,000〜15,000 行程度になる見込み。移植すべき Go テストは **1,675 行 / 約 45 本**。

**スコープに入らないもの**

- `biset` / `biset-ui` (クライアント側 E2E 暗号化 = Layer 2) — 変更しない
- `biset-anchor` (identity anchor) — HTTP 越しの外部サービスとして扱う。移植しない
- `cmd/vapidgen`, `cmd/pushtest` (go-jmapserver の補助 CLI) — 必要になった時点で判断

---

## 2. 調査で判明した重要事項

### 2.1 【解決済】動く参照実装 (oracle) が手に入った

当初、`go.mod` の `replace ... => /Users/n/go-jmapserver` が指すコピーが無く、
GitHub 公開版 (`6ad07a1`) では `devicekeys.go` / `diddht.go` / `ExtractAttachments` /
`anchor.VouchDevice` が未定義でビルドできなかった。

**`~/go-jmapserver/` (`39a4d0e`) の入手により解決。** 検証済み:

```
go build ./...              → OK
go build -tags noanchor ./... → OK
go test ./...               → ok github.com/yno9/go-jmap-smtp
                              ok github.com/yno9/go-jmap-smtp/cryptenv
（go-jmapserver 側も ok jmapserver / ok jmapserver/anchor）
```

**これが移植計画にとって決定的**：Go バイナリを oracle として走らせられるので、
**差分テスト (differential testing) を主要な安全網にできる**（§7）。
「仕様書から起こしたゴールデン」ではなく「Go 実装が実際に出したバイト列」を
正解として使える。

### 2.2 デバイス鍵・セッショントークンのディスク形式が確定した

`devicekeys.go` のヘッダコメントに明記されている:

```
<acctDir>/devices/<deviceID>.json     {"id":…,"label":…,"created_at":…}
<acctDir>/sessions/<tokenHash>.json   {"device_id":…,"expires_at":…}
```

| 項目 | 値 |
|---|---|
| `deviceID` | `base64url(ed25519 公開鍵 32B)` — decode は RawURL → URL の順に試行 |
| セッショントークン | `base64_std(ランダム 32B)`。**トークン自体は保存せずハッシュのみ** |
| `tokenHash` | `base64url_nopad(sha256(raw token))` |
| セッション署名対象 | `session:<did>:<devicePubKeyB64url>:<ts>` |
| vouch 署名対象 | `devkey:<did>:<devicePubKeyB64url>:<label>:<ts>` |
| 署名エンコード | `base64_std(ed25519 署名)` |
| 時刻ずれ許容 | `sessionFreshnessWindow = 300` 秒（前後とも） |
| `did:dht` の鍵 | `did:dht:<zbase32(ed25519 公開鍵)>` を自己証明的にデコード。ネットワーク呼び出し無し |
| zbase32 アルファベット | `ybndrfg8ejkmcpqxot1uwisza345h769` |

重要な挙動 2 点（Go 側にコメントで「本番で踏んだ」と書かれている。移植時に落とすと再発する）:

1. `ListDeviceKeys` は `devices/` が無くても **必ず非 nil の空配列**を返す
   （`null` を返すとクライアントの `devices.length` が例外になる）
2. `RemoveDeviceKey` はデバイスファイルだけでなく、**そのデバイスに発行済みの
   セッションファイルも全部消す**（失効が即時に効かないと revoke の意味が無い）

→ **`data/` 互換は完全に達成可能。§5.2 のリスクは消滅。**

### 2.3 環境

| 項目 | 状態 |
|---|---|
| Rust ツールチェイン | **未インストール** (`cargo`/`rustc` 無し) → M0 で導入 |
| Go | 1.22.4 あり (1.26.3 を自動 DL 済み) |
| `~/go-jmapserver/` | **あり** (`39a4d0e`)。ビルド・テスト green |
| crates.io | 到達可 (`index.crates.io` 200 / `static.crates.io` 200) |
| GitHub | 到達可 |
| `~/jmapsmtp/` | 本 PLAN.md のみ |
| git | `~/jmapsmtp/` は未初期化 → M0 で `git init` |

**oracle のセットアップ手順**（M0 で `oracle/` として固定する）:

```bash
cp -r ~/go-jmapsmtp oracle/go-jmapsmtp
sed -i 's|=> /Users/n/go-jmapserver|=> /home/ubuntu/go-jmapserver|' oracle/go-jmapsmtp/go.mod
cd oracle/go-jmapsmtp && go build -o jmapsmtp-oracle .
```

---

## 3. 成果物の構成

Go 側の 3 層構造 (アプリ / サーバライブラリ / 型) をそのまま Cargo workspace に写す。
1 クレートに全部入れるより、レイヤ境界がコンパイラに強制されてレビューしやすい。

```
~/jmapsmtp/
├── Cargo.toml                 # workspace
├── PLAN.md                    # 本ファイル
├── SPEC.md                    # M1 で作る「凍結された互換性契約」
├── ARC.md                     # 移植後アーキテクチャ (Go 版 ARC.md の Rust 版)
├── README.md
├── config.example.json        # Go 版と同一フォーマット
├── crates/
│   ├── cryptenv/              # ← cryptenv/envelope.go
│   │   └── src/lib.rs
│   ├── jmap-types/            # ← git.sr.ht/~rockorager/go-jmap のサブセット
│   │   └── src/{lib,core,email,mailbox,submission,identity,thread}.rs
│   ├── jmapserver/            # ← ~/go-jmapserver (全 5,113 行を取り込む)
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── email.rs       # ← email.go     (892行) MIME parse/build ★最大
│   │       ├── store.rs       # ← store.go     (699行)
│   │       ├── server.rs      # ← server.go    (562行) Session/API/SSE/blob/CORS/auth
│   │       ├── mailbox.rs     # ← mailbox.go   (277行)
│   │       ├── push.rs        # ← push.go      (252行) VAPID web push
│   │       ├── storage.rs     # ← storage.go   (247行)
│   │       ├── devicekeys.rs  # ← devicekeys.go(246行)
│   │       ├── admin.rs       # ← admin.go     (238行) + static/admin_dashboard.html
│   │       ├── identity.rs    # ← identity.go  (202行)
│   │       ├── thread.rs      # ← thread.go    (180行)
│   │       ├── submission.rs  # ← submission.go(164行)
│   │       ├── contacts.rs    # ← contacts.go  (165行)
│   │       ├── metrics.rs     # ← metrics.go   (136行)
│   │       ├── dispatch.rs    # ← dispatch.go  (130行) JMAP 26 メソッド振り分け
│   │       ├── diddht.rs      # ← diddht.go    (130行) zbase32 + did:dht 自己証明検証
│   │       ├── activity.rs    # ← activity.go  (110行)
│   │       ├── vacation.rs    # ← vacation.go  (69行)
│   │       ├── authtoken.rs   # ← authtoken.go (37行)
│   │       └── anchor/
│   │           ├── client.rs      # ← anchor/client.go     (241行) Claim/Release/VouchDevice/Drain
│   │           ├── pkarr_proxy.rs # ← anchor/pkarrproxy.go (82行)
│   │           └── reconcile.rs   # ← anchor/reconcile.go  (54行)
│   └── jmapsmtp/              # ← go-jmapsmtp 本体 (バイナリ)
│       └── src/
│           ├── main.rs        # ← main.go
│           ├── config.rs
│           ├── handler.rs     # ← main.go の handler / makeStore / drainBuffer
│           ├── smtp_in.rs     # ← main.go の SMTP サーバ部
│           ├── smtp_out.rs    # ← main.go の sendEmail / smtpSend
│           ├── auth_env.rs, autocrypt.rs, dkim.rs, wkd.rs
│           ├── provision.rs, devices.rs, customdomain.rs, maintenance.rs
│           ├── anchor.rs      # ← anchor_on.go / anchor_off.go (feature フラグ)
│           ├── metrics.rs
│           └── setup_html.rs  # ← setupHTMLTemplate (中の JS はそのまま流用)
└── tests/                     # 統合テスト (SMTP↔JMAP 往復など)
```

### Go ビルドタグ → Cargo feature

`-tags noanchor` は Cargo の **default feature `anchor`** に置き換える:

```toml
[features]
default = ["anchor"]
anchor = ["dep:reqwest"]   # anchor_on.go 相当
```

`#[cfg(feature = "anchor")]` / `#[cfg(not(feature = "anchor"))]` で
`anchor_on.rs` / `anchor_off.rs` を切り替える。
`cargo build --no-default-features` が `go build -tags noanchor` に対応する。

---

## 4. 依存クレート対応表

| Go | Rust | 備考 |
|---|---|---|
| `net/http` + `ServeMux` | **axum 0.8** + `tower-http` | ルーティング。CORS は Go 版が手書きなので**手書きのまま移植** (ヘッダを 1 バイトも変えないため) |
| goroutine / channel | **tokio** 1.x | `bufCh` (cap 256) は `tokio::sync::mpsc::channel(256)` |
| `sync.RWMutex` | `parking_lot::RwLock` / `tokio::sync::RwLock` | ハンドラ内の短いロックは parking_lot |
| `encoding/json` | **serde / serde_json** | `json.RawMessage` → `serde_json::value::RawValue` |
| `emersion/go-smtp` (受信) | **自前実装** (tokio + `tokio-rustls`) | 使っている機能は MAIL/RCPT/DATA/RSET/QUIT + STARTTLS + SMTPUTF8 のみ。Rust の既存 SMTP サーバ crate は保守状況が弱く、依存させるより 300 行書いた方が安全 |
| `net/smtp` (送信) | **自前実装** (tokio) | 当初 lettre を予定したが、**RCPT 拒否でも送信継続**という挙動を提供していない。複数宛先送信では「1 件 bounce したら全体失敗」は誤りなので自前にした (M5e) |
| `net.LookupMX` / `LookupTXT` | **hickory-resolver** | MX (送信) / TXT (カスタムドメイン検証) |
| `emersion/go-msgauth/dkim` | **mail-auth** | RSA-SHA256, relaxed/relaxed, ヘッダ選択に対応 |
| `ProtonMail/go-crypto/openpgp` | **pgp** (rpgp) | keyring 読み込み / armor / インライン暗号化 |
| `golang.org/x/crypto/argon2` | **argon2** | Argon2id (t=3, m=64MiB, p=4) |
| `golang.org/x/crypto/hkdf` | **hkdf** + **sha2** | |
| `crypto/aes` + `cipher.GCM` | **aes-gcm** | nonce(12)‖ct‖tag のレイアウトは自前で維持 |
| `crypto/subtle` | **subtle** | 定数時間比較 |
| `crypto/rsa`, `crypto/x509` | **rsa**, **pkcs8** / **rustls-pemfile** | DKIM 鍵の PKCS#8 PEM 生成・読み込み |
| 自己署名証明書生成 | **rcgen** | `generateSelfSignedCert` 相当 |
| `crypto/ed25519` | **ed25519-dalek** 2.x | デバイス vouch / セッション署名検証 |
| `crypto/hmac`+`sha256` | **hmac** + **sha2** | カスタムドメインの verify token |
| MIME パース | **mail-parser** | `ParseMIMEEmail`, `ExtractAttachments` |
| MIME 組み立て | **mail-builder** (+ 手書き) | `BuildRFC5322`。境界文字列など既存フォーマット再現のため一部手書き |
| `JohannesKaufmann/html-to-markdown` | **htmd** (または `html2md`) | `email.go:641` HTML 本文 → テキスト変換。**出力差が出やすい** → §8-G |
| `prometheus/client_golang` | **prometheus** | `biset_smtp_outbound_total{result}` など |
| `SherClockHolmes/webpush-go` | **web-push** | VAPID push (go-jmapserver の `push.go`) |
| SSE (EventSource) | `axum::response::sse` | `/jmap/eventsource` |
| zbase32 (WKD / did:dht) | **自前 32 行** | Go 版もアルファベット直書き。crate 依存不要 |
| `filepath.Walk` | **walkdir** | `dirSizeMB`, `lastActivity` |
| `log.Printf` | **tracing** + `tracing-subscriber` | ログ **文字列は Go 版と同一に保つ** (運用の grep が壊れるため) |
| `regexp` | **regex** | `validUsername`, `validCustomDomain` |

---

## 5. 互換性契約 (何を絶対に変えないか)

> **注**: Go 版が常に正しいわけではない。明らかなバグは移植せず修正する。
> ただし差異は必ず `SPEC.md §11` に記録する（記録のない差異は移植ミスと区別がつかない）。
> 本節が「変えてはならない」と言うのは**外部と合意済みのワイヤ/ディスク形式**であって、
> Go 版の実装上の欠陥ではない。

このデーモンは稼働中のリレーであり、`biset` クライアントと `biset-anchor` が
外側にいる。**「Rust で書き直したらクライアントが動かなくなった」を防ぐのが本移植の最大の制約**。

### 5.1 変えてはならないもの (bit-for-bit)

| 対象 | 理由 |
|---|---|
| **HTTP のパスとメソッド** 全 20 種 (§5.3) | biset クライアントが直叩き |
| **リクエスト/レスポンス JSON のキー名・型・HTTP ステータスコード** | 同上。エラー時のステータス (400/401/403/404/409/412/503) まで含む |
| **CORS ヘッダの値** | Go 版はハンドラ毎に手書きで、値がまちまち。汎用ミドルウェアで統一すると壊れる |
| **`config.json` のスキーマ** | 既存の本番 config をそのまま読めること |
| **`data/` のディレクトリ構造とファイル名** (§5.2) | 既存デプロイの無停止移行のため |
| **cryptenv のパラメータ**: Argon2id t=3/m=65536/p=4, salt 16B, nonce 12B, HKDF info `biset-jmapsmtp/auth/v1` / `biset-jmapsmtp/enc/v1` | 変えると全ユーザがログイン不能 |
| **envelope.json の JSON 形状**: `{v, salt, kdf:{t,m,p}, wrapped_secret, auth_token_hash}` (バイト列は base64) | ブラウザ側 (`setupHTMLTemplate` 内 JS) が生成する形と一致必須 |
| **署名対象文字列** `session:<did>:<devicePubKey>:<ts>` | クライアントの `devicebind.ts` と一致必須 |
| **JMAP capability URI** `urn:ietf:params:jmap:mail` / `:submission` | |
| **メッセージ ID / メールボックス ID の生成規則** (`makeMessageID` / `makeMailboxID`) | 既存データとの整合 |
| **anchor への HTTP 呼び出し形式** | biset-anchor 側は変更しない |
| **DKIM 署名対象ヘッダ順** `From, To, Cc, Subject, Date, Message-Id, Content-Type` + relaxed/relaxed | 署名検証が通らなくなる |
| **WKD の zbase32 実装** | 公開鍵が引けなくなる |
| **ログ行の prefix** (`[smtp]`, `[autocrypt]`, `[setup]`, `[provision]`, `[maintenance]`, `[delete]`, `[anchor]`, `[drain]`) | 運用スクリプト・監視 |

### 5.2 `data/` 互換は必須 — 全ファイル一覧

**ユーザ確定事項: 既存デプロイをバイナリ差し替えで移行する。`data/` 互換は必須。**
§2.2 でデバイス鍵・セッションの形式も判明したため、**完全な互換が達成可能**。

```
data/
├── smtp-tls-cert.pem / smtp-tls-key.pem   自己署名 or 設定由来の証明書
├── _domains/<domain>/
│   ├── domain.json      DomainConfig (allow_provision, provision_secret, dkim_selector)
│   ├── key.pem          DKIM 秘密鍵 (PKCS#8 PEM)
│   └── dkim-dns.txt     公開用 TXT レコード
└── <domain>/
    ├── key.pem, dkim-dns.txt
    ├── peers/<addr>.pgp                    Autocrypt ピア公開鍵 (バイナリ OpenPGP)
    └── <localpart>/
        ├── setup.token                     初回ログイン前のみ存在
        ├── envelope.json                   cryptenv エンベロープ
        ├── auth_token_hash                 base64(sha256(auth_token)) の 1 行
        ├── pubkey.pgp                      armored 公開鍵
        ├── privkey.enc                     クライアント暗号化済み秘密鍵 (不透明)
        ├── devices/<deviceID>.json         {"id","label","created_at"}
        ├── sessions/<tokenHash>.json       {"device_id","expires_at"}
        ├── messages/<encid>.json           encid = encodeURIComponent(jmap-id)
        ├── mailboxes.json, identities.json, delta.json
        └── activity.log                    追記型の監査ログ
```

**M3 / M6 の受け入れ基準**: Go 版が書いた `data/` を Rust 版で起動して全機能が動き、
その逆（Rust が書いた `data/` を Go 版で起動）も動くこと。両方向でテストする。

### 5.3 HTTP エンドポイント一覧 (移植の完了判定に使う)

jmapsmtp 本体:

| メソッド | パス | 認証 |
|---|---|---|
| GET | `/setup?token=` | setup token |
| GET/PUT/OPTIONS | `/auth/envelope` | GET:なし / PUT:Basic |
| POST | `/auth/signup?token=` | setup token |
| POST | `/account/provision` | なし (署名 or provision_secret) |
| POST | `/account/delete` | Basic |
| POST | `/account/session` | デバイス署名 |
| GET/POST/DELETE | `/account/devices` | GET/DELETE:Basic, POST:vouch 署名 |
| PUT | `/account/did` | Basic (anchor 有効時のみ) |
| GET | `/relay-info` | なし |
| GET | `/.well-known/openpgpkey/policy` | なし |
| GET | `/.well-known/openpgpkey/hu/<hash>?l=` | なし |
| PUT | `/pgp/pubkey` | Basic |
| GET/PUT | `/pgp/privkey` | Basic |
| GET/PUT | `/pgp/peerkey?addr=` | Basic |
| GET | `/domain/verify-token?domain=` | なし |
| POST | `/domain/add` | DNS TXT 所有証明 |
| POST | `/admin/drain-anchor` | ADMIN_TOKEN (anchor 有効時のみ) |
| * | `/pkarr/*` | anchor へプロキシ (anchor 有効時のみ) |

jmapserver 由来 (NewMux / Register*):

| メソッド | パス |
|---|---|
| GET | `/.well-known/jmap` (JMAP Session) |
| POST | `/jmap/api` (JMAP メソッド呼び出し) |
| GET | `/jmap/eventsource` (SSE) |
| POST | `/jmap/upload/...` (blob) |
| GET | `/jmap/download/...` (blob) |
| — | `/contacts/*`, `/storage/*`, `/metrics`, `/admin/*` |

### 5.4 JMAP メソッド (26 個) — `dispatch.rs` の実装対象

```
Mailbox/get,changes,query,queryChanges,set
Thread/get,changes
Email/get,changes,query,queryChanges,set,copy,import,parse
SearchSnippet/get
Identity/get,changes,set
EmailSubmission/get,changes,query,queryChanges,set
VacationResponse/get,set
```
加えて JMAP の **back-reference 解決** (`#` 参照 / JSON Pointer, `resolveRefs`/`jsonPath`) が必須。

---

## 6. フェーズ計画

各フェーズは「完了条件」を満たしたらコミットする。M0 で `git init` する。

### M0: 環境整備

- `rustup` インストール → stable toolchain (`rustc`, `cargo`, `clippy`, `rustfmt`)
- `~/jmapsmtp/` で `git init`、`.gitignore` (Go 版のものを Rust 用に調整: `target/`, `data/`, `config.json`, `*.pem`)
- workspace の `Cargo.toml` と 4 クレートの雛形を作成
- `cargo build` / `cargo test` / `cargo clippy -- -D warnings` が通る空の状態を作る
- `justfile` (または `Makefile`): `build` / `test` / `lint` / `run` / **`oracle`** / **`difftest`**
- **oracle の固定** (§2.3 の手順)。`oracle/` は `.gitignore` に入れ、ビルド手順のみコミット

**完了条件**: `cargo clippy --all-targets -- -D warnings` が無警告で通り、
`just oracle` で Go バイナリがビルドできる。

### M1: 差分テスト基盤 + 仕様の凍結 — `SPEC.md`

**oracle が動くので、M1 の主眼は「文書を書くこと」より「Go と Rust を突き合わせる仕組みを作ること」**。

1. **差分ハーネス** (`xtask/` または `tests/differential/`):
   - 同一の `config.json` + `data/` を用意し、Go 版と Rust 版を別ポートで起動
   - 同一のリクエスト列を両方に投げ、**ステータス / ヘッダ / ボディ JSON / `data/` の差分**を比較
   - 非決定要素（乱数 ID、タイムスタンプ、PGP セッション鍵、DKIM の `t=`）は
     正規化フィルタを通してから比較する。**このフィルタの一覧が実質的な仕様書になる**
2. **ゴールデン生成**: Go 版に `.eml` を食わせて `ParseMIMEEmail` / `BuildRFC5322` の
   出力を吐かせる小さな Go プログラムを書き、`tests/golden/` に固める
3. **`SPEC.md`**: 差分では捉えられないもの（起動時の副作用、6 時間毎の purge、
   エラー時の分岐条件、変換パイプラインの段構成）を文章で残す。
   **ハーネスで検証できることは書かない** — 二重管理になり必ず片方が腐る
4. **変異テスト** (`--self-test`): oracle を意図的に壊したコピーと比較し、
   全変異が検出されることを確認する。比較軸ごとに 1 変異用意する

```
[受信] SMTP → ParseMIME → Autocrypt ヘッダ抽出 → peers/ 保存
      → 本文が PGP か? → yes: $e2e キーワード付与でそのまま保存
                        → no : 添付を multipart/mixed に再構築 → 受信者公開鍵でインライン暗号化 → 保存
      → bufCh (256) → Email/query 時に drainBuffer → Store.Put

[送信] EmailSubmission/set → 容量チェック → reply_only チェック
      → BuildRFC5322 → Autocrypt ヘッダ注入 → Chat-Version 注入
      → 本文が PGP なら PGP/MIME (RFC 3156) にラップ → DKIM 署名
      → relay_host あり: 1 接続で全宛先 / なし: 宛先ドメイン毎に MX 引いて配送
```

**完了条件**（3 つとも満たすこと）:

1. `just difftest-selftest` — oracle 対 **意図的に壊した oracle**。
   全変異が検出されること。**green な差分テストは、red が到達可能でなければ無意味**
2. `just difftest-oracle` — oracle 対 oracle が green
   （＝正規化フィルタが非決定性だけを潰せている）
3. `SPEC.md` に、ハーネスでは検証できない事項が揃っていること

`just difftest-check` が 1 と 2 をまとめて走らせる。

**【実績】完了 (`5ef227c`)。** 2 は当初から通ったが、それだけでは
「何も比較していないハーネス」と区別がつかないため 1 を追加した（当初計画には無い）。
詳細は JOURNAL.md 参照。

### M2: `cryptenv` クレート

最小で自己完結し、既存テスト (`envelope_test.go`, 125 行) がそのまま移植できる。
最初の縦切りとして暗号スタック (argon2 / aes-gcm / hkdf / subtle) の疎通を確認する。

- `NewEnvelope` / `Unseal` / `Rewrap` / `VerifyAuth` / `Bytes` / `FromBytes`
- serde の `#[serde(with = "base64")]` で Go の `[]byte`→base64 と同じ JSON を出す

**完了条件**:
1. `envelope_test.go` の全ケースを Rust に移植して green
2. **相互運用テスト**: Go 版が生成した `envelope.json` を Rust で `Unseal` でき、逆も可

**【実績】完了 (`d218fb2`)。** Go テスト 10 件 + 定数ピン + 相互運用 5 件。
Go 版の `FromBytes` が無検証で、`POST /auth/signup` に `{}` を送るだけで
**未認証でアカウントを永久に潰せる**バグを発見し、修正して移植した（SPEC.md §11.2）。

### M3: `jmap-types` + `Store`

- `jmap-types`: `Email`, `Mailbox`, `EmailSubmission`, `Identity`, `Thread`, `EmailAddress`,
  `BodyPart`, `BodyValue`, `Header`, `ID`, capability URI
  — Go 版の struct タグと 1:1 の serde 定義
- `Store` (`store.go` 699 行): メッセージ永続化、state 管理 (`changeRecord`), スレッド解決,
  keyword パッチ, mailbox, identity, blob, submission
- **ファイル名エンコード**: `safeFilename` = `encodeURIComponent(id)` 相当。ここは要精密移植

**完了条件**（双方向の `data/` 互換）:
1. Go 版が書いた `data/<domain>/<lp>/` を Rust の `Store` が読み、`All()` の結果が一致
2. **Rust が書いた `data/` を Go 版バイナリが起動時に読めて、同じ JMAP レスポンスを返す**
3. `mimeparse_test.go` / `storage_test.go` / `contacts_test.go` を移植して green

**【実績】完了 (`fbd8748`)。** 1 と 2 は達成（相互運用テスト 4 件）。
3 は該当コード（MIME / storage / contacts）が M5・M7 なのでそちらへ繰り延べ。
**Go の `encoding/json` が `<` `>` `&` を HTML エスケープする**ことを相互運用テストが
発見し、`jmap_types::go_json` で対応（SPEC.md §4）。

### M4: JMAP HTTP サーバ

- `server.rs`: JMAP Session (`/.well-known/jmap`), `/jmap/api`, SSE, blob upload/download,
  auth (`AuthFunc` 相当をトレイトかクロージャで), CORS (手書き移植)
- `dispatch.rs`: 26 メソッド
- back-reference 解決 (`resolveRefs` / `jsonPath`)
- `Hub` (通知の pub/sub, `SetPersistDir`)

**完了条件（改訂）**: 当初は「差分ハーネスを oracle 対 Rust で green」としていたが、
これには jmapsmtp バイナリ全体が必要で、実質 M4+M6 だった。M4 単独の基準は:

1. **dispatch 相互運用テスト**が green — Go と Rust が同じ store を seed し、
   同じメソッド呼び出し列をそれぞれの `Dispatch` に通して結果 JSON を比較
2. 変異テストで検出力を確認

**【実績】完了 (`3fd59b4`)。** 47 呼び出し一致、宣言済み差異 1 件（§11.7）。
HTTP 層（axum ルータ・CORS・SSE）と全体 difftest は **M6 に繰り延べ**。
`route_registration_test.go` 相当も M6。

### M5: MIME + SMTP

- `email.rs` (892 行のうち MIME 部): `ParseMIMEEmail` / `BuildRFC5322` /
  `ExtractAttachments` / `MessageBody` / `BuildEnvelope` / HTML→テキスト変換
  （ハンドラ部は M4 で完了。`Email/import` と `Email/parse` のスタブをここで埋める）
- `smtp_in.rs`: 受信サーバ (自前 ESMTP + STARTTLS + 証明書リロード + 自己署名生成)
- `smtp_out.rs`: MX 引き / relay_host / STARTTLS 日和見
- `dkim.rs`: 鍵生成・永続化・署名・`dkim-dns.txt` 出力
- `autocrypt.rs`: ヘッダ注入/解析、peer 鍵保存、`pgpEncryptInline`, `pgpMIMEWrapInline`

**進捗**:
- **M5a（MIME）完了 (`45a3e99`)** — 17 件の corpus で Go と一致
- **M5b（DKIM）完了 (`36ebcd1`)** — Go の検証器が Rust の署名を受理
- **M5c（Autocrypt/PGP-MIME）完了 (`c4f08ca`)** — 決定的 4 関数がバイト一致。
  **リモート DoS を発見**（SPEC §11.11）
- **M5d（SMTP 受信サーバ）完了 (`a4f49b5`)** — Go の `net/smtp` で配送できる
- **M5e（SMTP 送信クライアント）完了 (`dc5c71b`)** — 本物の go-smtp サーバが受理
- **M5f（OpenPGP）完了 (`e429dc1`)** — 交差復号を両方向
- **→ M5 完了。** 次は M6

**完了条件**:
1. **M1 のゴールデン**（Go 版が実際に出力した `ParseMIMEEmail` / `BuildRFC5322` の結果）に
   Rust の出力が一致。実在の `.eml` を最低 20 件（添付あり / multipart / 日本語 /
   PGP 済み / HTML のみ）用意して回す
2. **同一の平文を Go 版と Rust 版それぞれで DKIM 署名し、両方の署名を
   両方の検証器で交差検証**（Go の `dkim.Verify` × `mail-auth`、計 4 通り）
3. ローカルの偽 SMTP サーバ相手にエンドツーエンド送信
4. 受信 → JMAP `Email/query` で読める統合テスト

### M6: アカウント / 認証

- `auth_env.rs`: `buildAuthFunc`, `authenticate`, envelope の R/W, `/auth/*`
- `devicekeys.rs` + `diddht.rs` + `devices.rs`（§2.2 の形式に厳密に従う）
- `provision.rs`: `/account/provision`, `/account/delete`
- `anchor.rs`: claim / release / vouch / drain / pkarr proxy (feature ゲート)
- `customdomain.rs`: `/domain/verify-token`, `/domain/add`
- `wkd.rs`: WKD + `/pgp/*`

**進捗**:

| | 内容 | commit |
|---|---|---|
| M6a | 認証プリミティブ（`authtoken` / `diddht` / `devicekeys`） | `a6b8186` |
| M6b | config パースと認証層（`config` / `auth_env`） | `9006f4f` |
| M6c | 起動シーケンス（`startup`、孤児掃除は oracle と差分比較） | `0430c38` |
| M6d | ルート表と `ServeMux` 移植（`gomux` / `routes` / `bearer`） | `00e8b84` |
| M6e | handler の識別子・容量計算・エイリアス表（`handler`） | `b0e436a` |
| — | DID アイデンティティモデルの確定（SPEC §10-A） | `dedbd37` |
| M6f | provision（`provision`。oracle の実エンドポイントと差分比較） | `cf7ed67` |
| M6g | Store フック（`hooks`。oracle の JMAP API 経由で保存結果を比較） | `aa6c72d` |

| M6h | デバイス / セッションエンドポイント（`devices`） | `bad538c` |
| M6i | WKD と PGP 鍵配布（`wkd`） | `6ad1881` |
| M6j | オンボーディング（`setup`。`/auth/*` `/relay-info`） | `3791c3e` |
| M6k | カスタムドメインと自己削除（`customdomain`） | `1045ad7` |
| M6l | ストレージ透明性（`jmapserver::storage`） | `07b17eb` |
| M6m | DID 起点の連絡先キャッシュ（`jmapserver::contacts`） | `6f348a6` |
| M6n | 管理系とメトリクス（`jmapserver::admin`） | `cea246d` |
| M6o | アクティビティログ（`jmapserver::activity`） | `e266c68` |
| M6p | `/setup` ページ（`setup_page`。逐語コピー + バイト比較） | `310b299` |

| M6q | HTTP サーバ配線（`server` / `main`） | `293d65b` |

**エンドポイントの移植と、サーバの骨格は終わった。**

| M6r | WKD・オンボーディング・連絡先の配線（11 ルート） | `a5b98d0` |

| M6s | セッション・デバイス・ストレージ・管理系の配線（7 ルート） | `8d96b10` |

| M6t | JMAP 本体（session / api）と Store 構築 | `afb0836` |

| M6u | アカウントのライフサイクル（provision / delete / purge） | `a340b87` |

| M6v | 管理ダッシュボードと Prometheus メトリクス | `71de8c1` |

| M6w | カスタムドメインと DNS クライアント（`dns`） | `e9586f8` |

| M6x | Web Push と event-source（`jmapserver::push`） | `c4d0e72` |

**oracle が提供する全ルートの配線が完了した。**

| M6y | 受信配送・SMTP リスナ・非活動掃除（`delivery` / `maintenance`） | `ba44b7e` |

| M6z | 送信サブミッション（`submit` / `outbound`） | `75b6e9a` |

**M6 完了 — 受信と送信の両方が通るリレーになった。**

| M7a | 受信 STARTTLS（`inbound_tls`） | `defd9e3` |

| M7b | identity anchor クライアント（`jmapserver::anchor` / `jmapsmtp::anchor`） | `87dce4f` |

| M7c | Web Push 送信（`webpush`） | `c0558f8` |

**M7 完了 — SPEC §2 の起動シーケンスが全ステップ組み上がった。**

| M8a | difftest が oracle 対 Rust で green（`just check`） | `11f7906` |

| M8b | ARC.md / MIGRATION.md / README.md、`just bench` | `1f719bc` `e888d9d` `0d371e9` |

**M8 完了 — ただし「移植は終わり」ではなかった（下記 0 番）。**
テスト 757 件（35 スイート）、difftest 3 モードとも green。

### 残件

0. ~~**`PUT /account/did` と `/pkarr/` が未実装（501）**~~
   → **M9 で両方実装**（`did_bind.rs` / `pkarr.rs` / `did_bind_interop`）。
   **oracle が出すルートは全部埋まった。**
   `dispatch` に arm が無く、`_ => 501` に落ちている。
   Go は `anchor_on.go` の `registerDidUpdate` で認証してから
   anchor に DID クレームを転送する。**biset のアイデンティティは DID なので、
   これが無いとクライアントは identity を bind できない。**

   **見落とした理由を記録しておく** —
   `mux_interop` は**ルート表**を比べるので両側にあって一致する。
   `server_interop` の未配線リストは**空にされていて**、
   空配列はループが 0 回なので**何も検査していなかった**。
   difftest のシナリオはどちらのパスも叩かない。
   3 層の比較の**継ぎ目**に落ちていた。
   v2 に deploy して 501 が返って初めて分かった。

1. **`Email/query`（1,000 通）が Go より 10〜20% 遅い**（`just bench` で 0.83〜0.88×）。
   起動時間・常駐メモリ・小さいルートは移植側が上なので、
   **ここだけ**。正しさの問題ではない。手を付けていない
2. **本番相当での 24 時間動作**（M8 の完了条件のうち唯一未実施）。
   biset クライアントを実際に繋いだ確認も未実施
3. `cargo build --no-default-features` と `go build -tags noanchor` の
   difftest 比較は**単体テストでは見ているが、difftest では走らせていない**

なお §4 の「ルーティングは axum」は M6d で**取り下げた**。
二重登録 panic・サブツリー一致・リダイレクトが観測可能な挙動なので、
`net/http.ServeMux` を移植した（`gomux.rs` 冒頭に理由）。

**完了条件**:
1. Go のテスト **45 本すべて**を Rust に移植して green。特に
   `anchorless_test.go` / `devices_test.go` / `provision_did_bound_test.go` /
   `customdomain_test.go` / `devicekeys_test.go` / `diddht_test.go` /
   `anchor/client_test.go` は署名検証・拒否条件の仕様そのもの
2. **`devices/` `sessions/` の相互運用**: Go 版で発行したセッショントークンが
   Rust 版で認証を通り、逆も通る。Go 版で vouch したデバイスを Rust 版で revoke でき、
   その逆も可
3. anchor はモックサーバ（`anchor/client_test.go` と同じ形）で検証

### M7: 周辺機能

- `activity.rs` (`AppendActivity` / `ActivityEvent`), `metrics.rs`, `admin.rs` (+ ダッシュボード HTML),
  `contacts.rs`, `storage.rs`, `push.rs` (VAPID), `vacation.rs`
- `maintenance.rs`: `dirSizeMB` / `lastActivity` / 6 時間毎の purge / peer_data_dirs 判定
- `setup_html.rs`: HTML テンプレート (中の JS は**そのまま**流用。Argon2id は hash-wasm のまま)

**完了条件**: `/metrics` の**メトリクス名・ラベル・型が Go 版と完全一致**
（`promtool` か単純な行集合比較で検証）。`/admin` が開く。

### M8: 統合検証と移行

- 実 config + 実 `data/` のコピーで起動、差分ハーネスを全エンドポイントに対して走らせる
- biset クライアントを実際に繋いで、送受信・ログイン・デバイス追加を確認
- `cargo build --no-default-features` (= noanchor) と `go build -tags noanchor` の
  挙動を差分ハーネスで比較
- `ARC.md` / `README.md` / `MIGRATION.md` を書く
- **ベンチ**: 起動時間、常駐メモリ、1,000 通での `Email/query` レイテンシを
  **Go 版と実測比較**（oracle があるので数値で示せる）

**完了条件**: 本番相当の構成で 24 時間動作。差分ハーネス全項目 green。

---

## 7. テスト戦略

参照実装が動かない (§2.1) 以上、テストが唯一の安全網になる。

| 層 | 内容 |
|---|---|
| **差分テスト**（**主軸**） | Go 版と Rust 版に同一入力を投げ、正規化後にバイト比較。M1 で基盤を作り、M4 以降の全フェーズの受け入れ基準に使う |
| **移植テスト** | Go の全 45 テスト（jmapsmtp 19 + cryptenv + jmapserver 側）を Rust に 1:1 移植。**必須、省略しない** |
| **相互運用テスト** | `envelope.json` / `messages/` / `devices/` / `sessions/` を Go↔Rust の**双方向**で読み書き |
| **ゴールデンファイル** | Go 版に実際に生成させた MIME / DKIM 署名 / JMAP レスポンス JSON |
| **統合テスト** (`tests/`) | SMTP 受信 → JMAP 読み出し、JMAP 送信 → SMTP 配送 の往復 |
| **プロパティテスト** | `proptest` で MIME parse→build ラウンドトリップ、zbase32 encode/decode |
| **negative テスト** | 認証拒否、reply_only 拒否、容量超過、重複ユーザ名、DNS 未検証ドメイン、期限切れセッション、失効デバイス |

**差分テストで正規化が必要な非決定要素**（M1 でフィルタを作る）:
乱数由来 ID (`srv-<ms>-<hex>`, `msg-…`, MIME boundary, PGP セッション鍵, セッショントークン),
タイムスタンプ (`receivedAt`, `created_at`, `expires_at`, DKIM `t=`, `Date:`),
`Message-Id`, JMAP `state` 文字列, マップ反復順（Go の map は順不同なので
`Accounts()` や `ListDeviceKeys()` の順序は**比較前にソートする**）。

---

## 8. リスクと未決事項

### A. 【解決済】go-jmapserver のソース

`~/go-jmapserver` (`39a4d0e`) の入手により解決 (§2.1 / §2.2)。
**残る作業**: `~/go-jmapserver` は移植中に更新される可能性があるので、
移植の基準コミットを `39a4d0e` に固定し、M8 で `git log 39a4d0e..HEAD` を確認して
差分があれば取り込む。

### A'. 【新規】oracle の陳腐化

差分テストは「Go 版が正しい」という前提に立つ。移植中に Go 版側にバグ修正が入ると
差分が出るが、それは Rust のバグではない。
→ `oracle/` のコミットハッシュを `SPEC.md` に記録し、更新は意図的な操作としてのみ行う。

### B. rpgp と ProtonMail/go-crypto の出力差

インライン PGP 暗号化の armor 出力は、鍵・アルゴリズムが同じでも
セッション鍵がランダムなのでバイト一致はしない (これは正常)。
ただし **DeltaChat / biset-ui が復号できること**は必須。
→ M5 で **Rust が暗号化 → Go の go-crypto で復号 / Go が暗号化 → rpgp で復号** の
交差テストを行い、さらに biset-ui の復号コードにも食わせる。

### C. 自前 SMTP サーバ実装

`go-smtp` を捨てて書くので、プロトコル準拠のバグが混入しうる (パイプライン、
行長制限 1000B、ドットスタッフィング、`BDAT`、SMTPUTF8)。
→ 送信テストは実 MTA (Postfix コンテナ) 相手に行い、`swaks` でエッジケースを叩く。
→ **受信側は差分テストできる**: 同じ生バイト列を Go 版と Rust 版の 25 番に流し込み、
結果として `data/` に落ちたメッセージ JSON を比較する。

### D. `main.go` の巨大 `handler`

`makeStore` のクロージャ (`OnCreateEmail` / `OnSubmitEmail`) が `cfg` グローバル、
`store`、`hub`、`dataDir` を全部キャプチャしている。Rust では所有権が問題になる。
→ グローバル `cfg` は `OnceLock<Config>` (または `Arc<Config>` を明示的に配る)、
クロージャは `Arc<AccountCtx>` を 1 つ捕まえる形に整理する。**構造の再設計はここだけ**、
それ以外は Go の構造をなるべく写す (差分レビューを可能にするため)。

### E. `os.WriteFile("/tmp/jmapsmtp-last-in.eml")` などのデバッグ出力

Go 版は受信・送信のたびに `/tmp/jmapsmtp-last-{in,out}.eml` に生メールを書いている
（平文が残る）。

**【確定】`debug_dump_eml: bool` の config フラグを追加し、既定 off にする。**
これが Go 版と意図的に挙動を変える**唯一の箇所**。差分テストでは
`debug_dump_eml: true` を立てて Go 版と揃えて比較し、既定値の差だけを別途テストする。

### F. 【確定済】設計判断

1. **`data/` 互換は必須** ✔ 確定。§5.2 の全ファイルについて双方向互換をテストする。
2. **`go-jmapserver` は本リポジトリの workspace crate として取り込む** ✔ 確定。
   将来 `go-jmapap` (AP リレー) も Rust 化する段階になったら、
   `crates/jmapserver` を独立リポジトリに切り出す（そのため crate 内から
   `jmapsmtp` 固有の型を参照しない、という制約は M3 以降ずっと守る）。
3. **ドキュメントの言語** ✔ 確定 — `PLAN.md` / `SPEC.md` / `JOURNAL.md` は日本語、
   `ARC.md` / `README.md` / `MIGRATION.md` は**英語**（移植元に合わせる）。
   コード中のコメントは英語（Go 版のコメントは設計判断の記録として価値が高いので、
   移植時にできるだけ内容を保存する）。

### G. 【新規】HTML→テキスト変換の出力差

`email.go:641` が `JohannesKaufmann/html-to-markdown` で HTML 本文を Markdown に
変換している。Rust 側 (`htmd` / `html2md`) は**同じ HTML から違う Markdown を出す**
可能性が高く、ここは差分テストが確実に赤くなる箇所。

→ 影響範囲は「HTML メールを受信したときの `textBody` の中身」。
選択肢は (a) 差異を許容して正規化フィルタで吸収、(b) Go の変換ルールに合わせて
薄いラッパを自前で書く。**M5 で実際の差分を見てから決める**（先に決め打ちしない）。

---

## 9. 見積り

| フェーズ | 内容 | 移植元 Go 行数 | 規模感 |
|---|---|---:|---|
| M0 | 環境整備 + oracle 固定 | — | 小 |
| M1 | 差分テスト基盤 + SPEC.md | — | 中 — **ここが後半の速度と安全性を決める** |
| M2 | cryptenv | 219 | 小 |
| M3 | 型 + Store | 699 + 〜1,500 | 大 |
| M4 | JMAP HTTP サーバ | 562 + 130 + 各メソッド 〜900 | 大 |
| M5 | MIME + SMTP | 892 + jmapsmtp 側 〜900 | **最大**（自前 SMTP サーバ含む） |
| M6 | アカウント/認証 | 246 + 130 + 241 + jmapsmtp 側 〜1,000 | 中〜大 |
| M7 | 周辺機能 | 〜1,000 | 中 |
| M8 | 統合検証 | — | 中 |

M1 に時間をかけるのが最も費用対効果が高い。差分ハーネスが動けば、以降の
全フェーズで「合っているか」を自分で判定できるようになる。

---

## 10. 次のアクション

**着手前の確認はすべて完了**（§8-A 解決、§8-E 確定、§8-F 1〜3 確定）。**未決事項なし。**

1. **M0**: rustup 導入 → `git init` → workspace 雛形 → `oracle/` 固定
2. **M1**: 差分ハーネスを作り、Go 対 Go で green にする
3. **M2**: cryptenv（最初の縦切り、Go と相互運用検証）

作業の進捗・判断・詰まった点は [`JOURNAL.md`](JOURNAL.md) に随時記録する。

# SPEC — 互換性契約

Rust 版が Go 版と一致していなければならない事項のうち、
**差分ハーネス (`xtask difftest`) では検証できないもの**を記録する。

ハーネスで検証できるものはここに書かない。書くと二重管理になり、必ず片方が腐る。
「HTTP のこのレスポンスがこう」は `target/difftest/*/transcript.txt` が正解であり、
その正解は oracle が生成する。**この文書が扱うのは、リクエストを投げるだけでは
観測できない事柄**（起動順序、周期処理、暗号定数、ディスク形式、外部プロトコル）に限る。

---

## 0. 基準リビジョン

| 対象 | リビジョン |
|---|---|
| `go-jmapsmtp` | `1b5cf06` |
| `go-jmapserver` | `39a4d0e` |
| `git.sr.ht/~rockorager/go-jmap` | `v0.5.3` |

`just oracle-check` が go-jmapserver の drift を報告する。
**基準を動かすのは意図的な操作に限る**（PLAN.md §8-A'）。動かしたらこの表を更新し、
ゴールデンを取り直す。

---

## 1. 差分ハーネスの守備範囲

### 検証できる（＝ SPEC に書かない）

- HTTP のステータス / ヘッダ / ボディ、全エンドポイント
- CORS ヘッダの値（**ハンドラごとに違う**。`/jmap/api/` は `GET, POST, OPTIONS`、
  `WrapCORS` 経由は `GET, POST, PUT, OPTIONS` ——
  この不揃いは Go 版の実態であり、統一してはいけない）
- `data/` に生成されるファイルの集合と内容
- 起動ログの行

### 検証できない（＝ SPEC に書く）

| 項目 | 理由 | 節 |
|---|---|---|
| 起動シーケンスの**順序** | 最終状態は同じでも順序依存のバグは出る | §2 |
| 周期処理 | 6 時間待たないと発火しない | §3 |
| 暗号パラメータ・署名対象文字列 | 外部（クライアント・anchor）と合わせる必要がある | §4 |
| ディスク形式の意味 | ハーネスはバイト比較しかせず、意図を知らない | §5 |
| SMTP プロトコル挙動 | HTTP ハーネスの外 | §6 |
| メッセージ変換パイプライン | 段ごとの責務は最終出力から逆算できない | §7 |
| 外部サービスとの通信 | anchor / MX / DNS | §8 |

---

## 2. 起動シーケンス（順序が契約）

`main.go:main()` の順序。**入れ替えてはいけない箇所に理由を付す。**

1. 実行ファイルのあるディレクトリを解決 → `config.json` を読む
   - `dir = filepath.Abs(filepath.Dir(os.Args[0]))`。カレントディレクトリではない
   - `dataDir = dir/data`
2. `domain` が空なら **fatal**
3. `checkAnchorConfig()`
   - anchor 有効ビルド: `anchor_url` があって `anchor_token` が空なら **fatal**
     （警告で済ませてはいけない。認証なしの anchor 書き込みは誰でも名前を奪える）
   - noanchor ビルド: `anchor_url` があれば警告のみ
4. `loadPGPEntity()` — 環境変数 `BISET_PGP_KEY`（armored）から全体公開鍵
5. **`loadDynDomains(dataDir)`** ← 6 より必ず先
   - 直後の孤児掃除が、検証済みカスタムドメインを孤児と誤認して消すため
6. `cleanupOrphanedData(dir)`
   - `data/<domain>/` のうち config にも動的ドメインにも無いものを削除
   - `data/<domain>/<lp>/` のうち静的アカウントでなく **`auth_token_hash` も無い**ものを削除
   - `_domains` と `peers` は対象外
   - **`envelope.json` の有無で判定してはいけない**。envelope を持たない
     third-party/DID-only アカウントが正当に存在し、再起動ごとに消える
7. `loadOrGenerateDKIMKeys(dir)` — ドメイン毎に `key.pem` を load-or-create、`dkim-dns.txt` 出力
8. handler 構築 → `hub.SetPersistDir(dataDir)`
9. `cfg.AuthFunc = buildAuthFunc(h, dataDir)`
10. envelope の無い静的アカウントに setup token を発行（既存ファイルがあれば再利用）
    - ログ: `[setup] <lp>@<domain>: <base_url>/setup?token=<token>`
11. エイリアスマップと Store を構築
    - `@` を含まないエイリアスは当該ドメインを補う。すべて小文字化
12. `scanDynAccounts(h, dataDir)` — 動的アカウントの復旧
    - **存在の定義は `auth_token_hash` があること**（6 と同じ理由）
13. `startMaintenance(h, dataDir)`
14. SMTP サーバを goroutine で起動
15. mux 構築 → 各 `register*` → `ListenAndServe(addr, WrapCORS(mux))`
    - `addr` 既定 `0.0.0.0:8765`（`config.example.json` の `8767` とは別物）

**ルート登録は 1 パス 1 回**。`net/http` の `ServeMux` は同一パターンの二重登録で
起動時 panic する。`/account/devices` の GET/POST/DELETE を別々に登録した実装が
実際に本番の anchored relay を全滅させた（devices.go 冒頭のコメント）。
Rust では axum が同じ制約を持たないため**コンパイル時にも実行時にも気づけない**。
`route_registration_test.go` 相当のテストを必ず移植すること。

---

## 3. 周期処理

`startMaintenance`: `inactive_purge_days <= 0` なら**起動しない**。
それ以外は 6 時間ごとに `purgeInactiveAccounts`。

削除条件（全部満たすこと）:

1. `allow_provision: true` のドメイン配下
2. 静的アカウントでない
3. `data/<domain>/<lp>/` 配下の最新 mtime が `now - inactive_purge_days` より古い
4. `peer_data_dirs` の各 `<peer>/<domain>/<lp>/` も同様に古い
   （**片方で活動していれば削除しない**。jmapap と jmapsmtp のどちらかで生きていれば生存）

削除操作: `os.RemoveAll(acctDir)` + 書き込みロック下で `stores` / `dyn` / `aliases` から除去。
`aliases` は **値が当該アドレスのものすべて**を消す（キー一致だけでは足りない）。

容量制限: `max_account_storage_mb > 0` のとき、`OnCreateEmail`（受信）と
`OnSubmitEmail`（送信）の**両方**が `dirSizeMB` を先に見る。到達していればエラーを返す。

---

## 4. 凍結された暗号定数

**ここを変えると全ユーザがログインできなくなる。**

### cryptenv エンベロープ

| 項目 | 値 |
|---|---|
| KDF | Argon2id, `t=3`, `m=65536` (KiB), `p=4`, 出力 32B |
| salt | 16B |
| master_secret | 32B |
| AES-GCM nonce | 12B。`wrapped_secret = nonce ‖ ciphertext ‖ tag` |
| HKDF | SHA-256, salt なし |
| auth の info | `biset-jmapsmtp/auth/v1` → 32B |
| KEK の info | `biset-jmapsmtp/enc/v1` → 32B |
| `auth_token_hash` | `sha256(auth_token)` |
| バージョン | `1`。他は拒否 |

JSON 形状（バイト列は base64、`encoding/json` の `[]byte` 既定）:

```json
{"v":1,"salt":"…","kdf":{"t":3,"m":65536,"p":4},"wrapped_secret":"…","auth_token_hash":"…"}
```

**ブラウザ側 (`setupHTMLTemplate` 内の JS) がこの形を生成する**ため、
サーバだけ変えることはできない。

### 署名対象文字列

クライアント (`biset/src/did/devicebind.ts`) と anchor の 3 者が
バイト単位で一致していなければならない。

| 用途 | 文字列 |
|---|---|
| セッションログイン | `session:<did>:<devicePubKeyB64url>:<ts>` |
| デバイス vouch | `devkey:<did>:<devicePubKeyB64url>:<label>:<ts>` |

- 署名アルゴリズム: ed25519
- 署名のエンコード: **base64 標準**（URL-safe ではない）
- `devicePubKeyB64url`: **base64url**。デコードは RawURL → URL の順に試す
- 時刻ずれ許容: **±300 秒**（anchor の `BIND_WINDOW_SECONDS` と同値）

### did:dht

`did:dht:<zbase32(ed25519公開鍵32B)>` は自己証明的。
**ネットワークアクセスなしで**識別子から鍵を復元して検証する。

zbase32 アルファベット（RFC 4648 の base32 とは別物）:

```
ybndrfg8ejkmcpqxot1uwisza345h769
```

- エンコード: 5bit ずつ、末尾は左シフトでパディング
- デコード: **正確に `byteLen` バイト**を取り出し、末尾の余剰ビットは捨てる。
  取り出せた長さが `byteLen` と違えば失敗
- `did:dht:` 以外の DID にこの近道は無い（did:webvh の root key は識別子に無い）

### WKD ハッシュ

`zbase32(sha1(lowercase(localpart)))`。

Go 版では `wkd.go` の `wkdHash` と `diddht.go` の `Zbase32Encode` が
**同じアルゴリズムの重複実装**になっている（実際に両者を走らせて出力一致を確認済み。
`zbase32(sha1("alice")) = kei1q4tipxxu1yj79k9kfukdhfy631xe`）。
Rust では 1 つの実装を共有してよい。

### カスタムドメインのトークン

| 用途 | 計算 |
|---|---|
| 所有証明 TXT | `"biset-verify=" + hex(hmac_sha256(domain_verify_secret, domain))[:32]` |
| provision secret | `hex(hmac_sha256(domain_verify_secret, "provision:" + domain))[:32]` |

いずれも**決定的**（保存も期限管理もしない）。TXT のレコード名は `_biset-verify.<domain>`。

---

## 5. `data/` の意味論

形式そのものはハーネスがバイト比較する。ここに書くのは**なぜそうなっているか**。

| パス | 内容 | 注意 |
|---|---|---|
| `smtp-tls-{cert,key}.pem` | 受信 STARTTLS 用 | 無ければ自己署名を生成。`smtp_tls_cert/key` 設定時はそちらを modtime 監視付きで再読み込み |
| `<domain>/key.pem` | DKIM 秘密鍵 (PKCS#8) | **絶対に再生成しない** load-or-create。`O_EXCL` で作る |
| `<domain>/dkim-dns.txt` | 公開用 TXT | 人間向け。先頭 2 行はコメント |
| `<domain>/peers/<addr>.pgp` | Autocrypt ピア公開鍵 | **バイナリ** OpenPGP（armor ではない）。`addr` は小文字化 |
| `_domains/<domain>/domain.json` | 動的ドメイン設定 | `DomainConfig` そのまま。`allow_provision` は常に false、`provision_secret` で門番 |
| `<domain>/<lp>/setup.token` | 初回設定トークン | 消費されたら削除。存在＝未初期化 |
| `<domain>/<lp>/envelope.json` | cryptenv エンベロープ | **任意**。third-party relay には無い |
| `<domain>/<lp>/auth_token_hash` | relay スコープの credential | **アカウント存在の定義はこれ**（envelope ではない） |
| `<domain>/<lp>/devices/<id>.json` | `{"id","label","created_at"}` | `id` = base64url 公開鍵。ファイル名がそのまま ID |
| `<domain>/<lp>/sessions/<hash>.json` | `{"device_id","expires_at"}` | `hash` = `base64url_nopad(sha256(生トークン))`。**トークン本体は保存しない** |
| `<domain>/<lp>/pubkey.pgp` | armored 公開鍵 | |
| `<domain>/<lp>/privkey.enc` | クライアント暗号化済み秘密鍵 | サーバにとって不透明 |
| `<domain>/<lp>/messages/<encid>.json` | JMAP メール | `encid` = `encodeURIComponent(id)`。AP の ID が URL で `/` `:` を含むため |
| `<domain>/<lp>/activity.log` | 追記型監査ログ | 書き込み失敗は配送を止めない（best-effort） |

**一ファイル一事実**。共有リストファイルを作らない（並行書き込みの競合を避けるため、
`devices/` も `sessions/` も index を持たない）。

### 落とすと壊れる挙動

1. `ListDeviceKeys` は `devices/` が無くても **`[]` を返す**（`null` 不可）。
   `null.length` でクライアントの Devices モーダルが例外落ちする
2. `RemoveDeviceKey` は **そのデバイスの `sessions/` も全部消す**。
   消さないと revoke 済みデバイスがトークン期限まで動き続ける
3. `CheckSessionToken` は期限切れと未知を**区別しない**（どちらも `ok=false`）

---

## 6. SMTP

### 受信 (port 25)

- 使用機能は `MAIL` / `RCPT` / `DATA` / `RSET` / `QUIT` / `STARTTLS` / `SMTPUTF8` のみ
- `AuthPlain` は**無条件で成功**を返す（受信時に認証しない）
- `RCPT TO` はエイリアスマップに**無ければ黙って捨てる**（エラーを返さない）
- 宛先が 0 件の `DATA` は成功として捨てる
- 同一 primary に解決される複数宛先は 1 通だけ配送
- 受信メールは容量 256 のチャネルに積む。**溢れたらログを出して捨てる**
- チャネルは `Email/query` 到達時に `drainBuffer` で Store に流し込む
  （受信直後ではない。ここは JMAP のリクエストが引き金）

### 送信

- `relay_host` あり: 1 接続に全宛先
- なし: 宛先ドメインごとに `LookupMX` → **最優先 MX の 1 件だけ**に `:25` で接続
  （フォールバックしない）
- STARTTLS は日和見。失敗しても**平文で継続**
- `RCPT TO` が拒否されてもログのみで**継続**（他の宛先には送る）
- 失敗は最初のエラーだけを返す

---

## 7. メッセージ変換パイプライン

段の順序が契約。出力だけ見ても復元できない。

### 受信

```
生バイト → ParseMIMEEmail
  → Autocrypt: ヘッダがあれば addr/keydata を取り出し peers/<addr>.pgp に保存
     （最初に解決できた宛先のドメイン配下に 1 回だけ）
  → 宛先ごとに:
       ID = makeMessageID(元Message-ID, primary, now)
       MailboxIDs = { makeMailboxID(primary): true }
       本文に "-----BEGIN PGP MESSAGE-----" を含む
         → yes: keywords に $e2e を付けてそのまま
         → no : 受信者 pubkey.pgp があれば
                  添付があれば buildEncryptedMultipart で multipart/mixed に再構築
                  → pgpEncryptInline → textBody の各 partID に格納、htmlBody を捨てる
  → bufCh へ
```

### 送信

```
EmailSubmission/set
  → 容量チェック
  → envelope が無ければ BuildEnvelope(msg)。宛先ゼロならエラー
  → reply_only_outbound かつ送信者が exempt でない
       → Store 内の全メールの From を集め、全宛先がその中に無ければ拒否
  → keywords から $draft を削除
  → 保存用のコピーを作る（SMTP 用とは別）
       本文が PGP → $e2e
       そうでなく pubkey.pgp があれば → pgpEncryptInline して textBody を差し替え、htmlBody を捨てる
  → Store.Put → hub.Notify
  → 非同期で:
       BuildRFC5322 → Autocrypt ヘッダ注入 → Chat-Version: 1.0 注入
       → 本文が inline PGP なら pgpMIMEWrapInline で RFC 3156 multipart/encrypted に
       → signDKIMForDomain(From のドメイン)
       → 配送
       → activity.log に記録
       → 成功かつ Message-ID が生成されていれば Store を更新して再 Notify
```

**注意**: SMTP に流すメッセージと Store に保存するメッセージは**別物**。
保存側だけ Layer 1 暗号化される。

DKIM 署名ヘッダ（順序も含めて固定）:

```
From, To, Cc, Subject, Date, Message-Id, Content-Type
```
canonicalization は header/body とも `relaxed`。

---

## 8. 外部サービス

### identity anchor

`anchor_url` が空なら**DID を一切扱わない**。より緩いのではなく**より厳しい**モード:
DID 付きのアカウント作成は 400 で拒否する（証明する相手がいないため）。
`PUT /account/did` も 400。以前 204 を返していたが、やっていない仕事を成功と報告するのは嘘。

`anchorClaim` の戻り値は `"ok"` / `"invalid"` / `"conflict"` / `"error"` /
（noanchor ビルドのみ）`"unsupported"`。
`r.Host` は**クライアントが署名した値**なのでそのまま転送する。

### DNS

| 用途 | クエリ |
|---|---|
| 送信先 MX | `LookupMX(domain)` |
| カスタムドメイン所有証明 | `LookupTXT("_biset-verify." + domain)` |

---

## 9. エンドポイント一覧

ハーネスがカバーするので詳細は書かない。**存在すること**の確認用。

### jmapsmtp

`/setup` `/auth/envelope` `/auth/signup` `/account/provision` `/account/delete`
`/account/session` `/account/devices` `/account/did`※ `/relay-info`
`/.well-known/openpgpkey/policy` `/.well-known/openpgpkey/hu/` `/pgp/pubkey`
`/pgp/privkey` `/pgp/peerkey` `/domain/verify-token`† `/domain/add`†
`/admin/drain-anchor`※ `/pkarr/`※

### jmapserver

`/.well-known/jmap` `/jmap/api/` `/jmap/eventsource/` `/jmap/upload/` `/jmap/download/`
`/jmap/push/vapid-public-key` `/jmap/push/subscribe` `/jmap/push/unsubscribe`
`/contacts` `/contacts/` `/account/storage` `/account/storage/messages`
`/account/storage/export` `/account/storage/purge-messages`
`/metrics` `/admin/dashboard` `/admin/accounts` `/admin/accounts/`

※ anchor 有効ビルドのみ　† `domain_verify_secret` 設定時のみ

### JMAP メソッド (26)

```
Mailbox/get,changes,query,queryChanges,set   Thread/get,changes
Email/get,changes,query,queryChanges,set,copy,import,parse
SearchSnippet/get                            Identity/get,changes,set
EmailSubmission/get,changes,query,queryChanges,set
VacationResponse/get,set
```

加えて back-reference 解決（`#` 参照 / JSON Pointer）。

---

## 10. 認証の 3 経路

`buildAuthFunc`（JMAP 本体）と `authenticate`（補助エンドポイント）は
**別の関数だが同じ credential 形状を受け付けなければならない**。
片方だけ更新した結果、セッションログインしたアカウントが JMAP から締め出された
実績がある（auth_env.go 冒頭のコメント）。

| 順 | 経路 | 検証 |
|---|---|---|
| 1 | セッションベアラ | `CheckSessionToken(acctDir, password)` |
| 2 | 静的 auth_token | `VerifyAuthToken(base64decode(password), auth_token_hash)` |
| 3 | — | どちらも通らなければ 401 |

- username は `<lp>@<domain>` 形式。小文字化してから分割
- `authenticate` は先に `domainConfig(dm)` の存在を見る（未知ドメインは即 false）
- `buildAuthFunc` は静的アカウントか `h.dyn` 登録済みかを見る
- base64 デコードは Std → RawStd → URL → RawURL の順に試す

`POST /account/devices`（新デバイスの vouch）だけは `authenticate` の**外**。
vouch 署名そのものが証明であり、これが完全なコールドリカバリ
（ニーモニックのみ・既存セッション無し）の入口になる。

---

## 11. 意図的な差異

**Go 版が常に正しいわけではない。** 明らかなバグまで移植する必要はない。
ただし差異は必ずここに記録する。記録のない差異は移植ミスと区別がつかない。

各項目に **Go 版の挙動 / 変更後の挙動 / 変更する理由** を書く。
差分ハーネスで観測できる差異には、シナリオ側に
`divergence: Some("§11-N")` を宣言する（下記 §11.9）。

### 11.1 `debug_dump_eml`（設定追加、既定 off）

- **Go**: 受信・送信のたび `/tmp/jmapsmtp-last-{in,out}.eml` に生メールを書く。無条件
- **Rust**: `debug_dump_eml: bool` を追加し、既定 `false`
- **理由**: 平文メールが `/tmp` に残り続ける。デバッグ用途を消しはしないが、
  既定で有効にしておく理由がない
- **差分テスト**: fixture で `true` にして Go 版と揃える

### 11.2 エンベロープの検証（`cryptenv::Envelope::from_bytes`）

- **Go**: `FromBytes` は `json.Unmarshal` するだけで**何も検証しない**。
  `{}` も `null` もエラーなくゼロ値のエンベロープになる（実際に確認済み）
- **Rust**: 復号が原理的に不可能な値を拒否する
- **理由**: これは実害のあるバグ。`POST /auth/signup?token=X` に `{}` を送ると、
  **一度きりの setup token が消費され**、ゼロ値エンベロープが書かれて 204 が返る。
  以降 signup は「already initialized」で 409、どんなパスワードでも復号できない。
  **未認証の攻撃者が空の JSON オブジェクト 1 つでアカウントを永久に潰せる**

拒否する条件（**復号が不可能なものだけ**。異常だが動くパラメータは通す）:

| 条件 | 理由 |
|---|---|
| `v != 1` | `Unseal` が元々拒否する値 |
| `salt.len() < 8` | Argon2 が受け付けない下限 |
| `kdf.t < 1` | **Go の argon2 は panic する** |
| `kdf.p < 1` | 同上 |
| `kdf.m < 8*p` | Argon2 のメモリ下限 |
| `wrapped_secret.len() <= 28` | nonce(12) + tag(16) すら入らない |
| `auth_token_hash.len() != 32` | sha256 の出力長 |

**通す**もの: `t=1, m=8, p=1`（最小構成）、salt 8 バイト、`wrapped_secret` 29 バイト。
検証はポリシーの押し付けではなく、不可能値の排除に限る。

**HTTP レベルの影響**（M6 で観測されるようになる）:
`POST /auth/signup` と `PUT /auth/envelope`、`POST /account/provision` の
envelope フィールドで、壊れたエンベロープに対し Go=204/成功 → Rust=400。

### 11.3 `Rewrap` のバージョン検査

- **Go**: `Unseal` は `Version` を検査するが `Rewrap` は検査しない
- **Rust**: 両方で検査する
- **理由**: 将来の v2 エンベロープが v1 の解釈で黙って rewrap される。
  非対称に検査する理由がない
- **影響**: サーバは `Rewrap` を呼ばないので HTTP レベルの差異なし

### 11.4 `hkdfExtract` の panic

- **Go**: `io.ReadFull` 失敗時に `panic(err)`
- **Rust**: 32 バイトの HKDF 展開は型レベルで失敗しえないので `expect` のまま残す
- **理由**: 実質的な差異なし。到達不能

---

### 11.9 差分ハーネスでの扱い

観測可能な差異は、シナリオのステップに宣言する:

```rust
Step { name: "...", divergence: Some("§11.2"), .. }
```

宣言されたステップは:

1. 両サイドの出力が**異なることを要求する**。同じなら
   「宣言された差異が観測されない」= **修正が失われた**として失敗させる
2. レポートに両方の答えを併記する

これにより「意図的な差異」と「移植ミス」がハーネス上で区別でき、
かつ修正が後のリファクタで消えたことも検出できる。

**実装時期**: Rust 版が HTTP を提供するのは M4 以降なので、この機構も M4 で入れる。
それまでは本節の記録のみ。

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
| `biset`（クライアント。署名対象文字列と DID モデルの出典） | `6030a0b` |

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

### JSON エンコード

**Go の `encoding/json` は既定で HTML エスケープする。** これは差異ではなく
**満たすべき要件**（見落とすと全メッセージファイルが 1 バイト単位で食い違う）。

| 文字 | Go の出力 |
|---|---|
| `<` | `\u003c` |
| `>` | `\u003e` |
| `&` | `\u0026` |
| U+2028 | `\u2028` |
| U+2029 | `\u2029` |

メールでは山括弧が普遍的（`inReplyTo` / `references` は `<id@host>` を
そのまま保持）、件名の `&` も日常的。`serde_json` は 5 つとも生で出すので、
**ディスクに書く / クライアントに送る経路はすべて `jmap_types::go_json` を通す**。

その他の一致事項:

- マップキーは**ソート順**（`encoding/json` がソートする）
- 構造体フィールドは**宣言順**
- `omitempty` は 0 / false / 空文字列 / **nil と空の map・slice の両方**を省く
- **`BodyValue.isTruncated` だけ `omitempty` が無い**ので常に出力される
- 未知フィールドは**エラーにせず無視**
- `time.Time` は RFC3339、小数部は末尾ゼロを削る（`.12`）、オフセットは保持

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

## 10-A. アイデンティティは DID（インボックスを支えているもの）

**このリレーにとってユーザの同一性はアドレスではなく DID である。**
アドレスはその DID が claim している**ルーティングラベル**にすぎない。
credential の連鎖はこうなっている:

```
DID（ルート鍵）
  └─ vouch: devkey:<did>:<devicePubKey>:<label>:<ts>   ← ルート鍵が署名
       └─ device key（<acctDir>/devices/<pubkey>.json）
            └─ session: session:<did>:<devicePubKey>:<ts>  ← デバイス鍵が署名
                 └─ session token（<acctDir>/sessions/<hash>.json）
```

署名対象文字列は biset `src/did/devicebind.ts` の
`vouchStatement` / `sessionLoginStatement` と**バイト一致**していなければならない。
**3 実装（クライアント / リレー / anchor）が同じ 1 本の文字列に合意している。**

### DID はディスクに保存しない（意図的）

`POST /account/provision` は DID を**必須**にする（無ければ 400 `did required`）が、
**リレーはどこにも DID を保存しない。**

> No local DID index to maintain: which addresses trace back to a DID is
> cross-relay information … keeping a second copy is what let this one drift
> out of step with the registry.  — `provision.go`

つまり「どのアドレスがどの DID に属するか」は anchor が claim から導出する。
**移植で「便利だから」と DID ファイルを追加してはいけない。**
そのドリフトが既に一度起きている。

### did:dht と did:webvh は非対称

| | 識別子の中身 | ローカル検証 |
|---|---|---|
| `did:dht:<zbase32(pubkey)>` | **ルート公開鍵そのもの**（32B） | **できる**（anchor 不要） |
| `did:webvh:<SCID>:<domain>:<path…>` | **genesis log entry のハッシュ** | **できない** |

did:webvh の SCID は
`base58btc(multihash(JCS(genesis log entry), sha256))`（biset `src/did/webvh/scid.ts`、
base58btc 46 文字）。**自己証明しているのは DID document log であって署名鍵ではない。**
現在の鍵は解決済み log の中にしか無いので、**照合する相手がここに存在しない。**

したがって:

- anchorless リレーは **did:webvh アカウントを作れない**（作らせてはいけない）
- `verify_did_dht_vouch_local` は **`did:dht:` 接頭辞以外を必ず拒否する**

**SCID を鍵として扱うと、誰でも任意の webvh アイデンティティに対して
デバイス vouch を偽造できる。** `a_webvh_did_carrying_a_real_key_in_its_scid_slot_is_still_refused`
が、SCID スロットに**本物の zbase32 鍵**を入れた上で正しい署名まで付けた場合を拒否することを固定している。

> SCID が 46 文字で 32 バイトにデコードできないのは**偶然であって防壁ではない**。
> 防壁は接頭辞チェックのほうであり、テストはそちらを検証している。

### DID は不透明に扱う

did:webvh はポート番号と任意のパスセグメントを持てる（`did:webvh:<scid>:biset.md:dids:alice`）。
`:` で分割して解釈し直す実装は壊れる。
**署名対象文字列は DID を verbatim で埋め込む**ので、正規化も再エンコードもしてはいけない。

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

### 11.5 マップ反復順に由来する非決定性の解消

- **Go**: `msgs` / `newByID` などが `map` なので**反復順がランダム**。
  結果として `delta.json` の以下が実行ごとに変わる:
  - `Purge` の `Removed` 配列の順序
  - `SyncMailboxes` の `Created` / `Destroyed` 配列の順序
  - 同一 Message-ID を持つメッセージが複数あるときの `resolveThreadID` の勝者
- **Rust**: `BTreeMap` / `BTreeSet` を使い、すべて**ソート順で決定的**
- **理由**: Go の出力自体が非決定なので「一致させる」対象が存在しない。
  配列は意味的に集合、重複 Message-ID に定義された勝者は無い。
  決定的なほうが再現性の点で厳密に良い
- **差分テスト**: `delta.json` は比較前に配列をソートして正規化する
  （`xtask` の `sort_json_arrays`）。**Go 対 Go でも差が出るため**、
  この正規化が無いとハーネス自体が不安定になる

### 11.6 【あえて直さない】メッセージファイル名の衝突

`safeFilename` は `/ \ : * ? " < > |` をすべて `-` に置換し、200 文字で切る。
**多対一の写像**なので、異なる ID が同じファイルに衝突しうる
（`a/b` と `a:b` は同じ `a-b`）。長い AP の URL では切り詰めでも衝突する。

衝突すると: 後勝ちで一方が消え、`Delete` は両方のファイルを消す。

**直さない。** ファイル名そのものが on-disk フォーマットであり（§5.2 の
`data/` 互換要件）、別方式にすると既存ファイルが旧名のまま取り残されて
新規書き込みだけが新名になる — 同じメッセージが 2 つの内容で読める状態になる。
ハザードとして記録し、テスト
(`safe_filename_collisions_are_a_known_hazard`) で明示的に固定する。

### 11.7 `Mailbox/set` が create と同時の update を捨てる（Go の実バグ）

- **Go**: `create` と `update` を**同じ呼び出しに含めると、rename が黙って消える**。
  レスポンスは `updated` に入れて**成功を報告する**
- **Rust**: index 経由で更新するので正しく反映される
- **原因**: `mbByID` がスライスの backing array への**ポインタ**を持つ。
  create ループの `append` で再確保が起き、update ループは**捨てられた配列**に書く。
  最後の再構築は新しい配列を読むので変更が失われる。
  加えて `mbByID[mb.ID] = &mb` はループ変数のアドレスなので、
  作成直後のメールボックスも同様に更新できない

Go 版で実測:

```
update のみ                → mbx-inbox=Renamed        （正常）
create + update 同時       → mbx-inbox=Inbox          （消失、成功報告）
作成直後のものを update    → mbx-inbox=Inbox          （消失、成功報告）
```

**影響**: 「メールボックスを1つ作りつつ1つ名前変更する」は正当な JMAP 操作で、
一括整理では自然に出る。クライアントは成功を受け取り、変更は失われる。
サイレントなデータ損失なので移植しない。

`dispatch_interop` で**宣言済み差異**として固定している。宣言された差異は
一致と同じ厳密さで検査される — **差が出なくなったら失敗**する。
修正がリファクタで失われたときに黙って通るほうが元のバグより悪い。

### 11.8 【あえて直さない】`oldState` と `newState` が同値になる

`Email/copy` / `Email/import` / `EmailSubmission/set` は `oldState` も `newState` も
**書き込みの後**に読むので、常に等しくなる（本来 `oldState` は書き込み前の値）。

**直さない。** 出力が変わる観測可能な差異であり、実害は「クライアントが状態変化を
1 つ見落とす可能性」に留まる（状態は各 `*/get` の `state` でも配られる）。
記録のみ。

### 11.5 への追記 (2): `ParseMIMEEmail` のヘッダ順

`Email.headers`（Chat-Group-Id などの非標準ヘッダ）は Go が
`msg.Header` マップを range して作るので、**配列の順序が実行ごとに変わる**。
同じヘッダが 2 回現れたときにどちらが勝つかも未定義。

この順序は**ディスクに書かれるメッセージ JSON にそのまま入る**。

Rust は名前順・最初の出現優先で決定的。
`mime_interop` は比較前にヘッダをソートする —
**入れる前は 1 回目が偶然通り、2 回目で落ちた。**

### 11.5 への追記: 同値タイの順序

`Store::all` の並べ替えで `receivedAt` が同値のとき、Go の `sort.Slice` は
**不安定ソート**であり、入力もマップ順なので順序が未定義。
`Email/copy` は `receivedAt` を引き継ぐので、コピーと元は必ずタイになる。

Rust は安定ソート + `BTreeMap`（ID 順）なので決定的。
`dispatch_interop` では、タイをクエリが観測しないようスクリプトを並べている。

### 11.10 DKIM の `h=` タグの順序

- **Go (go-msgauth)**: 指定した順序のまま列挙
  （`From:To:Cc:Subject:Date:Message-Id:Content-Type`）
- **Rust (mail-auth)**: **メッセージ中の出現順の逆**で列挙し、
  存在しないヘッダを末尾に置く
  （`Content-Type:Message-Id:Date:Subject:To:From:Cc`）
- **どちらも正当**。`h=` は「署名者がどの順で処理したか」の宣言であり、
  各実装は自分の `h=` と整合している。**Go の検証器が Rust の署名を受理する**
  ことで実証済み（`dkim_interop`）
- mail-auth の順序は RFC 6376 §5.4.2 が推奨する bottom-up 方式
  （転送中に前置されたヘッダが署名済みヘッダを押しのけられない）
- **合わせない。** 一致させるには mail-auth の署名器を使わないしかない。
  署名される**ヘッダの集合**は一致しており、テストはそれを検証する

同時に確認できたこと（差異ではない）:

- `t=` は**両方とも出す**（当初 grep を誤り「Go は出さない」と誤認した）
- `bh=` / `d=` / `s=` / `a=` / `c=` / `v=` は完全一致
- `b=` は `t=` を含むため必然的に異なる（RSA PKCS#1 v1.5 自体は決定的）

### 11.11 【重大】`pgpMIMEWrapInline` のリモート DoS

- **Go**: 本文中に `-----END PGP MESSAGE-----` が
  `-----BEGIN PGP MESSAGE-----` より**前**にあると **panic する**
- **Rust**: END マーカーを **BEGIN 以降から**探す。
  完全なブロックが無ければ `None` を返し、ラップせずそのまま送る
- **影響**: **リレープロセス全体が停止する**

原因:

```go
start := bytes.Index(body, startMarker)   // 全体から独立に検索
end   := bytes.Index(body, endMarker)     // 同上
if start < 0 || end < 0 { ... }           // 「両方見つかった」しか見ていない
pgpBlock := body[start : end+len(endMarker)]   // start > end で slice が逆走 → panic
```

到達経路:

1. `sendEmail` は raw に BEGIN が含まれれば `pgpMIMEWrapInline` を呼ぶ
2. `sendEmail` は `OnSubmitEmail` の中の **`go func()`** から呼ばれる
3. **回復されない goroutine の panic は Go プロセス全体を終了させる**

本文は認証済み送信者が自由に決められる値なので、
**1 通のメールでリレー上の全アカウントを止められる**。

`autocrypt_interop` で**宣言済み差異**として固定している。
Go 側ヘルパは `recover()` で panic を観測可能にしてあるが、
**本物のリレーにその防御は無い**。

---

### 11.12 `config.example.json` を実際に起動する内容にした

Go リポジトリの `config.example.json` は**コピーしても起動しない**。2 点:

1. `anchor_url` が設定済みで `anchor_token` が空。
   `checkAnchorConfig()` が `log.Fatalf` する組み合わせそのもの。
   **初回起動が、操作した覚えのないフィールドの話をして死ぬ**
2. `account` のキーが**フルアドレス**（`you@example.com`）。
   キーは localpart で、`Accounts()` は `localpart + "@" + domain` を作るので
   `you@example.com@example.com` になる

Rust 側は `anchor_url` を空にし、キーを localpart にした。

**設定パーサの挙動は変えていない** — 変えたのは同梱のサンプルだけ。
`the_shipped_example_config_loads_and_validates` が、このファイルが
実際にパースと検証を通ることを固定する。サンプルは互換性の対象ではなく
ドキュメントなので、Go 版と一致させる理由が無い。

---

### 11.13 【重大】`ADMIN_TOKEN` 未設定で管理エンドポイントが全開になる

`go-jmapserver/metrics.go:bearerAuth`:

```go
if token != "" {
    ... Authorization を検証、不一致なら 401 ...
}
next.ServeHTTP(w, r)
```

**トークンが空だと検証を一切しない。** つまり環境変数 `ADMIN_TOKEN` /
`METRICS_TOKEN` を設定せずに起動したリレーは、**ポートに到達できる誰にでも**
管理エンドポイントを提供する。oracle で実測:

| リクエスト（無認証） | 応答 |
|---|---|
| `GET /admin/accounts` | **200 + 全アカウントのアドレス一覧**（メッセージ数・使用バイト数つき） |
| `GET /metrics` | 200 |
| `POST /admin/drain-anchor` | ハンドラに到達（400 = 認証は通過している） |

最後のものは特に悪く、**anchor 上のこのリレーの claim を全部 release する
POST** が無認証で叩ける。

「トークン未設定 = 公開してよい」という読み方は成り立たない。
**設定していない運用者は、公開を選んだのではなく、考えていない。**

Rust 側は**空トークンを「閉じる」**として扱う（401）。
`bearer_interop` が**両実装が今も食い違っていること**を要求するので、
「忠実に移植し直す」と赤くなる。

#### アップグレードで壊れるケース（1 つある）

`METRICS_TOKEN` 未設定で Prometheus が `/metrics` を無認証スクレイプしている
構成は、401 になる。**これは意図的**:

- 破損は即座に見え、直し方は環境変数 1 つ（対して情報漏洩は見えない）
- 代替案は「`/admin/accounts` を開けたままにして監視を維持する」であり、
  取引として成立しない

「起動を拒否する」案も検討した（`checkAnchorConfig` と同じ形）。
採らなかったのは、**アップグレード後にリレーが起動しなくなる**のは
401 より重い障害だから。

---

### 11.14 【重大】封印した保存コピーに平文 HTML が残る

送信メッセージの保存コピーをアカウント自身の公開鍵で封じるのは、
**リレーがユーザの送信メールを読めないようにするため**。
ところが Go の実装は封印しきれていない。

```go
storedValues := ...   // BodyValues 全部をコピー
for _, part := range msg.TextBody {
    storedValues[part.PartID] = &email.BodyValue{Value: string(enc)}  // text だけ差し替え
}
msg.BodyValues = storedValues
msg.HTMLBody = nil    // ← 「参照」は消すが「値」は残る
```

oracle で実測した保存ファイル:

```json
{"bodyValues":{
   "1":{"value":"-----BEGIN PGP MESSAGE-----\n\nwcBMA0tv…"},
   "2":{"value":"<p>the secret plaintext</p>"}          ← 平文がそのまま
 },
 "textBody":[{"partId":"1",…}]}          ← htmlBody は消えている
```

**`htmlBody` の参照は消えているのに、part `2` の平文が残っている。**
リッチテキストのクライアントは HTML 代替を必ず送るので、
**実運用では大半のメッセージがこれに該当する。**

Rust 側は**参照と一緒に値も消す**。Go が始めた処理を完了させただけで、
意図を変えてはいない（参照されていない part には誰も到達できない）。

`hooks_interop` が**両実装が今も食い違っていること**を要求する。
Go 側が直れば「§11.14 は stale」と言って落ちる。

#### 直していないもの（意図的に範囲を広げていない）

**添付ファイルの body value はそのまま保存される。**
これは `seal_stored_body` の範囲を超える判断:
添付は「封印した本文の別レンダリング」ではないので、
どう扱うかを決めるとクライアントが開けるものが変わる。
**黙って広げず、ここに記録する。**

---

### 11.15 【重大】WKD で大文字混じりの `l=` がリレーの鍵を返す

`wkdHash` は入力を小文字化するのでハッシュ比較は**大文字小文字を無視する**。
ところが直後のアカウント検索は `domCfg.Accounts[localpart]` で、
**生のパラメータを使う**。

結果、`?l=Alice` は
1. ハッシュ比較を**通る**（「これは alice だ」）
2. アカウント検索で**外れる**（「そんな localpart は無い」）
3. **リレー全体の鍵にフォールバックする**

oracle で実測（リレー鍵を alice の鍵と**別のもの**にして）:

| リクエスト | 返る鍵 |
|---|---|
| `?l=alice` | **alice の鍵**（2294 バイト） |
| `?l=Alice` | **リレーの鍵**（2359 バイト） |

#### なぜ重大か

アドレス帳に `Alice@a.test` を持つ送信者は、WKD 検索で
**リレーが持っていて alice が持っていない鍵**を受け取り、それで暗号化する。

- **リレーはそのメールを読める**
- **alice は読めない**
- 送信者は E2E 暗号化したと思っている
- **どこにもエラーは出ない**

Rust 側はアカウント検索の前に小文字化する。
安全である理由: アカウントキーは常に小文字（provision が username を小文字化する）。
つまり小文字化しても、**ハッシュが既に特定した 1 アカウント**にしか当たらず、
別のユーザの鍵に当たることは原理的に無い。

`wkd_interop` が**両実装が今も食い違っていること**を要求する。

#### 見つかった経緯

**fixture を 1 つで兼用していたので、最初は見えなかった。**
リレー鍵とアカウント鍵に同じファイルを使うと
「alice の鍵が返った」という assert が**恒真**になる。

鍵を 2 つに分けた瞬間に露見した。
**「テストの入力が現実を代表していない」の 2 例目**（1 例目は §11.14 の HTML パート）。

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

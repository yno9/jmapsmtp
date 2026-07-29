# 作業記録 — go-jmapsmtp → Rust 移植

新しいエントリを**上に**追記する（最新が先頭）。
計画は [PLAN.md](PLAN.md)、凍結された仕様は `SPEC.md`（M1 で作成）。

書き方の方針:
- **判断とその理由**を残す。コードを読めばわかることは書かない
- 詰まった点・回り道は消さずに残す。同じ罠を二度踏まないため
- 各エントリに、実際に走らせて確認したコマンドと結果を添える

---

## 2026-07-29 — M6f（provision = DID がアカウントになる場所）完了 (`f240fa6`)

### 成果物

- `jmapsmtp/src/provision.rs` — HTTP も I/O も含まない判断ロジック
- `provision_interop` — **oracle の実エンドポイントに 14 リクエスト**投げて突き合わせ

テスト 387 件 green。

### なぜ判断ロジックを HTTP から分けたか

`/account/provision` の答えは
**ビルド（anchor 有無）× config × DID のメソッド × ディスクの状態**で決まる。
ハンドラの中に埋めると、この直積のうちテストから到達できない枝が必ず出る。

分けた結果、13 種の拒否すべてに単体テストと差分テストが付いた。

### 記録した挙動（SPEC §10-A）

| | 理由 |
|---|---|
| **デバイス鍵が credential そのもの** | このフローは `auth_token_hash` を一切書かない。vouch 検証→書き込みがアカウント登録より先なので「作ってから後でデバイス追加」の隙間が無い |
| did:dht は **anchor があってもローカル検証** | 識別子が鍵を持っているので往復に意味が無い |
| did:webvh は anchorless で**作れない** | SCID は genesis log entry のハッシュ。照合相手が存在しない |
| 名前の重複は**両方の credential 形状**で見る | `auth_token_hash` だけ見ると、このフローで作られたアカウントを他人に渡す |
| 存在しないドメイン指定は**開放ドメインに落とさない** | クライアントが頼んでいない場所に、別ドメイン向けに署名された名前で作られる |
| 空の `provision_secret` は空の提出と**一致してはいけない** | 素の `!=` だとそうなる。特権ドメインが作成可能になる |

did:webvh の拒否は `DeviceVouchRejected` と**別のメッセージ**にした。
「vouch は正しい、*リレー*が検証できない」はクライアントが対処できる情報だから。

### oracle は anchorless で動かした

これが**退化した設定ではなく、一番面白い設定**。
2 つの DID メソッドが分岐するのはここだけ。
anchored oracle だと本物の anchor に接続しにいってしまう。

各ケースに**専用の did:dht アイデンティティと本物の vouch 署名**を作った
（`seed` を変えた ed25519 鍵から `devkey:...` を署名）。
先のケースが作ったアカウントが後のケースの答えを変えないように、
username も全部別にした。

### 変異テストが 1 件通り抜けて、未検証の挙動が見つかった

`valid_username` の「先頭は小文字か数字」を `is_ascii_alphanumeric` に緩めても
**何も落ちなかった**。理由: `validate` が**先に小文字化している**ので
その枝に到達しない。

つまり **大文字 username は拒否ではなく成功する**（`Alice` → `alice`）。
これは今までどのテストも見ていなかった実際の挙動。

固定したもの:

1. `valid_username("Alice") == false`（述語単体としては拒否する）
2. `validate` は trim + 小文字化してから聞くので `"  Alice  "` は **Ok**
3. 差分テストで **`open.test/nora` が作られ、`open.test/  Nora  ` は無い**

これで 3 件目。**変異が通り抜けた時は、たいてい「テストが弱い」のではなく
「知らない挙動がある」**というパターンが見えてきた。

---

## 2026-07-29 — アイデンティティは DID である（`8f92815`）

biset 本体を読んだ（https://github.com/yno9/biset @ `6030a0b` → `~/biset/`）。
**リレー側のコードから推測せず、クライアントの `src/did/` を読んだ。**

### 判明したこと（SPEC §10-A にした）

**このリレーにとってユーザの同一性はアドレスではなく DID。**
アドレスはその DID が claim しているルーティングラベルにすぎない。

```
DID（ルート鍵）
  └─ devkey:<did>:<devicePubKey>:<label>:<ts>   ← ルート鍵が署名
       └─ device key
            └─ session:<did>:<devicePubKey>:<ts>  ← デバイス鍵が署名
                 └─ session token
```

署名対象文字列は biset `src/did/devicebind.ts` の
`vouchStatement` / `sessionLoginStatement` と**バイト一致していた**（確認済み）。

### DID はディスクに保存しない（意図的）

`POST /account/provision` は DID を**必須**にする（無ければ 400）のに、
**リレーはどこにも DID を保存しない。**

> keeping a second copy is what let this one drift out of step with the
> registry — `provision.go`

**移植で「便利だから」DID ファイルを足してはいけない。** 一度やって壊れている。

### did:dht と did:webvh は非対称 — SCID は鍵ではない

| | 識別子の中身 | ローカル検証 |
|---|---|---|
| `did:dht:<zbase32(pubkey)>` | **ルート公開鍵そのもの** | できる |
| `did:webvh:<SCID>:<domain>:<path…>` | **genesis log entry のハッシュ** | **できない** |

SCID = `base58btc(multihash(JCS(genesis log entry), sha256))`
（biset `src/did/webvh/scid.ts`、base58btc 46 文字）。
**自己証明しているのは DID document log であって署名鍵ではない。**
現在の鍵は解決済み log の中にしか無い。

だから anchorless リレーは **did:webvh アカウントを作れない**。

### 敵対的テストを書いた

**SCID を鍵として扱うと、誰でも任意の webvh アイデンティティに対して
デバイス vouch を偽造できる。**

そこで「webvh の形をしていて、SCID スロットに**本物の zbase32 鍵**が入っていて、
**正しい署名まで付いている**」ケースを拒否することを固定した。
同じ鍵を `did:dht:` にすると通る — つまり拒否の理由が
**接頭辞チェックだけであること**まで確認している。

> SCID が 46 文字で 32 バイトにデコードできないのは**偶然であって防壁ではない。**

### ついでに、既存テストの実質的な穴を潰した

`did_dht_vouches_are_judged_identically` は
**署名を 1 回作って全行で再利用**していた。
つまり拒否ケースは「DID が拒否されたから」ではなく
**「署名が合わなかったから」**通っていた。

`did_dht_root_key` に `did:webvh:` を受け入れさせる変異を入れても**緑のまま**だった。
行ごとに署名し直すよう直したら、その変異で落ちるようになった。

**M6e の `out.sort()` と同じ種類の穴** — 2 件目。
「赤にできないテストは無価値」を、既存テストにも遡って当てる必要がある。

---

## 2026-07-29 — M6e（handler の識別子とアカウント配送表）完了 (`cc22df7`)

### 成果物

- `jmapsmtp/src/handler.rs` — `makeStore` の識別子・容量計算・エイリアス表の部分
- `handler_interop` — **oracle が起動時にディスクへ書いたファイル**とバイト比較

テスト 356 件 green。

### Go ヘルパを書かずに済んだ

`defaultInbox` / `makeMailboxID` / `writeDKIMDNSFile` は
`package main` の非公開関数なのでリンクできない。しかし**通常起動すれば出力がディスクにある**:

```
data/a.test/alice/mailboxes.json
data/a.test/dkim-dns.txt
data/a.test/alice/setup.token
```

ヘルパを書くより強い。**実運用に存在するのはこのファイルそのもの**だから。
しかもこれらは**プロセスより長生きする** — 差異は
「アップグレード後にクライアントの mailbox id が変わる」
「移行後にメールが DKIM で落ちる」として現れる。

### 識別子の 2 つの性質

| | 理由 |
|---|---|
| mailbox id は**アドレスから導出**（採番しない） | 再起動でクライアントのキャッシュが無効化されない |
| message id は **RFC Message-ID 優先** | 再配送（リトライ、2 番目の MX）が重複ではなく上書きになる |

`/` の置換文字が 2 関数で 3 種類（`~` `_` `-`）ある。
醜いが**そのまま維持**した — 既にディスク上のファイル名に現れているので、
統一すると保存済みメッセージが全部孤児になる。

### 変異テストが 1 件、捕まえられなかった（隠さず記録した）

`extract_text_headers` の `out.sort()` を消しても**どのテストも落ちない**。
`serde_json::Map` は `preserve_order` feature が無ければ `BTreeMap` なので、
**入力が既にソート済み**だから。

つまり「ソートを固定している」と称するテストは、実際には何も固定していなかった。

対応:

1. `sort()` は**残す**。tree 内のどのクレートでも `preserve_order` を
   有効化できてしまい、その時これが Go の map 順序非決定性との唯一の防壁になる
2. コメントに「**defensive であって load-bearing ではない**」と明記
3. **前提そのものをテストにした** — `serde_json_object_iteration_is_already_ordered`。
   feature が有効化されたらこれが先に落ちて理由を名乗る

「緑のテストは、赤にできなければ無価値」を、
**赤にできないと分かった時にどうするか**まで含めて適用した形。

### 気づいた点

- `dir_size_mb` は**切り捨て**（Go と同じ）。1.9MB は 1 と読む。
  切り上げると上限直下のアカウントを拒否してしまう
- 読めないツリーは 0 として扱う。**容量チェックが送信を壊す手段になってはいけない**
- `Accounts::remove` はエイリアスも消す。残すと
  **到達できない store に解決され、そのアドレス宛のメールがエラー無く消える**

### 次

`OnCreateEmail` / `OnSubmitEmail` フック本体、そして各エンドポイント。

## 2026-07-29 — M6d（ルートテーブルと ServeMux 移植）完了 (`ce1e78d`)

### 成果物

- `jmapsmtp/src/gomux.rs` — `net/http.ServeMux` のルーティング移植
- `jmapsmtp/src/routes.rs` — 全ルートを 1 箇所に（登録が重複判定を兼ねる）
- `jmapsmtp/src/bearer.rs` — 管理系のトークン検証（**Go と意図的に違う**）
- `mux_interop` — ルート表とルーティング規則を oracle と突き合わせ
- `tests/oracle_harness/` — oracle を起動して叩く共通ハーネス

テスト 333 件 green（anchor / noanchor 両方で clippy clean）。

### axum を使わなかった理由 3 つ

1. **同じパターンの二重登録が panic する**。これが `route_registration_test.go` の
   守っている本番障害そのもの。axum は黙って受け入れるので、
   **移植すると「クラッシュを失い、バグを残す」**
2. **サブツリーパターン**。`/jmap/api/` は `/jmap/api/何でも` に一致し、
   残りはハンドラが自分で切る。axum なら 404
3. **リダイレクト**（クエリ付きで保存）

### Go のバージョンでリダイレクトのステータスが違う

**このマシンの `go` は 1.22 で、そのソースは 301 と書いてある。
oracle は 1.26.3 でビルドされていて、実際は 307。**

```
$ curl -si .../jmap/api
HTTP/1.1 307 Temporary Redirect
Location: /jmap/api/
```

ソースを読んでいたら**全サブツリールートで誤ったリダイレクト**を返す移植に
なっていた。**動いているバイナリに聞く**方針が、また効いた。

`gomux.rs` の冒頭にこの事情を書き、
「oracle を古い toolchain で再ビルドすると `mux_interop` が落ちる。
それが正しい挙動で、**テストを緩めるのではなく、どちらを送るか決める**」
と明記した。

### oracle に聞いて、ルート表が 3 箇所直った

登録箇所を読むだけでは分からない条件が付いていた:

| ルート | 実際の条件 |
|---|---|
| `/jmap/upload/` `/jmap/download/` | ハンドラが `BlobHandler` を実装している必要。**このリレーは実装していない** |
| `/pkarr/` | anchor ビルドだけでは足りず、**`anchor_url` が非空**である必要 |

### 【重大】`ADMIN_TOKEN` 未設定で管理系が全開になる

`bearerAuth` は `if token != ""` で囲まれている。
**空なら検証を一切しない。** oracle で実測:

```
GET /admin/accounts  → 200 {"accounts":[{"address":"alice@a.test",...}]}
GET /metrics         → 200
POST /admin/drain-anchor → ハンドラ到達（400）
```

最後は **anchor 上の claim を全部 release する POST が無認証**。

Rust は空トークンを**閉じる**扱いにした（SPEC §11.13）。
理由: 「設定していない運用者は、公開を選んだのではなく、考えていない」。

**アップグレードで 1 ケース壊れる**ことは認識している —
`METRICS_TOKEN` 無しの Prometheus スクレイプが 401 になる。
それでもこちらを選んだ。破損は即座に見えて直し方は環境変数 1 つだが、
情報漏洩は見えない。「起動を拒否する」案は、
**アップグレード後に起動しなくなるほうが 401 より重い**ので却下した。

### ハーネスがビルドを取り違えていた

`--no-default-features`（= `-tags noanchor`）のテストが
**anchor 版 oracle と比較していた**。別のプログラムなので比較が成立しない。
`ORACLE_BIN` を `cfg!(feature = "anchor")` で切り替えた。
noanchor ビルドで anchor ルートを主張させると、ちゃんと落ちる。

### このテスト対で捕まえられないもの（明記した）

**oracle にあって移植側が一度も挙げていないルート**は検出できない。
`ServeMux` を HTTP 越しに列挙する方法が無いため。
両リポジトリの `HandleFunc(` / `mux.Handle(` を網羅 grep して作り、
**ルート数を assert** して、減った時に diff に出るようにした。
テストファイルにこの限界をそのまま書いた。

### 存在確認の方法（ハンドラの 404 と区別する）

ステータスコードでは判定できない —
`/.well-known/openpgpkey/hu/` は鍵が無いとき `http.NotFound` を呼ぶので、
**mux 自身の 404 とバイト単位で同一**。

サブツリーパターンを**末尾スラッシュ無しで**要求すると 307 が返る。
これは mux にしか出せない答えなので曖昧さが無い。
（`/contacts` のように末尾無しも登録済みの場合だけ、弱い判定に落とす）

### 次

M6e: handler と Store 構築、そして各エンドポイントの中身。

## 2026-07-29 — M6c（起動シーケンス）完了 (`263f307`)

### 成果物

- `jmapsmtp/src/startup.rs` — SPEC §2 のステップ 5〜12（listener を開く前まで）
- `startup_interop` — **孤児掃除を oracle バイナリと突き合わせる**

テスト 298 件 green。

### 「順序が契約」を、順序を壊したテストで固定した

SPEC §2 に書いてあるだけでは移植で守られない。実際に**壊した側も書いた**:

```
// 誤った順序: レジストリが空のまま掃除
removed == ["data/byo.test"]   ← これが防ぎたいデータ損失
// 正しい順序
removed.is_empty()
```

検証済みカスタムドメインは `data/_domains/` にしか存在しないので、
先に掃除すると**そのドメインの全アカウントのメールが消える**。
テスト名にも `..._survives_only_because_it_was_loaded_first` と書いた。

### アカウントの定義は 2 箇所で一致していなければならない

掃除（消す側）と復旧スキャン（戻す側）が**別の定義を持つと、
どちらの向きでも再起動が破壊的になる**。片方が消し、片方が戻す。

両方 `auth_token_hash` を見る。`envelope.json` は見ない。
`the_scan_recovers_exactly_what_the_sweep_keeps` がこの一致を固定する。

### `remove_dir_all` を Go ソースの読解で済ませたくなかった

掃除はユーザのメールを消す。**oracle バイナリを実際に起動して**
生き残ったディレクトリを比較する形にした。

- Go ヘルパを書かない。**検証対象がバイナリの起動そのもの**なので、
  ヘルパを挟むと「テストと対象の間に再実装が入る」
- oracle は `argv[0]` のディレクトリから `config.json` を読むので、
  symlink を temp dir に置けばよい（`filepath.Abs` は symlink を解決しない）
- 起動完了の合図は **HTTP listener が開くこと**（ステップ 15 = 最後）

seed には**鏡像のアカウントを 2 つ**入れた —
「hash あり envelope 無し」と「envelope あり hash 無し」。
これで envelope 基準の実装は**両方向で**落ちる。実際に変異させると:

```
left:  [..., "a.test/enveloped", ...]        ← Rust が残した
right: [..., "a.test/dynamic", "byo.test/carol"] ← Go が残した
```

### 気づいた点

- setup token は**既存ファイルを再利用**する。毎回発行すると
  「オンボーディング中の再起動が、送信済みリンクを黙って無効にする」
- `peers/` はアカウントディレクトリと同じ階層にあり、
  **ドメイン全体の Autocrypt 鍵**が入っている。予約名リストで守った

---

## 2026-07-29 — M6b（config と認証層）完了 (`0b2a9d6`)

### 成果物

- `jmapsmtp/src/config.rs` — `config.json`（Go とスキーマ同一）
- `jmapsmtp/src/auth_env.rs` — ログインと、資格情報が載る 2 ファイル

テスト 284 件 green。

### 同梱の `config.example.json` が起動しなかった

**コピーしても起動しない**サンプルだった。2 点:

1. `anchor_url` あり + `anchor_token` 空 = `checkAnchorConfig()` が
   `log.Fatalf` する組み合わせそのもの。
   **初回起動が、操作した覚えのないフィールドの話をして死ぬ**
2. `account` のキーがフルアドレス（`you@example.com`）。
   キーは localpart なので `you@example.com@example.com` になる

サンプルは互換性の対象ではなく**ドキュメント**なので直した（SPEC §11.12）。
パーサは 1 バイトも変えていない。
`the_shipped_example_config_loads_and_validates` が、
このファイルが実際に通ることを固定する。

### 認証は「順序」が効いている

1. **セッショントークン**を先に見る。よくある経路であり、かつ**失効できる**方
2. 次に静的 `auth_token_hash`

そして「アカウントが既知か」を**ハッシュファイルを読む前に**確認する。
逆順だと、ディスクに残骸ディレクトリがある localpart
（削除済み、バックアップから戻したもの）が、
**設定されていないドメインで認証を通る**。

### アカウントの存在は `auth_token_hash` で決まる

`envelope.json` ではない。署名フローで作られたアカウントは envelope を
持たないので、そちらを見ると 404 になる。M6c の掃除と同じ規則で、
**この 2 つは一致していなければならない**。

### 気づいた点

- 未知フィールドは**拒否せず無視**する（Go の `encoding/json` と同じ）。
  新しいビルド用の config が**切り戻しで死なない**ため
- `anchor_token` 検査に「警告して続行」は無い。
  認証なしの anchor 書き込みは、誰でも未取得の名前を主張でき、
  他人の名前を release して DNS ごと奪える
- `provision_domain()` は Go だと map を range するので**実行ごとに答えが変わる**。
  ソート順にした（SPEC §11.5）。開放ドメイン 2 つは元々設定ミスだが、
  **せめて毎回同じ壊れ方**をする

---

## 2026-07-28 — M6a（認証プリミティブ）完了 (`1259cf2`)

### 成果物

- `jmapserver/src/authtoken.rs` — `auth_token_hash` の生成・検証・4 種 base64 デコード
- `jmapserver/src/diddht.rs` — zbase32、did:dht 自己証明検証、署名対象文字列
- `jmapserver/src/devicekeys.rs` — デバイス鍵とセッショントークンの保存
- `devicekeys_interop` — **両実装が互いのファイルを読む**

テスト 225 件 green。

### ここは `data/` 互換の要

SPEC §5.2 の「ディスク形式は互換必須」が最も直接効く部分。検証した組み合わせ:

| | 意味 |
|---|---|
| Go が書いたデバイス鍵を Rust が読む | 移行方向 |
| Rust が発行したトークンを Go が受理 | 切り戻し方向 |
| **失効が両方向で効く** | 権限だけ消してセッションが残ると「失効済みデバイスが期限まで動く」 |
| 署名判定（正常 / 別データ署名 / 期限切れ / 未来 / 未登録デバイス） | 判断が一致するか |
| did:dht vouch（自分 / 別 ID / 非 did:dht） | anchor 無しでも動く経路 |

### 落としやすい挙動を明示テストで固定

`ListDeviceKeys` は `devices/` が無くても **`[]` を返す**（`null` ではない）。
Go のコメントに「`null.length` で Devices モーダルが本番で真っ白になった」と
書かれている類。テストで `to_string(...) == "[]"` まで確認した —
**移植で黙って落ちる典型**だから。

### また自分のテストが間違っていた

zbase32 のデコードで「要求より短い/長い」は両方失敗すると思っていたが、
Go は**要求バイト数を満たしたら残り入力を無視する**ので、少なく要求すると
切り詰めて成功する。did:dht は常に 32 バイトなので実害は無いが、
**契約を推測ではなく明記**するようテストを書き直した。

### 気づいた点

- `decode_auth_token` は base64 を 4 種類（標準/パディング無し/URL-safe/両方）
  順に試す。クライアントがまちまちで、**デコード失敗と誤トークンは区別できない**から
- 署名は**標準 base64**、デバイス鍵は**base64url**。混ざっている。
  URL-safe を受け付けないことをテストで固定した

### 次

M6 の残り: config パース → 認証層 → axum ルータ → 起動シーケンス。

---

## 2026-07-28 — M5f（OpenPGP）完了 = **M5 完了** (`0205cf7`)

### 成果物

- `crates/jmapsmtp/src/pgp.rs` — 鍵パース（armor / binary）、インライン暗号化、
  Autocrypt ピア鍵の保存
- `pgp_interop` — **交差復号**を両方向

テスト 211 件 green。**M5（MIME + SMTP + 暗号）が全部終わった。**

### 検証は交差復号しかない

セッション鍵が毎回変わるのでバイト比較は原理的に不可能。
「一方が封じたものを他方が開けるか」だけが意味を持つ。

| 方向 | 意味 |
|---|---|
| Go が Rust の暗号文を開く | **移行方向**。Rust 稼働中に保存したメールが切り戻し後も読める |
| Rust が Go の暗号文を開く | **既存データ**。ディスク上のメールは全部 Go が封じたもの |

corpus: 平文 / 非 ASCII / multipart / 空 / **全 256 バイト値** / 200KB。

後者の Rust 側復号は**テスト専用**（リレーは秘密鍵を持たず復号しない）。
それでも価値がある — **鍵パースとパケット形状が噛み合っていることの証明**になる。

### rand のバージョンが 3 つ

- workspace: `rand` 0.9
- `rsa` 0.9: `rand_core` 0.6
- `rpgp` 0.16: `rand` 0.8

`RngCore` が別トレイトなので混ぜるとコンパイルエラーになる。
エイリアス依存 (`pgp_rand = { package = "rand", version = "0.8" }`) で解決。
**RNG は「黙って弱くなる」より「コンパイルが通らない」ほうが正しい失敗**。

### またテスト側のバグ

Autocrypt の**非 armor 形式（生パケット）は UTF-8 ではない**のに
JSON の文字列フィールドに載せていた。Go 側でパケットが壊れ、
「Go が鍵をパースできない」ように見えた。base64 で運ぶよう修正。

**エラーメッセージが指す先が原因とは限らない** — 3 回目の教訓。

### 設計判断: `store_peer_key` は書く前にパースする

後で読めないファイルは、ファイルが無いより悪い。
「ピアの鍵がある」ように見えて、そのピア宛の送信が全部平文になる。

### M5 全体の総括

| | 検証方法 |
|---|---|
| MIME | 17 件の corpus を Go とバイト比較 |
| DKIM | Go の検証器が Rust の署名を受理 |
| Autocrypt | 決定的 4 関数をバイト比較 |
| SMTP 受信 | Go の `net/smtp` が配送できる |
| SMTP 送信 | 本物の go-smtp が受理 |
| PGP | 交差復号を両方向 |

**すべて「Go 実装を実際に走らせて」検証している。** 仕様書との突き合わせは 1 つも無い。

### 残り

**M6**: config + 起動シーケンス + axum ルータ + 認証 + 全エンドポイント + anchor。
これが終わると `just difftest` が oracle 対 Rust で意味を持つ。

---

## 2026-07-28 — M5e（SMTP 送信クライアント）完了 (`5544267`)

### 成果物

- `crates/jmapsmtp/src/smtp_out.rs` — 送信クライアント（MX ルーティング込み）
- `smtp_interop` に**逆方向**を追加 — **本物の go-smtp サーバが受け取る**

テスト 194 件 green。

### lettre を使わず自前にした理由

**RCPT 拒否でも送信を続ける**挙動。lettre は提供していない。
「1 宛先が bounce したからメッセージ全体を失敗させる」のは複数宛先送信では誤り。
Go の挙動が正しく、それを再現するには自前が要る。

（結果として lettre 依存も外れた。`rustls` feature の綱渡りも消えた）

### 一発目は 4 件とも落ちた: 末尾に空行が増える

クライアントが本文の後に無条件で `\r\n.\r\n` を書いていた。
Go の `textproto.DotWriter` は**本文が既に改行で終わっていれば CRLF を足さない**。
つまり**受信側が保存する全メッセージに空行が 1 行増えていた**。

条件付きにして解決。理由を行に書いた。

**相互運用テストが無ければ絶対に気づかなかった** — 自前サーバ相手だと
両側が同じ勘違いをしていて通ってしまう。だから
`the_rust_client_and_server_agree_with_each_other` は
「単体では何も証明しない、両側がそろって流されるのを捕まえるためにある」
とコメントに書いた。

### コードに理由を書いた継承事項 2 つ

1. **STARTTLS は日和見・無認証**。ハンドシェイク失敗は平文で続行。
   ポート 25 では「無認証 TLS」の対案は「認証 TLS」ではなく「配送しない」
2. **最優先 MX しか試さない**。次点へのフォールバック無し。
   失敗させて上位のキューに再試行させる

### 気づいた点

- `check()` は**返答のクラス**で判定する（250 も 251 も RCPT 成功）。
  コード完全一致にすると server ごとの差で落ちる
- MX 名の末尾ドットは DNS では絶対名の印だが接続文字列では邪魔。
  剥がすのを単体テストで固定した

### 残り

**PGP 暗号化本体**（rpgp 統合）、**M6**（config + 起動シーケンス + axum ルータ）。

---

## 2026-07-28 — M5d（SMTP 受信サーバ）完了 (`e855d4a`)

### 成果物

- `crates/jmapsmtp/src/smtp_in.rs` — 自前 ESMTP サーバ
- `smtp_interop` — **Go の `net/smtp`（リレー自身が送信に使う client）で叩く**

テスト 181 件 green。

### 検証の形: 「本物のクライアントが配送できるか」

受信サーバの本質はこれ。プロトコルの細部を仕様書と突き合わせるより、
**リレー自身が送信に使っている `net/smtp` を向けて配送させる**ほうが強い。
答えられない挙動があれば「配送失敗」として出る。

corpus: 通常配送 / 未知の宛先 / 宛先ゼロ / 大文字小文字 / dot-stuffing /
**250KB 本文**（バッファ境界越え）/ 1 接続 2 通 / 広告する拡張の一覧。

変異テストで検出力確認: dot-unstuffing を消す → 該当 1 件 FAILED、
`SMTPUTF8` を落とす → 拡張一覧 1 件 FAILED。

### バグに見えて仕様な挙動 2 つ

1. **未知の宛先を 250 で受けて黙って捨てる**
2. **宛先ゼロの DATA も 250 で受けて捨てる**

RCPT で拒否すると、**ポート 25 に到達できる誰にでもアドレスの存在を教える
オラクル**になる。Go の挙動をそのまま維持し、理由をコードに書いた。

### AUTH は広告しない

Go 側の session には `AuthPlain`（何でも通す）があるが、
**go-smtp 0.24 の auth インターフェースを実装していない**ので
ワイヤ上には何も出ない。public MX で AUTH を広告するのは
「どこにも届かない資格情報を送らせる」だけなので、
502 を返し拡張一覧にも出さない。相互運用テストで**不在を固定**した。

### STARTTLS は広告するが 454

`handle` は transport ジェネリックにしてあるので、
呼び出し側が TLS 側で再入すればいい。その配線は起動シーケンス（M6）と一緒。
**stall させるより拒否**するほうが日和見送信者には親切。

### 詰まった点: 10 分溶かしたデッドロック

各テストが「サーバをタスクで動かしつつ Go ヘルパを**同期的に**待つ」形。
`#[tokio::test]` の既定は current_thread なので、
**待っている間サーバタスクが 1 度も動かない**。

`flavor = "multi_thread"` に変更。理由を呼び出し箇所にコメントで残した。
（タイムアウトが 10 分だったので気づくのが遅れた。以降は短いタイムアウトで叩く）

### 残り

**SMTP 送信クライアント**、**PGP 暗号化本体**（rpgp 統合）、**M6**（起動シーケンス）。

---

## 2026-07-28 — M5c（Autocrypt / PGP-MIME）完了 (`0f89e22`)

### 成果物

- `crates/jmapsmtp/src/autocrypt.rs` — ヘッダ注入/解析、RFC 3156 ラップ
- `autocrypt_interop` — 決定的な 4 関数を Go とバイト単位で比較

テスト 165 件 green。

### 見つけた: **リモート DoS**（M4 の Mailbox/set より重い）

`pgpMIMEWrapInline` が BEGIN / END マーカーを**それぞれ独立に**検索し、
「両方見つかった」しか確認しないまま `body[start : end+len(endMarker)]` する。
本文で **END が BEGIN より前**にあると slice が逆走して panic:

```
panic: runtime error: slice bounds out of range [32:25]
```

到達経路が悪い:

1. `sendEmail` は raw に BEGIN があれば必ず `pgpMIMEWrapInline` を呼ぶ
2. `sendEmail` は `OnSubmitEmail` 内の **裸の `go func()`** から呼ばれる
3. **回復されない goroutine の panic は Go プロセス全体を終了させる**

本文は認証済み送信者が自由に決める値。**メール 1 通でリレー上の全アカウントが停止**。

Rust は END を **BEGIN 以降から**探し、完全なブロックが無ければ
`None`（ラップせずそのまま送る）。SPEC §11.11。

**自分の実装も同じバグを持っていた** — Go を写したので当然で、
corpus に「逆順マーカー」を入れて初めて両方で露見した。

### 宣言済み差異の使い方が一段深まった

Go 側ヘルパに `recover()` を入れて panic を**観測可能な結果**にした。
テストは「Go は panic する / Rust は None を返す」の両方を要求する。

- Go が直れば → テストが「もう panic しない」と教える
- Rust が退行すれば → テストが落ちる

本物のリレーには `recover()` は無い。ヘルパにあるのは**比較のためだけ**で、
そのことをコメントに明記した。

### Go ヘルパは verbatim コピー

`autocrypt.go` の関数は `package main` の非公開なのでリンクできない。
verbatim コピーを置いたが、**この比較自体がコピーの鮮度を保証する** —
go-jmapsmtp 側が変われば赤くなる。信用ではなく検査。

### 気づいた点

- ヘッダ注入は「本文に `\nChat-Version:` があるだけ」でも既存扱いになる
  （Go は `bytes.Contains` を raw 全体にかけている）。重複注入よりマシなので踏襲
- PGP/MIME の boundary は**暗号文の sha1** なので出力が完全に決定的。
  だから相互運用テストがバイト比較できる
- 実際の OpenPGP 暗号化はセッション鍵がランダムなので、この方法では比較不能。
  交差復号テストが必要（未着手）

### 残り

**SMTP 受信サーバ / 送信クライアント**、**PGP 暗号化本体**（rpgp 統合）、
**config + main の起動シーケンス**（M6）。

---

## 2026-07-28 — M5b（DKIM）完了 (`03592bf`)

### 成果物

- `crates/jmapsmtp/src/dkim.rs` — 鍵の load-or-create、DNS レコード、署名
- `jmapsmtp` crate を lib + 薄い bin に分割（統合テストから触れるように）
- `dkim_interop` — **Go の検証器が Rust の署名を受理するか**

テスト 147 件 green。

### 検証の設計: 片方向だけでいい

**Go が Rust の署名を検証できること**が本質。Go の検証器はメッセージから
ヘッダ正準化・本文正準化の両方を再計算するので、受理された時点で
正準化・署名ヘッダ集合・鍵エンコードが全部一致していることになる。

逆方向（Rust が Go の署名を検証）は**テストしない**。
このリレーは署名するだけで検証しないので、**存在しないコードのテスト**になる。

### 2 回間違えた。どちらも単体では説得力があった

1. **grep するファイルを間違えて**「go-msgauth は `t=` を出さない」と誤認し、
   差異として SPEC に書きかけた。実際は両方出す
2. タグ抽出が `bh=` の中の `h=` にマッチしていたので、
   **ヘッダリストと base64 本文ハッシュを比較していた** —
   これが 1 の誤りを裏付けているように見えた

Go が実際に署名したヘッダを 1 回ダンプして両方まとめて解決。
**推測の連鎖より実測 1 回**。

### 残った本物の差異（最初に疑ったのと逆方向）

`h=` の順序:

- **Go**: 指定順 (`From:To:Cc:Subject:Date:Message-Id:Content-Type`)
- **Rust (mail-auth)**: **メッセージ中の出現順の逆** + 不在ヘッダを末尾
  (`Content-Type:Message-Id:Date:Subject:To:From:Cc`)

mail-auth のほうが RFC 6376 §5.4.2 推奨の bottom-up 方式
（転送中に前置されたヘッダが署名済みヘッダを押しのけられない）。
どちらも正当で、各実装は自分の `h=` と整合。**Go の検証が通ることで実証済み**。

合わせるには mail-auth の署名器を使わないしかないので、
SPEC §11.10 に記録し、テストは**ヘッダの集合**を比較する。
`bh=` / `d=` / `s=` / `a=` / `c=` / `v=` は完全一致。

### 気づいた点

- `.rev()` で入力を反転しても `h=` は変わらなかった。
  mail-auth の順序は**入力順ではなくメッセージのヘッダ順**に依存していた。
  一度試して初めてわかった
- `rsa` 0.9 は `rand_core` 0.6 を要求し、workspace の `rand` 0.9 と非互換。
  `rsa::rand_core::OsRng` を使う
- 破損した `key.pem` は Go だと**黙って新しい鍵を作る**（DNS レコードが取り残される）。
  Rust は `create_new` が既存ファイルで失敗するのでエラーになる。テストで固定

### 次

**M5c: SMTP。** 受信サーバ（自前 ESMTP + STARTTLS）と送信（MX 引き / relay_host）。
Autocrypt / PGP も残っている。

---

## 2026-07-28 — M5a（MIME）完了 (`0de4327`)

### 成果物

`crates/jmapserver/src/mime.rs` — `ParseMIMEEmail` / `extractMIMEText` /
`ExtractAttachments` / `MessageBody` / `BuildRFC5322` / `BuildEnvelope`。
M4 でスタブにしていた `Email/import` と `Email/parse` も埋めた。

テスト 134 件 green。

### MIME crate に任せず手書きにした

Go は `net/mail` と `mime/multipart` に依存していて、**その特有の判断こそが
保存済みメッセージの中身**:

- Content-Type の無いパートは text/plain と見なさず**スキップ**
  （RFC 2045 の既定とは違う）
- アドレスリストは 1 件でも壊れていれば**ヘッダごと破棄**
- `multipart/encrypted` は text/plain フォールバックを**意図的に無視**
  （PGP メッセージの平文がサーバに残らないように）

汎用パーサは「MIME 一般」に強く「この MIME」に弱い。相互運用テストが判定者。

### パースは 17 件の corpus が一発で一致

組み立て側だけ差が出て、それが有益だった: `mail.Address.String()` は
**印字可能 ASCII の表示名を無条件で引用符で囲む** — `"Alice" <a@x>` であって
`Alice <a@x>` ではない。マルチバイトが入ると RFC 2047 encoded word に切り替わる。
どちらも RFC 5322 を読んでも出てこない。

### corpus が自分自身の flakiness を捕まえた

`Email.headers`（Chat-Group-Id など）は Go がヘッダマップを range して作るので
**実行ごとに順序が変わり**、その順序が**保存されるメッセージ JSON にそのまま入る**。

**1 回目は偶然通り、2 回目で落ちた。** 比較時にソートし、Rust 側は決定的に。
SPEC §11.5 に追記。3 回連続で安定を確認。

### 気づいた点

- 時刻と生成 Message-ID は**注入**にした（Go は直接 clock/RNG を読む）。
  でないと組み立て経路が比較不能
- HTML→Markdown は素通しのまま。§8-G の判断は
  **Go の変換器と実際に差分を取ってから**でないと決められない

---

## 2026-07-28 — M4（メソッド層）完了 (`28967f2`)

### 成果物

- `methods/` — RFC 8621 の 26 メソッド全部
- `dispatch.rs` / `refs.rs`（result reference）/ `server.rs`（Session・batch・auth・encode）
- `dispatch_interop` — **Go の `Store.Dispatch` と 47 呼び出しを突き合わせるテスト**

テスト 105 件 green。

### スコープを 1 つ落とした（正直に記録）

PLAN の M4 完了条件は「`just difftest` が oracle 対 Rust で green」だった。
これには **jmapsmtp バイナリ全体**（config・handler・auth・全ルート）が要る。
つまり実質 M4+M6 で、M4 単独では達成できない。

代わりに **dispatch レベルの相互運用テスト**を作った。Go と Rust が同じ store を
seed し、同じメソッド呼び出しスクリプトを**それぞれの Dispatch に通して**、
返る JSON を比較する。HTTP 層（ルーティング・CORS・SSE）は未検証で、
バイナリができる M6 に回す。**PLAN の完了条件も実態に合わせて書き換えた。**

axum のルータも今回は書いていない。アプリ層が無いと 1 行も実行できないため。

### 見つけた Go の実バグ: `Mailbox/set` が create 同時の update を捨てる

`mbByID` がスライスの backing array への**ポインタ**を持ち、create ループの
`append` で再確保が起きる。update ループは**捨てられた配列**に名前を書き、
最後の再構築は新しい配列を読む。Go 版で実測:

```
update のみ                → mbx-inbox=Renamed   （正常）
create + update 同時       → mbx-inbox=Inbox     （消失）
作成直後のものを update    → mbx-inbox=Inbox     （消失）
```

**どちらの消失ケースもレスポンスは `updated` に入れて成功を報告する。**
「1 つ作りつつ 1 つ改名」は正当な JMAP で一括整理では自然に出るので、
サイレントなデータ損失。移植しない（SPEC §11.7）。

### 宣言済み差異の機構

`dispatch_interop` のスクリプト各行に `divergence: Option<&str>` を持たせた。
宣言された差異は**一致と同じ厳密さで検査**する — **差が出なくなったら失敗**。

意図はこれ: 修正がリファクタで失われたとき、黙って Go のバグ挙動に戻るほうが、
元のバグより悪い。SPEC §11.9 に書いた機構を先に dispatch 層で実装した形。

### 順序の非決定性がさらに 2 つ出た

1. **`*/changes` の集合フィールド**（created/updated/destroyed/removed）は
   Go がマップを range して作るので**Go 対 Go でも順序が違う**。
   `queryChanges` は `index` までその反復順で振っている
2. **`Store::all` の同値タイ**: `sort.Slice` は**不安定ソート**で、
   入力もマップ順。`Email/copy` は `receivedAt` を引き継ぐので必ずタイになる

1 は比較時にソートして正規化。2 は**スクリプトの並べ替え**で対処した
（`Email/copy` を最後に置き、以降クエリしない）。正規化で潰すと
「順序が本当に壊れた」場合まで隠れるので、観測させないほうを選んだ。

### 詰まった点

- `Handler::authenticate` をトレイトのデフォルトメソッドにしたら、
  Go の「AuthFunc が**在るかどうか**で分岐が変わる」を表現できなかった
  （Rust ではトレイトメソッドが override されたか問い合わせられない）。
  Go の `Config.AuthFunc` と同じく**値**（`Option<AuthFn>`）に戻した
- ヒアドキュメントの `cd` が失敗して別ディレクトリに書きかけた。以降は絶対パス

### 気づいた点

- `identityState` は Go でも**永続化されていない**（`persistedState` に無い）。
  identities は残るのに state は再起動で 0 に戻る。そのまま移植
- `Email/copy` / `Email/import` / `EmailSubmission/set` は `oldState` も
  `newState` も**書き込み後**に読むので常に同値。実害が小さいので記録のみ（§11.8）
- `Email/import` と `Email/parse` は `ParseMIMEEmail` 待ちで空スタブ

### 次

**M5: MIME + SMTP。** 最大フェーズ。`email.go` の残り半分（892 行中の MIME 部）と、
自前 ESMTP サーバ、DKIM、Autocrypt/PGP。

---

## 2026-07-28 — M3 完了 (`39ecc7f`)

### 成果物

- `crates/jmap-types` — Email / Mailbox / Address / Identity / Thread / Envelope / `JmapTime` / **`go_json`**
- `crates/jmapserver/src/store.rs` — Store 全体
- 相互運用ヘルパ `xtask/interop/store/`

テスト 82 件 green。うち `data/` 双方向相互運用 4 件が M3 の受け入れ基準。

### 一番の収穫: **Go の `encoding/json` は `<` `>` `&` を HTML エスケープする**

`\u003c` / `\u003e` / `\u0026`（加えて U+2028/2029）。serde_json は 5 つとも生で出す。

**メールでは致命的。** `inReplyTo` / `references` は `<id@host>` をそのまま保持するし、
件名の `&` も日常的。気づかなければ:

- 既存メッセージファイルに触れた瞬間に全部書き換わる
- 差分ハーネスが数百件の偽の差分で埋まり、本物の差分が埋もれる

→ `jmap_types::go_json` を作り、**ディスクに書く経路すべて**を通した。

**これはソースを読んでも仕様を推測しても出てこなかった。** Go 実装と実際に
突き合わせる相互運用テストだけが見つけた。

### そしてその修正自体が 2 回間違っていた

1. エスケープ表が `'<' => "<"` と**各文字を自分自身に写していた**（完全な no-op）
2. 単体テストの期待値も未エスケープ形だったので、**何も検証せずに green**

自己完結したウソ。Go 実装との比較だけが破った。M1 の `--self-test` と同じ教訓を、
別の場所でもう一度踏んだ形。

（余談: 修正の適用も 2 回失敗した。ファイル中に**実在する U+2028 文字**を
Python の `splitlines()` が改行として扱い、行が分割されて残骸が出た。
バイト単位で `\n` だけで分割して解決）

### `delta.json` は実測しないと絶対に書けなかった

`changeRecord` に **JSON タグが無い**ので、キーが `Added` / `Updated` / `Removed` と
**大文字始まり**。nil スライスは `null`（`[]` でも省略でもない）。

```json
{"state":2,"changes":{"1":{"Added":["msg-a"],"Updated":null,"Removed":null}},...}
```

推測で `added` と書いていたら、Go 版は**エラーも出さず空として読む**。
サイレントな状態消失になっていた。

### 時刻は文字列のまま保持することにした

`JmapTime` は**到着した文字列をそのまま**持つ。パースして再フォーマットすると:

- `+09:00` → `Z`、`.12` → `.120000000` に化ける
- Store は「1 フィールド触って全体を書き戻す」ので、**触るたびに全ファイルが書き換わる**

SMTP 受信経路は `time.Now()` を `.UTC()` なしで使っているので、
**ローカルオフセット付きの時刻が実際にディスクにある**。順序比較のときだけパースする。

### Go のマップ反復順に由来する非決定性

Go が `map` を range する箇所の出力順はランダム:

- `Purge` の `Removed` 配列
- `SyncMailboxes` の `Created` / `Destroyed` 配列
- 同一 Message-ID 複数時の `resolveThreadID` の勝者

**Go 対 Go でも一致しない**ので「合わせる」対象が無い。`BTreeMap`/`BTreeSet` で
決定的にした（SPEC §11.5）。

ついでに**差分ハーネスの潜在バグを 1 つ塞いだ**: `delta.json` を素の文字列比較して
いたので、シナリオが一度に 2 つ以上のメールボックスを作った瞬間に
Go 対 Go でも落ちるところだった。比較前に配列をソートする正規化を入れた。

### あえて直さなかったもの: `safeFilename` の衝突

`/ \\ : * ? " < > |` を全部 `-` に置換し 200 文字で切る **多対一の写像**。
`a/b` と `a:b` が同じファイルになる。長い AP URL は切り詰めでも衝突する。

**直さない。** ファイル名そのものが on-disk フォーマット（§5.2 の `data/` 互換要件）。
別方式にすると既存ファイルが旧名で取り残され、新規書き込みだけ新名になり、
**同じメッセージが 2 つの内容で読める**状態になる。テストで明示的に固定した。

### 自分のテストが間違っていた件

`references_are_walked_when_in_reply_to_misses` が落ちた。原因は私の想定違いで、
Go は新スレッド ID を作るとき Message-ID を**トリムしない** —
索引側だけ `<>` を剥がす非対称な作りだった。正しい期待値は `thr-<parent@x>`。
コメントに非対称性を明記して残した。

### 気づいた点

- `Email` の全フィールドが `omitempty` なので `Email{}` は `{}` になる。
  `skip_serializing_if` を 1 つ落とすだけで壊れるため、専用テストで固定
- `preserve_order` を M0 で入れていたが**外した**。Go はマップキーをソートするので、
  挿入順保持は不一致になる
- Store のフックは型だけ定義して未配線（呼ぶのは M4 の dispatch）

### 次

**M4: JMAP HTTP サーバ。** Session / `/jmap/api/` / SSE / blob / CORS / 26 メソッド。
`just difftest`（oracle 対 Rust）が初めて意味を持つフェーズ。
SPEC §11.9 の divergence 宣言機構もここで入れる。

---

## 2026-07-28 — M2 完了 (`658e841`)

### 方針変更: Go 版のバグは移植しない

ユーザ指示。**Go 版が常に正しいわけではない**ので、明らかにおかしい箇所は直す。
ただし差異は `SPEC.md §11` に必ず記録する — 記録のない差異は移植ミスと区別がつかない。

§11 を「唯一の例外」から「意図的な差異の一覧」に格上げし、
各項目に **Go の挙動 / 変更後 / 理由** を書く形式に変えた。

### 最初に呼び出し側を読んだら、モジュールの性格が変わった

`cryptenv.` の全使用箇所を grep したところ、**サーバは
`Unseal` / `Rewrap` / `VerifyAuth` / `NewEnvelope` を一度も呼んでいない**。
使うのは `FromBytes` と `Bytes()` だけ。パスワードはサーバに届かないので、
サーバ側では原理的に復号できない。

つまりエンベロープはサーバにとって**完全に不透明**で、
`FromBytes` だけが唯一「実際に動く」関数。ここが甘いと直接被害が出る。

### 見つけたバグ: 空の JSON でアカウントを永久に潰せる

`FromBytes` は `json.Unmarshal` するだけで**何も検証しない**。Go 版で実験:

```
{}                → err=<nil>  env=&{Version:0 Salt:[] KDF:{0 0 0} ...}
null              → err=<nil>  env=&{Version:0 ...}
{"v":1}           → err=<nil>  env=&{Version:1 ...}
```

これで何が起きるか:

1. `POST /auth/signup?token=X` に `{}` を送る
2. **一度きりの setup token が消費され削除される**
3. ゼロ値エンベロープが `envelope.json` に書かれ、204 が返る
4. 以降 signup は「already initialized」で 409
5. どんなパスワードでも復号できない → **アカウントが永久に使用不能**

**未認証**で実行できる。setup token は 16 バイトなので総当たりは非現実的だが、
トークンは起動時にログへ平文で出るし、正規ユーザが壊れた JSON を送るだけでも同じ結果。

→ `from_bytes` で**復号が原理的に不可能な値だけ**を拒否するようにした（§11.2）。
`t=1, m=8, p=1` や 8 バイト salt は通す。**検証はポリシーの押し付けではなく、
不可能値の排除に限る**という線引きをテストにも書いた
(`accepts_unusual_but_workable_parameters`)。

副次的に: `kdf.t=0` / `p=0` は **Go の argon2 が panic する**値。
サーバは Unseal しないので現状は踏まないが、潜在的な地雷ではある。

### もう 1 つ: `Rewrap` だけバージョン検査が無い

`Unseal` は `e.Version != currentVersion` を見るが `Rewrap` は見ない。
将来の v2 エンベロープが v1 の解釈で黙って rewrap される。
非対称にする理由が見当たらないので両方で検査（§11.3）。
サーバは Rewrap を呼ばないので HTTP レベルの差異なし。

### 相互運用テスト

`xtask/interop/cryptenv/main.go` を `just interop` で **oracle チェックアウト内に
コピーしてビルド**する。これで Go 版の**本物の** cryptenv パッケージにリンクされる
（再実装ではない）。Rust 側がサブプロセスとして駆動。

検証した方向:

| テスト | 意味 |
|---|---|
| `rust_opens_a_go_sealed_envelope` | **移行方向**。既存デプロイの `envelope.json` は全部 Go 製 |
| `go_opens_a_rust_sealed_envelope` | **切り戻し方向**。Rust 稼働中に作られたアカウントが失われないか |
| `go_rejects_the_wrong_password_...` | 誤パスワードが両側で失敗するか |
| `go_opens_a_rust_rewrapped_...` | rewrap 後も派生鍵が不変か |
| `interoperates_at_the_real_cost_parameters` | **p=4 は p=1 と別コードパス**。実パラメータで 1 回だけ確認 |

### 変異テストで検出力を確認（M1 の規律を継続）

`HKDF_INFO_AUTH` を `v1` → `v2` に改変して実行:

- 単体テスト 2 件 FAILED（`hkdf_info_strings_are_frozen`, `hkdf_derivation_...`）
- 相互運用テスト **3/5 FAILED**（`auth_token differs`）

**そしてこれが穴を 1 つ露出させた。** ヘルパのバイナリを消して実行すると
**「5 passed」と表示される**（0.00s で）。何も実行していないのに green。
M1 で潰したはずの「落ちないテスト」がここに再発していた。

→ `CRYPTENV_INTEROP=required` を導入。`just test` が設定するので、
**通常のワークフローではヘルパ欠落が明示的なエラーになる**。
素の `cargo test` は Go 未インストール環境のために skip のまま。

### 気づいた点

- `hkdf_derivation_matches_the_go_implementation` の期待値は
  **Go 側で実際に計算させた**もの（`master_secret = 0x42 × 32`）。
  自前実装の出力を貼ると自己満足のテストになる
- `go_opens_a_rust_rewrapped_envelope_with_unchanged_keys` は
  Go の gen → Rust rewrap → Go unseal なので、**Rust の派生ロジックは比較していない**
  （rewrap が master_secret を保存したかだけを見る）。派生は他のテストがカバー
- `Unsealed` に `Debug` を自前実装して `<redacted>` にした。
  panic メッセージに鍵が載るのを防ぐ

### 次

**M3: `jmap-types` + `Store`。** 699 行 + 型定義で、ここから規模が大きくなる。
`data/` の双方向互換が受け入れ基準。

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

# Aethel 企業向けPoC導入ガイド

## 1. このPoCで確認すること

Aethelは、継続的な支払予定そのものを債権として扱い、外部の与信事業者を差し替え可能な形で接続するための基盤です。企業PoCでは、請求書を単に登録するのではなく、署名付きの支払ストリームから債権を組成し、与信、保証、資金供給、トークン化、流通、回収までを一つの追跡可能な流れとして確認します。

PoCの中心的な確認事項は次のとおりです。

- 支払義務者と債権者が合意した支払ストリームだけが債権化されること
- 与信判断、保証、資金供給を別々の事業者が担当できること
- 一社が複数の役割を兼ねる場合も、権限が役割ごとに制限されること
- DeKYXの法人資格を利用し、Aethel自身が本人確認台帳を重複して持たないこと
- host adapterがDeCCPの保証枠や清算結果を検証し、Aethel自身が保証元帳を重複して持たないこと
- zkPIで生成した決済指図をDeFMIへ渡し、債権移転と資金移動を結び付けられること
- 債権トークンの発行、保有、譲渡、回収、延滞・不履行処理を監査できること

## 2. 対象範囲と責任分界

Aethelは、支払ストリームから債権を作り、そのライフサイクルを管理します。周辺機能は次の基盤へ委ねます。

| 領域 | 担当 |
|---|---|
| 法人確認、資格、失効、鍵更新 | DeKYX |
| 保証枠、清算、証拠金、債務不履行時の損失負担 | DeCCP |
| 匿名の決済指図と検証証拠 | zkPI |
| 資金・証券・債権の正本台帳と最終決済 | DeFMI |
| 支払ストリーム、債権組成、外部与信事業者の接続、債権管理 | Aethel |

この分担により、PoCで同じ残高、資格、保証枠を複数の台帳へコピーしないことを重要な受入条件とします。
Aethelの各crateはDeCCPを直接依存に持たない。DeCCPとAethelを同じ業務へ結ぶのはhost VMまたは
専用adapterであり、Aethelが保存するのはopaqueなhold IDやcommitment、release/claimの
settlement digestです。DeCCP receipt全体をAethelの正本として複製しません。

## 3. PoCの参加者

最低限、次の役割を別の鍵または別のテスト主体として用意してください。

- 支払義務者: 将来の支払ストリームへ署名する企業
- 債権者・組成者: 支払ストリームを債権として登録する企業
- 支払事実の確認者: 請求・検収・利用実績などの根拠を証明するシステム
- 与信事業者: 支払義務者や支払ストリームを評価する外部事業者
- 保証事業者: 保証枠を提供する銀行、保険会社、DeCCP等
- 資金提供者: 債権を買い取る、または担保融資を行う主体
- 発行・流通・回収担当: 債権トークンの発行、移転、回収を行うサービス
- DeFMI運営者: 最終決済と正本台帳を管理する主体
- 監査担当者: 署名、権限、状態遷移、外部台帳との参照関係を確認する主体

一人で試す場合でも、鍵と設定は役割ごとに分離してください。権限分離が機能しているかを検証できなくなるため、全役割を同一の管理者鍵へ集約しないでください。

## 4. 準備

### 4.1 推奨環境

- Git
- Rust toolchain。現在は `rust-toolchain.toml` がないため、PoC開始時の `rustc --version` を記録し、
  承認版を全build機で揃える。統合Docker buildが現在使う参照版はRust 1.97.1
- Cargo
- 外部接続を試す場合は、DeKYX、DeCCP、zkPI、DeFMIの各PoC環境
- 組織ごとに分離した鍵管理領域。初回PoCでも秘密鍵をリポジトリへ保存しないこと

ビルドとテストは、開発者PCではなく、企業が管理する隔離済みLinux環境またはCIで実行することを推奨します。

### 4.2 取得と固定依存関係の確認

```bash
git clone https://github.com/shukob/aethel.git
cd aethel
cargo test --workspace --locked
```

`--locked` で失敗した場合は、勝手に依存関係を更新せず、リポジトリが指定する `Cargo.lock` とRust版が一致しているかを確認してください。

現行の公開リポジトリには、支払ストリームの中核だけでなく、後述する8クレートが
すべて含まれます。取得した配布物が完全構成かどうかは、ディレクトリ名ではなく
`cargo metadata --locked --no-deps --format-version 1` の結果で確認してください。

中核機能だけを対象にするPoCでは、次の最小確認を行えます。

```bash
cargo test --locked -p aethel-core --test protocol \
  assessor_guarantor_and_liquidity_provider_are_independent_capabilities \
  -- --exact --nocapture
```

このテストは、与信、保証、資金供給が一つの暗黙的な管理者権限へまとめられていないことを確認します。

## 5. 最小PoCシナリオ

### 5.1 支払ストリームを作る

業務システムから次の情報を取得し、支払義務者と債権者が同じ内容へ署名します。

- 契約または注文の識別子
- 支払義務者と債権者のDeKYX上の主体参照
- 支払額、通貨、支払日または支払周期
- 検収や利用実績など、支払が発生する条件
- 改訂番号と有効期間

生の法人番号、個人情報、銀行口座番号をAethelへ複製せず、外部台帳の主体参照と検証可能な証拠を使います。

### 5.2 与信事業者を登録する

与信事業者ごとに、次を登録します。

- 事業者識別子と署名鍵
- DeKYXで検証する資格条件
- 対応する商品、通貨、地域、金額帯
- 判断結果の有効期限
- モデルまたは審査規則の版
- 取消・鍵更新の方法

与信事業者の実装はAethel本体へ埋め込まず、公開された入力・出力契約へ接続します。モデルの内部情報を公開しなくても、誰が、どの版で、いつ判断したかは監査できるようにします。

### 5.3 債権を組成する

署名済み支払ストリーム、与信判断、必要な場合は保証を結び付けて債権を作ります。次を確認してください。

- 支払ストリームの版が一致している
- 与信判断が期限内である
- 商品方針が保証を必須とする場合、与信判断だけでは発行できない
- 保証事業者が有効なDeFMI上の保証主体と結び付いている
- 同じ支払義務を二重に債権化できない

### 5.4 資金供給とトークン化を行う

資金提供者が債権を引き受けた後、債権の権利を表すトークンを発行します。企業PoCでは、少なくとも次を別の記録として追跡します。

- 元となる債権と残存元本
- トークンの発行総数と保有者別残高
- 発行、譲渡、償還の時系列
- 譲渡制限とDeKYX資格条件
- 回収金の配分規則

トークン残高の合計が元の債権額を超えないこと、償還済みの権利を再利用できないことを確認します。

### 5.5 債務者向け管理と回収を試す

債務管理ウォレットまたは企業接続用モジュールから、次を確認します。

- 今後の支払予定、支払済み、延滞を区別できる
- DeFMIやMPCノードが一時停止しても、同じ依頼を二重送信せず再試行できる
- 支払結果が債権残高とトークン保有者への配分へ一度だけ反映される
- 不履行時にはDeCCPまたは保証事業者の処理結果を参照し、Aethelが独自に保証枠を減算しない

### 5.6 zkPIとDeFMIへ接続する

決済時は、Aethelが資金口座や証券口座を直接書き換えるのではなく、決済条件をzkPIへ渡します。zkPIの検証が成立した指図だけをDeFMIへ送ります。

最低限、次の関連付けを監査証跡へ残します。

- Aethelの債権識別子
- 支払ストリームの版
- zkPIの指図識別子と証明要約
- DeFMIの決済識別子と確定状態
- 再試行用の一意な処理識別子

DeFMIの確定結果を受ける前に、Aethel側だけで「決済済み」へ進めないでください。

## 6. 失敗系の確認

正常系だけでなく、次を必ず試してください。

1. 与信判断の期限切れ後に債権化する
2. 保証必須の商品を保証なしで発行する
3. 権限のない事業者が保証を解除する
4. 失効したDeKYX資格で債権トークンを取得する
5. 同じ支払ストリームを別の識別子で二重登録する
6. 古い鍵で新しい与信判断へ署名する
7. 同じ決済結果を二回受信する
8. DeFMIが未確定または失敗を返した状態で回収済みにする
9. 支払義務の残高を超えるトークンを発行する
10. 一部サービス停止後にキューを再処理し、順序と一意性が保たれるか確認する

各ケースで、状態が更新されないこと、理由が機械判読可能な形で残ること、秘密情報がログへ出ないことを確認します。

## 7. 自社システムとの接続

本番移行を見据えたPoCでは、Aethelの内部型をそのまま基幹システムへ漏らさず、境界アダプターを設けます。

- ERP・請求システム: 契約、請求、検収、支払予定を支払ストリームへ変換
- 与信サービス: 審査要求を受け、署名付き判断を返す
- 保証・清算基盤: DeCCPの保証枠参照と結果通知
- 本人確認基盤: DeKYXの資格証明と失効確認
- 決済基盤: zkPIを生成しDeFMIの確定結果を受信
- 会計・監査: 元の業務識別子と各基盤の識別子を相互参照

接続処理には、一意な依頼番号、冪等性キー、受信時刻、送信元、署名、参照した版を持たせてください。停止中の依頼は永続キューへ保存し、回復後も元の順序と一度だけの反映を守ります。

## 8. PoCで保存する証拠

次を一つの評価資料へまとめます。

- 使用したGitコミットと `Cargo.lock` の要約値
- Rust版、OS、実行コマンド、テスト結果
- 参加者、鍵、権限、DeKYX資格の対応表（秘密鍵や個人情報は除外）
- 支払ストリーム、与信判断、保証、債権、トークン、zkPI、DeFMI決済の識別子対応
- 正常系と失敗系の入力、期待結果、実結果
- 二重発行、二重決済、権限逸脱が拒否された証拠
- 障害時のキュー滞留、再開、重複排除の記録
- 処理時間、失敗率、運用担当者の手作業件数
- 未解決の法務、会計、データ保護、運用上の論点

## 9. 受入基準の例

企業ごとに数値は決め直してください。ただし、最低限の機能基準は次のとおりです。

- 署名されていない、または版が食い違う支払ストリームから債権を作れない
- 与信、保証、資金供給の権限が独立している
- 商品方針で必要な保証を与信判断で代替できない
- DeKYXの失効・鍵更新が新しい処理へ反映される
- 債権額を超えるトークン発行や二重償還が拒否される
- zkPIまたはDeFMIが失敗した場合、Aethelの決済状態が確定しない
- 再試行後も一つの業務依頼が一度だけ反映される
- すべての重要な状態遷移を、入力の版と署名まで遡って監査できる

## 10. 本番導入前に別途必要なもの

このPoCは、法的な債権譲渡、会計処理、投資商品規制、個人情報保護、業務継続を自動的に満たすものではありません。本番前には少なくとも次が必要です。

- 適用法域ごとの債権譲渡・対抗要件・証券性の整理
- 会計・税務上の認識時点と評価方法
- 与信モデルの説明責任、差別防止、変更管理
- 鍵管理、職務分離、緊急停止、復旧、監査ログ保全
- DeKYX、DeCCP、zkPI、DeFMIとの契約上・運用上の責任分界
- 性能、可用性、災害復旧、データ保持期間の本番試験
- 外部監査を含む暗号実装、Rust状態機械、host VM・adapterの安全性評価

PoCの合格は本番運用の承認ではありません。技術検証、法務・会計評価、運用設計、第三者監査を別々の判定として残してください。

---

## 11. 製品モジュールとPoC範囲を決める

### 11.1 Aethelを構成するモジュール

Aethelの完全構成は、次の8クレートへ責務を分離します。一つの巨大なコントラクトへ
与信、保証、債権管理、流通、回収を集約せず、各モジュールの入力、権限、状態遷移を
個別に検証できるようにするためです。

| クレート | 技術的な責務 | 自分では持たないもの |
|---|---|---|
| `aethel-types` | 32-byte識別子/commitment、zero・時刻上限、ID表現、正規digest、期間・Ed25519署名検査、共有error | 金額型、通貨型、業務状態、台帳、暗号鍵、外部通信 |
| `aethel-provider-sdk` | 与信・保証・資金供給事業者が実装する要求・応答境界 | 各事業者のモデル、審査データ |
| `aethel-core` | 署名付き支払ストリーム、債権series、provider権限、与信、保証、発行、不履行の意味 | 証券・資金の正本残高 |
| `aethel-tokenization` | token series、発行上限、mint/burn intent、正本ledgerへの冪等な提出、policy宣言 | holder別残高、transfer操作、法的な権利移転そのもの |
| `aethel-distribution` | circulation request、venue fill、settlement context、適格性・譲渡制限digest | 募集管理、割当台帳、価格発見・matching、DeKYX資格の発行 |
| `aethel-obligation-wallet` | 支払義務者向け予定、処理待ち、再試行、一意性の管理 | 銀行口座・DeFMI正本 |
| `aethel-servicing` | installment別支払証拠、延滞、cure、不履行証拠とattestation受理 | 投資家別配分、allocation、保証claim、DeCCP保証枠の正本 |
| `aethel` | 上記モジュールを一つのアプリケーション状態として組み合わせる境界 | Avalanche consensus、外部API |

完全な導入試験では、この8クレートを一つのCargo workspaceとして試験します。
中核機能だけを配布または導入する構成では、`aethel-core`の試験結果を、トークン化、
流通、ウォレット、回収まで動作した証拠として扱ってはいけません。導入するモジュールと
検証対象をPoC計画書へ明記します。

PoC開始時には次を記録します。

```sh
git rev-parse HEAD
git status --short
cargo metadata --locked --no-deps --format-version 1 > poc-output/cargo-metadata.json
```

公開用workspaceの標準配置ではcrateが `crates/` 配下にあるため、必要なら
`find crates -mindepth 1 -maxdepth 1 -type d` で目視できます。ただし配置名は正本ではない。
`cargo metadata` の `packages[].name` に8クレートが揃っている場合だけ、本章の完全経路を
実行します。`aethel-core`だけを導入した場合は、支払ストリーム、与信、保証、債権seriesの
生成までを最小範囲とし、トークン化、流通、支払義務者ウォレット、回収は未検証と記録します。

### 11.2 Aethelは単独で動く決済ネットワークではない

AethelのRustクレートは、組込み可能な決定的状態機械です。現時点では、企業が
`aethel-server`という完成済みデーモンを起動すれば本番利用できる製品ではありません。
ホストアプリケーションが次を提供する必要があります。

- 認証済みAPIと利用者・サービス間の認可。
- 永続化、同時実行制御、snapshot、復旧。
- DeKYX、DeCCP、zkPI、DeFMIとの接続adapter。
- 鍵管理、署名、監査ログ、時刻源。
- 業務イベントをAethelのコマンドへ変換する処理。
- Aethelの結果を会計・請求・入出金消込へ返す処理。

PoCで最初に作るべきものは、新しい債権台帳ではなく、この状態機械を呼び出す薄い
企業参加サービスです。企業参加サービスが独自に残高や保証枠を複製すると、Aethel、
DeCCP、DeFMIの三つの正本が生まれてしまいます。

### 11.3 正本の所在

| 情報 | 正本 | Aethelに保存する情報 |
|---|---|---|
| 法人の法的名称、登録番号、KYC/KYB証跡 | DeKYX発行者または企業本人確認基盤 | 匿名または仮名のsubject参照、資格証明の要約 |
| 支払ストリーム | Aethel | 両当事者の署名、版、条件、現在状態 |
| 与信判断 | 与信事業者が署名しAethelが状態として受理 | 署名付き判断、対象、版、有効期限、provider参照 |
| 保証枠と残容量 | DeCCPまたは保証事業者 | opaqueなhold識別子とcommitment。release/claim時はsettlement digest |
| 債権seriesと残存元本 | Aethel | 発行条件、残存元本、状態、外部決済参照 |
| 債権トークンの発行上限・供給intent | Aethel tokenization | series、authorization、発行別supply counter、ledger receipt |
| 債権トークンのholder別残高・権利状態 | DeFMI等の外部asset ledger | Aethelにはholder別残高を置かない |
| 資金・証券・担保残高 | DeFMI | note/lock/settlementの参照と確定root |
| 決済指図 | zkPI | 指図ID、nullifier、domain、証明・署名の要約 |

トークン残高をAethelとDeFMIの両方で正本にしないでください。現在の実装境界は、Aethelが
債権の意味、発行上限、外部ledgerへ出すintentとreceiptを持ち、DeFMI等が保有と決済の正本を
持つ構成です。法的な権利の正本をどこへ対応づけるかはPoC開始前に決めます。

## 12. 推奨ハードウェアと配置

以下は測定済み性能保証ではなく、PoC開始時に資源不足で検証が止まらないための
初期値です。実測後にCPU、メモリ、ディスク、帯域を下げるか増やしてください。

### 12.1 最小の機能確認

一台でRust試験とホストadapterの開発だけを行う構成です。

| 項目 | 初期推奨値 |
|---|---:|
| CPU | x86-64またはArm64、4物理/仮想CPU以上 |
| メモリ | 8 GiB以上 |
| ディスク | 空き30 GiB以上のSSD |
| OS | 64-bit Linux |
| ネットワーク | package取得時だけ外向き通信。試験実行中は閉域可 |
| 用途 | `cargo test`、adapter単体試験、少量の状態遷移確認 |

これは役割分離、可用性、WAN、鍵分離を証明しません。一人の開発者がAPI契約を確認する
段階に限ります。

### 12.2 一社内の統合PoC

役割をコンテナまたはVMで分け、企業システムとの接続を確認する構成です。

| ノード | 台数 | CPU | メモリ | 永続ディスク | 主な処理 |
|---|---:|---:|---:|---:|---|
| Aethelホスト | 2 | 4–8 vCPU | 16 GiB | 100 GiB SSD | 状態機械、API、冪等性、監査 |
| PostgreSQL等の企業管理DB | 2 | 4 vCPU | 16 GiB | 200 GiB SSD | command log、snapshot、outbox |
| provider gateway | 1–3 | 2–4 vCPU | 8 GiB | 30 GiB | 与信・保証・資金供給接続 |
| obligation wallet gateway | 2 | 2–4 vCPU | 8 GiB | 50 GiB | 支払予定、キュー、再試行 |
| 監視・ログ | 1 | 4 vCPU | 16 GiB | 200 GiB | metrics、trace、改ざん検知ログ |
| 負荷生成・監査端末 | 1 | 4 vCPU | 8 GiB | 30 GiB | シナリオ実行と証拠収集 |

Aethelホスト二台を同時書込み可能にする場合は、DB行ロック、compare-and-swap、または
単一leaderでコマンド順序を確定してください。同じ債権へ二台が独立に状態遷移を適用する
構成は禁止します。

### 12.3 zkPI・DeFMIまで含む複数組織PoC

Aethelだけでなく決済まで通す場合、Aethel用計算資源よりもMPC、証明、Avalanche L1の
資源が支配的になります。最初は次のように分離します。

| セキュリティ領域 | 推奨配置 | 理由 |
|---|---|---|
| Aethel API・状態機械 | 業務アプリ領域 | 契約・請求イベントを受けるため |
| provider gateway | 外部接続DMZまたは専用統合領域 | 与信API障害や入力を中核から隔離するため |
| DeKYX verifier | 資格検証領域 | 生の本人情報をAethelへ入れないため |
| zkPI署名・検証 | HSM接続可能な署名領域 | threshold鍵shareと業務APIを分離するため |
| DeFMI validator | 独立VMまたは独立ホスト | consensus障害をAethel障害と分離するため |
| 監査保管 | 書込み後変更できない保管領域 | 業務DB管理者による証拠改変を防ぐため |

同一Kubernetes clusterを使う場合でも、namespaceだけの分離を独立運営と呼ばないで
ください。PoC報告には、同一物理ホスト、同一cluster、同一cloud account、同一管理者の
どこまでが共通障害点かを明記します。

### 12.4 CPU、メモリ、ディスクを決める計算方法

Aethelの状態機械自体はGPUを前提にしません。GPUが必要になる可能性があるのは、外部
与信モデルがGPU推論を行う場合だけです。AethelのためにGPUを用意したと記録しないで
ください。

容量は次の順で決めます。

1. 一日の新規支払ストリーム数を `S_day` とする。
2. 一ストリーム当たりの平均状態遷移数を `E_stream` とする。
3. token transfer、回収、再試行を含む一日のイベント数を別々に測る。
4. peak 15分のイベント数を一秒当たりへ変換する。
5. 一イベントのp95処理時間と最大同時数を実測する。
6. snapshot、index、監査ログを含む一イベント当たり保存量を測る。
7. 12か月分、監査保持期間分、複製係数、30%以上の空き容量を加える。

概算式は次です。

```text
events_per_day = S_day * E_stream + transfers + collections + retries
peak_events_per_second = peak_15min_events / 900
storage_year = events_per_day * bytes_per_event * 365 * replica_factor
required_workers = ceil(peak_events_per_second / measured_worker_eps * safety_factor)
```

`safety_factor`は最初のPoCでは2.0を置き、負荷試験後に変更します。この値は製品の
性能保証ではなく、測定前の安全側仮定です。

## 13. OS、時刻、ネットワーク、保存領域

### 13.1 Linuxホストの最低設定

- 64-bit Linuxを使用し、Rust toolchainとCライブラリの版を固定する。
- ホスト名、時刻同期先、timezone、kernel版を証拠へ残す。
- swap発生、ディスク残量、inode残量を監視する。
- build用ホストと運用用ホストを分ける。
- 本番候補binaryはCIで作り、運用ホスト上で`cargo build`しない。
- rootでAethelホストを動かさず、専用service accountを使う。
- core dumpに秘密や業務データが残る可能性を評価する。

### 13.2 時刻の扱い

与信判断の有効期限、支払日、延滞、鍵更新、zkPI期限があるため、時刻はセキュリティ
入力です。

- UTCで保存し、画面表示だけ利用者のtimezoneへ変換する。
- 単調時刻とwall clockを分ける。
- 署名付きイベントには発行時刻と受理時刻の両方を残す。
- 許容するclock skewを設定し、境界値を試験する。
- 時刻同期が閾値を超えてずれたノードは新しい判断を受理しない。
- 過去状態の再生で現在時刻を使わず、記録された評価時刻を使う。

### 13.3 通信経路

最低限、次の論理経路を分けます。

```text
ERP / billing
    -> corporate participant gateway
    -> Aethel command API
    -> durable command log
    -> Aethel deterministic state transition
    -> outbox
       -> DeKYX verifier
       -> credit provider
       -> DeCCP guarantee adapter
       -> zkPI issuer/verifier
       -> DeFMI settlement adapter
    -> accounting / audit callbacks
```

外部providerがAethel DBへ直接接続する構成は禁止します。providerは署名付き応答を
gatewayへ返し、gatewayがschema、署名、資格、有効期限、重複を確認してからAethelへ
渡します。

### 13.4 推奨ポート方針

現在のAethelクレートは固定のネットワークポートを要求しません。したがって、以下は
企業ホストアプリケーションが決める設定例です。

| 経路 | 例 | 公開範囲 |
|---|---:|---|
| 利用者・ERPからparticipant gateway | TCP 8443 | 社内または取引先閉域 |
| gatewayからAethel command API | TCP 9443 | service mesh内のみ |
| provider callback | TCP 9543 | 許可したprovider送信元だけ |
| metrics | TCP 9100 | 監視ネットワークだけ |
| health | TCP 9080 | load balancerと監視だけ |
| database | TCP 5432等 | Aethelホストだけ |

番号自体に互換性はありません。重要なのは、API、metrics、DBを同じ公開listenerへ載せず、
送信元とクライアント証明書を制限することです。

## 14. 鍵と権限のセットアップ

### 14.1 PoCでも分ける鍵

| 鍵 | 署名する対象 | 保持者 |
|---|---|---|
| 支払義務者鍵 | 支払ストリーム、改訂、取消 | 支払義務者 |
| 債権者鍵 | 支払ストリーム、債権化要求 | 債権者 |
| attestor鍵 | 検収、利用量、支払発生条件 | 業務確認サービス |
| assessor鍵 | 与信判断 | 与信事業者 |
| guarantor鍵 | 保証提示、変更、解除 | 保証事業者またはDeCCP adapter |
| liquidity provider鍵 | funding quote、引受 | 資金提供者 |
| operator鍵 | series方針、緊急停止 | Aethel運営権限者 |
| settlement adapter鍵 | zkPI要求とDeFMI結果の関連付け | 決済adapter |
| audit seal鍵 | 日次監査束の要約 | 独立監査サービス |

PoCでよくある誤りは、すべての署名を一つのテスト鍵で作ることです。それでは、
`assessor`が保証を解除できないことや、債権者が支払義務者の同意を偽造できないことを
検証できません。

### 14.2 鍵のライフサイクル

各鍵に次のmetadataを持たせます。

```text
key_id
owner_subject_reference
role
algorithm_and_parameter_set
public_key
valid_from
valid_until
revoked_at
revocation_reason
predecessor_key_id
successor_key_id
allowed_domains
```

秘密鍵そのものをAethel状態やログへ保存しません。開発用ファイル鍵を使う場合でも、
権限600、暗号化volume、短い有効期間、PoC終了時の廃棄記録が必要です。

### 14.3 認可表

API gatewayで最低限次を強制します。

| 操作 | 許可主体 | 追加条件 |
|---|---|---|
| 支払ストリーム作成 | 支払義務者または債権者 | 相手方署名が揃うまでdraft |
| 支払ストリーム改訂 | 両当事者 | revisionが直前値+1 |
| assessor登録 | operator quorum | DeKYX資格、有効な鍵 |
| credit decision登録 | 対象assessor | 対象・policy版・期限が一致 |
| guarantee登録 | guarantor | hostがDeCCP holdを検証し、Aethelへhold ID・commitment・proof digestを渡す |
| funding quote登録 | liquidity provider | quote期限、商品範囲 |
| 債権発行 | issuer/operator | 必須条件と外部予約が成立 |
| circulation request | 現保有者を表すinitiator | hostが外部ledger上の保有を確認し、distributionが受取人資格・譲渡制限を検査 |
| 回収反映 | servicing adapter | DeFMI確定receipt、一意な決済ID |
| default確定 | 規定した権限集合 | grace period、証拠、二重実行防止 |

## 15. データベースと同時実行の設計

### 15.1 推奨する保存単位

Aethel状態を一つの巨大JSONとして上書きするのではなく、少なくとも次を分けます。

- `commands`: 受理前を含む全コマンド、署名、冪等性キー。
- `command_results`: 成功・拒否、エラーコード、前後状態digest。
- `streams`: 支払ストリームの最新状態と版。
- `stream_events`: append-onlyの改訂・停止・終了イベント。
- `receivable_series`: series方針、上限、現在状態。
- `provider_artifacts`: 与信、保証、funding quoteの署名付き原文。
- `token_positions`: 採用した正本設計に応じた残高またはDeFMI参照。
- `settlement_bindings`: zkPI、DeFMI取引、Aethel操作の対応。
- `outbox`: 外部送信待ち、試行回数、次回時刻。
- `inbox_dedup`: 外部callbackの一意性。
- `snapshots`: 検証済み状態とcommand位置。
- `audit_roots`: 定期的な監査束の要約。

### 15.2 一つの債権へ同時要求が来た場合

一つの債権またはseriesに対する状態遷移は、次のいずれかで直列化します。

1. `aggregate_id`ごとのDB行ロック。
2. `expected_revision`を使うcompare-and-swap。
3. partition keyを債権IDとする単一consumer queue。

推奨は2と3の併用です。APIは要求をqueueへ入れ、consumerが現在revisionを確認します。
古いrevisionの要求は自動的に新状態へ適用せず、競合として返します。

```text
UPDATE receivable_series
SET state = :new_state, revision = revision + 1
WHERE series_id = :series_id
  AND revision = :expected_revision;
```

更新行数が0なら、外部副作用を実行せず、現在状態を読んで再評価します。

### 15.3 outboxによる外部決済

DB commitの途中でDeFMIへ同期HTTP要求を送りません。次の二段階にします。

1. Aethel状態を「決済要求作成済み」にし、同じtransactionでoutboxへ書く。
2. workerがoutboxを読み、zkPI生成とDeFMI提出を行う。
3. DeFMI確定receiptをinboxへ保存する。
4. 同じreceiptを再受信しても、一度だけAethel状態を確定する。

worker停止中はoutboxが残り、Aethel状態は「決済済み」になりません。タイムアウトだけを
根拠に成功または失敗へ進めず、DeFMIの正本を照会してから再送または確定します。

## 16. ソースから完全版を構築する

### 16.1 取得した版を固定する

```sh
git clone https://github.com/shukob/aethel.git
cd aethel
git fetch --tags --prune
git checkout <組織内で承認したcommit>
git rev-parse HEAD
sha256sum Cargo.lock
rustc --version --verbose
cargo --version
mkdir -p poc-output
```

`git checkout main`のまま試験しないでください。同じPoC報告書を後日再現できなくなります。
`cargo update`、`cargo generate-lockfile`、lockを変更するIDE操作も、承認前には実行しません。

### 16.2 workspace構成を確認する

```sh
cargo metadata --locked --no-deps --format-version 1 \
  > poc-output/cargo-metadata.json
cargo tree --workspace --locked > poc-output/cargo-tree.txt
```

完全版では、少なくとも次のpackage名が必要です。

```text
aethel-types
aethel-provider-sdk
aethel-core
aethel-tokenization
aethel-distribution
aethel-obligation-wallet
aethel-servicing
aethel
```

不足がある場合は、そのmoduleに対応するPoC項目を「不合格」ではなく「未実施」と記録し、
別のmockで置き換えて完全経路成功と報告しないでください。

### 16.3 構築と試験

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --release --locked
```

本リポジトリのライブラリ試験は、状態機械とmodule間の不変条件を検査します。HTTP、DB、
HSM、DeFMI validator、実provider APIは検査しません。企業PoCでは、これらの試験を
削らず、その後に企業adapterの統合試験を追加します。

### 16.4 完全経路の基準試験

完全版に `aethel/tests/end_to_end.rs` が含まれる場合は、次を実行します。

```sh
cargo test --locked -p aethel --test end_to_end \
  a_receivable_flows_from_signed_stream_to_default_across_every_module \
  -- --exact --nocapture
```

この試験は次を一周します。

1. `AethelBook`へproviderを登録する。
2. `RegisterStream`で署名付き支払ストリームを登録する。
3. `RegisterSeries`で債権seriesを登録する。
4. `CreditDecision`を検証して記録する。
5. `ReceivableIssuance`を作成する。
6. `TokenizationBook`で発行上限へ束縛する。
7. `SupplyIntent`を正本ledger portへ渡す。
8. `DistributionBook`で流通要求と決済文脈を管理する。
9. `ObligationWallet`で支払をqueueへ入れる。
10. `SettlementReceipt`で決済結果を一度だけ反映する。
11. `ServicingBook`で入金証拠、延滞、不履行証拠を管理する。
12. 正当なproviderだけが不履行attestationを作れることを確認する。

ここで使うledgerは試験用実装です。試験が成功してもDeFMI接続済みとはみなしません。

## 17. Provider SDKを使う具体手順

### 17.1 capabilityを一つずつ割り当てる

`ProviderCapability`には、支払ストリーム確認、与信、保証、資金供給、回収、DeKYX資格発行者の
確認（`CredentialIssuer`）などの権限を
用途別に割り当てます。PoCでは最初に一事業者一capabilityとし、その後に兼業構成を
試します。

provider登録で必要になる代表的な値は次です。

```text
provider_id                 Aethel内の一意ID
participant_id              DeFMIまたは参加者台帳への参照
capabilities                許可された役割集合
public_key                  署名検証鍵
policy_registry_digest      審査・保証方針registryの要約
defmi_guarantor_id           保証権限がある場合のDeFMI参照
valid_from / valid_until     provider資格の期間
sequence                    更新順序
status                      Active等の状態
retired_keys                過去artifact検証用の退役鍵情報
```

登録時は `ProviderDefinition::validate_initial`、通常利用時は`validate`とcapability判定を
通します。API gatewayのroleだけを見て、Rust状態機械の検証を省略してはいけません。

### 17.2 与信判断の入力と出力

与信事業者へ渡す入力を、業務目的に必要な最小限へ絞ります。Aethelの
`CreditDecision`が持つのは、モデルの全入力ではなく、対象と判断を結び付ける情報です。

```text
operation_id
decision_id
request_id
provider_id
series_id
stream_state_version
stream_state_root
model_digest
policy_digest
decision_terms_commitment
relation_proof_digest
valid_until
nonce
signature
```

これにより、判断がどの支払ストリーム状態、どのモデル版、どの方針版へ対するものかを
固定できます。`decision_terms_commitment`の内容を別DBへ保存する場合、openingの保存者、
開示権限、保持期間を決めます。

### 17.3 与信API adapter

企業adapterの要求は、例えば次の形にします。これはHTTP仕様の例であり、Aethelが固定で
要求するwire形式ではありません。

```json
{
  "schema": "aethel.credit.request/v1",
  "request_id": "hex-32-byte-id",
  "series_id": "hex-32-byte-id",
  "stream_state_version": 12,
  "stream_state_root": "hex-commitment",
  "policy_digest": "hex-commitment",
  "subject_presentation": "opaque-dekyx-presentation",
  "requested_at": 1788451200,
  "expires_at": 1788451500
}
```

応答は、providerの署名済みartifactをそのまま保持します。

```json
{
  "schema": "aethel.credit.response/v1",
  "request_id": "hex-32-byte-id",
  "provider_id": "hex-32-byte-id",
  "artifact": "canonical-encoded-credit-decision",
  "signature": "provider-signature",
  "received_at": 1788451212
}
```

gatewayは次の順で確認します。

1. bodyサイズとschema版。
2. `request_id`が送信済み要求に存在する。
3. `series_id`とstream rootが要求と一致する。
4. providerが現在ActiveでCreditAssessor capabilityを持つ。
5. `valid_until`が受理時刻より後で、上限期間以内。
6. 署名文を正規化して署名を検証する。
7. `operation_id`、`decision_id`、`nonce`が未使用。
8. 同じ内容の再送なら同じ結果を返し、異なる内容なら衝突として拒否する。

### 17.4 provider障害時

- timeoutを信用拒否へ変換しない。
- 別providerへ切り替える場合は、新しいrequest IDと選択理由を記録する。
- 二つのprovider結果を黙って平均しない。
- 古い結果を有効期限だけ延ばさない。
- circuit breaker解除後に、期限切れ要求を再送しない。
- provider応答が遅れて到着した場合、現在のstream versionと再度比較する。

## 18. 支払ストリームを業務システムから作る

### 18.1 どのイベントを取り込むか

支払ストリームは単なる月額請求の配列ではありません。少なくとも次のsource eventを
区別します。

- 契約締結。
- 発注・注文確定。
- 納品・役務提供。
- 検収。
- 使用量・出来高確定。
- 請求確定。
- 値引、返品、相殺、異議。
- 支払。
- 契約変更・終了。

ERP側の一つの「更新」イベントを、理由を失った残高上書きとしてAethelへ渡さないで
ください。source event digestと、どの規則で`StreamState`へ反映したかを残します。

### 18.2 StreamStateの対応表

| Aethel値 | 業務上の意味 | 更新元 |
|---|---|---|
| `stream_id` | 契約・支払系列の不変ID | 初回組成 |
| `payer_commitment` | 支払義務者への秘匿参照 | DeKYX/参加者adapter |
| `payee_commitment` | 債権者への秘匿参照 | DeKYX/参加者adapter |
| `settlement_asset_id` | 決済通貨または資産 | 商品master |
| `source_domain_digest` | ERP、metering等のsource領域 | connector設定 |
| `terms_digest` | 契約条件の正規化要約 | 契約adapter |
| `event_root` | 取り込んだsource event集合 | event accumulator |
| `accrued_commitment` | 発生済み支払義務 | attestor計算 |
| `paid_commitment` | 支払済み | DeFMI確定receipt |
| `eligible_commitment` | 債権化可能額 | policy計算 |
| `pledged_commitment` | すでに債権化・担保化した額 | Aethel発行状態 |
| `as_of` | 状態が表す基準時刻 | source event時刻 |
| `version` | 単調増加する版 | 状態遷移 |
| `status` | Active等 | 契約・不履行処理 |

### 18.3 更新規則

`StreamTransition`は直前状態の正当な後継でなければなりません。次を試験します。

- `stream_id`、payer/payee、settlement asset、source domain、termsが変わらない。
- `version`が一つだけ増える。
- `as_of`が厳密に増える。
- source更新では`pledged_commitment`が変わらない。
- 許可されたstatus遷移だけを通す。
- attestorが登録済み鍵とcapabilityを持つ。
- source evidence digestが空でない。

現在のgeneric state machineはcommitmentのopeningを持たないため、`paid_commitment <=
accrued_commitment` やeligible/pledgedの金額関係を比較しない。`relation_proof_digest` は証拠への
束縛であって、digestだけでは関係を検証しない。商品adapterが登録済みverifierで関係証明を確認して
から `StreamTransition` を渡すことを、本番相当PoCの追加gateにする。

## 19. 債権seriesと発行方針

### 19.1 SeriesPolicyを先に決める

商品を作る前に次を決めます。

| 方針 | 検討内容 |
|---|---|
| `requires_credit_decision` | 外部与信判断を必須にするか |
| `requires_guarantee` | 保証を必須にするか |
| `requires_funding_reservation` | 発行前に資金供給枠を予約するか |
| `requires_confidential_subject` | DeKYX匿名資格を必須にするか |
| `subject_kind` | 法人、個人、機器等のどの主体か |
| `required_qualifications` | 地域、業種、投資家区分等 |
| `accepted_issuer_namespace_digest` | 誰の資格発行を信頼するか |
| `allow_secondary_transfer` | 二次流通を許可するか |
| `eligibility_policy_digest` | 適格性規則の版 |
| `claim_policy_digest` | 不履行・保証請求規則の版 |

方針変更は既発行債権へ黙って遡及させません。seriesを新しい版または新しいIDとして作り、
既存保有者への影響を別に扱います。

### 19.2 発行前チェック

`issue_receivable`相当の処理前に次を一つのtransactional decisionとして確認します。

1. coreがseriesをActiveかつ `now <= maturity` と確認し、hostも `valid_from <= now` を確認する。
2. streamがseriesと一致し、Cancelled/Defaulted/Closedでない。coreの発行更新はPausedも許すため、
   Paused時に止める商品ではhost policyを追加する。
3. `before_stream_state_version`とrootが現在値と一致。
4. hostが対象額とeligible/pledged commitmentの関係証明を検証する。coreは
   `relation_proof_digest` とafter pledged commitmentを束縛するが、openingなしに金額大小を比較しない。
5. `operation_id`、`issuance_id`、`note_id`、`allocation_nullifier`が未使用。
6. 必須与信判断が存在し、有効期限内。
7. 必須保証が存在し、series・request・額commitmentへ結び付く。
8. 必須funding reservationが存在する。
9. DeKYXのsubject bindingは与信判断または保証を記録する時点で検証済みである。発行時にcoreが
   新しいpresentationを再検証するわけではないため、必要ならhostが発行直前の失効を再確認する。
10. DeFMI側の発行・決済予約はhost adapterが確認する。Aethel coreの発行処理にはDeFMI照会がない。

`request_id` は関連する与信判断・保証・funding quote・発行を同じ文脈へ合わせるために使うが、
発行の独立した一意keyとしては消費しない。同一requestから複数発行を許さない商品では、hostまたは
追加policyで一意制約を設ける。

一つでも失敗したら、streamのpledged状態、token supply、DeCCP hold、DeFMI noteの一部だけを
更新しないようにします。

## 20. トークン化と流通を使う

### 20.1 AssetLedgerPortが重要な理由

`aethel-tokenization`は`AssetLedgerPort`越しに発行・消却を正本ledgerへ依頼します。
これは、Aethel内部の数値をそのまま資産残高とみなさないための境界です。

実装adapterは少なくとも次を行います。

- `SupplyIntent`のstatementと署名・権限を検証する。
- `intent_id`を冪等性キーとして保存する。
- 対象assetとrecipient/holder commitmentをDeFMIの事前登録へ束縛する。
- mintまたはburnをzkPIへ変換する。
- DeFMI確定後にだけ`SupplyReceipt`を返す。
- 拒否時は構造化された`LedgerRejection`を返す。
- network timeout時は結果不明として照会し、別intentを作らない。

### 20.2 発行上限

`IssuanceAuthorization`と`SupplyAccount`により、一つの債権発行から作れるtoken数量を
制限します。次を必ず試験します。

- 上限と同じ数量のmintは成功する。
- 上限+1は失敗する。
- 同時に二要求を送っても合計が上限を超えない。
- 一方のledger提出が失敗した場合、予約が解放または再照会される。
- burn済み数量だけを再mint可能にするか、商品方針どおり固定する。

### 20.3 DistributionBook

`CirculationRequest`、`VenueFill`、`SettlementContext`、`SettlementOutcome`を使い、注文と
決済を分離します。

```text
admit request
  -> verify holder/investor eligibility
  -> bind transfer restriction digest
  -> hand off to venue
  -> accept signed fill
  -> create settlement context
  -> submit zkPI to DeFMI
  -> record settled, expired, or rejected outcome
```

venueが約定を返しただけでtoken保有者を変えません。`SettlementOutcome`はDeFMIの確定証拠と
一致した場合だけ `Settled` にします。ほかのvariantは `Expired` と `Rejected` であり、
`Finalized` というvariantはありません。

## 21. Obligation Walletを使う

### 21.1 事前承認

`PreAuthorization`には、支払義務者が事前に認めた範囲を持たせます。PoCでは少なくとも
次を束縛します。

- 支払ストリーム。
- 決済資産。
- 一回または期間内の最大額。
- 有効期間。
- 支払先commitment。

現在の `PreAuthorization` が直接持つfieldは、authorization ID、stream ID、payee commitment、
settlement asset、per-payment ceiling、period ceiling/seconds、valid-from/untilである。取消しsequence、
署名鍵、署名domainはこの型にはない。個々の `SignedPayment` の署名と固定domainは別にあり、
事前承認の途中取消しが必要ならhost側の失効台帳またはcore拡張を追加する。

この事前承認により、支払期日ごとに人が再署名しなくても、条件内の支払をqueueへ入れられ
ます。Aethel運営者が任意の支払を作れる一般委任にはしません。

### 21.2 Queueの状態

`QueueStatus`は次の5状態を区別して扱います。画面では「失敗」一語にまとめないでください。

| 状態 | 利用者表示 | 運用処理 |
|---|---|---|
| `Pending` | 送信待ち | 順序どおりworkerが取得 |
| `InFlight` | 決済確認中 | attemptと提出時刻を保持し、同じpayment IDを再生成しない |
| `RetryScheduled` | 一時失敗・再試行予定 | attempts、次回時刻、失敗digestを保持してbackoff後に照会 |
| `Acknowledged` | 支払確認済み | receipt digest、settled units、確定時刻を表示 |
| `Abandoned` | 自動再試行終了 | attemptsと最終失敗digestを示し、運用判断を求める |

### 21.3 冪等な回復

1. `enqueue`を同じpayment IDで二回呼ぶ。
2. 同じ内容なら既存entryを返す。
3. 異なる内容なら衝突を拒否する。
4. `mark_in_flight`後にworkerを停止する。
5. 再起動後、DeFMIへpayment IDを照会する。
6. 確定済みならreceiptをreconcileする。
7. 未提出なら同じzkPI/nullifierを再送する。
8. 不明なら自動で別支払を作らず運用queueへ移す。

## 22. Servicingと不履行処理

### 22.1 回収証拠

`PaymentEvidence`は、単なる銀行入金CSVではなく、対象installment、支払量、決済参照、
provider署名を結び付けます。DeFMIを使う場合、最終性が確認できるreceiptとrootを含む
外部証拠digestへ束縛します。

### 22.2 延滞判定

`ServicingTerms`には支払予定と猶予期間を持たせ、`evaluate(now)`で状態を更新します。
時刻を手入力で過去へ戻したり、休日調整をコード外で黙って行わないでください。
現在の型が持つのはstream ID、支払schedule、grace seconds、cure window seconds、
default判定に必要な未払回数であり、calendar digest fieldはない。営業日調整が必要なら、hostが
calendar版を別の署名済み設定へ束縛するか、型をversion upしてから使う。未知fieldをJSONへ足すだけでは
`deny_unknown_fields` により拒否される。

### 22.3 不履行

`default_evidence`は、未払いinstallmentと時刻から機械的な証拠を作ります。その後、
許可されたproviderが`DefaultAttestation`へ署名し、`accept_default_attestation`で受理します。

PoCでは次を拒否させます。

- 未到来の支払を不履行とする。
- 全額支払済みを不履行とする。
- creditorまたはissuer自身が、権限なしに不履行を確定する。
- 退役済み鍵で新しいattestationを作る。
- 別seriesの証拠を流用する。
- 同じ保証を二回claimする。

## 23. 監視項目

最低限、次をmetricsとして収集します。主体名、金額、契約原文をlabelへ入れません。

```text
aethel_commands_total{type,result,error_code}
aethel_command_duration_seconds{type}
aethel_revision_conflicts_total{aggregate_type}
aethel_outbox_depth{destination}
aethel_outbox_oldest_seconds{destination}
aethel_provider_requests_total{provider_class,result}
aethel_provider_latency_seconds{provider_class}
aethel_wallet_queue_depth{status}
aethel_settlement_pending_seconds{venue}
aethel_reconciliation_total{result}
aethel_snapshot_age_seconds
aethel_audit_root_age_seconds
```

避けるべきlabelは、`stream_id`、`series_id`、法人ID、asset ID、request IDです。時系列DBの
高cardinality化だけでなく、監視担当者への情報漏えいになります。

### 23.1 alertの初期値

次はPoC開始時の例であり、実測後に変更します。

- outbox最古イベントが5分を超える。
- provider timeout率が15分窓で5%を超える。
- revision conflictが通常時の3倍を超える。
- DeFMI確定待ちが想定finalityの3倍を超える。
- snapshotが30分以上作られていない。
- audit root生成が2周期連続で失敗する。
- 永続ディスク使用率が70%、85%、95%を超える。

## 24. 障害注入試験

| 試験 | 注入方法 | 期待結果 |
|---|---|---|
| provider timeout | gatewayからprovider宛通信を遮断 | requestはpending/expired、勝手な判断を作らない |
| provider二重応答 | 同じIDで同一応答を再送 | 一度だけ記録 |
| provider衝突応答 | 同じIDで別内容を送る | セキュリティ事象として拒否 |
| DB primary停止 | command commit直前に停止 | 未commitなら再実行、部分状態なし |
| outbox worker停止 | DB commit後・外部送信前に停止 | queueに残り再開後送信 |
| DeFMI応答喪失 | 決済後にHTTP応答を破棄 | 正本照会し二重決済なし |
| DeKYX失効 | 要求作成後、発行前に失効 | 発行直前再検証で拒否 |
| DeCCP枠競合 | 同じ保証枠へ同時要求 | 一方だけ成功、枠超過なし |
| clock skew | 一台を許容幅外へずらす | 新規期限付きartifactを受理しない |
| snapshot破損 | byteを変更して復旧 | digest不一致で起動拒否 |
| event順序逆転 | 新版の後に旧版を配信 | 旧版を拒否 |
| audit storage停止 | seal書込みを失敗させる | 監査未完了をalert、成功扱いしない |

各試験で、利用者画面、API応答、DB状態、outbox、DeFMI正本、metrics、監査ログを同じ
時系列へ並べます。

## 25. 性能試験

### 25.1 測る経路

単体関数の速度だけでなく、次を別々に測ります。

1. Stream registration: API受信から状態commitまで。
2. Credit request: request作成から署名付き判断受理まで。
3. Receivable issuance: 条件確認から発行intent作成まで。
4. Token mint: intent作成からDeFMI確定まで。
5. Distribution: 流通要求からDvP確定まで。
6. Scheduled payment: queue readyからreceipt reconcileまで。
7. Default: grace終了から正当なattestation受理まで。
8. Recovery: process停止からqueue処理再開まで。

### 25.2 記録する値

- request数、成功数、拒否数、timeout数。
- p50、p95、p99、最大遅延。
- CPU時間、最大RSS、ディスクread/write、network bytes。
- DB transaction時間とlock待ち。
- queue深さと最古イベント時間。
- provider別の外部待ち時間。
- zkPI生成・検証時間、DeFMI finality時間。
- 同時実行数を増やしたときのthroughputと誤り率。

### 25.3 負荷段階

```text
stage 1: 1 req/s for 10 min        配線確認
stage 2: expected average for 30 min
stage 3: expected peak for 60 min
stage 4: 2x peak for 30 min        余裕確認
stage 5: provider/DeFMI degradation under expected peak
stage 6: recovery and backlog drain
```

数値は自社の業務量から決めます。上記は時間と順序の例であり、性能合格値ではありません。

## 26. セキュリティ確認

### 26.1 ログに出してはいけない値

- 生のKYC/KYB属性。
- 支払義務者・債権者の実名対応。
- 契約全文、請求明細、モデル入力。
- commitment opening。
- 秘密鍵、threshold share、HSM認証情報。
- bearer token、database URLのpassword。
- 平文金額を秘匿する商品での金額。

ログには、操作型、仮名化したcorrelation ID、状態版、結果コード、処理時間、公開可能な
digestを使います。

### 26.2 バックアップ

- command log、snapshot、outbox、inbox dedupを同じ復旧点へそろえる。
- DBだけを戻してDeFMI正本を巻き戻さない。
- 復旧後にDeFMI、DeCCP、providerの外部状態と照合する。
- backup暗号鍵を運用鍵と分ける。
- restore試験をPoC期間中に最低一度実行する。
- restore後のroot、最終command ID、未処理outboxを記録する。

### 26.3 脅威別確認

| 脅威 | 必要な防御 |
|---|---|
| providerの権限逸脱 | capability検査、署名、期間、policy digest |
| 古い判断の再利用 | stream root/version、有効期限、nonce |
| 二重債権化 | operation/request/issuance ID、一意制約、pledged commitment |
| 二重mint | SupplyIntent冪等性、発行上限、DeFMI nullifier |
| adapter管理者による改変 | canonical encoding、署名、監査seal |
| DB rollback | 外部rootとsequence照合、append-only audit root |
| callback偽造 | mTLS、署名、送信元制限、request binding |
| 障害を利用した二重支払 | outbox/inbox、正本照会、同じID再送 |
| 資格失効の見落とし | 発行・譲渡直前のDeKYX再検証 |
| 保証枠競合 | DeCCP側の原子的hold、Aethelはopaqueなhold ID・commitmentを保持 |

## 27. トラブルシューティング

### `cargo test --locked`がlock変更を要求する

Rust toolchain、Git commit、外部Git依存のcommitが承認済み組合せと異なります。lockを
更新せず、`rustc --version --verbose`、`git rev-parse HEAD`、`sha256sum Cargo.lock`、
エラー全文を保存します。

### provider署名が検証できない

次を順に確認します。

1. provider IDが期待するregistry entryと一致する。
2. artifact作成時刻に鍵が有効だった。
3. 新規artifact用鍵と過去artifact検証用退役鍵を混同していない。
4. canonical encoding前後でfield順や整数表現を変えていない。
5. domainとstatement digestが一致する。
6. base64/hex変換でbyteを変えていない。

### 発行可能額が合わない

`stream_state_version`、`eligible_commitment`、`pledged_commitment`、既存issuance、保留中
operationを同じsnapshotで確認します。画面用projectionを正本として再計算しません。

### 決済済みなのにAethelがpending

payment ID、zkPI nullifier、DeFMI transaction IDで正本を照会します。確定receiptを取得し、
inbox dedupを通してreconcileします。新しい支払やmint intentを作らないでください。

### AethelはsettledだがDeFMIに記録がない

重大な不変条件違反です。新規発行・譲渡・支払を停止し、Aethelを手修正せず、当該状態へ
至ったcommand、receipt、operator操作、DB audit logを保全します。

### queueが減らない

destination別に、資格失効、provider停止、DeFMI停止、時刻ずれ、恒久拒否、retry backoffを
分けます。全entryを一括再送しないでください。

## 28. 企業PoCの最終成果物

PoC完了時には、最低限次を残します。

1. 対象業務、法域、商品、除外範囲。
2. 全componentと運営主体を示す配置図。
3. 物理ホスト、VM、container、cloud accountの共通障害点一覧。
4. Git commit、Cargo.lock、Rust版、build artifact digest。
5. 8クレートの有無と実施した機能範囲。
6. provider登録・鍵・capability・policy版一覧。
7. 正常系のstreamから回収までのtrace。
8. 拒否・障害注入全ケースの結果。
9. DeKYX、DeCCP、zkPI、DeFMIとの正本責任分界。
10. 性能値と測定条件。
11. 未解決のセキュリティ、法務、会計、運用課題。
12. 本番化判定、追加PoC判定、却下判定と承認者。

「画面上で一件成功した」だけでは完了にしません。正本状態、署名、root、外部receipt、
失敗時の不変性、復旧後の一意性まで揃った一件を、代表的な完全証拠とします。

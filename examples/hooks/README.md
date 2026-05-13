# フックスクリプト例

## ds-lite

DS-Lite 方式で IPv4 over IPv6 トンネルを構成するフックスクリプトです。

HB46PP を使わず、フックスクリプトが AFTR への IPIP6 トンネルを自分で作成・削除します。

### 前提

`/etc/default/ipoed` の `IPOED_OPTS` に `--disable-hb46pp` を指定してください。
HB46PP が有効のままだと ipoed とスクリプトの両方がトンネルを操作しようとして競合します。

```shell
IPOED_OPTS="--disable-hb46pp --lan-addr4 192.168.1.1/24 --hook-path /path/to/examples/hooks/ds-lite/hook"
```

### 設定

`ds-lite/hook.conf.example` を `ds-lite/hook.conf` にコピーして編集します。
`hook.conf` は `.gitignore` に登録されているのでコミットされません。

```shell
cp examples/hooks/ds-lite/hook.conf.example examples/hooks/ds-lite/hook.conf
vi examples/hooks/ds-lite/hook.conf
```

| 変数 | 必須 | 説明 |
|---|---|---|
| `AFTR_HOST` | ○ | AFTR のホスト名（AAAA レコードで解決されます） |
| `TUN_IF` | — | トンネル IF 名（デフォルト: `dslite0`） |
| `MSS` | — | TCP MSS 値（デフォルト: `1420`） |

`AFTR_HOST` の解決は `IPV6_UP` イベント時に行われます。
このとき IPv6 のデフォルトルートはすでに設定済みのため、IPv6 DNS で引けます。

### 動作

| イベント | 処理 |
|---|---|
| `IPV6_UP` | AFTR アドレスを解決 → IPIP6 トンネル作成 → IPv4 デフォルトルート設定 → iptables MSS クランプ追加 |
| `IPV6_DOWN` | iptables MSS クランプ削除 → IPv4 デフォルトルート削除 → トンネル削除 |

### 確認

```shell
ip -6 tunnel show
ip route
journalctl -t ipoed-hook
```

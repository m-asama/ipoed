# フックスクリプト例

## (Manually-configured) DS-Lite (`ds-lite/hook`)

手動設定の (HB46PP を使わない) DS-Lite 方式で IPv4 over IPv6 トンネルを構成するフックスクリプトです。
HB46PP を使わず、フックスクリプトが AFTR への IPIP6 トンネルを作成・削除します。

### 前提

`/etc/default/ipoed` の `IPOED_OPTS` に `--disable-hb46pp` を指定してください。
HB46PP が有効のままだと IPoEd とスクリプトの両方がトンネルを操作しようとして競合します。
特に、スクリプトの `TUN_IF` がデフォルトの `ipoetun` の場合は IPoEd と同じインターフェースを操作しあうので挙動が想定外になります。

```shell
IPOED_OPTS="--disable-hb46pp --lan-addr4 192.168.1.1/24 --hook-path /path/to/examples/hooks/ds-lite/hook"
```

`--hook-path` はスクリプトをデフォルトのパス (`/usr/libexec/ipoed/hook`) 以外に置いた場合に指定してください。

### 設定

```shell
sudo mkdir /usr/libexec/ipoed
sudo cp examples/hooks/ds-lite/hook /usr/libexec/ipoed/hook
sudo cp examples/hooks/ds-lite/hook.conf.example /usr/libexec/ipoed/hook.conf
sudo vi /usr/libexec/ipoed/hook.conf  # 環境に応じて設定してください。設定項目は下記の通りです。
sudo chmod 755 /usr/libexec/ipoed/hook
```

| 変数                         | 必須? | デフォルト | 説明                                                                                  |
|------------------------------|-------|------------|---------------------------------------------------------------------------------------|
| `AFTR_HOST`                  | 必須  | —          | AFTR のホスト名または IPv6 アドレス                                                   |
| `TUN_IF`                     | —     | `ipoetun`  | トンネル IF 名                                                                        |
| `SET_DEFAULT_ROUTE`          | —     | `true`     | IPv4 デフォルトルートをトンネルに向けるか                                             |
| `SET_DEFAULT_ROUTE_OVERRIDE` | —     | `true`     | 既存の IPv4 デフォルトルートを上書きするか (`SET_DEFAULT_ROUTE=true` の場合のみ有効)  |
| `MSS_CLAMP`                  | —     | `false`    | iptables で TCP MSS クランプを設定するか                                              |
| `MSS`                        | —     | `1420`     | クランプする TCP MSS (`MSS_CLAMP=true` の場合のみ使用)  |

`AFTR_HOST` にホスト名を指定した場合、`IPV6_UP` イベント時に解決を試みます。
このとき IPv6 のデフォルトルートは IPoEd によってすでに設定済みのため、`netplan` の設定などに問題がなければ ([/README.md](/README.md) 参照) 回線から得られた IPv6 DNS キャッシュサーバが利用されます。

### 動作

#### `IPV6_UP`
- AFTR アドレスを解決
- IPIP6 トンネル作成
- IPv4 デフォルトルート設定 (`SET_DEFAULT_ROUTE=true` の場合) 
- iptables MSS クランプ設定 (`MSS_CLAMP=true` の場合) 

#### `IPV6_DOWN`

- iptables MSS クランプ削除 (`MSS_CLAMP=true` の場合) 
- IPv4 デフォルトルート削除 (`SET_DEFAULT_ROUTE=true` の場合) 
- トンネル削除

### 確認

```shell
ip -6 tunnel show
ip route show
journalctl -t ipoed-hook
```

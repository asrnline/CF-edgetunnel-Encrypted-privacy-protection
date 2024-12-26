免责声明
本免责声明适用于 GitHub 上的 “edgetunnel” 项目（以下简称“本项目”），项目链接为：https://github.com/cmliu/edgetunnel 。

用途
本项目仅供教育、研究和安全测试目的而设计和开发。旨在为安全研究人员、学术界人士及技术爱好者提供一个探索和实践网络通信技术的工具。

合法性
在下载和使用本项目代码时，必须遵守使用者所适用的法律和规定。使用者有责任确保其行为符合所在地区的法律框架、规章制度及其他相关规定。

免责
作为本项目的 二次开发作者（以下简称“作者”），我 cmliu 强调本项目仅应用于合法、道德和教育目的。
作者不认可、不支持亦不鼓励任何形式的非法使用。如果发现本项目被用于任何非法或不道德的活动，作者将对此强烈谴责。
作者对任何人或组织利用本项目代码从事的任何非法活动不承担责任。使用本项目代码所产生的任何后果，均由使用者自行承担。
作者不对使用本项目代码可能引起的任何直接或间接损害负责。
为避免任何意外后果或法律风险，使用者应在使用本项目代码后的 24 小时内删除代码。
通过使用本项目代码，使用者即表示理解并同意本免责声明的所有条款。如使用者不同意这些条款，应立即停止使用本项目。

作者保留随时更新本免责声明的权利，且不另行通知。最新版本的免责声明将发布在本项目的 GitHub 页面上。

风险提示
通过提交虚假的节点配置给订阅服务，避免节点配置信息泄露。
另外，您也可以选择自行部署 WorkerVless2sub 订阅生成服务，这样既可以利用订阅生成器的便利。

变量说明
UUID	90cd4a77-141a-43c9-991b-08263cfe9c10	✅	可输入任意值(非UUIDv4标准的值会自动切换成动态UUID)	Video

KEY	token	❌	动态UUID秘钥，使用变量KEY的时候，将不再启用变量UUID	

TIME	7	❌	动态UUID有效时间(默认值:7天)	

UPTIME	3	❌	动态UUID更新时间(默认值:北京时间3点更新)	

PROXYIP	proxyip.fxxk.dedyn.io:443	❌	备选作为访问CFCDN站点的代理节点(支持自定义ProxyIP端口, 支持多ProxyIP, ProxyIP之间使用,或换行作间隔)	Video

SOCKS5	user:password@127.0.0.1:1080	❌	优先作为访问CFCDN站点的SOCKS5代理(支持多socks5, socks5之间使用,或换行作间隔)	Video

GO2SOCKS5	blog.cmliussss.com,*.ip111.cn,*google.com	❌	设置SOCKS5变量之后，可设置强制使用socks5访问名单(*可作为通配符，换行作多元素间隔)	

ADD	icook.tw:2053#官方优选域名	❌	本地优选TLS域名/优选IP(支持多元素之间,或换行作间隔)	

ADDAPI	https://raw.github.../addressesapi.txt	❌	优选IP的API地址(支持多元素之间,或 换行 作间隔)	

ADDNOTLS	icook.hk:8080#官方优选域名	❌	本地优选noTLS域名/优选IP(支持多元素之间,或换行作间隔)	

ADDNOTLSAPI	https://raw.github.../addressesapi.txt	❌	优选IP的API地址(支持多元素之间,或 换行 作间隔)	

ADDCSV	https://raw.github.../addressescsv.csv	❌	iptest测速结果(支持多元素, 元素之间使用,作间隔)	

DLS	8	❌	ADDCSV测速结果满足速度下限	

CSVREMARK	1	❌	CSV备注所在列偏移量	

TGTOKEN	6894123456:XXXXXXXXXX0qExVsBPUhHDAbXXX	❌	发送TG通知的机器人token	

TGID	6946912345	❌	接收TG通知的账户数字ID	

SUB	VLESS.fxxk.dedyn.io	❌	优选订阅生成器域名	Video

SUBAPI	SUBAPI.fxxk.dedyn.io	❌	clash、singbox等 订阅转换后端	Video

SUBCONFIG	https://raw.github.../ACL4SSR_Online_Full_MultiMode.ini	❌	clash、singbox等 订阅转换配置文件	Video

SUBEMOJI	false	❌	订阅转换是否启用Emoji(默认true)	

SUBNAME	edgetunnel	❌	订阅名称	

RPROXYIP	false	❌	设为 true 即可强制获取订阅器分配的ProxyIP(需订阅器支持)	Video

URL302	https://t.me/CMLiussss	❌	主页302跳转(支持多url, url之间使用,或换行作间隔, 小白别用)	

URL	https://blog.cmliussss.com	❌	主页反代伪装(支持多url, url之间使用,或换行作间隔, 乱设容易触发反诈)	

CFPORTS	2053,2096,8443	❌	CF账户标准端口列表	

加密变量
ENCRYPTION=true

ENCRYPTION_KEY=your-secure-key

ENCRYPTION_ITERATIONS=100000  # 可选

ENCRYPTION_SALT_SIZE=16      # 可选

环境变量

REGION

US: 美国

JP: 日本

TW: 台湾

SG: 新加坡

如果不指定 REGION,默认使用美国IP


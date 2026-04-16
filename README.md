# ArmorAuth

ArmorAuth 是一个基于 Spring Security 和 Spring Authorization Server 的认证授权实验项目。仓库当前同时包含核心能力、服务端示例、前端页面、Spring Boot 集成占位模块以及多个 OAuth2/OIDC 样例应用。

从代码现状看，这个项目更接近“可演示的认证框架原型”而不是已经收敛完成的通用产品：核心认证流程、JPA 持久化、设备授权、联邦登录和前端页面已经具备雏形，但部分模块仍处于占位或开发中状态。

## 最近更新

- 已升级到 `Spring Boot 4.0.5`
- 已兼容 `Spring Security 7.0.4`
- 已迁移到 `Spring Authorization Server 7.0.4`
- 认证服务端页面已从 Node/Vite 壳子切回服务端 `FreeMarker` 模板
- 当前仓库已验证通过：
- `mvn -q -DskipTests compile`
- `mvn -q test`
- `mvn -q -pl armorauth-server -am package -DskipTests`

## 项目定位

- 基于 Spring Authorization Server 实现 OAuth2 Authorization Server 和 OIDC 1.0 能力
- 提供基于 JPA 的客户端、授权记录、授权同意信息存储
- 提供登录页、授权确认页、设备激活页等前端页面
- 集成第三方联邦登录扩展，当前代码中已包含 GitHub、Gitee、QQ、微信相关适配
- 提供 OIDC 登录、PKCE、`client_credentials` 等样例工程

## 当前已实现的能力

- OAuth2/OIDC 服务端基础配置
- JPA 版 `RegisteredClientRepository`
- JPA 版 `OAuth2AuthorizationService`
- JPA 版 `OAuth2AuthorizationConsentService`
- 自定义授权确认页 `/consent`
- 自定义登录页 `/login`
- Device Authorization Flow 页面 `/activate`、`/activated`
- 验证码登录扩展
- 联邦登录扩展
- 服务端内嵌 FreeMarker 模板页面

## 仓库结构

| 模块 | 说明 | 当前状态 |
| --- | --- | --- |
| `armorauth-core` | 核心认证授权能力，包含配置、JPA 持久化、设备授权、验证码登录、联邦登录扩展等 | 核心模块 |
| `armorauth` | 对 `armorauth-core` 的简单聚合封装 | 可用但很薄 |
| `armorauth-server` | 独立运行的认证服务端，默认端口 `9000` | 可运行示例 |
| `armorauth-server-ui` | 服务端内嵌 UI 资源模块，提供 FreeMarker 模板和静态资源 | 可运行示例 |
| `armorauth-spring-boot` | Spring Boot 聚合模块 | 占位模块 |
| `armorauth-spring-boot/armorauth-spring-boot-starter` | 预留 starter 模块 | 当前只有 `pom.xml`，暂无源码实现 |
| `armorauth-samples/armorauth-samples-oidc-login` | OIDC 登录样例，默认端口 `8083` | 可演示 |
| `armorauth-samples/armorauth-samples-client` | `client_credentials` 样例，覆盖 `client_secret_basic`、`client_secret_jwt`、`private_key_jwt` | 可演示 |
| `armorauth-samples/armorauth-samples-pkce` | PKCE 授权码流程样例，默认端口 `8085` | 可演示 |
| `armorauth-admin` | 管理端后端模块 | 当前只有 `Hello world` 占位代码 |
| `armorauth-admin-ui` | 独立管理端前端，基于 Vue 3 + Vite + Ant Design Vue | 前端原型，未接入 Maven Reactor |

## 技术栈

- Java 21
- Spring Boot 4.0.5
- Spring Security 7.0.4
- Spring Authorization Server 7.0.4
- Spring Data JPA
- MariaDB / MySQL
- FreeMarker
- Ant Design Vue

## 快速开始

### 1. 环境要求

- JDK 21
- Maven 3.9+
- Node.js 18+（仅构建 `armorauth-admin-ui` 时需要）
- MariaDB / MySQL

说明：

- 父 POM 现在已经切换到 Java 21。
- `armorauth-server-ui` 不再依赖 Node/Vite 构建链，直接由 Spring Boot 加载 FreeMarker 模板和静态资源。

### 2. 配置本地域名

样例工程没有直接使用 `localhost`，而是使用了固定域名：

- `armorauth-server`
- `armorauth-demo`

可直接参考仓库中的文件：

```text
armorauth-samples/hosts/armorauth-hosts
```

内容如下：

```text
127.0.0.1 armorauth-demo
127.0.0.1 armorauth-server
```

### 3. 初始化数据库

服务端默认启用 `mysql` profile，数据库名为：

```text
identity_server
```

数据库脚本位于：

```text
armorauth-server/src/main/resources/sql/sas-schema.sql
armorauth-server/src/main/resources/sql/sas-data.sql
```

建议启动前手动执行这两个 SQL 文件。当前代码中没有看到自动初始化这两份脚本的配置。

### 4. 修改本地数据库与第三方登录配置

默认配置文件：

```text
armorauth-server/src/main/resources/application.yml
armorauth-server/src/main/resources/application-mysql.yml
```

默认行为：

- 服务端端口为 `9000`
- 默认激活 `mysql` profile
- 数据源指向本地 MariaDB

启动前建议至少检查并修改以下内容：

- 数据库地址、用户名、密码
- 第三方 OAuth 客户端配置
- 生产环境下的敏感密钥

### 5. 启动认证服务端

在仓库根目录执行：

```bash
mvn -pl armorauth-server -am clean package -DskipTests
java -jar armorauth-server/target/armorauth-server-0.0.1.jar
```

如果只是本地调试，也可以使用：

```bash
mvn -pl armorauth-server -am spring-boot:run
```

说明：

- `armorauth-server` 依赖 `armorauth-server-ui`
- 构建服务端时会一起打包 FreeMarker 页面和静态资源，不再执行 Node 构建

### 6. 启动样例工程

OIDC 登录样例：

```bash
mvn -pl armorauth-samples/armorauth-samples-oidc-login -am spring-boot:run
```

`client_credentials` 样例：

```bash
mvn -pl armorauth-samples/armorauth-samples-client -am spring-boot:run
```

PKCE 样例：

```bash
mvn -pl armorauth-samples/armorauth-samples-pkce -am spring-boot:run
```

对应端口：

- `armorauth-server`: `9000`
- `armorauth-samples-oidc-login`: `8083`
- `armorauth-samples-client`: `8084`
- `armorauth-samples-pkce`: `8085`

### 7. 单独启动管理端前端

`armorauth-admin-ui` 不在根 POM 的模块列表中，需要单独启动：

```bash
cd armorauth-admin-ui
npm install
npm run dev
```

## 样例说明

### `armorauth-samples-oidc-login`

- 演示标准 OIDC 登录
- 通过授权码流程完成登录
- 默认回调地址是 `http://armorauth-demo:8083/login/oauth2/code/autism`

### `armorauth-samples-pkce`

- 演示公有客户端 + PKCE 授权码流程
- 默认回调地址是 `http://armorauth-demo:8085/login/oauth2/code/clever`

### `armorauth-samples-client`

- 演示 `client_credentials`
- 当前代码里覆盖了三种客户端认证方式：
- `client_secret_basic`
- `client_secret_jwt`
- `private_key_jwt`

## 与代码现状一致的注意事项

### 1. 项目当前偏 demo / prototype

以下模块仍然明显处于未完成状态：

- `armorauth-spring-boot-starter`
- `armorauth-admin`

### 2. 验证码校验仍是 mock

在 `armorauth-core` 的默认安全配置中，验证码校验逻辑当前是硬编码 mock，验证码值为：

```text
1234
```

这适合本地联调，不适合生产环境。

### 3. JWK 是运行时动态生成的

当前 `AuthorizationServerConfig` 会在应用启动时动态生成 RSA Key。  
这意味着服务端重启后，之前签发的 JWT 在很多场景下将不再可验证，更适合本地演示，不适合作为生产配置直接使用。

### 4. 默认配置中包含示例凭据

仓库中的示例配置和 SQL 数据带有本地开发用途的数据库连接信息、示例客户端信息和第三方登录配置。  
在公开部署或继续开发前，建议统一替换为你自己的安全配置。

### 5. 测试覆盖还不高

当前仓库中存在少量测试，主要集中在：

- 微信 OAuth 转换器相关测试
- 样例模块中的 JWT / 状态值测试

整体上仍以功能演示为主。

## 推荐阅读顺序

如果你准备继续开发这个项目，建议按下面顺序阅读代码：

1. `armorauth-core/src/main/java/com/armorauth/config/AuthorizationServerConfig.java`
2. `armorauth-core/src/main/java/com/armorauth/config/DefaultSecurityConfig.java`
3. `armorauth-core/src/main/java/com/armorauth/endpoint/`
4. `armorauth-core/src/main/java/com/armorauth/authorization/`
5. `armorauth-server/src/main/resources/application*.yml`
6. `armorauth-server/src/main/resources/sql/`
7. `armorauth-samples/`

## License

Apache License 2.0

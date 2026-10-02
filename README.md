# OpenAPI 契约兼容性审计 API

用 Python + FastAPI 实现的 OpenAPI 3.x 契约服务，提供十一个接口：

- **`POST /audit`**：提交**基线版**与**候选版**两份 OpenAPI 3.x JSON 文档，服务会解析本地 `$ref`（循环安全），并按以下策略判定候选版是否向后兼容：

  - **请求侧约束不得收紧**：删除操作、新增必填请求参数 / 请求体 / 必填字段、类型变更、枚举收窄等均为破坏性变更。
  - **响应侧约束不得放宽**：删除响应状态码 / 媒体类型 / 字段、字段不再必填、类型变更、枚举放宽等均为破坏性变更。

  报告按 **JSON Pointer 稳定排序**，每条结果包含 `pointer`、`category`、`severity`、`reason`；
  无法解析的引用会以 HTTP 422 返回明确错误。

- **`POST /slice`**：提交**一份** OpenAPI 3.x 文档与一组不重复的 `METHOD /path` 选择器，
  生成只包含所选操作的**最小子契约**，并返回键序稳定的子契约及其 **SHA-256** 摘要。

- **`POST /compose`**：提交 **2～20 份**各自带 `service_id` 与 `path_prefix` 的 OpenAPI 3.x 文档
  以及合成后的 `info`，生成一份**网关契约**及**来源映射**（provenance）：路径按规范化前缀挂载合并，
  组件名 / security 键 / `operationId` / tag 均以 `service_id` 为前缀命名空间化，
  指向 `components` 的本地 `$ref` 同步改写，根级 `security` 物化到未声明该字段的操作上。

- **`POST /examples/validate`**：提交**一份** OpenAPI 3.x 文档，按各媒体类型的 Schema 校验
  所有 `requestBody` 与响应 **JSON 媒体类型**（`application/json` 及 `*+json`）上的
  `example` 与 `examples.<name>.value`（含经本地 `$ref` 引用的 Example Object）。
  请求示例出现 `readOnly` 字段、响应示例出现 `writeOnly` 字段即报错，`required` 按方向生效
  （跨 `allOf` 分支、经本地 `$ref` 的 `readOnly` / `writeOnly` 标记同样豁免对应方向的必填检查），
  区分 3.0 `nullable` 与 3.1 类型联合；纯 Schema 违规返回 `200` + `valid=false`，
  `externalValue` / 外部或悬空引用返回 `422`。

- **`POST /overlay/apply`**：提交**一份** OpenAPI 3.x 文档与 **1～50 个有序动作**，
  每个动作用**受限 JSONPath**（`$`、点成员、方括号引号成员、数组下标、对象/数组通配符，
  不支持过滤器与递归下降）定位节点，然后 `update`（对象递归合并、其余整体替换）或
  `remove`（禁止删除根节点）。同一动作先冻结全部命中再应用，数组删除按索引倒序执行，
  后续动作基于前序结果继续匹配；任一目标零命中、语法错误或动作非法时整批返回 `422`
  （错误含动作索引，不返回半成品）。成功返回变换后的契约、逐动作实际命中的 JSON Pointer
  与规范 JSON 的 **SHA-256**，命中与报告稳定排序，且不修改请求对象。

- **`POST /requests/materialize`**：提交**一份** OpenAPI 3.x 文档、一个 `METHOD /path`
  操作选择器与按位置分组（`path` / `query` / `header` / `cookie`）的参数值，
  生成可直接发出的 HTTP 请求三件套：**`request_target`**（路径模板替换后拼接查询串）、
  **`headers`** 与 **Cookie 头值**。本地 `$ref`（含参数引用与 OpenAPI 3.1 path-level
  `$ref` 链）循环安全解析；path-level 与 operation-level 参数按 `(in, name)` 合并、
  后者覆盖前者。遵循各位置默认 `style` / `explode`，支持 path 的
  simple/label/matrix、query 的 form/spaceDelimited/pipeDelimited/deepObject、
  header simple 与 cookie form，处理数组、对象、`allowReserved`、重复查询键与
  百分号编码。缺少必填值、未知值、重复参数、值与样式不匹配或悬空 / 循环引用一律
  返回 422，并附来源 JSON Pointer；输出稳定且不修改请求对象。

- **`POST /callbacks/resolve`**：提交**一份** OpenAPI 3.x 文档、一个 `METHOD /path`
  操作选择器与**一次实际请求 / 响应上下文**（`context`：`request` 的 `url` / `method` /
  `path` / `query` / `header` / `body`，`response` 的 `statusCode` / `header` / `body`，
  各字段均可选），服务循环安全地解析所选操作 `callbacks` 中每个 Callback Object 的本地
  `$ref`（含 OpenAPI 3.1 `$ref` 同级字段），把回调键中的**字面文本**与 **`{...}`
  Runtime Expression** 求值拼成实际回调 URL，并保留该 URL 对应的 Path Item Object。
  支持 `$url`、`$method`、`$statusCode`、`$request.path/query/header/body` 与
  `$response.header/body`；body 片段按 **JSON Pointer**（RFC 6901）取值，header 名
  **大小写不敏感**匹配，插值值必须是**标量**。缺值、非法表达式、非标量插值以及
  悬空 / 外部 / 循环引用一律返回 **422**，逐条给出**回调与表达式的来源 JSON Pointer**；
  结果按来源稳定排序，且不修改输入文档与上下文。

- **`POST /security/plan`**：为**联调受保护操作**规划鉴权方式。提交**一份** OpenAPI 3.x
  文档、一个 `METHOD /path` 操作选择器与**可用凭证清单**（已具备的方案名与已授予 scope
  名字，**绝不接收任何秘密值**——token / 密码 / API Key 都不需要、也不会回显）。服务取
  操作的**有效 `security`**：操作级数组**整体覆盖**根级数组，数组各项之间是 **OR**（任一
  满足即可）、同一项内的多个方案是 **AND**（必须全部具备），显式 `security: []` 表示
  **匿名**。本地 Security Scheme `$ref` 链（含 OpenAPI 3.1 同级字段）循环安全解析，
  并按规范校验 **apiKey / http / oauth2 / openIdConnect** 定义（apiKey 的 `name`+`in`、
  http 的 `scheme`、oauth2 各 flow 的 URL 与 `scopes`、openIdConnect 的
  `openIdConnectUrl`）以及要求的 scope（apiKey/http 不得带 scope，oauth2 只能要求已由
  某个 flow 声明的 scope）。在所有**可满足项**中选择**所需方案数最少**的一项，同数时按
  方案要求对象的**规范 JSON 排序**（键名升序）决胜。返回所选项、每个凭证注入 **header /
  query / cookie 或 `Authorization`** 的位置与线格式说明，以及方案定义与 requirement 的
  **来源 JSON Pointer**。**没有任何可满足项仍返回 200**，逐项列出缺少的方案或 scope；
  悬空 / 外部 / 循环引用、未定义方案名与非法定义返回 **422**，错误均不包含秘密值。

- **`POST /links/plan`**：为 OpenAPI Link 描述的**后续调用**生成计划。提交**一份**
  OpenAPI 3.x 文档、源操作选择器（`METHOD /path`）、Link 名称与一次实际请求 / 响应
  上下文（`context.response.statusCode` 必提供）。服务按 **精确状态码 → `nXX` 类通配
  （大小写不敏感）→ `default`** 的顺序选出声明该 Link 的 Response；Response、Link 与
  目标 Path Item 的本地 `$ref` 均**循环安全**解析（OpenAPI 3.1 合并 `$ref` 同级字段、
  3.0 忽略同级）。目标必须由**本地 `operationRef`**（`#/...`，末段为 HTTP 方法）与
  **全局唯一 `operationId`** **二选一**指定。`parameters` 的键按**目标参数名**匹配
  （同一名字出现在多个位置即歧义 422）；`parameters` 与 `requestBody` 的映射值以 `$`
  开头时按**完整 Runtime Expression** 求值（与回调 URL 不同，body/path/query 结果
  **允许是对象或数组**），其余 JSON 值为字面常量。返回目标操作、按
  path/query/header/cookie 分组的参数值、请求体以及每个映射的**来源 JSON Pointer**。
  表达式缺值、目标 / 参数无效或未知、必填参数未赋值、外部 / 悬空 / 循环引用一律
  **422**；不产生半成品、不修改输入。

- **`POST /interactions/graph`**：把一份 OpenAPI 3.x 契约中**会触发后续 HTTP 调用的关系**
  整理成有向交互图，供联调检查。服务遍历 `paths` 下全部操作：每个契约操作与每个回调
  操作都建立**以 JSON Pointer 为标识的稳定节点**（回调 Path Item 经本地 `$ref` 引用
  组件时跟随到声明位置，多处引用共享一个节点）；每个响应的 Link（**本地
  `operationRef`**——含 `components/pathItems` 可复用 Path Item——或**全局唯一
  `operationId`** 二选一）与每个操作 `callbacks` 的 Callback Object / 回调 Path Item
  都解析成**有向边**，边携带**来源 JSON Pointer、响应键、回调 URL 模板与 HTTP 方法**。
  **3.0 忽略 `$ref` 同级字段，3.1 按近端覆盖合并**。悬空 / 外部 / 循环引用、重复
  `operationId`、目标无法唯一定位等问题**一次汇总**返回 **422**，**不返回半成品图**；
  节点与边按 Pointer **稳定排序**，同一目标被多条声明到达时各自保留来源边。

- **`POST /representations/select`**：为**联调时的 HTTP 内容协商**选表示。调用方提交一份
  OpenAPI 3.x 契约、一个 `METHOD /path` 选择器、**真实请求 `Content-Type`** 与
  **`Accept`** 头值以及**响应状态码**。服务循环安全地解析所选操作的 `requestBody` 与响应
  （响应按**精确状态码 → `nXX`（大小写不敏感）→ `default`** 选出；requestBody / Response
  的本地 `$ref` 在 3.1 下合并同级字段、3.0 下忽略同级），然后按 RFC 9110 分别选出**唯一的
  请求与响应表示**：请求侧按**媒体类型参数包含关系、通配符具体度、契约声明顺序**匹配具体
  Content-Type；响应侧由**最具体的可用 Accept 区间**（精确 type/subtype 胜过 `type/*` 胜过
  `*/*`，匹配参数越多越具体）给出 **q 权重**，最高 q 胜出、同权按声明顺序稳定裁决。返回所用
  **JSON Pointer、规范化媒体类型以及对应 schema / example / examples**（含经本地 `$ref`
  引用的 Example Object）。请求 Content-Type 无匹配返回 **415**，Accept 无匹配返回
  **406**，任一错误都**不返回半成品**且**不修改输入**。

## 一条命令启动

需要安装 Docker（含 Compose 插件）。在项目根目录执行：

```bash
docker compose up --build
```

启动后访问地址与端口：

| 用途 | 地址 |
| --- | --- |
| 健康检查 | http://localhost:8080/health |
| 审计接口 | `POST http://localhost:8080/audit` |
| 子契约切片接口 | `POST http://localhost:8080/slice` |
| 网关契约合成接口 | `POST http://localhost:8080/compose` |
| 示例校验接口 | `POST http://localhost:8080/examples/validate` |
| 覆盖动作接口 | `POST http://localhost:8080/overlay/apply` |
| 请求物化接口 | `POST http://localhost:8080/requests/materialize` |
| 回调解析接口 | `POST http://localhost:8080/callbacks/resolve` |
| 安全方案规划接口 | `POST http://localhost:8080/security/plan` |
| Link 后续调用计划接口 | `POST http://localhost:8080/links/plan` |
| 交互图接口 | `POST http://localhost:8080/interactions/graph` |
| 内容协商选表示接口 | `POST http://localhost:8080/representations/select` |
| 交互式 API 文档（Swagger UI） | http://localhost:8080/docs |
| OpenAPI 描述文档 | http://localhost:8080/openapi.json |

> 容器内监听 `8080`，由 Compose 映射到宿主机同名端口。如宿主机 8080 被占用，
> 修改 `docker-compose.yml` 中 `"8080:8080"` 的左侧端口即可，例如 `"9090:8080"`。

后台运行与停止：

```bash
docker compose up --build -d   # 后台启动
docker compose down            # 停止并移除容器
```

## 调用示例

```bash
curl -s -X POST http://localhost:8080/audit \
  -H 'Content-Type: application/json' \
  -d '{"baseline": <基线版 OpenAPI JSON>, "candidate": <候选版 OpenAPI JSON>}'
```

请求体：

```json
{
  "baseline": { "openapi": "3.0.3", "paths": { "...": {} } },
  "candidate": { "openapi": "3.0.3", "paths": { "...": {} } }
}
```

成功响应（`200`）：

```json
{
  "compatible": false,
  "breaking_count": 2,
  "info_count": 1,
  "findings": [
    {
      "pointer": "/components/schemas/NewPet",
      "category": "required-added",
      "severity": "breaking",
      "reason": "property 'tag' became required in the request"
    },
    {
      "pointer": "/paths/~1pets/get/parameters",
      "category": "parameter-required-added",
      "severity": "breaking",
      "reason": "query parameter 'limit' became required; previously requests could omit it"
    },
    {
      "pointer": "/paths/~1pets",
      "category": "operation-added",
      "severity": "info",
      "reason": "new operation PUT /pets (compatible)"
    }
  ]
}
```

- `severity = "breaking"`：违反兼容性策略（请求收紧 / 响应放宽）。
- `severity = "info"`：安全方向的变更（新增操作、新增可选参数、请求枚举放宽等），仅作提示。
- `findings` 按 `(pointer, category, reason)` 升序稳定排序。

错误响应：

- `400 invalid_openapi_document`：缺少 `openapi: 3.x` 版本字段或 `paths` 对象。
- `422 unresolvable_reference`：存在无法解析的 `$ref`，错误体逐条给出文档归属、引用串与原因：

```json
{
  "error": "unresolvable_reference",
  "message": "one or more $ref entries could not be resolved; fix the references before the contract can be audited",
  "references": [
    {
      "document": "baseline",
      "ref": "#/components/schemas/DoesNotExist",
      "error": "unresolvable reference '#/components/schemas/DoesNotExist': object has no property 'DoesNotExist'"
    }
  ]
}
```

## `POST /slice`：抽取最小操作子契约

给定一份 OpenAPI 3.x 文档和一组不重复的 `METHOD /path` 选择器，服务生成只描述这些操作的最小子契约：

- 根节点只保留 **`openapi`** 与 **`info`**；其余根字段（`servers`、`tags`、`webhooks` 等）不进入子契约。
- `paths` 下只保留所选路径；**同一路径只保留被选中的方法与 path-level 字段**
  （共享的 `parameters`、`servers`、`summary`、`description`、`x-` 扩展等），
  其他 HTTP 方法一律剔除，不会混入。OpenAPI 3.1 的 path-level `$ref`（可带同级字段）会被解析并内联。
- 操作未声明 `security` 时**继承根级 `security`**（继承结果物化到操作上；显式 `security: []` 表示不鉴权，保持不变），
  并且 `components/securitySchemes` 只保留实际被引用到的方案；一个都没用到时整个 `components` 可以不出现。
- 从所有保留节点递归计算**本地 `$ref` 闭包**（含 `parameters` / `requestBody` / `responses` / schema 等任意位置，
  含 OpenAPI 3.1 `$ref` 的同级字段），并按**原 JSON Pointer** 在子契约中重建依赖，
  因此所有保留的引用仍然可解析。
- **循环引用安全**：循环目标只复制一次，不无限展开（包括 `Pet.parent -> Pet` 形式与纯 `A -> B -> A` 引用链）。
- **只有从保留节点可达的引用会被校验**：可达的悬空指针或非本地引用（`http(s)://`、文件路径等）返回 `422`；
  未选操作 / 未使用组件中的坏引用与本次切片无关，不会阻塞。
- 输出子契约的**对象键序稳定**（统一按键名排序的紧凑 JSON），并给出其 **SHA-256**；
  输入对象的键顺序与选择器顺序都不会影响子契约内容或摘要，同一选择器集合始终得到同一摘要。

### 请求

```bash
curl -s -X POST http://localhost:8080/slice \
  -H 'Content-Type: application/json' \
  -d '{
    "document": { "openapi": "3.0.3", "info": {"title": "Pet API", "version": "1.0"}, "paths": {"...": {}} },
    "selectors": ["GET /pets", "POST /pets/{petId}"]
  }'
```

- `document`：一份 OpenAPI 3.x JSON 文档（对象）。
- `selectors`：**非空**字符串数组，每项形如 `METHOD /path`；方法大小写不敏感（统一按小写匹配/输出），
  路径必须以 `/` 开头并与文档中的路径键逐字一致（路径参数写作 `GET /pets/{petId}`）。

### 成功响应（`200`）

```json
{
  "contract": {
    "openapi": "3.0.3",
    "info": {"title": "Pet API", "version": "1.0"},
    "paths": {
      "/pets": {
        "get": {
          "responses": {"200": {"content": {"application/json": {"schema": {
            "$ref": "#/components/schemas/Pets"}}}, "description": "ok"}},
          "security": [{"oauth": ["pets:read"]}]
        }
      }
    },
    "components": {
      "schemas": {
        "Pet": {"properties": {"id": {"$ref": "#/components/schemas/Id"},
                 "parent": {"$ref": "#/components/schemas/Pet"}}, "type": "object"},
        "Id": {"type": "integer"},
        "Pets": {"items": {"$ref": "#/components/schemas/Pet"}, "type": "array"}
      },
      "securitySchemes": {"oauth": {"flows": {}, "type": "oauth2"}}
    }
  },
  "sha256": "9f8c9a…（64 位十六进制）"
}
```

- `sha256` 是 `contract` 的规范化 JSON 编码（键名升序、无多余空白、UTF-8）的 SHA-256 十六进制摘要。
- 响应中的 `contract` 本身也按稳定键序返回，可直接重新序列化后自行复算摘要进行校验。

### 错误响应

- `400 invalid_openapi_document`：`document` 缺少 `openapi: 3.x` 或 `paths` 对象。
- `400 invalid_selector`：选择器问题，`messages` 逐条给出原因（顺序稳定，不随入参顺序变化）：
  - 选择器不是非空数组，或单项不满足 `METHOD /path` 形态（如 `"GET/pets"`、`"garbage"`）；
  - **重复选择器**（`GET /pets` 与 `get /pets` 视为同一个）；
  - **未知操作**：路径未声明，或该路径上不存在该方法（path-level `$ref` 目标提供的方法同样认可）。
- `422 unresolvable_reference`：所选操作（或其闭包依赖）中存在无法解析的引用，`references` 逐条给出引用串与原因：

```json
{
  "error": "unresolvable_reference",
  "message": "a $ref reachable from the selected operations could not be resolved; fix the reference or remove the operation that uses it",
  "references": [
    {
      "ref": "#/components/schemas/Missing",
      "error": "unresolvable reference '#/components/schemas/Missing': object has no property 'Missing'"
    }
  ]
}
```

> 400 与 422 的边界：选择器重复 / 指向不存在的方法属于请求错误（400）；
> 选择的方法确实存在、但其保留节点引用了悬空或非本地目标属于契约引用错误（422）。
> 未被选中的操作和组件即使含坏引用也不会被访问，因而不影响切片结果。

## `POST /compose`：合成多服务网关契约

将 **2～20 份** OpenAPI 3.x 源文档各自挂载到指定的路径前缀下，合成一份网关契约，
并返回覆盖每个输出路径、操作与组件的**来源映射**（provenance）。

### 合成规则

- **路径前缀规范化**：自动补前导 `/`、去除末尾 `/`；`""` 与 `"/"` 均表示挂载到网关根路径。
  前缀中不允许出现空白符、`?`、`#`。规范化后的前缀拼接到该源的每条路径前。
- **路径合并与冲突**：不同源贡献到同一合成路径的不同方法会合并进同一个 path item
  （path-level `parameters` 取并集去重，其余 path-level 字段按请求顺序**先写优先**）；
  **同一合成路径 + 同一方法**（方法名大小写不敏感）来自两个源时返回 **409**，并列出冲突双方来源。
  冲突判定会**循环安全地逐层解析 OpenAPI 3.1 path-level `$ref` 链**（目标与同级字段合并、同级优先），
  因此经 `components/pathItems` 引用提供的方法与直接声明的方法同等参与判定；
  409 的 `conflicts.sources` 分别指向各源文档中该操作的 JSON Pointer
  （引用提供的方法指向链终点组件内的操作位置）。
  多个源在同一合成路径上都使用 path-level `$ref` 时，合成 path item **保留先到的引用**，
  其余引用链提供的有效方法（同样按引用目标与同级字段的覆盖关系计算）会作为**同级操作内联**
  进合成 path item（OpenAPI 3.1 中 `$ref` 同级字段优先于引用目标），
  因此所有非冲突方法都能从合成路径解析，且内联操作已完成 security 物化与命名空间前缀化。
- **security 物化**：各源的根级 `security` 会物化到该源每个未声明 `security` 的操作上
  （显式 `security: []` 保持不变）；合成契约不再携带根级 `security`。
- **命名空间前缀**：组件名（`components` 下各 section 的键）、security requirement 的键、
  `operationId`、tag（操作级 `tags` 与根级 `tags` 声明）统一加上 `<service_id>_` 前缀，
  因此跨服务同名组件不会冲突。`service_id` 只能包含字母、数字、`.`、`_`、`-`（须以字母或数字开头），
  以保证前缀化后的组件键仍是合法的 OpenAPI 组件名。
- **`$ref` 改写**：所有指向 `components` 的本地引用（`#/components/<section>/<name>[/...]`，
  支持指向组件内部的深层指针）同步改写为前缀化后的名字；OpenAPI 3.1 的 path-level `$ref`
  （指向 `components/pathItems`）同样改写并保持引用形态，目标组件内的操作照常物化 security、加前缀。
- **引用限制（422）**：外部引用（`http(s)://`、文件路径等）、指向 `components` 以外位置的本地引用
  （如 `#/paths/...`、`#`、`#/info`）、悬空引用均返回 **422**，错误体逐条给出
  `service_id`、源文档中的 **JSON Pointer**、引用串与原因；path-level `$ref` 的**循环引用链**
  （含超过 100 层的异常链）与无法解析为对象的 path item 引用同样按此格式拒绝。
  只校验进入合成契约的内容
  （`paths` / `components` / `tags`）：被丢弃的根字段（`servers`、`webhooks`、`externalDocs`、
  `x-` 扩展等）中的坏引用不会阻塞合成。
- **其余根字段**：`openapi` 取各源最高版本；`info` 使用请求中给定的合成版本；
  根级 `tags` 合并（按前缀化后的名字去重，先写优先）。
- **错误优先级**：请求错误（400）→ 引用错误（422）→ 操作冲突（409）。

### 请求

```bash
curl -s -X POST http://localhost:8080/compose \
  -H 'Content-Type: application/json' \
  -d '{
    "info": {"title": "Gateway", "version": "1.0"},
    "services": [
      {"service_id": "pets", "path_prefix": "/pets", "document": { "openapi": "3.0.3", "...": "..." }},
      {"service_id": "store", "path_prefix": "/store", "document": { "openapi": "3.1.0", "...": "..." }}
    ]
  }'
```

- `info`：合成契约的 info 对象（原样使用）。
- `services`：**2～20** 个源服务，每项含 `service_id`（唯一）、`path_prefix`、`document`（OpenAPI 3.x 文档）。

### 成功响应（`200`）

```json
{
  "contract": {
    "openapi": "3.1.0",
    "info": {"title": "Gateway", "version": "1.0"},
    "tags": [{"name": "pets_animals", "description": "Animal operations"}],
    "paths": {
      "/pets/animals": {
        "get": {
          "operationId": "pets_listAnimals",
          "tags": ["pets_animals"],
          "security": [{"pets_oauth": ["animals:read"]}],
          "responses": {"200": {"content": {"application/json": {"schema": {
            "$ref": "#/components/schemas/pets_Animal"}}}, "description": "ok"}}
        }
      },
      "/store/items": {"get": {"operationId": "store_listItems", "responses": {"...": "..."}}}
    },
    "components": {
      "schemas": {"pets_Animal": {"...": "..."}, "store_Item": {"...": "..."}},
      "securitySchemes": {"pets_oauth": {"flows": {}, "type": "oauth2"}}
    }
  },
  "provenance": {
    "paths": {
      "/pets/animals": [
        {"service_id": "pets", "source_path": "/animals", "source_pointer": "/paths/~1animals"}
      ]
    },
    "operations": {
      "/pets/animals": {
        "get": {"service_id": "pets", "source_path": "/animals",
                "source_pointer": "/paths/~1animals/get"}
      }
    },
    "components": {
      "schemas": {
        "pets_Animal": {"service_id": "pets", "source_pointer": "/components/schemas/Animal"}
      }
    }
  }
}
```

- `provenance.paths`：每个合成路径 → 贡献它的源服务列表（含源路径与源 JSON Pointer）。
- `provenance.operations`：每个合成路径的每个方法 → 源操作位置。
- `provenance.components`：每个组件 section 的每个前缀化名字 → 源组件位置。

### 错误响应

- `400 invalid_compose_request`：服务数量不在 2～20、`service_id` 缺失 / 重复 / 含非法字符、
  `path_prefix` 含空白或 `?`/`#`、文档不是 OpenAPI 3.x、路径键未以 `/` 开头等；`messages` 逐条给出原因。
- `409 operation_conflict`：两个源声明了同一合成路径的同一方法；`conflicts` 逐条给出
  `path`、`method` 与冲突**双方**的来源（`service_id` + 源 JSON Pointer）：

```json
{
  "error": "operation_conflict",
  "message": "multiple services declare the same composed path and HTTP method; ...",
  "conflicts": [
    {
      "path": "/pets/animals",
      "method": "get",
      "sources": [
        {"service_id": "alpha", "source_path": "/animals", "source_pointer": "/paths/~1animals/get"},
        {"service_id": "beta", "source_path": "/animals", "source_pointer": "/paths/~1animals/get"}
      ]
    }
  ]
}
```

- `422 unsupported_reference`：保留内容中存在外部引用、指向 `components` 以外的引用或悬空引用；
  `references` 逐条给出 `service_id`、源文档中的 JSON Pointer、引用串与原因：

```json
{
  "error": "unsupported_reference",
  "message": "one or more retained $ref entries are external, unresolvable, or point outside components; ...",
  "references": [
    {
      "service_id": "pets",
      "pointer": "/paths/~1animals/get/responses/200/content/application~1json/schema",
      "ref": "https://example.com/schemas.json#/Animal",
      "error": "unsupported non-local reference 'https://example.com/schemas.json#/Animal': ..."
    }
  ]
}
```

> 与 `/audit`、`/slice` 一致：保留内容中任何位置的 `"$ref"` 字符串（包括示例值内部）都按引用处理。
> 混合 3.0 / 3.1 源时合成契约取最高版本，但 schema 方言差异（如 `nullable`）由调用方自行保证兼容。

## `POST /examples/validate`：校验请求 / 响应示例

给定**一份** OpenAPI 3.x 文档，服务遍历每个操作的 `requestBody` 与各响应，
对其中 **JSON 媒体类型**（精确匹配 `application/json`，或任意 `*+json` 结构媒体类型；
`text/plain`、`application/octet-stream` 等不检查）携带的示例逐一按该媒体类型的 `schema` 校验：

- Media Type Object 上的内联 `example`；
- `examples` 映射中的每个 Example Object，包括经本地 `$ref`
  （`#/components/examples/...`、`#/components/requestBodies/...`、
  `#/components/responses/...`、3.1 `components/pathItems/...`）解析到的对象；
  校验所用的 **Schema `$ref` 同样解析**（含递归 Schema，循环安全）。

### 方向性语义（OpenAPI 规范）

- **请求**示例中出现 Schema 标记为 `readOnly: true` 的属性 → 报错（`keyword: "readOnly"`）；
  **响应**示例中出现 `writeOnly: true` 的属性 → 报错（`keyword: "writeOnly"`）。
- `required` **只在对应方向生效**：`readOnly` 属性即使列入 `required`，也只要求响应必带
  （请求示例缺失不报错）；`writeOnly` 属性相反，只要求请求必带。
- **跨 `allOf` 分支的方向标记同样生效**：校验前会循环安全地汇总同一 `allOf` 对象各分支
  （含分支自身或属性经本地 `$ref` 到达、以及嵌套 `allOf`）的有效 `properties` 注解——
  一支声明 `required: [id]`、另一支把 `id` 标为 `readOnly: true` 时，请求示例省略 `id`
  合法；响应侧跨分支的 `writeOnly` 同理豁免。汇总只用于方向性 `required` 豁免，
  各分支的其他约束（`type`、`minProperties` 等）仍分别强制执行，`anyOf` / `oneOf`
  备选分支之间不共享这一视图。
- **类型可空性按版本区分**：OpenAPI 3.0 用 `nullable: true` 放行 `null`；
  OpenAPI 3.1（JSON Schema 2020-12 方言）用类型联合 `"type": ["string", "null"]`，
  此时 `nullable` 关键字被忽略。`integer` 是 `number` 的子集；无小数部分的数字也满足 `integer`。

### 支持的 Schema 关键字

`type` / `enum` / `const` / `required` / `properties` / `additionalProperties` /
`minProperties` / `maxProperties` / `items`（含 3.1 位置元组形态）/ `minItems` / `maxItems` /
`uniqueItems` / `minLength` / `maxLength` / `pattern` / `minimum` / `maximum` /
`exclusiveMinimum` / `exclusiveMaximum`（3.0 布尔修饰符与 3.1 数值边界两种写法均支持）/
`multipleOf` / `allOf` / `anyOf` / `oneOf`，以及布尔 Schema（3.1）。`$ref` 可出现在任意位置。

### 请求

```bash
curl -s -X POST http://localhost:8080/examples/validate \
  -H 'Content-Type: application/json' \
  -d '{"document": { "openapi": "3.0.3", "info": {"title": "Pet API", "version": "1.0"}, "paths": {"...": {}} }}'
```

### 成功响应（`200`，即使校验失败也是 200）

```json
{
  "valid": false,
  "error_count": 2,
  "errors": [
    {
      "side": "request",
      "example_pointer": "/paths/~1pets/post/requestBody/content/application~1json/example",
      "instance_pointer": "/created",
      "schema_pointer": "/components/schemas/Pet/properties/created",
      "keyword": "readOnly",
      "reason": "readOnly property 'created' must not appear in a request example"
    },
    {
      "side": "response",
      "example_pointer": "/paths/~1pets/post/responses/200/content/application~1json/examples/byId/value",
      "instance_pointer": "/id",
      "schema_pointer": "/components/schemas/Pet/properties/id",
      "keyword": "type",
      "reason": "expected type integer, got string"
    }
  ]
}
```

字段说明：

- `side`：示例方向，`request`（来自 `requestBody`）或 `response`（来自响应）。
- `example_pointer`：示例值在文档中的 JSON Pointer。经 `$ref` 引用的 Example Object
  会**跟随到组件定义位置**（如 `/components/examples/byId/value`），与 `/audit` 的 Pointer 约定一致；
  同一组件示例被多处复用时，相同违规只报告一次。
- `instance_pointer`：违规值在示例 JSON 内部的 JSON Pointer（根示例为 `""`，深层如 `/tags/0/name`）。
- `schema_pointer`：被违反的 Schema 位置（本地 `$ref` 跟随到组件定义）。
- `keyword` / `reason`：违反的 Schema 关键字与人类可读原因。
- `errors` 按 **`(example_pointer, instance_pointer, schema_pointer, keyword, reason)` 升序稳定排序**，
  与输入键序无关。

### 错误响应

- `400 invalid_openapi_document`：`document` 缺少 `openapi: 3.x` 或 `paths` 对象。
- `422 unsupported_reference`：示例使用了 `externalValue`（服务不会发起外部网络请求），
  或示例 / Schema 中出现外部 `$ref`（`http(s)://`、文件路径等）。
- `422 unresolvable_reference`：校验过程中可达的本地 `$ref` 悬空（包括示例组件间的纯 `$ref` 循环链）。
- `422 invalid_example`：示例 `$ref` 目标不是 Example Object。

422 响应体的 `references` 逐条给出**来源 JSON Pointer**（引用所在位置）、引用串与原因：

```json
{
  "error": "unresolvable_reference",
  "message": "one or more $ref entries reached while validating examples could not be resolved; fix the references first",
  "references": [
    {
      "pointer": "/paths/~1pets/get/responses/200/content/application~1json/schema",
      "ref": "#/components/schemas/Missing",
      "error": "unresolvable reference '#/components/schemas/Missing': object has no property 'Missing'"
    }
  ]
}
```

> 只有从被检查示例可达的引用才会触发 422；未被任何示例使用的组件里即使有坏引用也不影响结果。
> 媒体类型未声明 `schema` 时，示例不受任何约束（但 `externalValue` / 坏引用仍按上述规则返回 422）。
> Example Object 既无 `value` 也无 `externalValue` 时无可校验内容，跳过不报。

## `POST /overlay/apply`：对契约应用有序覆盖动作

给定**一份** OpenAPI 3.x 文档和 **1～50 个有序动作**，服务按顺序把每个动作应用到文档上，
返回变换后的契约、逐动作实际命中的 JSON Pointer 以及规范 JSON 的 SHA-256。
整个批次是**原子**的：任何一个动作非法、目标语法错误或零命中，整批以 `422` 拒绝，
不返回半成品，也绝不修改请求中的文档对象。

### 动作格式

每个动作是一个 JSON 对象，只能包含 `target`、`update`、`remove` 三个键：

- `target`（必填，非空字符串）：受限 JSONPath（见下）。
- `update`：任意 JSON 值。与 `remove` **二者必选其一**，不能同时出现或同时缺失。
- `remove`：必须为 `true`（`false`、其他值或与其他键组合均为非法动作）。

```json
{"target": "$.info", "update": {"contact": {"name": "team"}}}
{"target": "$.paths['/internal']", "remove": true}
```

### 受限 JSONPath 目标语法

只支持以下五种段（segment），**不允许任何空白符**：

| 语法 | 含义 |
| --- | --- |
| `$` | 文档根节点 |
| `.name` | 对象成员，名字限 `[A-Za-z0-9_]+`（如 `$.paths`、`$.responses.200`） |
| `['name']` / `["name"]` | 任意成员名（可含 `/`、`-`、空格等），支持反斜杠转义（`\\`、`\'`、`\"`、`\/`、`\b`、`\f`、`\n`、`\r`、`\t`、`\uXXXX`） |
| `[0]` | 数组下标（非负整数，不允许负下标与前导零） |
| `.*` / `[*]` | 通配符：对象的全部成员值或数组的全部元素（对标量不命中） |

**不支持**过滤器（`$[?(...)]`）与递归下降（`$..name`），出现即按语法错误拒绝（422）。
成员段作用于非对象、下标段作用于非数组、通配符作用于标量时均不命中。

### 应用语义

- **`update`**：目标值与更新值**都是对象**时**递归合并**（逐成员深入，子对象继续合并）；
  其余组合一律**整体替换**目标值（数组不逐元素合并，而是整体替换；`update: null` 会把目标置为 `null`）。
  同一动作的更新值对每个命中节点分别深拷贝应用，命中之间互不影响。
- **`remove`**：删除全部命中节点；**禁止删除根节点** `$`（非法动作，422）。
- **冻结与顺序**：同一动作先对当前文档状态**冻结全部命中**，再统一应用；
  数组元素的删除按**索引倒序**执行，避免前面的删除改变后面待删元素的位置。
  后续动作基于前序动作的结果继续匹配（例如先 `remove` 一个数组元素，后续动作看到的下标已前移）。
- **零命中**：任一动作的目标匹配到 0 个节点（成员不存在、下标越界、通配符作用于标量等），
  整批返回 `422 no_match`。

### 请求

```bash
curl -s -X POST http://localhost:8080/overlay/apply \
  -H 'Content-Type: application/json' \
  -d '{
    "document": { "openapi": "3.0.3", "info": {"title": "Pet API", "version": "1.0"},
                  "paths": {"/pets": {"get": {"responses": {"200": {"description": "ok"}}}}},
                  "servers": [{"url": "https://old.example.com"}] },
    "actions": [
      {"target": "$.servers[0]", "update": {"url": "https://api.example.com"}},
      {"target": "$.paths.*.get.responses.200", "update": {"content": {"application/json": {}}}}
    ]
  }'
```

- `document`：一份 OpenAPI 3.x JSON 文档（对象）。
- `actions`：**1～50** 个动作对象，按数组顺序依次应用。

### 成功响应（`200`）

```json
{
  "contract": { "openapi": "3.0.3", "info": {"...": "..."}, "paths": {"...": "..."} },
  "actions": [
    {"action_index": 0, "op": "update", "target": "$.servers[0]", "matches": ["/servers/0"]},
    {"action_index": 1, "op": "update", "target": "$.paths.*.get.responses.200",
     "matches": ["/paths/~1pets/get/responses/200"]}
  ],
  "sha256": "…（64 位十六进制）"
}
```

- `contract`：变换后的文档，按稳定键序（键名升序）返回。
- `actions`：逐动作报告，按请求中的动作顺序排列；`matches` 是该动作**实际命中**的
  JSON Pointer（RFC 6901 转义，如 `/paths/~1pets`），按 Pointer 字符串升序稳定排序。
- `sha256`：`contract` 的规范化 JSON 编码（键名升序、无多余空白、UTF-8）的 SHA-256；
  响应中的 `contract` 本身即稳定键序，可直接重新序列化复算摘要校验。

### 错误响应

- `400 invalid_openapi_document`：`document` 缺少 `openapi: 3.x` 或 `paths` 对象。
- `400 invalid_overlay_request`：动作数量不在 1～50 范围内。
- `422 invalid_action`：动作非法或目标语法错误，`actions` 逐条给出
  `action_index`（动作下标，从 0 开始）、`target`（如可得）与原因，**全部非法动作一次报齐**：

```json
{
  "error": "invalid_action",
  "message": "one or more overlay actions are malformed or carry an invalid target; the whole batch was rejected and the document was left untouched",
  "actions": [
    {"action_index": 1, "target": "$..info",
     "error": "invalid target '$..info': expected a member name or '*' after '.' (position 2)"},
    {"action_index": 3, "target": "$",
     "error": "the root node '$' cannot be removed"}
  ]
}
```

  非法情形包括：动作不是对象、含未知字段、`target` 缺失或非字符串、`update` 与 `remove`
  同时出现或同时缺失、`remove` 不是 `true`、删除根节点 `$`、目标语法错误
  （过滤器、递归下降、负下标、前导零、未闭合的括号/引号、多余空白等）。
- `422 no_match`：某动作目标零命中（按动作顺序报告第一个），`actions` 给出其
  `action_index` 与 `target`：

```json
{
  "error": "no_match",
  "message": "an action target matched zero nodes; the whole batch was rejected and the document was left untouched",
  "actions": [
    {"action_index": 2, "target": "$.paths['/missing']",
     "error": "target '$.paths['/missing']' matched 0 nodes"}
  ]
}
```

> 所有 422 都是整批拒绝：响应不含 `contract`，请求中的文档对象也不会被改动。
> `actions` 不是数组时由 FastAPI 以默认 422 格式返回。

## `POST /requests/materialize`：物化操作的请求目标、headers 与 Cookie

给定**一份** OpenAPI 3.x 文档、一个操作选择器与一组参数值，服务解析该操作的有效参数
（循环安全），按 OpenAPI 3 参数序列化规则生成实际 HTTP 请求的三个部分：

- **`request_target`**：origin-form 请求目标——路径模板中的 `{name}` 被替换为序列化后的
  path 参数，存在 query 参数时再拼接 `?` 与查询串；
- **`headers`**：每个 `in: header` 参数一个键值对（键为契约中声明的头名，值为序列化结果）；
- **`cookie`**：由全部 `in: cookie` 参数组成的 `Cookie` 头值（`name=value` 以 `; ` 连接）；
  Cookie 不会重复出现在 `headers` 中。

### 参数合并与引用解析

- **path-level 与 operation-level 合并**：先按文档顺序排列 path-level 参数，再追加仅在
  operation-level 声明的参数；operation-level 参数与 path-level 参数具有相同
  **`(in, name)`** 时**整体覆盖**前者（OpenAPI 3 规范）。
- **同级重复参数**（同一 parameters 数组中两个相同 `(in, name)`，或两个仅大小写不同的
  header 参数）为 422，错误同时给出两处来源 Pointer。
- 参数与 path item 上的本地 `$ref` 均被解析：参数 `$ref` 跟随到组件定义，报错时
  定义类问题（缺值、样式不合法等）指向**组件位置**、引用类问题（悬空、循环）指向
  **`$ref` 所在位置**。OpenAPI 3.1 下 `$ref` 的同级字段逐层合并（近者优先）；
  3.0 文档严格遵循旧规范、忽略同级字段。path-level `$ref` 链（含 3.1
  `components/pathItems`）同样循环安全，超深链按上限拒绝。

### 默认样式与支持矩阵

未声明 `style` / `explode` 时采用各位置默认值：

| 位置 | 支持的 style | 默认 style | 默认 explode |
| --- | --- | --- | --- |
| path | `simple` / `label` / `matrix` | `simple` | `false` |
| query | `form` / `spaceDelimited` / `pipeDelimited` / `deepObject` | `form` | `true` |
| header | `simple` | `simple` | `false` |
| cookie | `form` | `form` | （cookie 表忽略 explode） |

序列化与 OpenAPI 3.0.3 规范示例表一致，例如：

- path `simple`：标量 `id`；数组 `a,b,c`；对象 explode 为 `k=v,k2=v2`、非 explode 为
  `k,v,k2,v2`。`label` 带 `.` 前缀（数组 explode 用 `.` 连接）；`matrix` 为
  `;id=...`（数组 explode 重复 `;id=`，对象 explode 直接用属性名）。
- query `form`：数组 explode 产生**重复查询键** `id=a&id=b`，非 explode 为 `id=a,b`；
  对象 explode 用属性名作为查询键。`spaceDelimited` / `pipeDelimited` 仅接受数组
  （非 explode 分别用 `%20`、`|` 连接；explode 仍重复查询键）。`deepObject` 仅接受对象，
  输出 `id[role]=admin`，并始终是 exploded 形态。
- query 的 **`allowReserved: true`** 允许 RFC 3986 保留字符（`:/?#[]@!$&'()*+,;=`）
  原样出现在值中；默认情况下所有非 unreserved 字节都按 UTF-8 **百分号编码**
  （空格为 `%20`、`€` 为 `%E2%82%AC`）。序列化结构分隔符（`&`、`=`、`,`、`|`、`%20`、
  方括号）本身保持原样。
- header `simple` 不做百分号编码（逗号 / 等号为结构分隔符）；值中含 CR / LF / NUL
  时返回 422；请求里的头名按**大小写不敏感**匹配，输出使用契约声明的名字。
- cookie `form` 按 cookie 表序列化：数组 `a,b`、对象 `k,v,k2,v2`（explode 被忽略），
  各 token 按 unreserved 集合百分号编码，多个 cookie 以 `; ` 连接。
- 布尔值渲染为 `true` / `false`；数字按 JSON 数值文本渲染；数组元素与对象属性值必须是
  标量（字符串 / 数字 / 布尔），嵌套数组、对象或 `null` 元素返回 422。对象成员按
  **键名升序**输出，因此结果与输入键序无关。

### 请求

```bash
curl -s -X POST http://localhost:8080/requests/materialize \
  -H 'Content-Type: application/json' \
  -d '{
    "document": { "openapi": "3.0.3", "info": {"title": "Pet API", "version": "1.0"},
                  "paths": {"/pets/{petId}": {"...": "..."}} },
    "selector": "GET /pets/{petId}",
    "values": {
      "path":   {"petId": "cat/42"},
      "query":  {"tags": ["cute", "small"], "filter": {"status": "available"}},
      "header": {"X-Tenant": "demo"},
      "cookie": {"session": "abc"}
    }
  }'
```

- `document`：一份 OpenAPI 3.x JSON 文档（对象）。
- `selector`：形如 `METHOD /path` 的单个选择器（方法大小写不敏感，路径须逐字匹配）。
- `values`（可省略）：按位置分组的参数值；header 名大小写不敏感匹配。
  显式传 `null` 等同未提供该值——必填参数因此报错，可选参数则从请求中省略。

### 成功响应（`200`）

```json
{
  "request_target": "/pets/cat%2F42?tags=cute&tags=small&status=available",
  "headers": {"X-Tenant": "demo"},
  "cookie": "session=abc"
}
```

> 上例中 `filter` 是默认 form+explode 的对象，属性名直接成为查询键（`status=available`）；
> 若契约声明 `style: deepObject`，对应片段为 `filter[status]=available`（方括号保持原样）。
> 重复查询键按参数声明顺序排列；query 参数整体也按声明顺序输出。

### 错误响应

- `400 invalid_openapi_document`：`document` 缺少 `openapi: 3.x` 或 `paths` 对象。
- `400 invalid_selector`：选择器不是 `METHOD /path` 形态，或路径 / 方法不存在。
- `400 invalid_materialize_request`：`values` 不是对象、含未知分组（只允许
  `path` / `query` / `header` / `cookie`）或某个分组不是对象。
- `422 materialization_failed`：所有语义问题一次报齐，`errors` 按
  `(code, in, name, pointer, error)` 稳定排序，每条至少带一个**来源 JSON Pointer**：

| code | 触发情形 | 典型 pointer |
| --- | --- | --- |
| `missing_required_value` | 必填参数（path 参数恒必填）未提供值（含显式 `null`） | 参数定义位置（`$ref` 跟随到组件） |
| `unknown_value` | 为操作未声明的参数提供了值 | `/values/<in>/<name>` |
| `ambiguous_value` | header 分组里出现仅大小写不同的两个键 | `/values/header/<name>` |
| `duplicate_parameter` | 同级参数数组重复 `(in, name)`，或 header 参数仅大小写冲突 | 后一处定义位置，附 `first_pointer` |
| `invalid_value_shape` | 值与样式不匹配（deepObject 非对象、space/pipe 非数组、标量样式收到结构值等） | `/values/<in>/<name>` |
| `unsupported_style` | 样式不属于该位置的支持矩阵 | 参数的 `/style` 位置 |
| `unsupported_parameter` | 参数使用 `content` 媒体类型对象（不支持物化） | 参数定义位置 |
| `invalid_parameter` | 缺少字符串 `name`、`in` 非法、参数 / path item 不是对象、头名不是合法 token 等 | 问题节点位置 |
| `invalid_path_template` | 模板变量没有对应参数、path 参数未在模板中使用、模板花括号非法 | path item 或参数位置 |
| `unresolvable_reference` | 参数 / path item 的本地 `$ref` 悬空、非本地或循环 | `$ref` 所在位置，附 `ref` |

```json
{
  "error": "materialization_failed",
  "message": "the request could not be materialized; fix the reported parameters, values or references first",
  "errors": [
    {
      "code": "missing_required_value",
      "pointer": "/paths/~1pets~1{petId}/get/parameters/0",
      "in": "path",
      "name": "petId",
      "error": "missing value for required path parameter 'petId'"
    },
    {
      "code": "unresolvable_reference",
      "pointer": "/paths/~1pets/get/parameters/2",
      "ref": "#/components/parameters/Missing",
      "error": "unresolvable reference '#/components/parameters/Missing': object has no property 'Missing'"
    }
  ]
}
```

> 与其他接口一致：物化过程**不会修改**请求中的 `document` / `values` 对象；
> 对象类型的值按键名升序序列化、数组按声明顺序序列化，同样的契约与值无论输入键序如何，
> 始终得到字节相同的 `request_target` / `headers` / `cookie`。

## `POST /callbacks/resolve`：解析操作声明的异步回调 URL

用于**调试契约声明的异步回调**：给定一份 OpenAPI 3.x 文档、一个操作选择器和一次实际
请求 / 响应上下文，服务定位所选操作的 `callbacks`，逐个解析 Callback Object（循环安全），
把每个回调键求值为具体 URL，并连同该键声明的 **Path Item Object** 一起返回。

### 回调键（Runtime Expression）求值规则

Callback Object 的每个键要么是**固定 URL 字面量**（如 `https://hooks.example.com/ping`），
要么按 OpenAPI 3 Runtime Expression 求值：

- **完整表达式单独成键**：键整体是一个合法表达式，例如 `$url`、`$request.body#/callbackUrl`。
- **模板内嵌表达式**：键内出现一个或多个 `{...}` 片段，花括号内是完整表达式，
  其余文字逐字保留，例如 `https://hooks.example.com/{$request.path.txId}?status={$statusCode}`。
- 支持的表达式：
  - `$url`、`$method`：本次请求的 URL 与 HTTP 方法；
  - `$statusCode`：响应状态码（数字按 JSON 数值文本渲染）；
  - `$request.path.<name>` / `$request.query.<name>`：请求路径 / 查询参数；`<name>`
    遵循规范的 `name` 产生式，支持 `%HH` 百分号转义（求值前解码后再匹配上下文键）；
  - `$request.header.<token>` / `$response.header.<token>`：请求 / 响应 header，
    `<token>` 为 RFC 7230 tchar；匹配**大小写不敏感**（表达式用 `x-trace` 也能命中
    上下文里的 `X-Trace`）；上下文里若有仅大小写不同的两个同名 header，返回 422；
  - `$request.body` / `$response.body`：整个消息体（必须为标量才能插值）；
  - `$request.body#<JSON Pointer>` / `$response.body#<JSON Pointer>`：按 RFC 6901
    JSON Pointer 在 body 中取值（如 `#/items/0/href`、`#/nested/deep/url`；
    `~0`/`~1` 转义、数组下标规则与标准一致）。
- 插值值必须是**标量**（字符串 / 数字 / 布尔）：取到对象、数组（或整体 body 为结构值）
  一律 422；取到 `null`、路径不可达、对应 message（request/response）或字段未提供，
  均视为**缺值** 422。
- 非法表达式（未知根 / 源，如 `$foo`、`$response.path.x`、`{txId}` 裸变量、空 `{}`、
  未闭合或嵌套花括号、非法 JSON Pointer 转义、非法 `%HH`、尾部杂散字符等）返回 422。
  不含花括号、整体又不是合法完整表达式的键按**固定字面量**处理（如 `$url/x` 不会报错）。

### Callback Object 与 Path Item 的 `$ref` 解析

- 操作 `callbacks/<name>` 条目本身可以是本地 `$ref`（指向 `#/components/callbacks/...`
  等），表达式键对应的 **Path Item Object 也可以是本地 `$ref`**；两条链都**循环安全**
  （记录已访问指针，成环即 422，另有 100 层链长上限）。
- **OpenAPI 3.1**：`$ref` 的同级字段逐层合并（近者优先），同级键可覆盖 / 扩展引用目标
  中的同名表达式键；**OpenAPI 3.0**：严格遵循旧规范，`$ref` 同级字段被忽略，以链终点
  对象为准。
- 仅本地引用 `#/...` 受支持：外部引用（`http(s)://`、文件路径等）、悬空指针、引用目标
  非对象均返回 422。Path Item 内部更深层的 `$ref`（如 `requestBody: $ref`）不展开，
  随 Path Item 原样深拷贝返回，因此正常的递归 schema 不会被误判为循环。
- 操作所在的 path-level `$ref`（OpenAPI 3.1 `components/pathItems`）同样循环安全解析后
  再定位操作。

### 来源 JSON Pointer

- `callback_pointer`：回调条目（`callbacks/<name>`）位置；引用型条目指向 **`$ref` 出现处**。
- `expression_pointer`：表达式键在**有效 Callback Object** 中的位置；引用型回调会跟随到
  组件内的键声明（如 `/components/callbacks/OnEvent/$url`），被 3.1 同级字段覆盖的键
  则指向覆盖处。路径键按 RFC 6901 转义（`/` → `~1`、`~` → `~0`）。
- 422 错误中的 `pointer` 为主要修复位置（表达式错误指向表达式键，引用错误指向 `$ref`
  出现处），并同时附带 `callback_pointer`、`expression_pointer`、原始 `expression`、
  `ref` 与上下文中的 `context_pointer`。

### 请求

```bash
curl -s -X POST http://localhost:8080/callbacks/resolve \
  -H 'Content-Type: application/json' \
  -d '{
    "document": { "openapi": "3.0.3", "info": {"title": "Hook API", "version": "1.0"},
                  "paths": {"/subscribe": {"post": {"callbacks": {"...": "..."}}}} },
    "selector": "POST /subscribe",
    "context": {
      "request": {
        "url": "https://api.example.com/subscribe", "method": "POST",
        "path": {"txId": "abc-123"}, "query": {"limit": "50"},
        "header": {"X-Trace": "t-9"},
        "body": {"callbackUrl": "https://my.host/hook"}
      },
      "response": {"statusCode": 202, "header": {"X-Request-Id": "r1"}}
    }
  }'
```

- `document`：一份 OpenAPI 3.x JSON 文档（对象）。
- `selector`：形如 `METHOD /path` 的单个选择器（方法大小写不敏感，路径须逐字匹配）。
- `context`（可省略，默认为空对象）：请求 / 响应上下文。`request` 与 `response` 及其
  各字段均可选；`path` / `query` / `header` 为对象，header 值必须是标量字符串，
  `statusCode` 为整数或字符串，`body` 为任意 JSON。

### 成功响应（`200`）

```json
[
  {
    "name": "onEvent",
    "callback_pointer": "/paths/~1subscribe/post/callbacks/onEvent",
    "expression": "https://hooks.example.com/{$request.path.txId}?status={$statusCode}",
    "expression_pointer": "/paths/~1subscribe/post/callbacks/onEvent/https:~1~1hooks.example.com~1{$request.path.txId}?status={$statusCode}",
    "url": "https://hooks.example.com/abc-123?status=202",
    "path_item": {"post": {"responses": {"2XX": {"description": "ack"}}}}
  }
]
```

- 结果数组按 **`(callback_pointer, expression_pointer)` 升序稳定排序**，与回调键的
  JSON 输入顺序无关。
- 操作没有 `callbacks` 时返回空数组 `[]`。
- 每个结果的 `path_item` 是该 URL 对应 Path Item Object 的深拷贝（自身 `$ref` 链已解析、
  3.1 同级已合并；其内部 `$ref` 保持原样），供调试时查看回调请求的方法、请求体与响应。

### 错误响应

- `400 invalid_openapi_document`：`document` 缺少 `openapi: 3.x` 或 `paths` 对象。
- `400 invalid_selector`：选择器不是 `METHOD /path` 形态，或路径 / 方法不存在。
- `400 invalid_callback_request`：`context` 信封非法（未知 section / 字段、
  容器不是对象、`url` / `method` 非字符串、`statusCode` 非整数或字符串、
  header 值非标量等），`messages` 逐条给出原因。
- `422 callback_resolution_failed`：所有语义问题一次报齐并稳定排序，`errors` 每条至少带
  `code`、`pointer`、`error`，并附回调 / 表达式来源 Pointer：

| code | 触发情形 | pointer 指向 |
| --- | --- | --- |
| `missing_value` | 表达式取到 `null`、JSON Pointer 不可达，或对应 request/response/字段未提供 | 表达式键（另附 `context_pointer`） |
| `invalid_expression` | 表达式语法非法（未知源、空 / 嵌套 / 未闭合花括号、非法指针转义等） | 表达式键 |
| `non_scalar_interpolation` | 取到对象或数组，无法插入 URL | 表达式键（另附 `context_pointer`） |
| `ambiguous_header` | header 名大小写不敏感匹配到多个仅大小写不同的上下文键 | 表达式键 |
| `unresolvable_reference` | 回调 / Path Item 的本地 `$ref` 悬空、非本地、目标非对象或循环 | `$ref` 出现处（另附 `ref`） |
| `invalid_callback` | 回调值不是 Callback Object、表达式值不是 Path Item Object、`callbacks` 不是对象等 | 问题节点 |

```json
{
  "error": "callback_resolution_failed",
  "message": "one or more callback URLs could not be resolved; fix the reported expressions, context values or references first",
  "errors": [
    {
      "code": "missing_value",
      "pointer": "/paths/~1subscribe/post/callbacks/onEvent/{$request.body#~1callbackUrl}",
      "callback_pointer": "/paths/~1subscribe/post/callbacks/onEvent",
      "expression_pointer": "/paths/~1subscribe/post/callbacks/onEvent/{$request.body#~1callbackUrl}",
      "expression": "$request.body#/callbackUrl",
      "context_pointer": "/context/request/body/callbackUrl",
      "error": "runtime expression '$request.body#/callbackUrl' has no value in the supplied request/response context"
    }
  ]
}
```

> 解析过程**不会修改**请求中的 `document` 与 `context` 对象；不同回调 / 表达式的全部
> 错误会一次报齐。循环安全仅作用于回调与 Path Item 层的 `$ref` 链，Path Item 内部的
> 递归 schema 引用随 Path Item 原样返回，不会阻塞解析。

## `POST /security/plan`：为受保护操作规划鉴权方案

用于**联调前确认“该往请求里注入什么凭证”**：给定一份 OpenAPI 3.x 文档、一个操作选择器
和调用方**当前具备的方案与 scope 清单**，服务判定操作能否在当前凭证下通过鉴权，并给出
每个凭证注入 HTTP 请求的**位置与格式**及契约中的**来源 JSON Pointer**。

> **不接收秘密值**：`granted` 只声明“有没有某个方案的凭证”和“token 被授予了哪些
> scope 名”。实际的 API Key、密码、Bearer token 等秘密**绝不出现在请求中**；服务端
> 不需要也不会存储、回显它们（200 / 400 / 422 任何响应体都不含请求里的秘密字符串）。

### 有效 `security` 的取得与 OR / AND 语义

- 操作对象上声明了 `security` 时，**整体替换**根级 `security`（不是数组合并）；操作未
  声明时继承根级。根级与操作级都没有时，操作视为**匿名**。
- 显式 **`security: []`**（无论在根级还是操作级）表示**匿名访问**，返回
  `anonymous: true` 与空计划。
- `security` 是**Security Requirement Object 数组**：
  - **数组各项之间是 OR**——满足任意一项即可通过鉴权，服务对每项分别给出
    `satisfiable` 与缺失清单；
  - **同一项内的多个方案是 AND**——该项要求的所有方案（含各自 scope）必须同时具备。
- 服务在所有可满足项中选择**所需方案数最少**的一项；方案数相同时，按该 requirement
  对象的**规范 JSON**（键名升序、紧凑分隔符的 UTF-8 编码）字典序决胜；再相同取声明在前
  的一项。所选项放在 `selected`，全部逐项评估放在 `alternatives`（按声明顺序）。

### 方案定义与 scope 校验

Security Scheme Object 可以内联在 `components/securitySchemes`，也可以是本地 `$ref`
（仅支持 `#/...`）。`$ref` 链**循环安全**解析（多跳链跟随到终点，记录已访问目标，
成环或超过 100 跳均 422）；**OpenAPI 3.1** 下 `$ref` 同级字段逐层合并（近者优先），
**OpenAPI 3.0** 下严格忽略同级字段。按规范校验：

| type | 必填 / 校验 | 注入位置 |
| --- | --- | --- |
| `apiKey` | 非空字符串 `name`，且 `in` ∈ `header` / `query` / `cookie` | 具名 header / 查询参数 / Cookie（`name=<key>` 进 Cookie 头） |
| `http` | 非空字符串 `scheme`（HTTP 认证方案，如 `basic` / `bearer`）；`bearerFormat` 若有须为字符串 | `Authorization` 头（`Basic …` / `Bearer <token>` / `<scheme> <token>`） |
| `oauth2` | 对象 `flows`，至少含一个 flow；`implicit` 须有 `authorizationUrl`，`password` / `clientCredentials` 须有 `tokenUrl`，`authorizationCode` 两者皆须；每个 flow 的 `scopes` 须为 scope 名 → 描述字符串的对象 | `Authorization: Bearer <token>` |
| `openIdConnect` | 非空字符串 `openIdConnectUrl`（发现地址，不发起网络请求） | `Authorization: Bearer <token>` |

requirement 中的 scope 数组同样校验：必须是字符串数组；**apiKey / http 只能用空数组**
（这两类方案没有 scope 概念）；**oauth2 要求的每个 scope 必须已由某个 flow 的
`scopes` 声明**；openIdConnect 的 scope 在发现期才确定，不做枚举校验。

### 请求

```bash
curl -s -X POST http://localhost:8080/security/plan \
  -H 'Content-Type: application/json' \
  -d '{
    "document": { "openapi": "3.0.3", "info": {"title": "Pet API", "version": "1.0"},
                  "paths": {"...": {}} },
    "selector": "POST /pets",
    "granted": {"oauth": ["pets:write"], "partnerKey": []}
  }'
```

- `document`：一份 OpenAPI 3.x JSON 文档（对象）。
- `selector`：形如 `METHOD /path` 的单个选择器（方法大小写不敏感，路径须逐字匹配；
  OpenAPI 3.1 path-level `$ref` 提供的方法同样认可）。
- `granted`（可省略，默认 `{}`）：方案名 → **已授予 scope 名字符串数组**；apiKey /
  http 这类无 scope 方案用空数组 `[]` 表示“凭证在手”。数组里的 scope 会去重，键序不
  影响结果。列出文档中不存在的方案名不报错（只是用不上）。

### 成功响应（`200`，无可满足项时也仍然是 200）

```json
{
  "operation_pointer": "/paths/~1pets/post",
  "security_pointer": "/paths/~1pets/post/security",
  "inherited": false,
  "anonymous": false,
  "satisfiable": true,
  "selected": {
    "requirement": {"oauth": ["pets:write"]},
    "requirement_pointer": "/paths/~1pets/post/security/1",
    "scheme_count": 1,
    "plan": [
      {
        "scheme": "oauth",
        "type": "oauth2",
        "required_scopes": ["pets:write"],
        "injection": "send the OAuth 2.0 access token in the 'Authorization' header as 'Bearer <token>' carrying the required scopes",
        "location": "header",
        "parameter_name": "Authorization",
        "requirement_pointer": "/paths/~1pets/post/security/1",
        "source_pointer": "/components/securitySchemes/oauth"
      }
    ]
  },
  "alternatives": [
    {
      "requirement": {"partnerKey": []},
      "requirement_pointer": "/paths/~1pets/post/security/0",
      "satisfiable": false,
      "scheme_count": 1,
      "plan": [
        {
          "scheme": "partnerKey",
          "type": "apiKey",
          "required_scopes": [],
          "injection": "send the API key in the HTTP header 'X-Partner-Key'",
          "location": "header",
          "parameter_name": "X-Partner-Key",
          "requirement_pointer": "/paths/~1pets/post/security/0",
          "source_pointer": "/components/securitySchemes/partnerKey"
        }
      ],
      "missing": [
        {
          "scheme": "partnerKey",
          "type": "apiKey",
          "source_pointer": "/components/securitySchemes/partnerKey",
          "requirement_pointer": "/paths/~1pets/post/security/0",
          "error": "no credential granted for security scheme 'partnerKey' (apiKey)"
        }
      ]
    }
  ]
}
```

字段说明：

- `security_pointer`：生效 `security` 数组的来源 Pointer——继承根级时为 `/security`，
  操作自带时指向 `/paths/.../<method>/security`；根级与操作级都没有时为 `null`。
- `selected.plan[].injection`：凭证注入说明（英文稳定文案），明确 header / query /
  cookie 位置与线格式；占位符（`<key>` / `<token>`）表示**由联调方在请求时填入秘密
  值**，服务本身不接触秘密。
- `selected.plan[].source_pointer`：`$ref` 链**终点**的方案定义位置（修复定义问题的
  稳定位置）；`requirement_pointer` 指向引用该方案的 requirement 数组项。
- 匿名操作的 `selected` 为 `{requirement: {}, requirement_pointer: null,
  scheme_count: 0, plan: []}`。
- **无可满足项**：HTTP 状态仍是 **200**，`satisfiable: false`、`selected: null`，
  `alternatives[*].missing` 逐项列出缺什么：

```json
{
  "scheme": "oauth",
  "type": "oauth2",
  "scope": "pets:admin",
  "source_pointer": "/components/securitySchemes/oauth",
  "requirement_pointer": "/paths/~1pets/post/security/0/oauth",
  "error": "granted credential for 'oauth' is missing the required scope 'pets:admin'"
}
```

  “根本没有该方案的凭证”与“有凭证但缺 scope”分别报告（后者带 `scope`），同一
  requirement 内的多条缺失一次列齐并按 `(scheme, scope, error)` 稳定排序。

### 错误响应

- `400 invalid_openapi_document`：`document` 缺少 `openapi: 3.x` 或 `paths` 对象。
- `400 invalid_selector`：选择器不是 `METHOD /path` 形态，或路径 / 方法不存在。
- `400 invalid_granted_credentials`：`granted` 不是对象、方案名不是非空字符串，或某个
  值不是 scope 名字符串数组（apiKey/http 应给 `[]`，不要放 token 字符串）。
- `422 invalid_security_definition` / `unresolvable_reference`：契约层面的结构问题，
  `errors` 每条带 `code`、来源 `pointer`（必要时附 `ref`）与原因，**全部问题一次报齐、
  按 `(code, pointer, ref, error)` 稳定排序**，包括：

  - requirement 项不是对象、scope 值不是字符串数组、`security` 不是数组、方案节点不是对象；
  - requirement 引用了 `components/securitySchemes` 中不存在的方案名（422，pointer 指向
    requirement 中的方案名位置）；
  - 方案 `$ref` **悬空 / 外部（`http(s)://`、文件路径等）/ 指向根 `#` / 目标非对象 /
    循环 / 超深链**（pointer 指向出问题的 `$ref` 出现处，并附 `ref`）；
  - 非法 type，apiKey 缺 `name` 或 `in` 非法，http 缺 `scheme`，oauth2 缺 flow / flow
    URL / `scopes` 映射非法，openIdConnect 缺 `openIdConnectUrl`；
  - apiKey/http 的 requirement 带了 scope，或 oauth2 要求了未在任何 flow 中声明的 scope。

```json
{
  "error": "invalid_security_definition",
  "message": "one or more security requirements reference illegal, dangling, external or circular security scheme definitions; fix the contract before a plan can be produced",
  "errors": [
    {
      "code": "invalid_security_definition",
      "pointer": "/components/securitySchemes/oauth/flows/implicit/authorizationUrl",
      "error": "the 'implicit' oauth2 flow requires a non-empty string 'authorizationUrl'"
    },
    {
      "code": "unresolvable_reference",
      "pointer": "/components/securitySchemes/partnerKey",
      "ref": "#/components/securitySchemes/Missing",
      "error": "unresolvable reference '#/components/securitySchemes/Missing': object has no property 'Missing'"
    }
  ]
}
```

> 400 与 422 的边界：文档形态、选择器与 `granted` 信封问题是请求错误（400）；文档确实
> 选中了操作、但其安全定义 / 引用本身非法是契约错误（422）。未被选中操作的安全定义不
> 会被访问，因而不影响本次规划。规划过程**不会修改**请求中的任何对象，输出与输入键序、
> scope 顺序无关。

## `POST /links/plan`：按 Link 生成后续调用计划

用于**联调时顺着响应里的 Link 直接构造下一跳请求**：给定一份 OpenAPI 3.x 文档、源操作
选择器、一个 Link 名称与一次实际请求 / 响应上下文，服务定位该 Link 指向的目标操作，
求值 `parameters` / `requestBody` 中的 Runtime Expression，并返回**目标操作、分组参数值、
请求体及每个映射的来源 JSON Pointer**，可直接交给 `POST /requests/materialize` 完成
线格式序列化。

### Response 选择顺序

服务取 `context.response.statusCode`（整数或字符串均可），在源操作的 `responses` 中按
OpenAPI 规范顺序选择声明 Link 的 Response：

1. **精确键**：如 `201` 精确匹配（字符串 `"201"` 与数字状态码等价匹配）；
2. **类通配 `nXX`**：无精确键时按首位数字匹配 `2XX` / `4xx` 等，**大小写不敏感**；
3. **`default`**：以上都没有时使用兜底响应。

三者都不存在时返回 422；未提供 `context.response.statusCode` 同样 422（这是选出 Link
所必需的运行时值）。

### Response / Link / Path Item 的本地 `$ref`

- Response（`responses/<key>`）、Link（`<response>/links/<name>`）条目本身都可以是本地
  `$ref`（如 `#/components/responses/...`、`#/components/links/...`）；目标 Path Item 的
  自身 `$ref`（OpenAPI 3.1 `components/pathItems`）同样跟随。三条链都**循环安全**
  （记录已访问指针，成环即 422，另有 100 层链长上限）。
- **OpenAPI 3.1**：`$ref` 同级字段逐层合并（近者优先），Link 的 `parameters` 等成员可被
  同级字段覆盖；**OpenAPI 3.0**：严格遵循旧规范，`$ref` 同级字段被忽略。
- 仅本地引用 `#/...` 受支持：外部引用、悬空指针、目标非对象均 422。Path Item / 参数
  内部更深层的 `$ref`（如 schema 引用）不展开，因此正常的递归 schema 不会被误判为循环；
  但**目标参数自身的 `$ref`** 会跟随解析（悬空 / 循环即 422），以便按键名匹配。

### 目标定位：`operationRef` 与 `operationId` 二选一

- **`operationRef`**：必须是**本地** JSON Pointer 片段（`#/...`），末段是 HTTP 方法
  （get/put/post/delete/options/head/patch/trace），其上方节点为 Path Item（自身 `$ref`
  会被解析）。片段遵循 RFC 6901 转义，例如 `#/paths/~1orders~1{orderId}/get`。外部 URI、
  悬空指针、未指向操作、目标 Path Item 未声明该方法均 422。指向
  `#/components/pathItems/...` 时目标没有具体 URL 路径，响应里 `target.path` /
  `target.selector` 为 `null`。
- **`operationId`**：必须在文档 `paths` 下**全局唯一**；零个匹配（未定义）或多个匹配
  （重复 ID）都 422，错误中列出全部冲突位置。
- 同时给出两者或两者都不给均 422。

### `parameters` / `requestBody` 映射求值

- `parameters` 是一个对象，**键是目标操作的参数名**（不是 `in.name` 限定形式）。服务合并
  目标 Path Item 与操作两级参数（操作级按 `(in, name)` 覆盖路径级）后按键匹配：
  - 键在目标参数中不存在 → `unknown_parameter` 422；
  - 同名参数同时声明在**多个位置**（如同名的 header 与 query 参数）→
    `ambiguous_parameter` 422；
  - 目标的必填参数（path 参数恒为必填）未被任何映射赋值 →
    `missing_required_parameter` 422。可选参数缺省即省略。
- 映射值是**字符串且以 `$` 开头**时，必须是一个**完整的** Runtime Expression（支持
  `$url` / `$method` / `$statusCode` / `$request.path.<n>` / `$request.query.<n>` /
  `$request.header.<t>` / `$request.body[#/ptr]` / `$response.header.<t>` /
  `$response.body[#/ptr]`，语法与 `/callbacks/resolve` 完全一致）：
  - 与回调 URL 插值不同，Link 参数 / 请求体表达式的结果**允许是对象或数组**
    （如整个响应体或 `$response.body#/items`）；只有 header 表达式仍需解析为标量；
  - 取到 `null`、JSON Pointer 不可达、对应 message / 字段未提供 → `missing_value` 422；
  - header 名大小写不敏感匹配，命中仅大小写不同的多个上下文键 →
    `ambiguous_header` 422；
  - 以 `$` 开头但不是合法完整表达式（如 `$nope`）→ `invalid_expression` 422。
- 其余任意 JSON 值（含不以 `$` 开头的字符串，哪怕内含 `{...}`）都是**字面常量**，原样
  深拷贝赋值。`requestBody` 省略时 `provided=false`、`value=null`。

### 来源 JSON Pointer

- `source.link_pointer`：Link 条目出现处（引用型 Link 指向 **`$ref` 出现处**）；
- `response.pointer`：Response 条目出现处；`response.match` 为
  `exact` / `wildcard` / `default`；
- 每个参数值同时给出 `value_pointer`（映射值在 Link Object 中的位置；引用型 Link 跟随到
  组件内的声明，3.1 覆盖处指向覆盖层）与 `parameter_pointer`（目标参数定义位置，参数
  `$ref` 跟随到组件）；
- `request_body.value_pointer` 指向 Link 的 `requestBody` 成员（省略时为 `null`）。

### 请求

```bash
curl -s -X POST http://localhost:8080/links/plan \
  -H 'Content-Type: application/json' \
  -d '{
    "document": {
      "openapi": "3.0.3",
      "info": {"title": "Orders", "version": "1.0"},
      "paths": {
        "/orders": {"post": {"operationId": "createOrder", "responses": {
          "201": {"description": "created", "links": {"getOrder": {
            "operationId": "getOrder",
            "parameters": {
              "orderId": "$response.body#/id",
              "trace": "$request.header.x-trace",
              "verbose": true
            },
            "requestBody": "$response.body"
          }}}
        }}},
        "/orders/{orderId}": {"get": {"operationId": "getOrder", "parameters": [
          {"name": "orderId", "in": "path", "required": true, "schema": {"type": "string"}},
          {"name": "trace", "in": "header", "schema": {"type": "string"}},
          {"name": "verbose", "in": "query", "schema": {"type": "boolean"}}
        ], "responses": {"200": {"description": "ok"}}}}
      }
    },
    "selector": "POST /orders",
    "link": "getOrder",
    "context": {
      "request": {"header": {"X-Trace": "t-1"}},
      "response": {"statusCode": 201, "body": {"id": "ord-42", "total": 9}}
    }
  }'
```

- `document`：一份 OpenAPI 3.x JSON 文档（对象）。
- `selector`：形如 `METHOD /path` 的源操作选择器（方法大小写不敏感，路径逐字匹配）。
- `link`：所选 Response 的 `links` 成员名（非空字符串）。
- `context`（可省略，默认为空对象）：与 `/callbacks/resolve` 相同的请求 / 响应信封；
  `request` 与 `response` 各字段可选，但 `response.statusCode` 为选出 Response 所必需。

### 成功响应（`200`）

```json
{
  "source": {
    "selector": "POST /orders",
    "operation_pointer": "/paths/~1orders/post",
    "link_name": "getOrder",
    "link_pointer": "/paths/~1orders/post/responses/201/links/getOrder"
  },
  "response": {"status_code": 201, "key": "201", "match": "exact",
               "pointer": "/paths/~1orders/post/responses/201"},
  "target": {
    "selector": "GET /orders/{orderId}",
    "method": "get",
    "path": "/orders/{orderId}",
    "operation_pointer": "/paths/~1orders~1{orderId}/get",
    "operation_id": "getOrder",
    "operation_ref": null
  },
  "parameter_values": {
    "path": [{"name": "orderId", "value": "ord-42",
      "expression": "$response.body#/id",
      "value_pointer": "/paths/~1orders/post/responses/201/links/getOrder/parameters/orderId",
      "parameter_pointer": "/paths/~1orders~1{orderId}/get/parameters/0"}],
    "query": [{"name": "verbose", "value": true, "expression": null,
      "value_pointer": "/paths/~1orders/post/responses/201/links/getOrder/parameters/verbose",
      "parameter_pointer": "/paths/~1orders~1{orderId}/get/parameters/2"}],
    "header": [{"name": "trace", "value": "t-1",
      "expression": "$request.header.x-trace",
      "value_pointer": "/paths/~1orders/post/responses/201/links/getOrder/parameters/trace",
      "parameter_pointer": "/paths/~1orders~1{orderId}/get/parameters/1"}],
    "cookie": []
  },
  "request_body": {
    "provided": true,
    "value": {"id": "ord-42", "total": 9},
    "expression": "$response.body",
    "value_pointer": "/paths/~1orders/post/responses/201/links/getOrder/requestBody"
  }
}
```

- `parameter_values` 恒含 `path` / `query` / `header` / `cookie` 四组，无赋值时为 `[]`；
  字面常量映射的 `expression` 为 `null`。
- 输出值全部经过深拷贝，计划生成后再修改请求对象不会影响已返回的计划。

### 错误响应

- `400 invalid_openapi_document`：`document` 缺少 `openapi: 3.x` 或 `paths` 对象。
- `400 invalid_selector`：选择器不是 `METHOD /path` 形态，或路径 / 方法不存在。
- `400 invalid_link_request`：`link` 不是非空字符串，或 `context` 信封非法（未知
  section / 字段、容器不是对象、`statusCode` 非整数或字符串、header 值非标量等）。
- `422 link_planning_failed`：所有语义问题一次报齐并稳定排序，`errors` 每条至少带
  `code`、`pointer`、`error`：

| code | 触发情形 | pointer 指向 |
| --- | --- | --- |
| `missing_value` | 表达式取到 `null` / 指针不可达，或缺 statusCode、对应 message / 字段 | 映射值或 `/context/response/statusCode`（另附 `context_pointer`、`expression`） |
| `invalid_expression` | 以 `$` 开头但不是合法完整表达式，或 header 表达式解析为非标量 | 映射值 |
| `ambiguous_header` | header 名大小写不敏感匹配到多个仅大小写不同的上下文键 | 映射值 |
| `unknown_link_target` | `operationId` 未定义 / 不唯一，或 `operationRef` 不指向存在的操作 | `operationId` / `operationRef` 成员 |
| `ambiguous_parameter` | 映射键命中跨多个位置（path/query/header/cookie）声明的同名参数 | 映射键（或必填歧义参数定义处） |
| `unknown_parameter` | 映射键不是目标操作声明的参数名 | 映射键 |
| `missing_required_parameter` | 目标必填参数未被任何映射赋值 | 目标参数定义（另附 `in`、`name`） |
| `invalid_link` | 缺 Response、未知 Link 名、Link 同时 / 均未给两种目标、`parameters` 不是对象、目标不是对象等 | 问题节点 |
| `unresolvable_reference` | Response / Link / 目标 Path Item / 目标参数的本地 `$ref` 悬空、外部、目标非对象或循环 | `$ref` 出现处（另附 `ref`） |

```json
{
  "error": "link_planning_failed",
  "message": "the follow-up call could not be planned; fix the reported link target, expressions, parameters or references first",
  "errors": [
    {
      "code": "missing_required_parameter",
      "pointer": "/paths/~1orders~1{orderId}/get/parameters/0",
      "in": "path",
      "name": "orderId",
      "error": "required path parameter 'orderId' is not assigned by the link 'parameters' map"
    }
  ]
}
```

> 解析过程**不会修改**请求中的 `document` 与 `context`，发生任何 422 时都**不返回半成品**；
> 同一 Link 内的全部独立错误会一次报齐并稳定排序。该接口只负责“赋值计划”，参数的
> style / explode 线格式序列化请继续使用 `POST /requests/materialize`，两者的参数分组
> 信封完全一致；Docker 与 Docker Compose 的启动方式保持不变。

## `POST /interactions/graph`：生成契约交互图

用于**联调检查文档**：提交**一份** OpenAPI 3.x 文档，服务遍历 `paths` 下全部操作，
把契约中**会触发后续 HTTP 调用的关系**（响应 Link 与操作 callbacks）整理成一张
**有向交互图**，一次返回全部节点与边。

### 节点

- **契约操作节点**（`kind: "operation"`）：`paths` 下每个操作一个节点，`id` 即操作的
  JSON Pointer（如 `/paths/~1orders/post`），并携带 `method`（小写）、`path` 与
  `operation_id`（未声明为 `null`）。path-level `$ref` 链（含 OpenAPI 3.1
  `components/pathItems` 挂载）循环安全解析，节点仍按 **`/paths` 出现位置**编址。
- **回调操作节点**（`kind: "callback"`）：操作 `callbacks` 中回调 Path Item 声明的每个
  操作一个节点，`id` 指向其**声明位置**——内联 Path Item 编址在回调表达式键之下；
  经本地 `$ref` 引用的可复用 Path Item（如 `components/pathItems`）跟随到组件位置，
  因此多处引用同一组件 Path Item 时只产生**一个共享节点**。`path` 恒为 `null`。
- Link 经 `operationRef` 指向 `components/pathItems` 可复用 Path Item 时，目标操作
  也会成为 `operation` 节点（`path` 为 `null`）。
- 回调操作自身声明的 links / callbacks **不再展开**——只有 `paths` 操作是边的来源。

### 边

- **Link 边**（`kind: "link"`）：**每个响应键**（精确码、`nXX` 通配、`default` 全部
  扫描）的 `links` 每个条目产生一条边。目标按**本地 `operationRef`**（`#/...`、末段
  为 HTTP 方法，目标 Path Item 自身 `$ref` 会解析）或**全局唯一 `operationId`**
  二选一定位。边携带 `pointer`（Link 条目出现处；Response / Link 为 `$ref` 时跟随到
  声明层）、`response_key`（响应键）、`method`（目标 HTTP 方法）与 `name`
  （Link 名），`callback_url` 为 `null`。
- **回调边**（`kind: "callback"`）：`callbacks` 每个 Callback Object 的每个表达式键、
  对应 Path Item 中**每个 HTTP 方法**各产生一条边。边携带 `pointer`（表达式键出现处，
  Callback Object `$ref` 链跟随到声明层）、`callback_url`（**回调 URL 模板**，即
  表达式键原文）、`method` 与 `name`（回调名），`response_key` 为 `null`。
- 同一目标被多条声明到达时**不去重**：每条声明保留自己的来源边（各自 `pointer`）。

### `$ref` 语义与错误汇总

- Response / Link / Callback Object / 回调 Path Item 的本地 `$ref` 链均**循环安全**
  解析（另有 100 层链长上限）；**3.0 忽略 `$ref` 同级字段，3.1 按近端覆盖合并**。
- 悬空、外部、循环引用、**重复 `operationId`**（构图时即校验全局唯一性，即使未被任何
  Link 使用也会报告）、目标无法唯一定位（`operationId` 零个或多个匹配、
  `operationRef` 不指向存在的操作）等全部问题**一次汇总**为 422，**不返回半成品图**。
- 节点按 `id`、边按 `pointer` **稳定排序**；输入文档不被修改。

### 请求

```bash
curl -s -X POST http://localhost:8080/interactions/graph \
  -H 'Content-Type: application/json' \
  -d '{
    "document": {
      "openapi": "3.0.3",
      "info": {"title": "Orders", "version": "1.0"},
      "paths": {
        "/orders": {"post": {
          "operationId": "createOrder",
          "responses": {"201": {"description": "created", "links": {
            "fetchOrder": {"operationId": "getOrder"}
          }}},
          "callbacks": {"onShipped": {
            "{$request.body#/callbackUrl}": {
              "post": {"responses": {"200": {"description": "ok"}}}
            }
          }}
        }},
        "/orders/{orderId}": {"get": {
          "operationId": "getOrder",
          "responses": {"200": {"description": "ok"}}
        }}
      }
    }
  }'
```

- `document`：一份 OpenAPI 3.x JSON 文档（对象），是唯一的请求字段。

### 成功响应（`200`）

```json
{
  "node_count": 3,
  "edge_count": 2,
  "nodes": [
    {"id": "/paths/~1orders/post", "kind": "operation", "method": "post",
     "path": "/orders", "operation_id": "createOrder"},
    {"id": "/paths/~1orders/post/callbacks/onShipped/{$request.body#~1callbackUrl}/post",
     "kind": "callback", "method": "post", "path": null, "operation_id": null},
    {"id": "/paths/~1orders~1{orderId}/get", "kind": "operation", "method": "get",
     "path": "/orders/{orderId}", "operation_id": "getOrder"}
  ],
  "edges": [
    {"kind": "callback", "name": "onShipped",
     "pointer": "/paths/~1orders/post/callbacks/onShipped/{$request.body#~1callbackUrl}",
     "source": "/paths/~1orders/post",
     "target": "/paths/~1orders/post/callbacks/onShipped/{$request.body#~1callbackUrl}/post",
     "method": "post", "response_key": null,
     "callback_url": "{$request.body#/callbackUrl}"},
    {"kind": "link", "name": "fetchOrder",
     "pointer": "/paths/~1orders/post/responses/201/links/fetchOrder",
     "source": "/paths/~1orders/post",
     "target": "/paths/~1orders~1{orderId}/get",
     "method": "get", "response_key": "201", "callback_url": null}
  ]
}
```

- 节点 `id` 中的回调表达式键按 RFC 6901 转义（`/` → `~1`），`callback_url` 保留原文。
- `node_count` / `edge_count` 与数组长度一致，便于校验。

### 错误响应

- `400 invalid_openapi_document`：`document` 缺少 `openapi: 3.x` 或 `paths` 对象。
- `422 interaction_graph_failed`：所有问题一次报齐并稳定排序，`errors` 每条至少带
  `code`、`pointer`、`error`；**不返回任何节点或边**。

| code | 触发情形 | pointer 指向 |
| --- | --- | --- |
| `duplicate_operation_id` | 同一 `operationId` 被 2 个及以上操作声明（无论是否被 Link 使用） | 首个声明位置（另附 `operation_id` 与全部 `pointers`） |
| `unknown_link_target` | `operationId` 零个 / 多个匹配，或 `operationRef` 不指向存在的操作 | Link 的 `operationId` / `operationRef` 成员 |
| `invalid_link` | Link 同时 / 均未给两种目标、目标成员类型错误、`links` 或 Response 形态非法 | 问题节点 |
| `invalid_callback` | `callbacks` 容器、Callback Object、回调 Path Item 或回调操作形态非法 | 问题节点 |
| `invalid_operation` | path item、操作或 `responses` 容器形态非法 | 问题节点 |
| `unresolvable_reference` | 本地 `$ref` 悬空、外部、循环或目标非对象 | `$ref` 出现处（另附 `ref`） |

```json
{
  "error": "interaction_graph_failed",
  "message": "the interaction graph could not be built; fix the reported references, links, callbacks and operationIds first",
  "errors": [
    {
      "code": "duplicate_operation_id",
      "pointer": "/paths/~1copy/get",
      "operation_id": "getOrder",
      "pointers": ["/paths/~1copy/get", "/paths/~1orders~1{orderId}/get"],
      "error": "operationId 'getOrder' is declared by 2 operations (/paths/~1copy/get, /paths/~1orders~1{orderId}/get); operationIds must be globally unique"
    }
  ]
}
```

> 该接口只做**静态关系整理**：回调 URL 模板中的 Runtime Expression 不求值（联调时
> 用 `POST /callbacks/resolve` 代入实际上下文求值），Link 的参数映射也不展开
> （用 `POST /links/plan` 生成赋值计划）。Docker 与 Docker Compose 的启动方式保持不变。

## `POST /representations/select`：按真实 HTTP 头部协商请求 / 响应表示

用于**联调时确认“这个操作此刻该按哪个媒体类型发请求、按哪个媒体类型收响应”**：给定一份
OpenAPI 3.x 文档、一个操作选择器、真实请求的 **`Content-Type`** 与 **`Accept`** 头值以及
**响应状态码**，服务解析该操作的 `requestBody` 与所选响应，按 RFC 9110 内容协商规则分别
选出**唯一的请求表示与响应表示**，返回所用 **JSON Pointer、规范化媒体类型以及对应
schema / example / examples**。

### Response 选择顺序

按状态码在操作的 `responses` 中依次选择（与 `/links/plan` 一致）：

1. **精确键**：`200`、`"201"`（整数与数字字符串等价，输出统一为整数）；
2. **类通配 `nXX`**：无精确键时按首位数字匹配 `2XX` / `4xx` 等，**大小写不敏感**；
3. **`default`**：兜底响应。

三者都不存在时返回 **422**（`response_not_declared`）。状态码必须是 **100～599** 的整数或
纯数字字符串，否则 400。

### 请求表示（Content-Type）匹配

请求 `Content-Type` 在 HTTP 线上必须是**具体媒体类型**（不允许 `*/*`，否则 400）。
在 `requestBody.content` 的声明媒体类型中按下述规则选出唯一一项：

- **type / subtype 大小写不敏感**逐 token 匹配，`*` 为通配（`application/*` 匹配
  `application/json`；`*/*` 匹配一切；但 `application/*+json` 只与字面同名 token 匹配，
  不会对 `vnd.api+json` 做后缀子串匹配）。
- **参数包含关系**：契约声明上的每个参数（如 `version=1`）都必须出现在请求类型上且**值相同**
  （参数名大小写不敏感、值大小写敏感）；**请求类型允许携带声明未限制的额外参数**
  （如声明 `application/json` 时请求 `application/json; charset=utf-8` 合法）。
- **具体度决胜**：通配更少者优先（精确 `type/subtype` > `type/*` > `*/*`）；通档位相同
  时，与请求**取值相等的参数更多者**优先；仍相同则按 **content 对象的声明顺序**取第一项。
- 操作无 `requestBody` 时，即使带了 Content-Type 也忽略，`request` 为 `null`；
  `requestBody` 可选（`required: false`）且未提供 Content-Type 时 `request` 同样为 `null`；
  **必填**请求体未提供 Content-Type、或 Content-Type 无任何匹配时返回 **415**，
  响应体 `supported` 列出该请求体声明的全部媒体类型（按声明顺序）。

### 响应表示（Accept）匹配

- `Accept` 按逗号切分成若干媒体区间，每项可带 **`q` 权重**（`0`～`1`，至多三位小数；
  `q` 名大小写不敏感；带引号的 `q="0.5"` 按 RFC 是名为 `q` 的扩展参数而非权重）。
- 对每个**声明的响应媒体类型**，在所有**适用**区间（type/subtype 通配匹配、且区间要求的
  非 q 参数在声明类型上同值齐备；声明类型可有额外参数）中，取**最具体区间**的 q——
  具体度按 type/subtype 通档位（精确 > `type/*` > `*/*`）再按**匹配上的参数个数**比较，
  同具体度取**声明在前**的区间。
- 全体声明类型中 **q 最高且 > 0** 者胜出；**同权按 content 对象声明顺序**稳定裁决。
- **未提供 / 显式 `null` 的 Accept 等价于 `*/*;q=1`**（取声明第一项）；**空字符串 `""`
  表示什么都不接受**，所选响应带内容时返回 **406**；`q=0` 区间永不入选。
- 所选响应**没有 `content`**（如 `204 No Content`）时不做协商，`response.present=false`，
  任何 Accept 都不会导致 406。406 响应体的 `available` 列出该响应声明的全部媒体类型。

### `$ref` 解析与 3.0 / 3.1 内容对象合并

- `requestBody`、Response 条目与 path item 自身的本地 `$ref`（`#/components/requestBodies`、
  `#/components/responses`、3.1 `#/components/pathItems` 等）均**循环安全**解析
  （成环 / 超 100 层 / 悬空 / 外部 / 目标非对象均 422）。
- **OpenAPI 3.1**：`$ref` 同级字段逐层合并、**近端覆盖**（同名成员整体覆盖，不做深合并）；
  **OpenAPI 3.0**：严格忽略 `$ref` 同级字段。所选 Media Type Object 的
  `example` / `examples.<name>` 中的 Example Object 本地 `$ref` 同样跟随解析；
  `externalValue`、悬空 / 外部 / 循环 Example 引用均 422。
- Media Type 的 **`schema` 原样返回**（内部 `$ref` 字符串保留、不展开、不校验悬空），
  以便调用方自行按 schema 指针解析。

### 返回字段

- `operation_pointer`：所选操作的 JSON Pointer。
- `request`：无请求表示时为 `null`；否则含
  `present=true`、`required`、收到的规范化 `content_type`、命中的
  `declared_media_type`（content 对象的原始键）、规范化 `media_type`、
  `media_type_pointer`、`schema` / `schema_pointer`、内联 `example` /
  `example_pointer`（无则为 `null`）与 `examples` 数组（每项 `name`、示例条目所在
  `pointer`、解析后的 `value` 与 `value_pointer`——经 `$ref` 时跟随到组件位置——以及
  `summary` / `description`；数组按 `name` 排序）。
- `response`：含 `present`、整数 `status_code`、命中的响应 `key` 与
  `match`（`exact` / `wildcard` / `default`）、`response_pointer`；`present=true` 时
  携带与 `request` 相同的媒体类型 / schema / example 字段，`present=false`（无内容响应）时
  这些字段为 `null` / `[]`。

### 请求

```bash
curl -s -X POST http://localhost:8080/representations/select \
  -H 'Content-Type: application/json' \
  -d '{
    "document": {
      "openapi": "3.0.3",
      "info": {"title": "Pet API", "version": "1.0"},
      "paths": {
        "/pets": {
          "post": {
            "requestBody": {"required": true, "content": {
              "application/json": {"schema": {"$ref": "#/components/schemas/Pet"},
                                   "examples": {"cat": {"$ref": "#/components/examples/Cat"}}},
              "application/xml": {"schema": {"type": "string"}}
            }},
            "responses": {
              "200": {"description": "a pet", "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/Pet"},
                                     "example": {"id": 1, "name": "Rex"}},
                "application/xml": {"schema": {"type": "string"}}
              }},
              "4XX": {"description": "problem", "content": {
                "application/problem+json": {"schema": {"type": "object"}}}},
              "default": {"description": "unexpected"}
            }
          }
        }
      },
      "components": {
        "schemas": {"Pet": {"type": "object", "required": ["id", "name"],
                            "properties": {"id": {"type": "integer"}, "name": {"type": "string"}}}},
        "examples": {"Cat": {"summary": "A cat", "value": {"id": 7, "name": "Milo"}}}
      }
    },
    "selector": "POST /pets",
    "request_content_type": "application/json; charset=utf-8",
    "accept": "application/xml;q=0.4, application/json;q=0.9, */*;q=0.1",
    "status_code": 200
  }'
```

- `document`：一份 OpenAPI 3.x JSON 文档（对象）。
- `selector`：形如 `METHOD /path` 的单个选择器（方法大小写不敏感，路径逐字匹配；
  3.1 path-level `$ref` 提供的方法同样认可）。
- `request_content_type`（可省略 / `null`）：真实请求 Content-Type 头值（具体媒体类型，
  可带参数）。
- `accept`（可省略 / `null`）：真实 Accept 头值；省略等价 `*/*`，空字符串拒绝一切。
- `status_code`（必填）：整数或数字字符串，100～599。

### 成功响应（`200`，节选）

```json
{
  "operation_pointer": "/paths/~1pets/post",
  "request": {
    "present": true,
    "required": true,
    "content_type": "application/json; charset=utf-8",
    "declared_media_type": "application/json",
    "media_type": "application/json",
    "media_type_pointer": "/paths/~1pets/post/requestBody/content/application~1json",
    "schema": {"$ref": "#/components/schemas/Pet"},
    "schema_pointer": "/paths/~1pets/post/requestBody/content/application~1json/schema",
    "example": null,
    "example_pointer": null,
    "examples": [
      {"name": "cat",
       "pointer": "/paths/~1pets/post/requestBody/content/application~1json/examples/cat",
       "value": {"id": 7, "name": "Milo"},
       "value_pointer": "/components/examples/Cat/value",
       "summary": "A cat", "description": null}
    ]
  },
  "response": {
    "present": true,
    "status_code": 200,
    "key": "200",
    "match": "exact",
    "response_pointer": "/paths/~1pets/post/responses/200",
    "declared_media_type": "application/json",
    "media_type": "application/json",
    "media_type_pointer": "/paths/~1pets/post/responses/200/content/application~1json",
    "schema": {"$ref": "#/components/schemas/Pet"},
    "schema_pointer": "/paths/~1pets/post/responses/200/content/application~1json/schema",
    "example": {"id": 1, "name": "Rex"},
    "example_pointer": "/paths/~1pets/post/responses/200/content/application~1json/example",
    "examples": []
  }
}
```

> 上例中 `application/json;q=0.9` 比 `application/xml;q=0.4` 权重高，因此尽管 xml 声明在前，
> 响应仍选 json。把 `status_code` 改为 `404`、`accept` 改为 `application/problem+json`
> 时，响应命中 `4XX`（`match: "wildcard"`）。

### 错误响应

- `400 invalid_openapi_document`：`document` 缺少 `openapi: 3.x` 或 `paths` 对象。
- `400 invalid_selector`：选择器不是 `METHOD /path` 形态，或路径 / 方法不存在。
- `400 invalid_negotiation_request`：`status_code` 非 100～599 整数 / 数字字符串、
  Content-Type 语法非法或含通配、Accept 区间语法非法（如 `q=2`、`q=0.1234`、`*/json`、
  重复参数、空区间）、头字段不是字符串等；`messages` 逐条给出原因。
- **`415 unsupported_media_type`**：请求 Content-Type 不匹配任何请求表示
  （或必填请求体未给 Content-Type、content 为空）：

```json
{
  "error": "unsupported_media_type",
  "message": "the request Content-Type does not match any requestBody representation declared by the operation",
  "request_content_type": "text/csv",
  "supported": ["application/json", "application/xml"]
}
```

- **`406 not_acceptable`**：所选响应带内容、但没有任何声明媒体类型可接受（含空 Accept 与
  全体 `q=0`）：

```json
{
  "error": "not_acceptable",
  "message": "none of the response representations declared for the selected response is acceptable under the Accept header",
  "accept": "text/html",
  "available": ["application/json", "application/xml"]
}
```

- **`422 negotiation_failed`**：所选路径上的契约结构 / 引用问题，`errors` 每条带
  `code`、`pointer`、`error`，包括：
  - `response_not_declared`：状态码无精确 / `nXX` / `default` 响应（附 `status_code`）；
  - `invalid_operation`：操作 / requestBody / Response / content / Media Type Object 形态非法
    （如 requestBody 缺 `content`、媒体节点不是对象、`examples` 不是对象、操作缺
    `responses` 等）；
  - `invalid_media_type`：content 对象的键不是合法媒体类型（如 `not a media type`）；
  - `invalid_example`：`examples` 条目经解析后不是 Example Object；
  - `unsupported_reference`：示例使用 `externalValue`（附该 URL）；
  - `unresolvable_reference`：requestBody / Response / path item / Example 的本地 `$ref`
    悬空、外部、指向根 `#`、目标非对象或循环（pointer 指向 `$ref` 出现处，另附 `ref`）。

```json
{
  "error": "negotiation_failed",
  "message": "the representation could not be selected due to a contract-level problem on the selected operation; fix the reported structure or references first",
  "errors": [
    {"code": "response_not_declared", "pointer": "/paths/~1pets/post/responses",
     "status_code": 404,
     "error": "no response matches status code 404: expected the exact code, an 'nXX' wildcard key or 'default'"}
  ]
}
```

> **错误优先级**：请求包体错误（400）→ 契约结构 / 引用错误（422）→ 请求媒体不支持
> （415）→ 响应不可接受（406）。任何错误都**不返回半成品**（415 / 406 / 422 响应体不含
> `request` / `response`）；协商过程**不会修改**请求中的 `document` 与各字段，输出的
> schema / example 均为深拷贝。Docker 与 Docker Compose 的启动方式保持不变。

## 检查的变更类别

| category | 说明 | 判定为 breaking 的方向 |
| --- | --- | --- |
| `operation-removed` / `operation-added` | 路径上 HTTP 操作被删除 / 新增 | 删除操作 |
| `path-removed` / `path-added` | 整条路径被删除 / 新增 | 删除路径 |
| `parameter-added` / `parameter-removed` | 新增 / 删除参数（含路径级参数） | 新增**必填**参数 |
| `parameter-required-added` / `parameter-required-removed` | 参数必填性变化 | 参数由可选变必填 |
| `request-body-added` / `request-body-required-added` | 新增请求体或请求体变为必填 | 必填请求体被引入 |
| `type-changed` | 类型 / 可空性变化（参数、请求体、响应字段、数组 items），按值集合包含关系判定 | 请求侧收紧（如 `number`→`integer`、去除可空、新增类型约束）；响应侧放宽（如 `integer`→`number`、3.0 `nullable` / 3.1 `"null"` 联合新增可空） |
| `enum-changed` | 枚举值增删；缺省 `enum` 视为**无约束全集**而非空集 | 请求侧收紧（枚举收窄、新引入 enum）；响应侧放宽（枚举放宽、移除 enum 约束） |
| `required-added` / `required-removed` | 对象属性必填性变化 | 请求新增必填字段、响应取消必填保证 |
| `property-added` / `property-removed` | 对象属性增删 | 请求新增必填属性、响应删除属性 |
| `response-removed` / `response-added` | 响应状态码（含 `2XX` 范围码）增删 | 删除响应码 |
| `response-body-removed` | 响应体被移除 | 始终 breaking |
| `media-type-removed` / `media-type-added` | 请求/响应的媒体类型增删 | 删除调用方依赖的媒体类型 |
| `schema-variants-changed` | `oneOf` / `anyOf` 分支数量变化 | 始终 breaking |

### 类型与枚举的集合判定细则

schema 约束按**可接受 / 可产出的值集合**比较，而非关键字字面相等：

- **缺省即无约束**：未声明 `type` 视为接受所有基础类型，未声明 `enum` 视为接受该类型下所有值（均为全集，而非空集）。
  因此请求侧新增 `type` / `enum` 是收紧（breaking），响应侧移除 `type` / `enum` 约束是放宽（breaking）；反方向为 info。
- **integer 与 number 的包含关系**：`integer ⊂ number`。请求侧 `integer → number`（放宽）为 info，`number → integer`（收紧）为 breaking；
  响应侧结论相反（`integer → number` 可能产出小数，为 breaking）。
- **OpenAPI 3.0 `nullable: true`** 等价于在值集合中加入 `null`；与 OpenAPI 3.1 的类型联合 `"type": ["string", "null"]` 互相等价，
  两种写法之间迁移不报告。3.1 文档中的 `nullable` 关键字会被忽略（它不是 JSON Schema 2020-12 的关键字）。
- 当 `enum` 存在且未显式列出 `null` 时，`null` 不在允许集合内（此时 `nullable` / 联合中的 `"null"` 不生效）。

## JSON Pointer 约定

- **删除类**变更指向**基线文档**中的位置；**新增 / 修改类**变更指向**候选文档**中的位置。
- 节点为 `$ref` 时，Pointer 会跟随到最终组件定义，例如
  `#/components/schemas/Pet/properties/status`，这是修复契约问题的稳定位置；同一组件被多处引用时
  问题只需在组件定义处修复一次。
- Pointer 遵循 RFC 6901 转义（`~0` → `~`，`~1` → `/`），例如路径 `/pets` 显示为 `/paths/~1pets`。

## `$ref` 解析与循环引用保护

- 仅支持文档内本地引用（`#/...`，含根引用 `#`）；远程 URL、文件路径等非本地引用一律报为
  `unresolvable_reference`（服务不会发起任何外部网络请求）。
- 引用链记录已访问指针：
  - 正常的**递归 schema**（`Node.children -> #/components/schemas/Node`）会被识别并在成环处停止遍历，
    不会无限展开；
  - 纯 `$ref` 死循环（`A -> B -> A`）抛出明确的 `circular reference detected` 错误；
  - 超过 100 层的异常引用链有硬性上限保护；
- 结构比较阶段以“组件指针 / 节点身份 + 比较方向”做记忆化去重，并带有 300 层内联嵌套深度上限，
  双重保证循环引用不会失控。

## 本地开发（不使用 Docker）

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload --port 8080
```

运行测试：

```bash
pytest -q
```

测试覆盖：引用解析（缺失指针、数组越界、远程引用、转义 token、自循环）、操作/参数增删、
类型/枚举/required 双向规则、integer/number 包含、缺省约束、3.0 `nullable` 与 3.1 类型联合、
响应码与媒体类型删除、递归 schema 不爆炸、报告排序；以及 `/slice` 的子契约裁剪、
`$ref` 传递闭包与循环复制一次、未选分支坏引用不阻塞、`security` 继承与 `securitySchemes` 过滤、
3.1 path-level `$ref` 内联、400/422 边界、SHA-256 与键序 / 选择器顺序无关性；
以及 `/compose` 的前缀规范化与根挂载、路径合并与 409 冲突双方来源、security 物化与键前缀、
组件 / `operationId` / tag 命名空间化、`$ref` 改写与 422（外部 / 非 components / 悬空，含源 JSON Pointer）、
path-level `$ref` 链（含多级与中间层同级方法）的冲突检测与来源指针、
同一合成路径上多条 `$ref` 链的合并（非冲突方法内联后均可从输出路径解析、有效方法按同级覆盖取舍）、
循环 / 超深引用链 422、
来源映射完整性、2～20 数量边界、重复 `service_id` 400、被丢弃根字段中的坏引用不阻塞；
以及 `/examples/validate` 的内联 `example` 与 `examples.<name>.value`（含本地 `$ref` 示例组件）校验、
`readOnly` / `writeOnly` 方向报错、`required` 仅对应方向生效、跨 `allOf` 分支（内联与
属性 / 分支本地 `$ref`、嵌套 `allOf`、循环 `allOf`）的方向标记豁免、请求与响应双向回归、
`anyOf` / `oneOf` 备选间不串用分支视图、物理 Schema Pointer 与稳定排序保持不变、
3.0 `nullable` 与 3.1 类型联合、
integer/number 与布尔值区分、enum/const/allOf/anyOf/oneOf/数值·字符串·数组·对象约束关键字、
递归 Schema 不爆炸、按示例与实例 Pointer 稳定排序、同一示例组件复用去重、
`externalValue` / 外部引用 / 悬空引用 / 非对象示例引用 422（含来源 Pointer）、
不可达坏引用不阻塞、非 JSON 媒体类型跳过、400 文档形态错误；
以及 `/overlay/apply` 的受限 JSONPath 解析（点成员 / 引号成员与转义 / 下标 / 通配符、
过滤器与递归下降 422）、`update` 递归合并与整体替换、`remove` 根节点禁止、
同一动作命中冻结与数组倒序删除、后续动作基于前序结果匹配、逐命中独立深拷贝、
零命中 / 非法动作 422（含动作索引）与整批原子性、动作数量 1～50 边界、
请求对象不被修改、命中与报告稳定排序、SHA-256 可复算；
以及 `/requests/materialize` 的 path simple/label/matrix 与 query form/
spaceDelimited/pipeDelimited/deepObject（数组、对象、explode 两种形态、
空集合、重复查询键）、`allowReserved` 与百分号编码（保留字符 / Unicode /
方括号结构符）、header simple 与大小写不敏感匹配、cookie form 序列化与 Cookie
拼接、默认 style/explode、布尔与数值渲染、嵌套结构 / null 值 422、
path-level 与 operation-level 参数合并（后者按 `(in, name)` 覆盖、
仅追加 operation 独有参数）、同级重复参数与仅大小写冲突的 header 参数 422
（含两处 Pointer）、参数与 3.1 path-level `$ref` 解析（悬空 / 外部 / 循环 422、
3.1 同级字段覆盖、3.0 忽略同级）、必填缺失 / 未知值 / 歧义 header 键 422、
路径模板一致性、400 文档 / 选择器 / 请求包体边界、多错误齐报与稳定排序、
输出与输入键序无关、请求对象不被修改；
以及 `/callbacks/resolve` 的固定字面量键、`$url` / `$method` / `$statusCode`
标量渲染、请求 path/query/header/body 与响应 header/body 表达式（含 JSON Pointer
深层取值、数组下标、整体 body 标量、`%HH` 名字解码、header 大小写不敏感）、
模板多表达式与字面文本拼接、结果按来源 Pointer 稳定排序、
缺值（缺 section / 缺字段 / 指针不可达 / `null` / 越界与非法数组下标）、
非标量插值与歧义 header 422、非法表达式（未知根 / 源、response.path、裸变量、
空 / 嵌套 / 未闭合花括号、非法指针转义、非法百分号、空键）、
Callback Object 与 Path Item 本地 `$ref` 解析（多跳、3.1 同级覆盖与 3.0 忽略同级、
表达式 Pointer 跟随到组件）、悬空 / 外部 / 非对象 / 循环引用 422（含回调与表达式
来源 Pointer、path-level `$ref`、根引用 `#` 拒绝）、400 文档 / 选择器 / context 信封边界、
无 callbacks 返回空列表、多错误齐报与输入对象不被修改；
以及 `/security/plan` 的匿名（操作 `security: []`、根 `security: []`、完全无声明）、
根级继承与操作级整体覆盖、OR 多项与项内 AND、最少方案选择与规范 JSON 决胜
（含输入键序无关）、AND 计划按方案名排序、apiKey header/query/cookie、
http basic/bearer（含 bearerFormat）/其他 scheme、oauth2 与 openIdConnect 的
`Authorization: Bearer` 注入位置与来源 Pointer、oauth2 scope 满足 / 缺失 /
无凭证区分、openIdConnect scope 不枚举校验、Security Scheme 本地 `$ref`（单跳 /
多跳、3.0 忽略同级与 3.1 同级覆盖、循环 / 外部 / 悬空 / 根引用 / 目标非对象 422）、
未定义方案名与缺失 securitySchemes、非法 type、apiKey/http/oauth2/openIdConnect
定义校验（含各 flow URL 与 scopes、至少一个 flow）、scope 与方案类型一致性、
`security` / requirement / scope 容器形态错误、多错误齐报稳定排序、
无可满足项仍 200 且逐项列出缺失方案与 scope、400 文档 / 选择器 / granted 信封边界、
3.1 path-level `$ref` 提供操作、路径 token 的 RFC 6901 转义、
秘密值不回显（200 与 400）、请求对象不被修改、重复 scope 去重；
以及 `/links/plan` 的 Response 精确 / `nXX`（大小写不敏感）/ `default` 选择顺序
（数字与字符串状态码）、缺 statusCode 与无匹配 Response 422、未知 Link 名、
Response / Link 本地 `$ref`（多跳、3.1 同级覆盖与 3.0 忽略同级、组件来源 Pointer）、
悬空 / 外部 / 非对象 / 循环引用（Response 与 Link 两条链）422、
目标 Path Item 自身 `$ref` 与目标参数 `$ref` 解析、
本地 `operationRef`（RFC 6901 转义、根引用、非方法末段、缺失方法、悬空 / 外部指针、
指向 components Path Item 时 path 为 null）与 `operationId`（未定义 / 重复 / 唯一）定位、
两者同给或均不给 422、path-level 与 operation-level 参数合并（后者覆盖、歧义检测）、
映射键未知 / 跨位置同名歧义 / 必填未赋值 422、可选跨位置同名省略合法、
Runtime Expression 映射（body/path/query 结构化值允许、header 标量与大小写不敏感、
歧义 header、缺值 / null / 不可达、非法完整表达式、含花括号的非常量字面量、
`$statusCode`）、字面常量（数字 / 对象 / 数组 / null）、`requestBody` 省略与缺值、
400 文档 / 选择器 / Link 名 / context 信封边界、错误齐报稳定排序、
输入不被修改与无半成品；以及 `/interactions/graph` 的契约 / 回调节点编址
（`/paths` 出现位置 vs 声明位置、共享 components Path Item 单节点多边、
挂载型 path-level `$ref`、方法键大小写保留）、Link 边（全部响应键含 `nXX` 与
`default`、`operationRef` 指向 paths / `components/pathItems` / 转义路径 /
经 `$ref` 的 Path Item、`operationId` 定位、多声明到达同一目标各自保留来源）、
回调边（内联与组件 Callback Object / Path Item、多方法 Path Item、URL 模板原文）、
3.0 忽略 `$ref` 同级与 3.1 近端覆盖（Link 与 Callback 两条链、Path Item 同级方法覆盖）、
回调操作不再作为边的来源、重复 `operationId` 全局校验（未被 Link 使用也 422）、
悬空 / 外部 / 循环 / 根引用 422（path item / Response / Link / Callback /
回调 Path Item 各位置）、非法容器与操作形态 422、错误齐报稳定排序且不返回半成品、
节点与边按 Pointer 稳定排序、400 文档形态边界、输入不被修改；
以及 `/representations/select` 的响应精确 / `nXX`（大小写不敏感、1XX/3XX/5XX）/
`default` 选择（整数与字符串状态码、无匹配 422、状态码取值校验）、
请求 Content-Type 匹配（额外参数放行、声明参数必须同值齐备、参数名大小写不敏感 / 值大小写敏感、
type/subtype 通配与具体度决胜、参数数决胜、同权声明顺序、通配 Content-Type 与语法错误 400、
必填缺头 / 空 content 415、415 携带 supported 列表）、
Accept 协商（最具体区间赋 q、`type/*` 与 `*/*` 层次、同权声明顺序、参数包含、
`q=0` 排除、空 Accept 全拒、缺省 `*/*`、权重数字格式与带引号 q、空白与大小写、
结构化后缀不做子串匹配、406 携带 available）、
无请求体 / 可选请求体 / 无内容响应（204 不触发 406）、
内联 example 与具名 Example Object（含本地 `$ref` 跟随到组件 Pointer、无 value 为 null、
examples 按名排序）、`externalValue` 422、
requestBody / Response / path item / Example 本地 `$ref`（多跳、3.0 忽略同级与 3.1
近端覆盖合并、悬空 / 外部 / 非对象 / 循环 / 根引用 422）、schema 内部 `$ref` 原样返回不展开、
结构非法（缺 content、非对象 media node、非法媒体类型键、examples 容器）422、
415 优先于 406、契约 422 优先于协商错误、400 文档 / 选择器 / 信封边界、
错误不返回半成品与输入对象不被修改等共 633 个用例。

## 项目结构

```
.
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI 路由、请求/响应模型、输入校验（/audit、/slice、/compose、/examples/validate、/overlay/apply、/requests/materialize、/callbacks/resolve、/security/plan、/links/plan、/interactions/graph 与 /representations/select）
│   ├── audit.py         # 契约比较引擎（操作/参数/请求体/响应/schema）
│   ├── slicer.py        # 最小子契约切片（选择器校验、security 继承、$ref 闭包重建、SHA-256）
│   ├── composer.py      # 网关契约合成（前缀规范化、命名空间化、$ref 改写、冲突检测、来源映射）
│   ├── examples.py      # 媒体类型示例校验（方向化 readOnly/writeOnly/required、3.0/3.1 可空性、JSON Schema 关键字）
│   ├── overlay.py       # 有序覆盖动作（受限 JSONPath 解析、命中冻结、递归合并/倒序删除、SHA-256）
│   ├── materializer.py  # 请求物化（参数合并、循环安全 $ref、path/query/header/cookie 样式序列化、百分号编码）
│   ├── callbacks.py     # 回调 URL 解析（Runtime Expression、JSON Pointer body 片段、循环安全 Callback/Path Item $ref）
│   ├── linkplanner.py   # Link 后续调用计划（Response 精确/nXX/default 选择、Response/Link/Path Item 循环安全 $ref、operationRef/operationId 定位、参数与请求体表达式求值、来源 Pointer）
│   ├── interactions.py  # 契约交互图（稳定节点、Link/回调有向边、重复 operationId 校验、错误齐报、Pointer 稳定排序）
│   ├── negotiation.py   # HTTP 内容协商（Content-Type 参数包含/通配具体度、Accept 最具体区间与 q 权重、精确/nXX/default 响应选择、requestBody/Response/Example 循环安全 $ref、3.0/3.1 同级合并、来源 Pointer）
│   ├── security.py      # 受保护操作鉴权规划（OR/AND security、方案 $ref 循环解析、apiKey/http/oauth2/openIdConnect 校验、注入位置与来源 Pointer）
│   └── refresolver.py   # 本地 $ref 解析（RFC 6901 指针 + 循环检测）
├── tests/
│   ├── test_audit_api.py
│   ├── test_slice_api.py
│   ├── test_compose_api.py
│   ├── test_examples_api.py
│   ├── test_overlay_api.py
│   ├── test_materialize_api.py
│   ├── test_callbacks_api.py
│   ├── test_security_api.py
│   ├── test_links_api.py
│   ├── test_interactions_api.py
│   └── test_negotiation_api.py
├── Dockerfile           # 容器封装全部依赖，非 root 用户运行，含 HEALTHCHECK
├── docker-compose.yml   # 一条命令启动，映射 8080 端口
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

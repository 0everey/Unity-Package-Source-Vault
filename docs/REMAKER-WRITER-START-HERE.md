# ReMaker 原 writer 接入入口

目标是在 metadata 可读之后、昂贵 native 分析／草案选集之前，先辨认已有库，再决定复用、暂缓找包或继续恢复。用户已允许本窗口以文档交接；当前状态是 **adapter-ready / integration-pending**，没有修改 ReMaker 生产文件、采用源码或运行游戏。

## 1. 固定入口

```powershell
python -m pip install "git+https://github.com/0everey/Unity-Package-Source-Vault.git"
uvault --help
uvault identify --input <已有StructureAnalysis目录或实际Unity包> --out <新识别目录>
uvault resolve --matches <识别目录>/matches.json --out <libraries.lock.json>
uvault materialize --lock <libraries.lock.json> --target <唯一使用目录>
uvault export-remaker --lock <libraries.lock.json> --materialized <使用目录>/.uvault-receipt.json --out <REMAKER-LIBRARIES.json>
uvault classify --inventory <DECLARATIONS.json> --profile <profile.json> --out <新分类目录>
```

默认 catalog 为仓库 `main/catalog/catalog.json`，实际加载会先固定 Git commit。正式采用时记录实际 commit 并将 registry URL 中的 main 换成它。`resolve` 不会从歧义版本中选择 latest；手工选择也不会升级证据。退出码 0 为该操作成功、2 为无效／失败、3 为部分／未决。

## 2. 原 writer 提供完整原始声明

消费 Core 已有身份和 `MetadataIndex.Read(dumpPath, target)`／既有 SRM 结构导出，不重新解码 IL2CPP，也不先生成全量 native 草案。保留所有声明 ID，包括未知、零地址、无上界方法；按原 dump 的 typeIndex 映射程序集，不按 namespace 或源码首目录猜归属。

完整规范与合成样例见 [CLASSIFICATION.md](CLASSIFICATION.md)。输入核心字段：

```json
{
  "schemaVersion": "1.0",
  "targetId": "<Core原始身份>",
  "dumpSha256": "<实际dump SHA256>",
  "inputSha256": "<原始声明输入SHA256>",
  "declarations": [{
    "id": "<原始method ID>",
    "assemblyIdentity": {"name": "<实际程序集>", "version": "<实际版本>"},
    "typeFullName": "<完整类型>",
    "memberSignature": "<原始签名>",
    "aliases": [],
    "nativeAddress": "0x1000",
    "evidenceRefs": [{"kind": "original-metadata"}]
  }],
  "completeScope": {"complete": true, "declarationCount": 1, "declarationIds": ["<原始method ID>"]}
}
```

`completeScope` 必须从分类前的原始清点独立生成。不要从分类输出反填“完整范围”。共享地址和泛型 alias 保留声明身份；大量重复 alias 可用有据的星形关系及完整 group 表规范化，但不得丢掉原始组。

## 3. 接入位置与动作

在原项目 `scripts/benchmark-installation.py` 的 source-mapping-and-selection 阶段，以及 `tools/map_draft_sources.py` 产生选集之前接入，替换少数程序集硬编码的包判断。保留现有源码盘点、原生 eligibility 和 Core 认证。

| nativeAction | 本轮去向 |
| --- | --- |
| recover-native | 保留原恢复资格；业务、私改、弱线索、未知、应用生成代码进入这里 |
| defer-library-resolution | 暂缓昂贵草案，进入找包／辨版本／差分队列；仍未恢复 |
| provider-reference | 已登记准确程序集身份与至少两个模块官方 API 特征确认的 Unity 内置模块直接引用、跳过实现还原；安装／Unity 版本／profile 未证仍 pending、false |
| reuse-upstream / skip-native | 仅在原 writer 接收具名成员范围和已确认来源后减少恢复任务 |
| regenerate | 仅在生成器和完整输入已核实后进入再生成队列；不冒执行完成 |

R5 当前库为 43 个常用包族、23 个内置模块及 7 个商业／Editor／受限／待辨参考项，每包两至三版，实际缺口再补。SRP 17／14、UGUI 2 等 Editor 随附版本有固定官方 manifest／源码入口而无可下载归档时，保持 official-fetch-only、artifact=null、reference-only；不能当 exact 或静默改用旧版。独立包继续进入找源／辨版队列，不改称内置模块。

R5 补充见 [R5-ADDITIONS.md](R5-ADDITIONS.md)。Sentry 的 `sdkBundle` 保存每个实际 SDK 归档随附程序集的 full identity／version／SHA／相对路径，不以通用 `System.*` 代替 `Sentry.System.*`。Best HTTP 的已知 assembly 与官方 release 只能作商业版本候选，取材走官方商店或合法使用者提供，不冒原版正文已认证。Sprite 1.0.0 是 Editor core package，没有另造 Sprite runtime provider。

`namedPending` 必须从 matches 经过 lock/export 保留。Tekly／OOI 的 namespace 或程序集命中后，即使公共同名库有强候选、字节相同的当前源码或普通 `sourceConfirmed` 决定，也不清来源／原游戏差分未闭；分类仍 `recover-native`，同时列入找源工作集。原 writer 后续须核具体来源／版本／原目标差分，再作独立采用，不能按当前同名或当前恢复工程相等替换。

JSONSerialize／ImageConversion 的局部例外只在同完整 identity、唯一注册 type 内以两个不同 public static 完整签名确证；路由限定该 type。TextCore／XR／VR 继续双类型。provider 身份不等实现相同、已安装、编译通过或已恢复。

读取新字段 `nativeAction`。旧 `skipNativeRecovery` 始终为 false，不能用它表达“暂缓”。`isRecovered`、采用、编译、运行与调度分别记录。下载失败不自动把整个插件重新投入 native，也不永久排除它。

生成文件是 `CLASSIFICATION.json`、`LIBRARY-RESOLUTION-WORKSET.json`、`GENERATED-CODE-WORKSET.json`、`NATIVE-SELECTION-PROPOSAL.json`、`CLASSIFICATION-SUMMARY.json`。分类器会保留完整声明去向、外部未知 alias、源引用与缓存绑定。

## 4. 与现有 Core selection 的桥

proposal 明确 `authenticated=false`、`sourceInventory=null`，**不能直接传给现有 DraftSelection**。由原 writer：

1. 核 binding 的 target/dump/input/catalog/profile 与当前 Core 一致，并逐 ID 对账完整原始清点。
2. 从 `recover-native` ID 与现有真实、已认证 baseline selection 取交集；继续执行原有非零地址、上界、源码占用等 eligibility，不因分类器重放已有正文。
3. 将新 ID 列表写到一个新 selection，保留原 baseline 的实际 `sourceInventory` 引用和 SHA。不得伪造 census；metadata-only 模式若需支持，应由 Core 明确实现认证合同。
4. 交现有 `DraftSelection.Prepared` 独立验证。按声明分流，不按共享 VA 删除；同址业务 alias 仍参与地址分析。

采用决定须精确到程序集／类型／成员，绑定分类器输出的 `binding`，并有真实 writer receipt。名称、候选状态、DummyDLL hash 或 API 子集均不能证明原始正文相同。

## 5. 恢复与验收

```powershell
uvault classify --inventory <原DECLARATIONS.json> --profile <原profile.json> --restore-id <暂缓ID> --restore-reason "核查项目差分" --out <新恢复分类目录>
```

恢复会让有证 owner 的状态机／闭包链同步回到 native，保留找源未闭与恢复原因；不会继承或扩大采用范围。缓存键包含 target、dump/input、catalog commit/content、classifier、profile 和决策／恢复参数，变化后重新判定。

接回时核：每个原始声明恰有一个去向；库/业务共 VA、未知 alias、私改、同名业务、应用 protobuf 消息不丢；受限包先走合法源；离线和坏 SHA 不伪造取材；catalog/profile/dump 变化使旧结果失效；恢复 owner 能接回执行成员。

最后在 ReMaker 自己的工作区写回执：采用的 export/classification SHA、Core 输入身份、原／新 selection SHA、各动作声明数、保留业务 alias、找源／差分未闭、实际 writer 及验证结果。没有同输入前后计时就不写固定加速倍数。减少插件派工也不计作新增游戏逻辑恢复。

实际输入对照和采集状态以交付回执为准。声明去向守恒不证明 selection 已减少；使用更新目录重判后，仍需独立记录实际采用与工作变化。

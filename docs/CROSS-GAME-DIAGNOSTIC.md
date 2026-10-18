# R7 跨项目 metadata 诊断

本报告衡量固定公开样本内的 ID／版本记录，不能换算为市场覆盖率、游戏还原概率或编译通过率。
输入含 13 个仓库：6 个诊断、2 个此前已用于来源/选版证据的诊断、5 个未用于选版的对照。12 个至少观察到一份 manifest 或 lock；1 个 metadata 不可用保留在面板中。
完整 Runtime 消费者清点未取得，因此每项目及汇总的完整 Runtime 分母、比例均为 null。模板默认模块、Editor/Test 声明和未知消费者不冒实际运行依赖。

- 基线：`6d2e090768da3e294ae9f61f37a7e7690857236a`。
- R7 目录快照：`78317f743add445c2dc476393f1127dd32b6ecbe`。
- 输入文件 SHA256：`7db1c3ed9346af5bd6a848ed351065ca29f19caae74f2213dd74a88f88909763`；前后输入内容相同。
- [修正后逐项原始结果](verification/r7-panel-final.json)；[固定公开输入及来源 URL/SHA](../sources/coverage-panel-r7.json)。
- [9d 冻结测量原件](coverage-panel-r7-comparison.json)保留；随后许可／嵌入来源修正没有改变下列统计。

## 同输入前后结果

分母是面板内项目的已观察声明／版本计数，跨项目重复出现的 ID 分别计入；不是包生态或游戏总数。“已取得”只说 vault 已取得该 ID/版本标签的归档，不证明样本项目采用了相同来源、fork、变体或字节。

| 观察口径 | R6 | R7 | 新增观察命中 |
| --- | --- | --- | --- |
| manifest 声明 ID 已登记 | 293/550 | 362/550 | +69 |
| manifest/lock 观察 ID 已登记 | 332/652 | 416/652 | +84 |
| 观察到的精确版本标签已有记录 | 241/645 | 322/645 | +81 |
| 对应版本标签的归档已取得 | 11/645 | 41/645 | +30 |
| 对应版本标签仅有引用记录 | 230/645 | 281/645 | +51 |

仅引用记录含 Editor／内置 provider，不计作取得载荷；许可 metadata 不等于许可已独立清关。真实工程的安装、配置、程序集去重、平台、编译和运行均未在本任务执行。

## 逐项目观察

| 项目 | Editor 观察 | 分组 | ID 登记 R6 → R7 | 精确版本记录 R6 → R7 | R7 已取得对应归档 |
| --- | --- | --- | --- | --- | --- |
| [Unity-Technologies/BoatAttack](https://github.com/Unity-Technologies/BoatAttack) | 2020.3.23f1 | 诊断 | 28/44 → 32/44 | 19/44 → 27/44 | 3/44 |
| [Unity-Technologies/FPSSample](https://github.com/Unity-Technologies/FPSSample) | 2018.3.8f1 | 诊断 | 28/46 → 34/46 | 19/46 → 30/46 | 8/46 |
| [UnityTechnologies/open-project-1](https://github.com/UnityTechnologies/open-project-1) | 2020.3.17f1 | 诊断 | 33/61 → 40/61 | 20/61 → 28/61 | 3/61 |
| [Unity-Technologies/arfoundation-samples](https://github.com/Unity-Technologies/arfoundation-samples) | 6000.5.0b2 | 诊断 | 25/51 → 34/51 | 20/51 → 24/51 | 1/51 |
| [Unity-Technologies/com.unity.multiplayer.samples.coop](https://github.com/Unity-Technologies/com.unity.multiplayer.samples.coop) | 6000.0.52f1 | 诊断 | 39/83 → 49/83 | 27/82 → 38/82 | 9/82 |
| [Unity-Technologies/2d-techdemos](https://github.com/Unity-Technologies/2d-techdemos) | 6000.3.3f1 | 诊断 | 32/60 → 40/60 | 23/60 → 30/60 | 3/60 |
| [Noxalus/Unity-TowerDefense](https://github.com/Noxalus/Unity-TowerDefense) | 未观察（metadata 不可用） | 未用于选版的对照 | 未定 → 未定 | 未定 → 未定 | 未定 |
| [BayatGames/RedRunner](https://github.com/BayatGames/RedRunner) | 6000.2.6f2 | 已知证据诊断 | 24/46 → 29/46 | 21/46 → 26/46 | 0/46 |
| [unitystation/unitystation](https://github.com/unitystation/unitystation) | 6000.2.10f1 | 已知证据诊断 | 25/56 → 32/56 | 20/51 → 24/51 | 2/51 |
| [Unity-Technologies/megacity-metro](https://github.com/Unity-Technologies/megacity-metro) | 6000.1.0f1 | 未用于选版的对照 | 41/91 → 54/91 | 27/91 → 33/91 | 6/91 |
| [SebLague/Geographical-Adventures](https://github.com/SebLague/Geographical-Adventures) | 2021.3.2f1 | 未用于选版的对照 | 22/41 → 26/41 | 19/41 → 25/41 | 1/41 |
| [Unity-Technologies/EndlessRunnerSampleGame](https://github.com/Unity-Technologies/EndlessRunnerSampleGame) | 2021.3.6f1 | 未用于选版的对照 | 30/59 → 40/59 | 21/58 → 31/58 | 5/58 |
| [SebLague/Digital-Logic-Sim](https://github.com/SebLague/Digital-Logic-Sim) | 6000.0.46f1 | 未用于选版的对照 | 5/14 → 6/14 | 5/14 → 6/14 | 0/14 |

## 来源与剩余缺口

manifest 要求与 lock 观察分别保留。2D Tech 的 Extras Git 要求与 lock registry 6.0.1 是来源冲突；Unitystation 的 fork、未固定 Git/file 来源和 sourcePath 不因同名或版本标签相等就认证上游变体。逐项冲突、未收版本、仅引用、受限许可及未知对象均在 JSON 内保留。
已知旧项目的实际版本需求解释了本轮增补，但同类包的其它 patch、Editor/Test 工具和冷门包不会因此自动入队。后续只按真实消费者的 package/version/reason 请求，在逐包预算内增量补齐。
来源 URL/SHA 与 metadata 本身只证明本轮观察；本任务没有下载这些游戏或执行游戏。实际源包 CLI 取材验证单列于 [R7 增补交付](R7-ADDITIONS.md)。

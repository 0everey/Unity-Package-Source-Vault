# Vendor package increment - 2026-10-18

The public catalog now contains 190 entries, up from 162. This increment adds 22 official commercial acquisition entries and six fixed original source snapshots. Product entries without original payloads remain acquisition gaps. These counts do not measure project coverage.

## Available original source archives

| Entry | Fixed source | State |
| --- | --- | --- |
| Amplify.Color | `6d82f8c064fa614f01216fcf5f1d8ab8387450e8` | Stored in Releases; anonymous SHA-256 readback passed |
| Amplify.Occlusion | `dd6316f2da651cc5266698cd87f65c70f7d82504` | Stored in Releases; anonymous SHA-256 readback passed |
| Amplify.Bloom | `c66d459dc4025202ef75798c8ad5e7cafe25261d` | Official upstream acquisition; full archive redistribution remains unresolved |
| Amplify.Motion | `e658d333be1717cd85eb9a235aa34e8216674c86` | Official upstream acquisition; full archive redistribution remains unresolved |
| Dreamteck.Splines | `119cc0041b448b430b498ca7e72357e30d0a3103` | Stored in Releases; anonymous SHA-256 readback passed |
| Dreamteck.Utilities | `b486e4d7ca897497af39bafc0a63927fac0e598f` | Official upstream acquisition; full archive redistribution remains unresolved |

Amplify Color and Occlusion use explicitly selected older MIT snapshots before the vendor added unrelated Unity Asset Store publishing tools. They are original upstream snapshots; later changes are not implied. Bloom currently bundles those publishing tools; Motion contains DLL components. Their official root MIT notice does not clear every bundled component automatically.

Dreamteck Splines requires its Utilities submodule at `b486e4d7ca897497af39bafc0a63927fac0e598f`. The parent archive alone is incomplete. Utilities has no independently detected root license in this selected archive, so it remains an official-source acquisition instead of a public mirror grant. Import only the named component directories; whole upstream Unity sample projects include unrelated Packages and ProjectSettings.

## Unity 2022 check

Amplify Color and Occlusion compiled together, with original vendor C# bytes unchanged, in an isolated Unity 2022.3.45f1 project. The project required the built-in VR and XR modules. See [the bounded compilation receipt](verification/vendor-source-2022-compile.json). Rendering output, shaders, Player builds and target-project compatibility were not validated. No game was run for this increment.

## Download and import the two verified originals

These links require no GitHub login:

| Original source archive | Component to import |
| --- | --- |
| [Amplify Color](https://github.com/0everey/Unity-Package-Source-Vault/releases/download/objects-8f/8f306296d80af72a783e61fa6a1f25d95a4e16b524389118279e0b54c0ceba12.tar.gz) | `Assets/AmplifyColor` |
| [Amplify Occlusion](https://github.com/0everey/Unity-Package-Source-Vault/releases/download/objects-cd/cd8414f0fd06db9027b7359d07d2402bc91e19336ae48ad7dcb368b5ccb74737.tar.gz) | `Assets/AmplifyOcclusion` |

Extract the selected archive and copy its named component into your Unity project's `Assets` directory. Preserve each archive's root `LICENSE` with that component, for example as `Assets/AmplifyColor/LICENSE` and `Assets/AmplifyOcclusion/LICENSE`. Enable the built-in VR and XR modules; the compilation receipt above lists the complete module set used for validation. Importing the archive's upstream `Packages` or `ProjectSettings` is unnecessary for these components.

The [public download acceptance](verification/vendor-source-public-download.json) loads the actual catalog at commit `73f26cf4dd8ad92beb3a9e919614602bc1621da3`, selects these two source snapshots explicitly, and exercises `uvault resolve` and `uvault materialize`. Anonymous archive downloads, all 357 catalog file hashes, both license sidecars, and offline receipt reuse passed. Resolve retains `candidate` with exit code 3 because requesting an original source is not evidence of equivalence to a user's existing project; materialization and offline reuse return 0. This download check does not extend the compilation scope above.

## Commercial original acquisition gaps

The following 22 products were absent from the original public catalog and are now explicit entries. Existing commercial entries such as DOTween Pro, Rewired, Odin Inspector, Final IK and I2 Localization are retained. Company ownership does not create a public redistribution grant; originals must be acquired through the licensed owner and stored privately when required.

| Entry | Product | Official acquisition |
| --- | --- | --- |
| Amplify.Impostors | Amplify Impostors | https://amplify.pt/unity/amplify-impostors/ |
| Amplify.ShaderEditor | Amplify Shader Editor | https://amplify.pt/unity/amplify-shader-editor/ |
| AwesomeTechnologies.VegetationStudioPro | Vegetation Studio Pro | https://www.awesometech.no/index.php/home/vegetation-studio/ |
| Bakery.Lightmapper | Bakery GPU Lightmapper | https://geom.io/bakery/ |
| Doozy.UI | Doozy UI | https://doozyui.com/ |
| EasyRoads3D | EasyRoads3D | https://www.easyroads3d.com/ |
| Febucci.TextAnimator | Text Animator | https://www.febucci.com/text-animator-unity/ |
| GPUInstancer | GPU Instancer | https://www.gurbu.com/gpu-instancer |
| HutongGames.PlayMaker | PlayMaker | https://hutonggames.com/ |
| Kybernetik.Animancer | Animancer | https://kybernetik.com.au/animancer/ |
| MoreMountains.CorgiEngine | Corgi Engine | https://corgi-engine.moremountains.com/ |
| MoreMountains.Feel | Feel | https://feel.moremountains.com/ |
| MoreMountains.TopDownEngine | TopDown Engine | https://topdown-engine.moremountains.com/ |
| Opsive.BehaviorDesigner | Behavior Designer | https://opsive.com/assets/behavior-designer/ |
| Opsive.UltimateCharacterController | Ultimate Character Controller | https://opsive.com/assets/ultimate-character-controller/ |
| ParadoxNotion.NodeCanvas | NodeCanvas | https://nodecanvas.paradoxnotion.com/ |
| PixelCrushers.DialogueSystem | Dialogue System for Unity | https://www.pixelcrushers.com/dialogue-system/ |
| ProceduralWorlds.Gaia | Gaia | https://www.procedural-worlds.com/products/indie/gaia/ |
| RenderHeads.AVProVideo | AVPro Video | https://www.renderheads.com/products/avpro-video/ |
| StompyRobot.SRDebugger | SRDebugger | https://www.stompyrobot.uk/tools/srdebugger/ |
| SuperScrollView | Super ScrollView | https://assetstore.unity.com/packages/tools/gui/super-scrollview-86572 |
| VirtualMethod.Obi | Obi | https://obi.virtualmethodstudio.com/ |

No company project extracts, local inventories, local paths, commercial raw packages or private runtime evidence are included in this public increment. Trial/free editions and API alternatives do not satisfy commercial original-package gaps.

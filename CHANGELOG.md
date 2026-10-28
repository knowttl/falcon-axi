# Changelog

## [0.8.2](https://github.com/knowttl/falcon-axi/compare/v0.8.1...v0.8.2) (2026-10-28)


### Bug Fixes

* align CLI descriptions and reorganize user documentation ([#82](https://github.com/knowttl/falcon-axi/issues/82)) ([62ad887](https://github.com/knowttl/falcon-axi/commit/62ad887b8d60166f23c6604a1ac1b83b6cf9740c))
* guide agents directly into bounded investigations ([#85](https://github.com/knowttl/falcon-axi/issues/85)) ([a3e2500](https://github.com/knowttl/falcon-axi/commit/a3e2500c99a1563d2803144c9453317c49ed5f53))

## [0.8.1](https://github.com/knowttl/falcon-axi/compare/v0.8.0...v0.8.1) (2026-10-28)


### Bug Fixes

* collect remaining RTR output chunks ([#80](https://github.com/knowttl/falcon-axi/issues/80)) ([0d18970](https://github.com/knowttl/falcon-axi/commit/0d18970cb0a587c056fa68224278cc33fcc08299))

## [0.8.0](https://github.com/knowttl/falcon-axi/compare/v0.7.5...v0.8.0) (2026-10-27)


### Features

* **cli:** validate CQL structure before starting searches ([#78](https://github.com/knowttl/falcon-axi/issues/78)) ([21163ad](https://github.com/knowttl/falcon-axi/commit/21163ad75b080ea573df6bdf618abe9281816033))

## [0.7.5](https://github.com/knowttl/falcon-axi/compare/v0.7.4...v0.7.5) (2026-10-27)


### Bug Fixes

* improve NG-SIEM search diagnostics ([#76](https://github.com/knowttl/falcon-axi/issues/76)) ([5d0c1ba](https://github.com/knowttl/falcon-axi/commit/5d0c1ba1e95ce46161a549bcd019a90c714efeec))

## [0.7.4](https://github.com/knowttl/falcon-axi/compare/v0.7.3...v0.7.4) (2026-10-27)


### Bug Fixes

* preserve application inventory fields and host details (TD-017) ([#74](https://github.com/knowttl/falcon-axi/issues/74)) ([48b1237](https://github.com/knowttl/falcon-axi/commit/48b123713b4c1e63ada2fd26f116de50acfd5266))

## [0.7.3](https://github.com/knowttl/falcon-axi/compare/v0.7.2...v0.7.3) (2026-10-27)


### Bug Fixes

* clarify parsed_query guidance in search status ([#72](https://github.com/knowttl/falcon-axi/issues/72)) ([5d1accd](https://github.com/knowttl/falcon-axi/commit/5d1accdd0c23819cbac15f218024d370b4ea9605))

## [0.7.2](https://github.com/knowttl/falcon-axi/compare/v0.7.1...v0.7.2) (2026-10-23)


### Bug Fixes

* limit the RTR command set to commands the API accepts and record per-platform availability ([#71](https://github.com/knowttl/falcon-axi/issues/71)) ([a480ffd](https://github.com/knowttl/falcon-axi/commit/a480ffd3409bcecc1d06ec920e1822c8a51ad773))
* name the command when Falcon rejects an RTR command as not found ([#69](https://github.com/knowttl/falcon-axi/issues/69)) ([91551b8](https://github.com/knowttl/falcon-axi/commit/91551b8abfaf8fb9bc2a435f58fb3a9610805494))

## [0.7.1](https://github.com/knowttl/falcon-axi/compare/v0.7.0...v0.7.1) (2026-10-23)


### Bug Fixes

* remove the console-only help command from the RTR command set ([#65](https://github.com/knowttl/falcon-axi/issues/65)) ([682cf37](https://github.com/knowttl/falcon-axi/commit/682cf3761adfb7afd087604d0d68945cd0612bfb))
* return the output of a completed RTR command whose final status omits sequence_id ([#64](https://github.com/knowttl/falcon-axi/issues/64)) ([4c7c832](https://github.com/knowttl/falcon-axi/commit/4c7c8321dc1b355421cdf0074dab5ed1d035192f))


### Documentation

* teach the skill how to run RTR commands and read their results ([#67](https://github.com/knowttl/falcon-axi/issues/67)) ([7b82e20](https://github.com/knowttl/falcon-axi/commit/7b82e203b3819972cc1b3165377bc613c93dec2c))

## [0.7.0](https://github.com/knowttl/falcon-axi/compare/v0.6.0...v0.7.0) (2026-10-23)


### Features

* add bounded MalQuery exact and fuzzy searches ([#61](https://github.com/knowttl/falcon-axi/issues/61)) ([067d607](https://github.com/knowttl/falcon-axi/commit/067d6070c9d48357eaea6413deb652bad3518aed))
* add Device Control policy USB details ([#58](https://github.com/knowttl/falcon-axi/issues/58)) ([e1773ac](https://github.com/knowttl/falcon-axi/commit/e1773acc92a68d70ba2ebd574739f4085c163992))
* add existing sandbox report lookup ([#55](https://github.com/knowttl/falcon-axi/issues/55)) ([62c9089](https://github.com/knowttl/falcon-axi/commit/62c90897ef232e5fe93d3e2c14c8f8680ffa6f86))
* add host USB activity searches ([#59](https://github.com/knowttl/falcon-axi/issues/59)) ([f2650b0](https://github.com/knowttl/falcon-axi/commit/f2650b0987c99bb8cb50ec340f86d7c7cd1b9422))
* add MalQuery metadata and quota commands ([#60](https://github.com/knowttl/falcon-axi/issues/60)) ([f4d0794](https://github.com/knowttl/falcon-axi/commit/f4d0794eab01d5cb12760f68839dd899f73f2e6c))
* add process details and investigation pivots ([#51](https://github.com/knowttl/falcon-axi/issues/51)) ([106b941](https://github.com/knowttl/falcon-axi/commit/106b94190f9c2bbf3c7dcfb0216eb09e146b1f6a))
* add read-only FileVantage change history ([#57](https://github.com/knowttl/falcon-axi/issues/57)) ([9d4fab5](https://github.com/knowttl/falcon-axi/commit/9d4fab5f0ee718b43207821dc59ae1d9caab7ea9))
* add ThreatGraph process tree investigation ([#54](https://github.com/knowttl/falcon-axi/issues/54)) ([1387d46](https://github.com/knowttl/falcon-axi/commit/1387d465c9762e47cac471ef6292d7b08761e0f4))

## [0.6.0](https://github.com/knowttl/falcon-axi/compare/v0.5.1...v0.6.0) (2026-10-23)


### Features

* add guarded RTR read-only execution core ([#48](https://github.com/knowttl/falcon-axi/issues/48)) ([a6b7e6b](https://github.com/knowttl/falcon-axi/commit/a6b7e6b3072ba6c8a71421a2b56031baeb134526))
* add read-only RTR session and audit history commands ([#47](https://github.com/knowttl/falcon-axi/issues/47)) ([5a40e69](https://github.com/knowttl/falcon-axi/commit/5a40e694e674eb41736060012cdc64bf04c1f443))
* **cli:** expose guarded read-only RTR command execution ([#50](https://github.com/knowttl/falcon-axi/issues/50)) ([c7203d0](https://github.com/knowttl/falcon-axi/commit/c7203d03b27089779952a6fbf96919d4b1bd058b))
* **falcon_axi:** add detection process lineage view ([#49](https://github.com/knowttl/falcon-axi/issues/49)) ([085ea6d](https://github.com/knowttl/falcon-axi/commit/085ea6d95b3de1fc7e0acfa0f04b3f6997992e30))


### Documentation

* define guarded read-only RTR design and rollout ([#45](https://github.com/knowttl/falcon-axi/issues/45)) ([efe7efc](https://github.com/knowttl/falcon-axi/commit/efe7efcf897d01431107ebad86621283d56ce32f))

## [0.5.1](https://github.com/knowttl/falcon-axi/compare/v0.5.0...v0.5.1) (2026-10-22)


### Bug Fixes

* support group help and bounded search polling ([#43](https://github.com/knowttl/falcon-axi/issues/43)) ([84fde6b](https://github.com/knowttl/falcon-axi/commit/84fde6b2df1ae4b3b603db9fe56ab266c1ee653c))

## [0.5.0](https://github.com/knowttl/falcon-axi/compare/v0.4.1...v0.5.0) (2026-10-19)


### Features

* add bounded pagination walks to list commands ([#22](https://github.com/knowttl/falcon-axi/issues/22)) ([72b5e77](https://github.com/knowttl/falcon-axi/commit/72b5e77c2aae3360a9002393cdc2009f996cd3bb))
* add cloud inventory and posture read commands ([#33](https://github.com/knowttl/falcon-axi/issues/33)) ([6a12848](https://github.com/knowttl/falcon-axi/commit/6a1284875e0fee00683751d3ec0fedf3bf7baeee))
* add detection severity summary ([#14](https://github.com/knowttl/falcon-axi/issues/14)) ([fd5b316](https://github.com/knowttl/falcon-axi/commit/fd5b316a400465588588e03830afbc0cf703394a))
* add Falcon Intelligence actor and report commands ([#19](https://github.com/knowttl/falcon-axi/issues/19)) ([82a1529](https://github.com/knowttl/falcon-axi/commit/82a1529f8880d239a57ac6a4e2e2776f1c661f14))
* add Falcon Intelligence indicator commands ([#16](https://github.com/knowttl/falcon-axi/issues/16)) ([d6ad054](https://github.com/knowttl/falcon-axi/commit/d6ad05410f7f9917b6429e6f9ae5e791f3f64f41))
* add generated agent skill and home installation hint ([#13](https://github.com/knowttl/falcon-axi/issues/13)) ([e227137](https://github.com/knowttl/falcon-axi/commit/e22713775391c94ab0897e3a1cbbe32582ccc138))
* add per-command skill references and split golden fixtures ([#36](https://github.com/knowttl/falcon-axi/issues/36)) ([8723a8c](https://github.com/knowttl/falcon-axi/commit/8723a8cd60cbec4bd4d483089a637c1765859fdb))
* add setup commands and local session hooks ([#30](https://github.com/knowttl/falcon-axi/issues/30)) ([c0a1034](https://github.com/knowttl/falcon-axi/commit/c0a10347132672faa24d1a4c9e795f55a7d1fef5))
* **cli:** add fast version flags and refresh domain description ([#18](https://github.com/knowttl/falcon-axi/issues/18)) ([0ff408c](https://github.com/knowttl/falcon-axi/commit/0ff408c0277e5ed53349c7c8f8de983ba78c644e))
* **cli:** add field selection to detection and host lists ([#31](https://github.com/knowttl/falcon-axi/issues/31)) ([60d61de](https://github.com/knowttl/falcon-axi/commit/60d61de69636900aeb06d6287da82ec495b4448f))
* land Falcon pieces batch 2 (t1, t2, t4, t5) ([#39](https://github.com/knowttl/falcon-axi/issues/39)) ([3ab766e](https://github.com/knowttl/falcon-axi/commit/3ab766e9a86d5b33ef8484dd156a643fb8d4ac9a))
* land Falcon pieces batch 3 (d9, d10, d11) ([#40](https://github.com/knowttl/falcon-axi/issues/40)) ([6fc8efc](https://github.com/knowttl/falcon-axi/commit/6fc8efc85dcc4bccb6ba1af29ddc35f8c7612866))
* land Falcon read domains batch 1 (d1, d5, d6, d7, d8) ([#37](https://github.com/knowttl/falcon-axi/issues/37)) ([0c313d1](https://github.com/knowttl/falcon-axi/commit/0c313d1a5a506356254f478b441f156797d03580))


### Documentation

* close design questions and record falcon-mcp parity ([#15](https://github.com/knowttl/falcon-axi/issues/15)) ([f69c42b](https://github.com/knowttl/falcon-axi/commit/f69c42b71b6932fbb5e6a4e205e31bc1af186230))
* refresh onboarding and generate command references ([#42](https://github.com/knowttl/falcon-axi/issues/42)) ([6a0c55c](https://github.com/knowttl/falcon-axi/commit/6a0c55c728e6c043ac75fb13382f3e6fdce1cce1))

## [0.4.1](https://github.com/knowttl/falcon-axi/compare/v0.4.0...v0.4.1) (2026-10-18)


### Bug Fixes

* **ci:** pin setup-uv to a released version in the publish job ([#10](https://github.com/knowttl/falcon-axi/issues/10)) ([7055755](https://github.com/knowttl/falcon-axi/commit/70557559c1e24a01cc1599ccf90fd37e6e8ac25e))

## [0.4.0](https://github.com/knowttl/falcon-axi/compare/v0.3.0...v0.4.0) (2026-10-18)


### Features

* adopt AXI credential profiles ([#7](https://github.com/knowttl/falcon-axi/issues/7)) ([055546c](https://github.com/knowttl/falcon-axi/commit/055546c5fff46e8eebb8c7487d3f602f0fc1f939))
* enable PyPI releases through GitHub Actions ([#8](https://github.com/knowttl/falcon-axi/issues/8)) ([bcbf4e2](https://github.com/knowttl/falcon-axi/commit/bcbf4e291f4928e01be0c9bf09a9b4b2ea4f9523))

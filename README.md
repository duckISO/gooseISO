<h1 align="center">
  <a href="https://github.com/he3als/gooseISO/"><img src="https://github.com/he3als/gooseISO/raw/main/img/banner.png" alt="gooseISO Banner" width="900"></a>
  <br>gooseISO 🦆<br>
</h1>

<p align="center">
  <a href="https://github.com/he3als/gooseISO/src">Source code/building</a>
  ·
  <a href="https://github.com/he3als/gooseISO/src/GooseModules">Hashes of binaries</a>
</p>

My personal presets and scripts to modify Windows 11 with NTLite for performance and privacy. GooseISO is a fork of [AtlasOS](https://github.com/Atlas-OS/Atlas). It is focused on being a long term installation, with not a lot of items stripped (mostly UWP bloat is stripped), causing less issues in the future as you can re-enable what you have disabled.
- Defender is not stripped, but it is disabled by default
  - You may want or need it in the future, it is a good anti-virus that integrates into Windows well (your brain is better though mostly)
- Windows Update is not disabled, it is configured with policies and you can easily re-run the post installation script after an update
  - It is enabled for security and bug fixes (it is Windows 11 after all)
- Edge (configued with policies) is not stripped, it can be uninstalled and replaced with either LibreWolf of Brave
  - Couldn't strip it easily with free NTLite, plus it is nice to have an included web browser

### There are no ISOs provided
If you want to use this, [build it yourself](https://github.com/he3als/gooseISO/src). This is to avoid noobs using it and asking for help with simple things that they shouldn't need help for if they are knowingly using a custom ISO.

### Credits
- [AtlasOS](https://github.com/Atlas-OS/Atlas) - gooseISO a fork of Atlas - it wouldn't be able to be made without it
- [privacy.sexy](https://privacy.sexy/) - Disabling Defender and uninstalling Edge - a great project
- [ReviOS](https://www.revi.cc/revios) - Replacing Edge's associations in the Windows Registry
- Credit to the AtlasOS contributors as well

```
   _
>( . )__  <--- duck
 (_____/
```